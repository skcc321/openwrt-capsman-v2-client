#!/usr/bin/env python3
"""Offline verifier of one privately captured, approved HE80 run."""
from pathlib import Path
import re
import struct
import sys


def tlvs(data):
    pos = 0
    while pos + 4 <= len(data):
        tag, length = struct.unpack_from(">HH", data, pos)
        pos += 4
        if pos + length > len(data):
            raise ValueError("truncated TLV")
        yield tag, data[pos:pos + length]
        pos += length
    if pos != len(data):
        raise ValueError("trailing TLV bytes")


def beacons(path):
    data = path.read_bytes()
    assert data[:4] == b"\xd4\xc3\xb2\xa1", "expected little-endian pcap"
    assert struct.unpack_from("<I", data, 20)[0] == 127, "expected radiotap"
    off = 24
    while off + 16 <= len(data):
        length = struct.unpack_from("<I", data, off + 8)[0]
        off += 16
        pkt = data[off:off + length]
        assert len(pkt) == length
        off += length
        rtlen = struct.unpack_from("<H", pkt, 2)[0]
        frame = pkt[rtlen:]
        if frame[:2] != b"\x80\x00":
            continue
        tags = {}
        pos = 36  # 24-byte management header + 12-byte fixed beacon fields
        while pos + 2 <= len(frame):
            tag, size = frame[pos:pos + 2]
            pos += 2
            assert pos + size <= len(frame)
            value = frame[pos:pos + size]
            tags.setdefault((tag, value[0] if tag == 255 and value else None), []).append(value)
            pos += size
        assert pos == len(frame)
        if tags.get((0, None), [None])[0] != b"HWSIM-LAB-HE80":
            continue  # ignore unrelated virtual beacons, if any
        assert (45, None) in tags and (61, None) in tags, "HT elements missing"
        ht = tags[(61, None)][0]
        assert len(ht) >= 2 and ht[0] == 36 and ht[1] & 3 == 1, "not HT40+ on ch36"
        assert (191, None) in tags and (192, None) in tags, "VHT elements missing"
        vht = tags[(192, None)][0]
        assert len(vht) >= 2 and vht[0] == 1 and vht[1] == 42, (
            "VHT operation not 80 MHz/center channel 42")
        assert (255, 35) in tags and (255, 36) in tags, "HE elements missing"
        yield tags
    assert off == len(data)


def ack_observation(log, start_pos):
    """Report only what the logs establish, not a TLS write or receipt."""
    assert "0x6016: reject invalid channel descriptor" not in log
    assert "0x6016: AP not enabled" not in log
    assert re.search(r"RX 0x6027 poll .*-> 0xE027", log[start_pos:]), (
        "no manager 0x6027 poll observed after START")
    return ("ACK success path reached (TLS write not instrumented; "
            "RouterOS receipt unconfirmed); manager 0x6027 observed")


def main(path, polls=None):
    root = Path(path)
    trace = (root / "start-only.hex").read_text().splitlines()
    records = [s for s in trace if "start type=0x6016" in s]
    assert len(records) == 1, "expected exactly one manager START"
    match = re.fullmatch(
        r"\d+ start type=0x6016 port=0x0000 len=(\d+) ([0-9a-f]+)",
        records[0])
    assert match and len(bytes.fromhex(match[2])) == int(match[1])
    outer = dict(tlvs(bytes.fromhex(match[2])))
    assert 0x0a in outer, "START has no channel descriptor"
    channel = dict(tlvs(outer[0x0a]))
    assert channel[0x0b] == (5180).to_bytes(4, "big")
    assert channel[0x0c] == b"\x03"
    assert channel[0x0d] == (5210).to_bytes(4, "big")
    assert channel[0x10] == b"\x04"
    log = (root / "agent.log").read_text()
    assert log.count("RX 0x500b phy=") == 1
    assert log.count("RX 0x6016 start port=") == 1
    # Lifecycle order: JOIN -> NEWPHY -> CREATEVAP -> START -> hostapd up.
    steps = ("joined TLS to 192.168.88.1:5246", "NEWPHY phy=0",
             "RX 0xc029 joinresp", "RX 0x500b phy=0", "0xd00b phy=0",
             "RX 0x6016 start port=0x0000")
    pos = -1
    for step in steps:
        nxt = log.find(step, pos + 1)
        assert nxt > pos, f"lifecycle step missing or out of order: {step}"
        pos = nxt
    hostapd = re.search(r"vap: hostapd (phy0-ap0|cap0-0) .*freq=5180", log[pos:])
    assert hostapd, "no hostapd start after START"
    # Absence of a rejection only supports the code-path inference; the
    # response writer does not report a successful transport write.
    assert "reconnect in " not in log and "disconnected\n" not in log
    assert "STOP=30s session ceiling" in log, "session did not run to the ceiling"
    state = (root / "guest-state.log").read_text()
    assert "channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz" in state
    for name in ("phy0-ap0", "cap0-0"):
        hostlog = root / f"hostapd-{name}.log"
        conf = root / f"hostapd-{name}.conf"
        if hostlog.exists() and conf.exists():
            assert "AP-ENABLED" in hostlog.read_text()
            text = conf.read_text()
            for expected in ("ssid=HWSIM-LAB-HE80", "ht_capab=[HT40+]",
                             "ieee80211ax=1", "vht_oper_chwidth=1",
                             "vht_oper_centr_freq_seg0_idx=42",
                             "he_oper_chwidth=1",
                             "he_oper_centr_freq_seg0_idx=42"):
                assert expected in text
            assert "noscan=1" not in text
            break
    else:
        raise AssertionError("no hostapd config+AP-ENABLED pair")
    count = sum(1 for _ in beacons(root / "beacons.pcap"))
    assert count >= 1
    observation = ack_observation(log, pos)
    print(f"PASS: one decoded manager START 5180/width3/band04/center5210; "
          f"AP-ENABLED; iw 80 MHz/5210; "
          f"{count} matching HE/HT40+/VHT hwsim beacons; {observation}")
    if polls:
        text = Path(polls).read_text()
        flags = []
        in_wifi = False
        for line in text.splitlines():           # flags line may carry ;;;
            if line == "WIFI":
                in_wifi = True
            elif in_wifi and re.match(r"\s*0\s+[A-Z]+", line):
                flags.append(line.split()[1])
                in_wifi = False
        assert 'state="Ok"' in text, "RouterOS never reported Remote CAP state Ok"
        assert "5180/ax/Ceee" in text, "RouterOS radio lacks the AX 80 MHz channel"
        assert any("B" in f for f in flags), "cap-wifi1 never bound to the CAP"
        print(f"PASS: manager 0x6027 poll after START; RouterOS Remote CAP Ok, "
              f"5180/ax/Ceee, cap-wifi1 flags {' '.join(flags)}")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: verify_he80_live.py PRIVATE_EVIDENCE_DIR [ROUTER_POLLS]")
    main(sys.argv[1], sys.argv[2] if len(sys.argv) == 3 else None)
