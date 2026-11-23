#!/usr/bin/env python3
"""Verify saved isolated hwsim AP captures (not a physical RF or client test)."""
from pathlib import Path
import struct
import sys


def beacons(path):
    raw = Path(path).read_bytes()
    assert raw[:4] == b"\xd4\xc3\xb2\xa1"
    assert struct.unpack_from("<I", raw, 20)[0] == 127  # radiotap
    off = 24
    while off + 16 <= len(raw):
        size = struct.unpack_from("<I", raw, off + 8)[0]
        off += 16
        packet = raw[off:off + size]
        assert len(packet) == size
        off += size
        rt = struct.unpack_from("<H", packet, 2)[0]
        frame = packet[rt:]
        if len(frame) < 36 or frame[0] != 0x80:
            continue
        tags = {}
        elements = frame[36:]  # 24-byte management header + beacon fixed fields
        i = 0
        while i + 2 <= len(elements):
            kind, n = elements[i:i + 2]
            i += 2
            assert i + n <= len(elements)
            value = elements[i:i + n]
            tags[(kind, value[0] if kind == 255 and value else None)] = value
            i += n
        assert i == len(elements)
        yield tags
    assert off == len(raw)


def verify(base):
    root = Path(base)
    for name, width, centre in (("he20", 20, 5180),
                                ("he40", 40, 5190),
                                ("he80", 80, 5210)):
        info = (root / f"{name}.iw.txt").read_text()
        assert f"width: {width} MHz" in info
        assert f"center1: {centre} MHz" in info
        assert "AP-ENABLED" in (root / f"{name}.hostapd.log").read_text()
        rows = [tags for tags in beacons(root / f"{name}.pcap")
                if tags.get((0, None)) == f"PR3-{name.upper()}".encode()]
        assert rows
        for tags in rows:
            assert (255, 35) in tags and (255, 36) in tags
            assert (61, None) in tags and (192, None) in tags
            op = tags[(192, None)]
            assert op[0] == (width == 80)
            if width == 80:
                assert op[1] == 42
        print(f"{name}: {len(rows)} hwsim beacons, HE/HT/VHT, "
              f"nl80211 {width} MHz center {centre}: PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: verify_he_wide_hwsim.py EVIDENCE_DIR")
    verify(sys.argv[1])
