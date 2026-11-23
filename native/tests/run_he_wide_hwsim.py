#!/usr/bin/env python3
"""Approval-free, isolated hwsim AP probe; never connects to CAPsMAN.

Run as root in the dedicated Ubuntu VM with ./offline_ax_start built from
this tree. Output directory must not exist (old evidence is never overwritten).
"""
import os
import pathlib
import shutil
import signal
import subprocess
import sys
import time


def call(*args):
    return subprocess.run(args, text=True, capture_output=True, timeout=5)


def main(binary, out):
    out = pathlib.Path(out)
    assert os.geteuid() == 0 and not out.exists()
    assert pathlib.Path("/sys/class/net/wlan0/address").read_text().strip() == "02:ca:50:11:22:01"
    assert not pathlib.Path("/sys/class/net/heagent0").exists()
    assert not pathlib.Path("/tmp/vap-heagent0.conf").exists()
    assert not pathlib.Path("/var/run/vap-heagent0.pid").exists()
    assert not call("pgrep", "-x", "hostapd").stdout.strip()
    assert not call("pgrep", "-x", "capagent").stdout.strip()
    assert "country UA: DFS-ETSI" in call("iw", "reg", "get").stdout
    assert not call("ip", "-o", "addr", "show", "dev", "wlan0").stdout
    phy = call("iw", "phy", "phy0", "info").stdout
    for freq in (5180, 5200, 5220, 5240):
        line = next(s for s in phy.splitlines() if f"* {freq}.0 MHz" in s)
        assert not any(flag in line for flag in ("disabled", "no IR", "radar detection"))
    assert "HE40/HE80/5GHz" in phy
    out.mkdir(mode=0o700)
    was_up = "UP" in call("ip", "-br", "link", "show", "hwsim0").stdout
    cases = (("he20", 1, 0, True), ("he40", 2, 5190, True),
             ("he80", 3, 5210, True), ("bad40", 2, 5210, False),
             ("bad80", 3, 5190, False), ("he160", 4, 5210, False))
    try:
        for name, width, centre, good in cases:
            journal = out / f"{name}.state"
            env = {k: v for k, v in os.environ.items() if not k.startswith("CAPAGENT_")}
            env.update(CAPAGENT_HOSTAPD="/usr/sbin/hostapd",
                       CAPAGENT_TEST_JOURNAL=str(journal),
                       CAPAGENT_OFFLINE_HOLD_SEC="6")
            conf = pathlib.Path("/tmp/vap-heagent0.conf")
            proc = capture = None
            try:
                if good:
                    subprocess.run(("ip", "link", "set", "hwsim0", "up"), check=True, timeout=5)
                    capture = subprocess.Popen(
                        ("tcpdump", "-i", "hwsim0", "-U", "-s", "0",
                         "-w", str(out / f"{name}.pcap"), "type", "mgt",
                         "subtype", "beacon"), stdout=subprocess.DEVNULL,
                        stderr=(out / f"{name}.capture.log").open("w"),
                        start_new_session=True)
                    time.sleep(.3)
                    assert capture.poll() is None
                proc = subprocess.Popen(
                    (binary, "5180", str(width), str(centre), f"PR3-{name.upper()}"),
                    env=env, stdout=(out / f"{name}.agent.log").open("w"),
                    stderr=subprocess.STDOUT, start_new_session=True)
                seen = False
                for _ in range(240):
                    if conf.exists() and not seen:
                        shutil.copyfile(conf, out / f"{name}.conf")
                        seen = True
                    if good:
                        info = call("iw", "dev", "heagent0", "info").stdout
                        if f"width: {20 if width == 1 else 40 if width == 2 else 80} MHz" in info:
                            (out / f"{name}.iw.txt").write_text(info)
                    if proc.poll() is not None:
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError(f"{name}: agent exceeded 24 s")
                assert proc.returncode == (0 if good else 1), (name, proc.returncode)
                if good:
                    assert seen
                    info = (out / f"{name}.iw.txt").read_text()
                    assert "channel 36 (5180 MHz)" in info
                    if width > 1:
                        assert f"center1: {centre} MHz" in info
                    text = (out / f"{name}.conf").read_text()
                    assert "ieee80211ax=1" in text
                    assert f"he_oper_chwidth={int(width == 3)}" in text
                    if width > 1:
                        assert "ht_capab=[HT40+]" in text
                        assert "noscan=1" not in text
                    if width == 3:
                        assert "he_oper_centr_freq_seg0_idx=42" in text
                        assert "vht_oper_centr_freq_seg0_idx=42" in text
                    log = pathlib.Path("/tmp/vap-heagent0.log")
                    shutil.copyfile(log, out / f"{name}.hostapd.log")
                    assert "AP-ENABLED" in (out / f"{name}.hostapd.log").read_text()
                assert not pathlib.Path("/sys/class/net/heagent0").exists()
                assert not conf.exists() and not journal.exists()
                assert not call("pgrep", "-x", "hostapd").stdout.strip()
                print(name, "PASS", flush=True)
            finally:
                if proc and proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=2)
                if capture and capture.poll() is None:
                    os.killpg(capture.pid, signal.SIGTERM)
                    capture.wait(timeout=2)
                if pathlib.Path("/sys/class/net/heagent0").exists():
                    raise RuntimeError(f"{name}: owned AP VIF left behind; preserve for inspection")
    finally:
        if not was_up:
            subprocess.run(("ip", "link", "set", "hwsim0", "down"), check=True, timeout=5)
    assert call("iw", "dev").stdout.count("phy#") == 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: run_he_wide_hwsim.py BINARY NEW_EVIDENCE_DIR")
    main(sys.argv[1], sys.argv[2])
