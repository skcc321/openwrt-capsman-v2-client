#!/usr/bin/env python3
"""Same-PHY hwsim multi-BSS START reproduction; no CAP/TLS or router.

Use only in the preflighted isolated UA hwsim VM. Each case owns exactly
heagent0/heagent1, its own journal, and an evidence directory that does not
exist yet. A failure leaves its evidence intact for driver/agent diagnosis.
"""
import os
from pathlib import Path
import subprocess
import sys
import time


def cmd(*args):
    return subprocess.run(args, text=True, capture_output=True, timeout=5)


def snapshot(out, label):
    (out / f"{label}.iw-dev.txt").write_text(cmd("iw", "dev").stdout)
    (out / f"{label}.interfaces.txt").write_text(cmd("ip", "-br", "link").stdout)
    (out / f"{label}.hostapd-processes.txt").write_text(cmd("pgrep", "-a", "-x", "hostapd").stdout)
    for ifname in ("heagent0", "heagent1"):
        data = cmd("iw", "dev", ifname, "info").stdout
        if data:
            (out / f"{label}.{ifname}.iw.txt").write_text(data)


def checked_environment():
    assert os.geteuid() == 0
    assert Path("/sys/class/net/wlan0/address").read_text().strip() == "02:ca:50:11:22:01"
    assert not cmd("ip", "-o", "addr", "show", "dev", "wlan0").stdout
    assert "country UA: DFS-ETSI" in cmd("iw", "reg", "get").stdout
    phy = cmd("iw", "phy", "phy0", "info").stdout
    assert "HE40/HE80/5GHz" in phy
    for freq in (5180, 5200, 5220, 5240):
        line = next(s for s in phy.splitlines() if f"* {freq}.0 MHz" in s)
        assert not any(flag in line for flag in ("disabled", "no IR", "radar detection"))
    assert cmd("iw", "dev").stdout.count("phy#") == 1
    assert not cmd("pgrep", "-x", "hostapd").stdout
    assert not cmd("pgrep", "-x", "capagent").stdout
    for ifname in ("heagent0", "heagent1"):
        assert not Path(f"/sys/class/net/{ifname}").exists()
        assert not Path(f"/tmp/vap-{ifname}.conf").exists()
        assert not Path(f"/var/run/vap-{ifname}.pid").exists()


def run_case(binary, out, first, second):
    checked_environment()
    out.mkdir(mode=0o700)
    started = []
    try:
        for index, width in enumerate((first, second)):
            name = f"heagent{index}"
            center = {1: 0, 2: 5190, 3: 5210}[width]
            journal = out / f"{name}.state"
            env = {k: v for k, v in os.environ.items() if not k.startswith("CAPAGENT_")}
            env.update(CAPAGENT_HOSTAPD="/usr/sbin/hostapd",
                       CAPAGENT_TEST_JOURNAL=str(journal),
                       CAPAGENT_OFFLINE_HOLD_SEC="28" if index == 0 else "5")
            log = Path(f"/tmp/vap-{name}.log")
            old_log_mtime = log.stat().st_mtime_ns if log.exists() else 0
            proc = subprocess.Popen(
                (binary, "5180", str(width), str(center),
                 f"PR3-MULTI-{index}", name), env=env,
                stdout=(out / f"{name}.agent.log").open("w"),
                stderr=subprocess.STDOUT, start_new_session=True)
            started.append(proc)
            deadline = time.monotonic() + 17
            while time.monotonic() < deadline:
                info = cmd("iw", "dev", name, "info").stdout
                if (f"width: {20 if width == 1 else 40 if width == 2 else 80} MHz" in info
                        and log.exists() and log.stat().st_mtime_ns > old_log_mtime
                        and "AP-ENABLED" in log.read_text()):
                    (out / f"{name}.iw-at-ready.txt").write_text(info)
                    (out / f"{name}.hostapd.log").write_text(log.read_text())
                    break
                if proc.poll() is not None:
                    break
                time.sleep(.1)
            snapshot(out, f"after-{name}")
            if index == 0 and not (out / f"{name}.iw-at-ready.txt").exists():
                raise RuntimeError("first BSS did not start; see saved agent/hostapd logs")
            if index == 1:
                outcome = (out / f"{name}.iw-at-ready.txt").exists()
                if log.exists() and log.stat().st_mtime_ns > old_log_mtime:
                    (out / f"{name}.hostapd.log").write_text(log.read_text())
                (out / "second-outcome.txt").write_text(
                    f"first={first} second={second} second_ap_enabled={outcome}\n")
                print(f"first HE{first * 20 if first < 3 else 80}, "
                      f"second HE{second * 20 if second < 3 else 80}: "
                      f"{'both AP-ENABLED' if outcome else 'second did not enable'}",
                      flush=True)
                if not outcome:
                    raise RuntimeError("second BSS did not enable; see saved evidence")
        for proc in started:
            if proc.wait(timeout=36) != 0:
                raise RuntimeError("offline START injector failed; see saved agent logs")
    finally:
        for proc in started:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        snapshot(out, "after-cleanup")
        for name in ("heagent0", "heagent1"):
            if Path(f"/sys/class/net/{name}").exists():
                raise RuntimeError(f"{name} still exists: preserve evidence for owner-scoped inspection")
    assert not cmd("pgrep", "-x", "hostapd").stdout
    checked_environment()


def main(binary, root):
    root = Path(root)
    checked_environment()
    assert not root.exists()
    root.mkdir(mode=0o700)
    for label, first, second in (("he40-he40", 2, 2), ("he80-he80", 3, 3),
                                  ("he20-he40", 1, 2), ("he20-he80", 1, 3)):
        run_case(binary, root / label, first, second)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: run_he_wide_multibss.py BINARY NEW_EVIDENCE_DIR")
    main(sys.argv[1], sys.argv[2])
