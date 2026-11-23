# Local PR #3 review candidate — 5 GHz HE40/HE80

## Final HE40 live run and rollback (2026-11-23)

One approved HE40 session succeeded: START 5180/width 2/center 5190,
`AP-ENABLED`, 279 HE/HT40/VHT beacons, 28 `iw` snapshots at 40 MHz,
and the manager's subsequent `0x6027` poll. The `0xE016` success
**code path** was reached; its TLS transport write is not instrumented
and RouterOS receipt is unconfirmed. The subsequent `0x6027` is a
separate manager observation, **not proof** of ACK receipt. Bound
(`MB`) and Remote CAP `Ok` also occurred in a no-ACK run and do not
prove ACK receipt. NEWPHY
and CREATEVAP are logged as summaries only; no client or physical
ath11k test was performed.

The administrator discarded Safe Mode action 124. Read-only RouterOS
audit found it REDOABLE, no floating change, sole disabled `MX`
`cap-wifi1`, no HE40 settings, and all nine protected baseline sections
matched. See `capsman_discovery/he40-live-20261123T173219Z-report.md`
and `capsman_discovery/he40-final-20261123/`. All captures and failed
run evidence are preserved. No PR #3 commit or push.

## Independent review follow-ups (publication candidate)

The live verifiers now report only "ACK success path reached (TLS write
not instrumented; RouterOS receipt unconfirmed); manager `0x6027`
observed". A portable regression checks both HE40/HE80 wording,
including a simulated silent writer failure; neither verifier calls
the manager poll proof of ACK receipt. The old live report text is
historical and is corrected by this addendum rather than rewriting
the preserved raw evidence.

**Late AP-DISABLED:** the existing readiness check reads ordered
hostapd events through the one-second settle window; the watchdog
subsequently checks child/netdev liveness, not AP state. An
`AP-ENABLED` then `AP-DISABLED` while the child remains alive *after*
settling would not be detected as AP loss. The saved HE40/HE80
`AP-DISABLED` events occur during supervised shutdown, not during
the run; this scenario has not been reproduced on a live CAP or
physical driver. We do not claim continuous post-ACK AP availability,
and do not add a speculative new owner-scoped hostapd status
protocol in PR #3.

**PID directory trust:** `vap_write_pidfile()` creates
`/var/run/vap-<ifname>.pid.tmp` with `O_TRUNC` and then renames it.
The dedicated VM has `/var/run -> /run`, with `/run` root-owned
mode 0755: an unprivileged user cannot place a symlink there.
On a target where `VAP_RUN_DIR` is writable by an untrusted actor,
a pre-planted symlink at that fixed `.tmp` path could redirect
root's truncation. This is a real *conditional* path hazard,
not a confirmed exploit in the root-controlled deployment; preserve
the trusted-directory requirement. A future hardening change could
use `O_NOFOLLOW`/exclusive unpredictable temporary creation and
adversarial tests, but doing so here would alter W52 lifecycle
behavior without a verified target need.

Physical Xiaomi AX3000/ath11k, WPA2/WPA3 association, VLAN
forwarding, roaming, physical RF/DFS-CAC and throughput remain
untested. No hwsim or RouterOS result qualifies physical hardware.

**Stack:** `pr3/he40-he80` is based on unchanged `pr2/he20-ax`
(`d02ee6a81308642334d734a96848c9c24c5db707`). Nothing has been
pushed or submitted. PR #1 and PR #2, their captures and the original
uncommitted `openwrt-capsman-he-ax/` experiment were not modified.

## Experimental baseline and selective reuse

`capsman_discovery/HE40-HE80-2026-11-22.md` and
`HE40-HE80-agent-client-validation-2026-11-23.md` record independent
UA hwsim HE40/HE80 hostapd starts and production-path, separate-radio
open-SSID client association. Their experimental branch predates PR #2's
band-scoped frequency parser, rule-level width gates, strict START parser
and failed-START/retry behavior. This candidate selectively reuses its
wire encoding (widths 2/3, centers 5190/5210), hostapd scan lifecycle
and log-tail readiness behavior, **not** its permissive PHY parser,
regulatory handling, debug tracing or unrelated changes.

## Scope and policy

- 5 GHz AP HE PHY capability bit for HE40/HE80, band-local HT40 and
  VHT capability, shared PHY band, and all 20 MHz constituents are
  required. Only the standard 5 GHz 80 MHz blocks actually supported by
  the hostapd backend are considered; channel 165+ stays HT20-only.
- Both global and relevant wiphy `iw reg get` rules must cover the
  entire 40/80 MHz block with a sufficient *explicit maximum bandwidth*.
  Honor NO-HT40PLUS/MINUS, NO-80MHZ, NO-OUTDOOR/indoor and PR #2's
  unknown/no-IR/NO-HE denial. Any overlapping denying rule fails closed.
  No DFS AX channel is advertised: CAC/radar for AX has not been
  validated. Legacy DFS/CAC behavior is unchanged.
- NEWPHY width mask is derived from the same predicate as CREATEVAP
  descriptors and START validation. HE80 requires a valid HT40 primary
  pair; HE160, EHT, 6 GHz and unsupported combinations remain refused.
  HE20 wire output and failed-START ACK/retry semantics remain PR #2's.
- AX40/80 hostapd runs without `noscan`, lets hostapd perform HT
  coexistence on the CAP-owned VIF, stays in foreground for readiness,
  and writes HE operating width/center index (and existing VHT/HT
  operation) for the validated manager-selected channel.

## Local validation

- macOS: parser and production wire fixtures; UBSan channel wire.
  The macOS ASan+UBSan test binary exits with SIGILL in this environment;
  Linux ASan+UBSan passes. macOS cannot build Linux-only `extmux`
  (SOCK_NONBLOCK); Linux does.
- Ubuntu 24.04 x86_64 Lima/QEMU: parser, extmux, channel wire, offline
  START and retry; ASan/UBSan wire and START. Full saved UA `iw phy`
  plus `iw reg get` tested in addition to compact and synthetic rules.
- OpenWrt qualcommax/ipq50xx AArch64/musl, mbedTLS 3.6.2: static build
  and QEMU crypto, policy **27/27**, W34 ownership/netifd tests. Three
  existing compiler truncation warnings remain. Final ARM64 binary
  Earlier candidate SHA-256:
  `fe87348d4e1bce9b4b21244696f55a18d46c6f57e854af037c084b361340e334`.
  The uncommitted review-fix build has a different hash (recorded below).
- Isolated UA `mac80211_hwsim` VM: production START validator and
  provisioning, stock hostapd, owner-scoped cleanup. HE20/40/80 each
  reached AP-ENABLED; `iw` showed 5180 MHz at 20/40/80 MHz with center
  5180/5190/5210. Saved reviewed-build captures contain **66/96/95** SSID beacons
  with HE Capabilities/Operation and HT/VHT Operation; HE80 VHT center
  index 42. Bad HE40/HE80 centers and width 4 were rejected. Original
  wlan0, hwsim0 DOWN, UA domain and absent hostapd were checked after.
  Evidence: `capsman_discovery/pr3-he40-he80-offline-20261123/evidence-reviewed/`.
  Reproduce with `make -C native offline-ax-start HOST_MBEDTLS=...`,
  `sudo python3 native/tests/run_he_wide_hwsim.py BINARY NEW_EVIDENCE_DIR`
  **only in an independently preflighted isolated hwsim VM**, then
  `python3 native/tests/verify_he_wide_hwsim.py EVIDENCE_DIR`.

## Independent-review risks and missing gates

No real RouterOS HE40/HE80 selection or 0x6016 capture exists. The
width/center encoding is inferred from legacy wire observations and
offline fixtures. No final PR #3 secure-client association, actual
HE-data MCS, physical Xiaomi RA80/ath11k, RF, throughput, or OpenWrt
target-hostapd validation is claimed. Previous experimental open-SSID
client associations were for the **earlier uncommitted revision**, not
this candidate. The max-width parser is intentionally conservative
(overlapping rules can refuse otherwise legal blocks); recheck unusual
regdb and wiphy formats. Same-PHY hwsim coexistence and foreground
hostapd child/reaping are covered below; physical ath11k coexistence
remains unverified. A CAC-aware AX DFS path
would require its own tests and review; never bypass radar scans.

## Follow-up independent-review fixes (local, uncommitted)

- Production hostapd readiness now parses **complete log lines in order**,
  including logs longer than 4 KiB. The latest relevant AP state wins:
  `AP-DISABLED` followed by `AP-ENABLED` succeeds, and the reverse
  order fails. A transient disabled state is observed through the
  bounded readiness window so a later enabled event can recover;
  a disabled-only window fails. An incomplete final line is not a
  state. Legacy DFS-CAC
  readiness is retained, but an AX BSS needs `AP-ENABLED`; after its
  one-second settling interval AX is checked again for an enabled,
  live hostapd. Host-side regression tests cover both event orders.
- Every forked hostapd child is tracked by the CAP-owned interface name.
  The initial bounded `waitpid(WNOHANG)` catches early exits; failed or
  timed-out starts and owner-scoped teardown apply bounded TERM/KILL
  waits and reap foreground children. A periodic targeted watchdog
  sweep reaps children that exit after startup, without waiting on
  adopted/netifd processes. Host-side tests cover early failure,
  running foreground child, TERM-resistant timeout and late exit;
  each verifies `ECHILD` after cleanup.

### Same-PHY coexistence investigation

The upstream
[W54 MT7612E analysis](https://github.com/DarkNikGr/openwrt-capsman-v2-client/blob/main/docs/W54-MT7612E-PERBSS.md)
documents an `mt76x02`-specific MAC-to-BSS-index collision and a
separate HT40 offchannel scan `-EBUSY` when another BSS occupies that
driver's single-channel PHY. hostapd's
`ieee80211n_check_40mhz()` initiates an HT40 neighbor scan when
`secondary_channel != 0`, including for HE40 and HE80 (both use
`HT40+` here). The scan can switch primary/secondary placement or
fall back; disabling it blindly with OpenWrt's `noscan` patch would
change coexistence behavior. **This candidate does not do that.**

The isolated Ubuntu `mac80211_hwsim` production-START reproduction
creates two independently owned AP interfaces on the *same phy0*.
The second hostapd log records `UNINITIALIZED->HT_SCAN->ENABLED`.
HE40+HE40, HE80+HE80, HE20+HE40 and HE20+HE80 all reached simultaneous
`AP-ENABLED` with their expected nl80211 centers; owner-scoped
teardown removed both APs. The working hwsim result establishes that
W54's busy-scan problem is **not universal to mac80211_hwsim** under
this lab's kernel/stock hostapd/UA-domain configuration. It does
**not** establish any ath11k/Qualcomm behavior: that driver, firmware,
interface-address plan and OpenWrt hostapd must be tested on hardware.
The MT7612E BSSID-index workaround is not transplanted.
The verified two-process snapshots, each hostapd's `HT_SCAN` and
`AP-ENABLED` log, both `iw dev` states, and post-cleanup snapshots are
preserved under
`capsman_discovery/pr3-he40-he80-review-fixes-20261123/multibss-reviewed-source/`.
Its preserved guest archive SHA-256 is
`6035bdcb6efabf23e565ba246d0ae7a331c89a5ede5402281ebc88b5bf2420ac`.
Reproduce only in the preflighted isolated VM with
`sudo python3 native/tests/run_he_wide_multibss.py BINARY NEW_EVIDENCE_DIR`.

The final source revision also passed `make check` in Ubuntu 24.04
using the OpenWrt qualcommax/ipq50xx AArch64/musl toolchain and QEMU
(wire formats, parser, extmux, legacy START/ACK, ownership, automatic
retry, crypto and policy **27/27**). Linux ASan/UBSan START and wire
tests passed. Its AArch64 binary SHA-256 is
`a27207475e0365271e7e8b84eede57e91b53c21c26f98b1da65f71da11a79985`;
the three prior compiler truncation warnings remain. Final isolated
single-AP regression passed HE20/40/80 and wrong-center/HE160 rejection.
The post-delayed-event-fix HE20/40/80 captures contain **66/96/96**
SSID beacons and are
saved at
`capsman_discovery/pr3-he40-he80-review-fixes-20261123/single-delayed-events/`.
Its preserved guest archive SHA-256 is
`9f57707aa72921c0b9414d4e3c50099b9e4674751031104351b4de7e803cc4e9`.
The full build/test log and sanitizer log are saved alongside them.
Both hwsim AP interfaces, hostapd processes (including zombies),
test configs and pid files were absent after the multi-BSS and
single-AP runs; wlan0 and hwsim0 remained DOWN and UA unchanged.

There is no justified generic scan-suppression fix. For an eventual
separately authorized ath11k lab test, preflight the real PHY's
supported AP interface count, BSSID address list, per-band HE/HT/VHT
capabilities, full-block country rules and the absence of no-IR/DFS
on each constituent. Start two **isolated, CAP-owned** same-PHY APs
sequentially at legal indoor non-DFS HE40 and HE80 settings, retaining
normal coexistence scanning; capture each hostapd `HT_SCAN`,
offchannel scan errors/`-EBUSY`, `AP-ENABLED`/`AP-DISABLED`, independent
`iw` width/center and beacon operation fields. Distinguish driver
`add_interface`/address rejection from scan failure and from an
agent ACK/cleanup bug. Bound both starts and owner-scoped teardown.
Stop on any error and seek separate approval before involving
RouterOS; no DFS/CAC bypass or physical RA80 qualification is implied.

## Review disposition

The two reported lifecycle defects are corrected and covered by offline
regressions; the same-PHY hwsim reproduction found no generic scan
failure, so no driver-specific workaround was added. This uncommitted
candidate is **ready for another independent code review**, not for
physical ath11k/RA80 qualification or an approved HE40/HE80 RouterOS
session. Preserve the width-specific approval gates in the live plan.

## Live HE40 finding: START ACK withheld for foreground hostapd (fixed locally)

RouterOS 7.25.1 run 2026-11-23 16:45Z
(`capsman_discovery/he40-live-20261123T164519Z-report.md`): START
selected 5180 / width 2 / center 5190 / band 0x04. hostapd reached
`AP-ENABLED`, `iw` showed 40 MHz with center1 5190, and the capture held
280 HE/HT40+/VHT beacons. The agent logged `hostapd … pid=73736` and
`own: … restored pid=73736`, then `0x6016: AP not enabled … withholding
0xE016`.

**Root cause:** wide AX runs hostapd in the foreground (no `-B`, so the
HT coexistence scan completes before readiness), and hostapd writes its
`-P` pid file only when it daemonizes. `vap_hostapd_start_one()` found
the process through a `/proc` fallback, but `vap_provision()` derives
the ACK from `vap_hostapd_pid()` (pid file + cmdline), which returned 0.
The same pid-file identity also drives W52 reconnect restore, adoption,
stale cleanup and the "one hostapd per BSS" guard. The offline test
mock always wrote the pid file, and the hwsim injector ignored
`vap_provision()`'s result and used its own fallback, so both masked it.

**Fix:** for a foreground child (wide AX or `CAPAGENT_HOSTAPD_DEBUG`),
after `AP-ENABLED`, the agent confirms the tracked child is still
running and atomically writes its pid to the same pid file. A child
that has already exited, or a failed write, is a failed start: no ACK,
bounded reap. The startup and settle checks now use only
`vap_hostapd_pid()` (no fallback), so the start path and the ACK
decision agree. When a tracked child is reaped, its agent-written pid
file is removed only if it still names that pid; a `-B` daemon's file
is never touched. `own_stop_pid()` reaps tracked children through the
bounded `vap_child_stop()` (a zombie passes `kill(pid, 0)`). `-B`
(HE20/legacy) behavior is unchanged. This keeps upstream W52's
identity rule (pid file + `/proc` cmdline + journal) and its
"no zombie" guarantee. Upstream's foreground `-dd` debug mode had the
same latent gap and is covered by the same path.

**Regression:** `test_start_offline` sends a production HE40 START
through `cap_handle_start` and the ownership start path, using a
foreground mock hostapd that never writes a pid file. It asserts that
`0xE016` is sent, that the agent-written pid file names the tracked
child, that an identical repeat and the reconcile tick start no
duplicate, and that ownership teardown reaps the child and drops the
pid file. It also covers late death (sweep reaps it and drops the pid
file) and early exit after `AP-ENABLED` (no ACK, no zombie). With only
the pid-file write disabled, the test fails at the HE40 START with the
live log line `0x6016: AP not enabled … withholding success 0xE016`.
The hwsim injector now prints and requires `vap_provision()`'s ACK
decision: `ack=1` for HE20 (`-B`), HE40 and HE80; `ack=0` for wrong
centers and HE160. A W34 test stub was added for the new helper.
