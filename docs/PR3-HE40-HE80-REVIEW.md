# Local PR #3 review candidate — 5 GHz HE40/HE80

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
  SHA-256: `fe87348d4e1bce9b4b21244696f55a18d46c6f57e854af037c084b361340e334`.
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
regdb and wiphy formats, multi-BSS scan behavior, and foreground
hostapd child/reaping under independent review. A CAC-aware AX DFS path
would require its own tests and review; never bypass radar scans.
