# HE40 / HE80 RB5009 integration — plan only, NOT approved to run

**STOP:** Offline validation does not authorize a CAP/TLS session,
RouterOS changes, router Safe Mode, or touching Xiaomi RA80. Obtain
**separate explicit approval for HE40 and for HE80** after independent
review of the candidate and test supervisor. Consult the preserved
`capsman_discovery/HE40-live-runbook.md` and `HE80-live-runbook.md`;
their older pinned binaries/HE20 runner are **not** this candidate.

Before requesting approval, create width-specific, hash-pinned guest
and host supervisors. Each must assert the exact PR #3 binary SHA,
dedicated virtual radio and MAC, indoor UA domain, all constituents
non-no-IR/non-DFS, PHY AP HE/HT40/VHT, absent prior CAP/hostapd,
isolated capture and unchanged route/eth0/wlan0. A human administrator
must own any RouterOS Safe Mode transaction and documented rollback.
Never use a physical RA80 or a real wireless client as a substitute.

For each *separately approved* bounded session, check NEWPHY band
`0x04` width mask; CREATEVAP exact channel descriptor and complete
`0x61`/`0xb7` tail; actual manager-selected START
`5180/2/0x04/5190` for HE40 or `5180/3/0x04/5210` for HE80; then
agent-generated hostapd config, AP-ENABLED, independent nl80211
40/80 MHz center, and HE/HT/VHT beacon elements. Abort on any other
width/center, failure to enable, unexpected hostapd/DFS behavior,
unbounded retry, or isolation/state drift. Roll back only resources
created for that approved session and independently verify the router
and guest baselines. Never infer manager acceptance from offline
fixtures or earlier HE20 integration.
