#include <errno.h>
#include <stdlib.h>

/* Channel restrictions printed after PR #1's validated "* N MHz [ch]" prefix
 * (iw_freq.inc). Every "(...)" group must be a power or a known flag, and the
 * line must end there; a damaged suffix may have hidden a restriction. */
static int iw_freq_flags(const char *line, int *dfs)
{
    const char *p = strstr(line, "MHz");
    if (!p) return 0;
    p += 3;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '[') {
        p = strchr(p, ']');
        if (!p) return 0;
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    *dfs = 0;
    while (*p == '(') {
        const char *start = ++p;
        while (*p && *p != ')' && *p != '\n' && *p != '\r') p++;
        if (*p != ')') return 0;
        size_t n = (size_t)(p - start);
        for (size_t j = 0; j < n; j++) {
            if ((n - j >= 8 && !memcmp(start + j, "disabled", 8)) ||
                (n - j >= 5 && !memcmp(start + j, "no IR", 5)) ||
                (n - j >= 7 && !memcmp(start + j, "no OFDM", 7)) ||
                (n - j >= 10 && !memcmp(start + j, "NO-OUTDOOR", 10)))
                return 0;
        }
        if (n == 15 && !memcmp(start, "radar detection", n)) {
            *dfs = 1;
        } else {
            char *power_end;
            if (!n || start[0] < '0' || start[0] > '9') return 0;
            errno = 0;
            (void)strtod(start, &power_end);
            if (errno == ERANGE || power_end + 4 != p ||
                memcmp(power_end, " dBm", 4)) return 0;
        }
        p++;
        while (*p == ' ' || *p == '\t') p++;
    }
    if (*p == '\r') p++;
    return *p == '\n' || *p == '\0';
}

/* Mark only frequencies belonging to this band as HE AP eligible. Duplicate
 * frequencies in multiple iw bands remain eligible if either band has HE AP. */
static void mark_phy_he_band(struct phy_bands *pb, const uint32_t *freq,
                             int nfreq, int he_ap)
{
    if (!he_ap) return;
    for (int i = 0; i < pb->nfreq; i++) {
        if (pb->freq[i] < 4900 || pb->freq[i] >= 5925) continue;
        for (int j = 0; j < nfreq; j++)
            if (freq[j] == pb->freq[i]) {
                if (!pb->dfs[i]) {
                    pb->he5freq[i] = 1;
                    pb->he5 = 1;
                }
                break;
            }
    }
}

/* Parse iw's band-scoped AP capabilities and per-channel regulatory flags.
 * Legacy DFS/CAC is supported by hostapd; HE20 DFS needs separate validation.
 * Rule-level restrictions (NO-OUTDOOR, NO-HE, ...) come from apply_reg_he20. */
static void parse_phy_channel_info(FILE *fp, struct phy_bands *pb)
{
    char line[512];
    int band = 0, band_he_ap = 0, band_nfreq = 0;
    uint32_t band_freq[PHY_MAX_FREQ];
    memset(pb, 0, sizeof(*pb));
    while (fgets(line, sizeof(line), fp)) {
        int b, dfs = 0;
        uint32_t f;
        /* A truncated iw line could hide a trailing "(no IR)" / radar
         * marker. Discard it rather than advertising a restricted channel. */
        if (!strchr(line, '\n') && !feof(fp)) {
            int ch;
            while ((ch = fgetc(fp)) != '\n' && ch != EOF) {}
            continue;
        }
        if (sscanf(line, " Band %d:", &b) == 1) {
            mark_phy_he_band(pb, band_freq, band_nfreq, band_he_ap);
            band = b;
            band_he_ap = band_nfreq = 0;
            continue;
        }
        if (!band) continue;
        if (strstr(line, "HE Iftypes: AP")) {
            band_he_ap = 1;
            continue;
        }
        if (!parse_iw_frequency(line, &f) || !iw_freq_flags(line, &dfs) ||
            f < 2400 || f >= 5925) continue;   /* no validated 6 GHz path */
        int idx = -1;
        for (int i = 0; i < pb->nfreq; i++)
            if (pb->freq[i] == f) { idx = i; break; }
        if (idx < 0 && pb->nfreq < PHY_MAX_FREQ) {
            idx = pb->nfreq++;
            pb->freq[idx] = f;
            pb->dfs[idx] = (uint8_t)dfs;
        } else if (idx >= 0 && !dfs) {
            pb->dfs[idx] = 0;
        }
        if (!dfs && band_nfreq < PHY_MAX_FREQ)
            band_freq[band_nfreq++] = f;
    }
    mark_phy_he_band(pb, band_freq, band_nfreq, band_he_ap);
    int have2 = 0, have5 = 0;
    for (int i = 0; i < pb->nfreq; i++) {
        if (pb->freq[i] < 3000) have2 = 1;
        else have5 = 1;
    }
    if (have2) { pb->band[pb->nband++] = 0x81; pb->band[pb->nband++] = 0x82; }
    if (have5) { pb->band[pb->nband++] = 0x01; pb->band[pb->nband++] = 0x03; }
}

/* Flags of one regdb rule that still permit a 20 MHz HE AP. Anything else
 * (NO-IR/PASSIVE-SCAN, DFS, NO-HE, NO-OFDM, PTP-ONLY, PTMP-ONLY, unknown
 * future flags) fails closed for AX; legacy channels are not filtered here. */
static int reg_rule_he20_ok(const char *flags, int indoor)
{
    static const char *const ok[] = {
        "AUTO-BW", "NO-HT40MINUS", "NO-HT40PLUS", "NO-80MHZ", "NO-160MHZ",
        "NO-320MHZ", "NO-EHT"
    };
    const char *p = flags;
    for (;;) {
        while (*p == ',' || *p == ' ' || *p == '\t') p++;
        if (!*p || *p == '\n' || *p == '\r') return 1;
        const char *s = p;
        while ((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
               *p == '-') p++;
        size_t n = (size_t)(p - s);
        if (!n || (*p && *p != ',' && *p != ' ' && *p != '\t' &&
                   *p != '\n' && *p != '\r')) return 0;
        int good = indoor && n == 10 && !memcmp(s, "NO-OUTDOOR", n);
        for (size_t i = 0; !good && i < sizeof(ok) / sizeof(ok[0]); i++)
            good = strlen(ok[i]) == n && !memcmp(s, ok[i], n);
        if (!good) return 0;
    }
}

/* `iw reg get`: the global domain, then one optional section per wiphy with
 * its own regdomain ("phy#N", possibly self-managed). Which one cfg80211
 * applies depends on the last hint, so for phy N require both the global
 * rules and phy#N's own rules to permit HE20; other phys never apply.
 * Missing, unreadable or malformed rules cannot authorize AX. */
enum { REG_GLOBAL, REG_THIS_PHY, REG_OTHER_PHY };

static void apply_reg_he20(FILE *fp, struct phy_bands *pb, int indoor,
                           int phyidx)
{
    uint8_t ok[2][PHY_MAX_FREQ] = {{0}}, bad[2][PHY_MAX_FREQ] = {{0}};
    int seen[2] = {0, 0}, broken = 0, sect = REG_GLOBAL;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        int idx;
        if (!strchr(line, '\n') && !feof(fp)) {
            int c;
            while ((c = fgetc(fp)) != '\n' && c != EOF) {}
            broken = 1;
            continue;
        }
        if (!strncmp(line, "global", 6) &&
            (line[6] == '\n' || line[6] == '\r' || !line[6])) {
            sect = REG_GLOBAL;
            continue;
        }
        if (sscanf(line, "phy#%d", &idx) == 1) {
            sect = idx == phyidx ? REG_THIS_PHY : REG_OTHER_PHY;
            if (sect == REG_THIS_PHY) seen[1] = 1;
            continue;
        }
        const char *r = line;
        while (*r == ' ' || *r == '\t') r++;
        if (*r != '(' || sect == REG_OTHER_PHY) continue;
        unsigned lo, hi, width;
        const char *end = strrchr(r, ')');
        if (sscanf(r, "(%u - %u @ %u)", &lo, &hi, &width) != 3 ||
            lo >= hi || hi > 70000 || !end) {
            broken = 1;
            continue;
        }
        int s = sect == REG_THIS_PHY;
        int good = width >= 20 && reg_rule_he20_ok(end + 1, indoor);
        seen[s] = 1;
        for (int i = 0; i < pb->nfreq; i++) {
            uint32_t f = pb->freq[i];
            if (lo < f + 10 && hi > f - 10 && !good) bad[s][i] = 1;
            if (good && lo <= f - 10 && f + 10 <= hi) ok[s][i] = 1;
        }
    }
    pb->he5 = 0;
    for (int i = 0; i < pb->nfreq; i++) {
        int allowed = !broken && seen[0] && ok[0][i] && !bad[0][i] &&
                      (!seen[1] || (ok[1][i] && !bad[1][i]));
        pb->he5freq[i] &= (uint8_t)allowed;
        if (pb->he5freq[i]) pb->he5 = 1;
    }
}

/* Alpha2 of the global domain in `iw reg get`, or "" if not reported. */
static void reg_global_country(FILE *fp, char cc[3])
{
    char line[512];
    cc[0] = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!strncmp(line, "phy#", 4)) return;
        if (sscanf(line, "country %2[A-Z0-9]:", cc) == 1) return;
        cc[0] = 0;
    }
}
