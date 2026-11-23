/* Compile the production wire builders with fixture PHY readers.
 * These are characterization tests: they do not claim a RouterOS acceptance
 * result or that a synthetic frequency list is legal on a real radio. */
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PHY_MAX_FREQ 96
#define BODY_MAX 8192
struct phy_caps {
    uint8_t ciphers[32];
    int nciphers;
    uint32_t tx_chain, rx_chain;
    int max_ap, has_he, has_eht;
};
struct phy_bands {
    uint32_t freq[PHY_MAX_FREQ];
    int nfreq;
    uint8_t band[8];
    int nband;
    int he5;
    uint8_t he5freq[PHY_MAX_FREQ];
    uint8_t dfs[PHY_MAX_FREQ];
};
#include "../src/iw_freq.inc"
#include "../src/phy_channel_parse.inc"
static struct phy_caps fixture_caps;
static struct phy_bands fixture_bands;

static void put16(uint8_t *p, uint16_t x)
{
    p[0] = (uint8_t)(x >> 8); p[1] = (uint8_t)x;
}
static void put32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24); p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8); p[3] = (uint8_t)x;
}
static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
static size_t put_el(uint8_t *p, uint16_t id, const void *data, uint16_t len)
{
    put16(p, id); put16(p + 2, len);
    if (len && data) memcpy(p + 4, data, len);
    return (size_t)4 + len;
}
static void read_phy_bands(int phy, struct phy_bands *pb)
{
    assert(phy == 0);
    *pb = fixture_bands;
}
static void read_phy_caps(int phy, struct phy_caps *pc)
{
    assert(phy == 0);
    *pc = fixture_caps;
}
static const char *phy_hwtype(int phy)
{
    assert(phy == 0);
    return "fixture";
}
static uint32_t chan_base_for_freq(uint32_t f)
{
    if (f < 3000) return 2407;
    if (f < 5925) return 5000;
    return 5950;
}
#include "../src/newphy_wire.inc"
#include "../src/channel_reply_wire.inc"
#include "../src/start_channel_wire.inc"

static size_t next(const uint8_t *b, size_t n, size_t i)
{
    assert(i + 4 <= n);
    size_t end = i + 4 + rd16(b + i + 2);
    assert(end <= n);
    return end;
}
static int count_band(const uint8_t *b, size_t n, uint8_t band)
{
    int count = 0;
    for (size_t i = 0; i < n; i = next(b, n, i))
        if (rd16(b + i) == 0x4d && rd16(b + i + 2) == 5 &&
            b[i + 4] == band) count++;
    return count;
}
static int band_mask(const uint8_t *b, size_t n, uint8_t band)
{
    for (size_t i = 0; i < n; i = next(b, n, i))
        if (rd16(b + i) == 0x4d && rd16(b + i + 2) == 5 &&
            b[i + 4] == band) return b[i + 8];
    return 0;
}
static int count_channel(const uint8_t *b, size_t n, uint32_t freq,
                         uint8_t band, uint8_t width, uint32_t centre)
{
    int count = 0;
    for (size_t i = 0; i < n; i = next(b, n, i)) {
        if (rd16(b + i) != 0x0a) continue;
        size_t end = next(b, n, i), j = i + 4;
        uint32_t f = 0, c = 0;
        uint8_t w = 0, bd = 0;
        for (; j < end; j = next(b, end, j)) {
            uint16_t t = rd16(b + j), len = rd16(b + j + 2);
            if (t == 0x0b) { assert(len == 4); f = rd32(b + j + 4); }
            if (t == 0x0c) { assert(len == 1); w = b[j + 4]; }
            if (t == 0x0d) { assert(len == 4); c = rd32(b + j + 4); }
            if (t == 0x10) { assert(len == 1); bd = b[j + 4]; }
        }
        assert(j == end);
        if (f == freq && bd == band && w == width && c == centre)
            count++;
    }
    return count;
}
static void reset_fixture(int he)
{
    memset(&fixture_bands, 0, sizeof(fixture_bands));
    memset(&fixture_caps, 0, sizeof(fixture_caps));
    fixture_caps.has_he = he;
    fixture_bands.he5 = he;
    if (he) memset(fixture_bands.he5freq, 1, sizeof(fixture_bands.he5freq));
}

static void check_small(int he)
{
    uint8_t nphy[1024], reply[1024], mac[6] = {0x02};
    size_t nn = 0;
    reset_fixture(he);
    fixture_bands.freq[0] = 5180;
    fixture_bands.freq[1] = 5200;
    fixture_bands.nfreq = 2;
    fixture_bands.band[0] = 0x01;
    fixture_bands.band[1] = 0x03;
    fixture_bands.nband = 2;
    build_newphy(nphy, mac, 0, &nn);
    size_t cn = add_channel_tlvs(reply, 0, 0);
    assert(count_band(nphy, nn, 0x04) == he);
    assert(count_channel(reply, cn, 5180, 0x01, 1, 0) == 1);
    assert(count_channel(reply, cn, 5180, 0x03, 3, 5210) == 0);
    assert(count_channel(reply, cn, 5200, 0x02, 2, 5190) == 1);
    assert(count_channel(reply, cn, 5180, 0x04, 1, 0) == he);
    assert(count_channel(reply, cn, 5180, 0x04, 3, 5210) == 0);
    const uint16_t order[] = {0x01, 0x02, 0x03, 0x04, 0x02, 0x03};
    const uint8_t widths[] = {1, 1, 1, 1, 2, 2};
    size_t i = 0;
    for (int k = 0; k < (he ? 6 : 5); k++) {
        assert(rd16(reply + i) == 0x0a);
        size_t end = next(reply, cn, i);
        int found_band = 0, found_width = 0;
        for (size_t j = i + 4; j < end; j = next(reply, end, j)) {
            if (rd16(reply + j) == 0x10) {
                uint8_t expected = he ? order[k] :
                    (k == 3 ? 0x02 : k == 4 ? 0x03 : order[k]);
                assert(reply[j + 4] == expected);
                found_band = 1;
            }
            if (rd16(reply + j) == 0x0c) {
                assert(reply[j + 4] == (he ? widths[k] : (k >= 3 ? 2 : 1)));
                found_width = 1;
            }
        }
        assert(found_band && found_width);
        i = end;
    }
    cn = add_current_frequency_tlv(reply, cn, 5180);
    size_t tail = cn;
    cn = add_channel_number_tlv(reply, cn, 0);
    assert(rd16(reply + tail) == 0xb7);
    assert(rd16(reply + tail + 2) == 8);
    assert(rd32(reply + tail + 4) == 36);
    assert(rd32(reply + tail + 8) == 40);
    assert(rd16(reply + tail - 8) == 0x61);
    assert(rd32(reply + tail - 4) == 5180);
    assert(next(reply, cn, tail) == cn);
}

static void check_limits(void)
{
    uint8_t reply[32768], nphy[1024], mac[6] = {0x02};
    size_t nn = 0;
    reset_fixture(0);
    fixture_bands.band[0] = 0x01;
    fixture_bands.band[1] = 0x03;
    fixture_bands.nband = 2;
    for (uint32_t f = 5180; f <= 5320; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    for (uint32_t f = 5500; f <= 5640; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    for (uint32_t f = 5660; f <= 5720; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    for (uint32_t f = 5745; f <= 5805; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    for (uint32_t f = 5825; f <= 5885; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    assert(fixture_bands.nfreq == 28);
    build_newphy(nphy, mac, 0, &nn);
    assert(count_band(nphy, nn, 0x04) == 0);
    size_t channels = add_channel_tlvs(reply, 0, 0);
    assert(channels > 0);
    assert(channels < BODY_MAX);
    /* The START backend downgrades ch165+ to HT20: never offer 80 MHz. */
    assert(count_channel(reply, channels, 5885, 0x03, 3, 5855) == 0);
    assert(count_channel(reply, channels, 5825, 0x02, 2, 5835) == 0);
    size_t with_freq = add_current_frequency_tlv(reply, channels, 5180);
    size_t total = add_channel_number_tlv(reply, with_freq, 0);
    assert(total <= BODY_MAX);
    assert(rd16(reply + channels) == 0x61);
    assert(rd16(reply + with_freq) == 0xb7);
    assert(rd16(reply + with_freq + 2) == 28 * 4);
    assert(next(reply, total, with_freq) == total);

    /* Synthetic stress fixture: no write beyond the supplied body limit. */
    reset_fixture(1);
    for (int i = 0; i < PHY_MAX_FREQ; i++)
        fixture_bands.freq[fixture_bands.nfreq++] = 5180 + 5u * (uint32_t)i;
    channels = add_channel_tlvs(reply, 0, 0);
    /* Invalid synthetic primaries must not inflate the wire inventory. */
    assert(channels != SIZE_MAX && channels < BODY_MAX);
    assert(count_channel(reply, channels, 5190, 0x03, 3, 5210) == 0);
}

static void check_mixed_phy(void)
{
    uint8_t reply[1024], nphy[1024], mac[6] = {0x02};
    size_t nn = 0;
    reset_fixture(1);
    fixture_bands.freq[0] = 2412;
    fixture_bands.freq[1] = 5180;
    fixture_bands.nfreq = 2;
    fixture_bands.band[0] = 0x81;
    fixture_bands.band[1] = 0x82;
    fixture_bands.band[2] = 0x01;
    fixture_bands.band[3] = 0x03;
    fixture_bands.nband = 4;
    build_newphy(nphy, mac, 0, &nn);
    size_t cn = add_channel_tlvs(reply, 0, 0);
    assert(count_band(nphy, nn, 0x04) == 1);
    assert(count_channel(reply, cn, 2412, 0x81, 1, 0) == 1);
    assert(count_channel(reply, cn, 2412, 0x82, 1, 0) == 1);
    assert(count_channel(reply, cn, 2412, 0x82, 2, 2422) == 0);
    assert(count_channel(reply, cn, 2412, 0x04, 1, 0) == 0);
    assert(count_channel(reply, cn, 5180, 0x03, 3, 5210) == 0);
    assert(count_channel(reply, cn, 5180, 0x04, 1, 0) == 1);
    /* When no current frequency is known the production tail omits 0x61. */
    assert(add_current_frequency_tlv(reply, cn, 0) == cn);
    size_t total = add_channel_number_tlv(reply, cn, 0);
    assert(rd16(reply + cn) == 0xb7);
    assert(next(reply, total, cn) == total);
}

static void check_ax20_only(void)
{
    static const uint8_t he20[] = {
        0x00,0x0a,0x00,0x12, 0x00,0x0b,0x00,0x04,0x00,0x00,0x14,0x3c,
        0x00,0x0c,0x00,0x01,0x01, 0x00,0x10,0x00,0x01,0x04
    };
    uint8_t wire[BODY_MAX], again[BODY_MAX], nphy[1024], mac[6] = {0x02};
    size_t nn;
    reset_fixture(1);
    for (uint32_t f = 5180; f <= 5240; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    fixture_bands.band[fixture_bands.nband++] = 0x01;
    fixture_bands.band[fixture_bands.nband++] = 0x03;
    build_newphy(nphy, mac, 0, &nn);
    assert(band_mask(nphy, nn, 0x04) == 0x01);
    size_t n = add_channel_tlvs(wire, 0, 0);
    assert(n != SIZE_MAX && add_channel_tlvs(again, 0, 0) == n);
    assert(!memcmp(wire, again, n));
    assert(count_channel(wire, n, 5180, 0x04, 1, 0) == 1);
    int exact = 0;
    for (size_t i = 0; i < n; i = next(wire, n, i))
        if (next(wire, n, i) - i == sizeof(he20) &&
            !memcmp(wire + i, he20, sizeof(he20))) exact++;
    assert(exact == 1);
    assert(count_channel(wire, n, 5180, 0x04, 2, 5190) == 0);
    assert(count_channel(wire, n, 5180, 0x04, 3, 5210) == 0);
    assert(count_channel(wire, n, 5180, 0x03, 3, 5210) == 1);
    assert(ax_channel_ok(&fixture_bands, &fixture_caps, 5180, 1, 0) == 1);
    assert(ax_channel_ok(&fixture_bands, &fixture_caps, 5180, 2, 5190) == 0);
    assert(ax_channel_ok(&fixture_bands, &fixture_caps, 5180, 3, 5210) == 0);
    assert(ax_channel_ok(&fixture_bands, &fixture_caps, 5180, 2, 5210) == 0);
    assert(ax_channel_ok(&fixture_bands, &fixture_caps, 5180, 3, 5190) == 0);
    fixture_bands.nfreq--;
    build_newphy(nphy, mac, 0, &nn);
    assert(band_mask(nphy, nn, 0x04) == 0x01);
    n = add_channel_tlvs(wire, 0, 0);
    assert(count_channel(wire, n, 5180, 0x04, 3, 5210) == 0);
    assert(count_channel(wire, n, 5180, 0x04, 1, 0) == 1);
    assert(count_channel(wire, n, 5180, 0x04, 2, 5190) == 0);
}

/* Nested 0x0A from a real RouterOS 7.25.1 0x6016 START, after the
 * manager selected our 2.4 GHz VAP on channel 1.  This is only a
 * non-secret channel record, not a captured AX manager response. */
static void check_captured_start_channel(void)
{
    static const uint8_t start_channel[] = {
        0x00, 0x0b, 0x00, 0x04, 0x00, 0x00, 0x09, 0x6c,
        0x00, 0x0c, 0x00, 0x01, 0x01,
        0x00, 0x10, 0x00, 0x01, 0x81
    };
    uint8_t reply[1024];
    reset_fixture(1);
    fixture_bands.freq[fixture_bands.nfreq++] = 2412;
    fixture_bands.band[fixture_bands.nband++] = 0x81;
    fixture_bands.band[fixture_bands.nband++] = 0x82;
    size_t n = add_channel_tlvs(reply, 0, 0);
    assert(count_channel(reply, n, 2412, 0x81, 1, 0) == 1);
    /* Match the actual nested descriptor bytes, not just its decoded fields.
     * The manager's 0x6016 uses the same channel-record layout as 0xD00B. */
    assert(rd16(reply) == 0x0a);
    assert(rd16(reply + 2) == sizeof(start_channel));
    assert(memcmp(reply + 4, start_channel, sizeof(start_channel)) == 0);
}

/* Frequencies from the key-free NEWPHY 0x05 TLV in the bounded hwsim run.
 * These are reported PHY frequencies; all 5 GHz channels were NO-IR in
 * `iw phy` and must NOT be presented as eligible AP channels. */
static void check_hwsim_frequency_inventory(void)
{
    static const uint32_t freqs[] = {
        2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447,
        2452, 2457, 2462, 2467, 2472, 2484,
        5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320,
        5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640,
        5660, 5680, 5700, 5745, 5765, 5785, 5805, 5825
    };
    uint8_t nphy[1024], reply[32768], again[32768], mac[6] = {0x02};
    size_t nn = 0, n, total;
    reset_fixture(1);
    memcpy(fixture_bands.freq, freqs, sizeof(freqs));
    fixture_bands.nfreq = (int)(sizeof(freqs) / sizeof(freqs[0]));
    const uint8_t bands[] = {0x81, 0x82, 0x01, 0x03};
    memcpy(fixture_bands.band, bands, sizeof(bands));
    fixture_bands.nband = (int)sizeof(bands);
    build_newphy(nphy, mac, 0, &nn);
    assert(count_band(nphy, nn, 0x04) == 1);
    n = add_channel_tlvs(reply, 0, 0);
    assert(add_channel_tlvs(again, 0, 0) == n);
    assert(memcmp(reply, again, n) == 0); /* same input, same wire order */
    assert(count_channel(reply, n, 5180, 0x03, 3, 5210) == 1);
    assert(count_channel(reply, n, 5180, 0x04, 1, 0) == 1);
    assert(count_channel(reply, n, 5180, 0x04, 2, 5190) == 0);
    assert(count_channel(reply, n, 5180, 0x04, 3, 5210) == 0);
    size_t tail = add_current_frequency_tlv(reply, n, 2412);
    total = add_channel_number_tlv(reply, tail, 0);
    assert(total < BODY_MAX); /* this specific inventory fits today */
    assert(rd16(reply + n) == 0x61);
    assert(rd16(reply + tail) == 0xb7);
    assert(rd16(reply + tail + 2) == sizeof(freqs));
    assert(next(reply, total, tail) == total);
}

static void check_real_iw(const char *world, const char *ua)
{
    FILE *fp = fopen(world, "r");
    assert(fp);
    parse_phy_channel_info(fp, &fixture_bands);
    fclose(fp);
    assert(!fixture_bands.he5);
    assert(!phy_has_freq(&fixture_bands, 5180));
    fixture_caps.has_he = 1; /* a 2.4 GHz HE AP alone is insufficient */
    uint8_t wire[BODY_MAX], mac[6] = {0x02};
    size_t len;
    build_newphy(wire, mac, 0, &len);
    assert(count_band(wire, len, 0x04) == 0);
    fp = fopen(ua, "r");
    assert(fp);
    parse_phy_channel_info(fp, &fixture_bands);
    fclose(fp);
    assert(fixture_bands.he5 && phy_has_freq(&fixture_bands, 5180));
    assert(phy_has_freq(&fixture_bands, 5260)); /* legacy DFS/CAC remains */
    build_newphy(wire, mac, 0, &len);
    assert(count_band(wire, len, 0x04) == 1);
    size_t n = add_channel_tlvs(wire, 0, 0);
    assert(count_channel(wire, n, 5180, 0x04, 1, 0) == 1);
    assert(count_channel(wire, n, 5260, 0x04, 1, 0) == 0);
    assert(count_channel(wire, n, 5260, 0x03, 1, 0) == 1);
    assert(count_channel(wire, n, 5180, 0x04, 2, 5190) == 0);
    assert(count_channel(wire, n, 5180, 0x04, 3, 5210) == 0);
    assert(band_mask(wire, n, 0x04) == 0); /* reply, not NEWPHY */
    assert(count_channel(wire, n, 5180, 0x03, 3, 5210) == 1);
    size_t end = add_channel_number_tlv(wire,
                 add_current_frequency_tlv(wire, n, 5180), 0);
    assert(end <= BODY_MAX);
    /* Explicit small-capacity path must leave room for both tails. */
    n = add_channel_tlvs_cap(wire, 64, 0, 64 + 8 + 4 + fixture_bands.nfreq * 4);
    assert(n == SIZE_MAX);
}

/* Feed iw text through the production parser, or the regulatory filter. */
static FILE *text_file(const char *s)
{
    FILE *fp = tmpfile();
    assert(fp);
    fputs(s, fp);
    rewind(fp);
    return fp;
}
static void parse_text(const char *s)
{
    FILE *fp = text_file(s);
    parse_phy_channel_info(fp, &fixture_bands);
    fclose(fp);
}
static void apply_reg_file(FILE *fp, int indoor, int phy)
{
    assert(fp);
    apply_reg_he20(fp, &fixture_bands, indoor, phy);
    fclose(fp);
}

static const char he_phy[] = " Band 1:\n\tHE Iftypes: AP\n"
    "\t* 5180 MHz [36] (20.0 dBm)\n"
    "\t* 5260 MHz [52] (20.0 dBm) (radar detection)\n";

/* HE20 AX eligibility of 5180 MHz on PHY `phy` under the rules in `reg`. */
static int ax5180_with(const char *reg, int indoor, int phy)
{
    parse_text(he_phy);
    apply_reg_file(text_file(reg), indoor, phy);
    return fixture_bands.he5freq[0];
}

static void check_reg_he20(const char *reg)
{
    parse_text(he_phy);
    assert(fixture_bands.he5);
    apply_reg_file(fopen(reg, "r"), 0, 0);
    assert(!fixture_bands.he5);
    assert(phy_has_freq(&fixture_bands, 5180)); /* legacy stays available */
    parse_text(he_phy);
    apply_reg_file(fopen(reg, "r"), 1, 0);
    assert(fixture_bands.he5);
    assert(fixture_bands.he5freq[0] && !fixture_bands.he5freq[1]);
    apply_reg_file(text_file("global\ncountry ZZ:\n"), 1, 0);
    assert(!fixture_bands.he5); /* missing rules fail closed */

#define UA_GLOBAL "global\ncountry UA: DFS-ETSI\n" \
    "\t(5150 - 5250 @ 80), (N/A, 20), (N/A), NO-OUTDOOR, AUTO-BW\n"
#define RULE(flags) "\t(5150 - 5250 @ 80), (N/A, 23), (N/A)" flags "\n"
    /* World domain 00 marks 5 GHz no-IR: no AX before the country applies. */
    assert(!ax5180_with("global\ncountry 00: DFS-UNSET\n"
                        "\t(5170 - 5250 @ 80), (N/A, 20), (N/A), "
                        "NO-IR, AUTO-BW\n", 1, 0));
    assert(ax5180_with(UA_GLOBAL, 1, 0));
    /* Old iw without a "global" header. */
    assert(ax5180_with("country UA: DFS-ETSI\n" RULE(", NO-OUTDOOR"), 1, 0));
    /* Flags that forbid or are unknown for HE20 AX fail closed. */
    assert(!ax5180_with("global\n" RULE(", NO-HE"), 1, 0));
    assert(!ax5180_with("global\n" RULE(", NO-OFDM"), 1, 0));
    assert(!ax5180_with("global\n" RULE(", PTP-ONLY"), 1, 0));
    assert(!ax5180_with("global\n" RULE(", PTMP-ONLY"), 1, 0));
    assert(!ax5180_with("global\n" RULE(", PASSIVE-SCAN"), 1, 0));
    assert(!ax5180_with("global\n" RULE(", DFS"), 1, 0));
    assert(!ax5180_with("global\n" RULE(", NO-FUTURE-THING"), 1, 0));
    assert(!ax5180_with("global\n" RULE(", no-he"), 1, 0));
    assert(ax5180_with("global\n" RULE(", NO-HT40PLUS, NO-80MHZ, NO-EHT"),
                       0, 0));
    /* A malformed rule or a narrow rule cannot authorize AX. */
    assert(!ax5180_with(UA_GLOBAL "\t(5150 - x @ 80), (N/A, 20)\n", 1, 0));
    assert(!ax5180_with("global\n\t(5170 - 5190 @ 10), (N/A, 20)\n", 1, 0));
    /* A rule overlapping the channel with a forbidding flag wins. */
    assert(!ax5180_with(UA_GLOBAL "\t(5170 - 5190 @ 20), (N/A, 20), "
                        "(N/A), NO-HE\n", 1, 0));

    /* Multi-radio: another PHY's own domain never applies to this one; this
     * PHY's own section must also permit HE20. */
    static const char multi[] = UA_GLOBAL "\n"
        "phy#1 (self-managed)\ncountry US: DFS-FCC\n" RULE(", NO-HE") "\n"
        "phy#2\ncountry DE: DFS-ETSI\n" RULE("") "\n";
    assert(ax5180_with(multi, 1, 0));   /* only global applies to phy0 */
    assert(!ax5180_with(multi, 1, 1));  /* phy1 forbids HE */
    assert(ax5180_with(multi, 1, 2));   /* phy2 and global both permit */
    assert(!ax5180_with(multi, 0, 2));  /* ...but global is indoor-only */
    assert(!ax5180_with(UA_GLOBAL "phy#0\ncountry US:\n", 1, 0));
    assert(!ax5180_with(UA_GLOBAL "phy#0\n\t(5490 - 5730 @ 160), (N/A, 20)\n",
                        1, 0));
    assert(!ax5180_with("phy#0\n" RULE(""), 1, 0)); /* no global section */
#undef RULE
#undef UA_GLOBAL

    char cc[3];
    FILE *fp = text_file("global\ncountry UA: DFS-ETSI\n\nphy#1\ncountry US:\n");
    reg_global_country(fp, cc);
    fclose(fp);
    assert(!strcmp(cc, "UA"));
    fp = text_file("phy#1\ncountry US:\nglobal\ncountry 00:\n");
    reg_global_country(fp, cc);
    fclose(fp);
    assert(cc[0] == 0);
}

static void check_band_scope_and_bounds(void)
{
    parse_text(" Band 1:\n\tHE Iftypes: AP\n"
               "\t* 2412.0 MHz [1] (20.0 dBm)\n"
               " Band 2:\n\tHE Iftypes: managed\n"
               "\t* 5180.0 MHz [36] (20.0 dBm)\n");
    assert(!fixture_bands.he5 && phy_has_freq(&fixture_bands, 5180));
    fixture_caps.has_he = 1;
    uint8_t wire[BODY_MAX], mac[6] = {0x02};
    size_t nn;
    build_newphy(wire, mac, 0, &nn);
    assert(count_band(wire, nn, 0x04) == 0);
    size_t n = add_channel_tlvs(wire, 0, 0);
    assert(count_channel(wire, n, 5180, 0x04, 1, 0) == 0);

    /* A long frequency line must not hide a later no-IR flag. */
    FILE *fp = tmpfile();
    assert(fp);
    fputs(" Band 1:\n\tHE Iftypes: AP\n\t* 5180.0 MHz [36] (", fp);
    for (int i = 0; i < 600; i++) fputc('x', fp);
    fputs(" no IR)\n\t* 5200.0 MHz [40] (20.0 dBm) (no IR)\n"
          "\t* 5260 MHz [52] (20.0 dBm) (radar detection)\n"
          "\t* 5240junk MHz [48] (20.0 dBm)\n", fp);
    rewind(fp);
    parse_phy_channel_info(fp, &fixture_bands);
    fclose(fp);
    assert(!fixture_bands.he5 && fixture_bands.nfreq == 1);
    assert(fixture_bands.freq[0] == 5260 && fixture_bands.dfs[0]);

    /* A HE AP in one 5 GHz band must not enable another PHY band's
     * frequencies; duplicate frequencies gain HE only from a HE AP band. */
    parse_text(" Band 1:\n\t* 5180 MHz [36] (20.0 dBm)\n"
               "\tHE Iftypes: AP\n"
               " Band 2:\n\t* 5200 MHz [40] (20.0 dBm)\n"
               "\tHE Iftypes: managed\n");
    assert(fixture_bands.he5 && fixture_bands.nfreq == 2);
    assert(ax_channel_ok(&fixture_bands, &fixture_caps, 5180, 1, 0));
    assert(!ax_channel_ok(&fixture_bands, &fixture_caps, 5200, 1, 0));
    n = add_channel_tlvs(wire, 0, 0);
    assert(count_channel(wire, n, 5180, 0x04, 1, 0) == 1);
    assert(count_channel(wire, n, 5200, 0x04, 1, 0) == 0);
    parse_text(" Band 1:\n\t* 5200 MHz [40] (20.0 dBm)\n"
               "\tHE Iftypes: managed\n"
               " Band 2:\n\t* 5200 MHz [40] (20.0 dBm)\n"
               "\tHE Iftypes: AP\n");
    assert(fixture_bands.he5 && fixture_bands.nfreq == 1);
    assert(ax_channel_ok(&fixture_bands, &fixture_caps, 5200, 1, 0));

    reset_fixture(1);
    fixture_bands.freq[fixture_bands.nfreq++] = 5180;
    memset(wire, 0xa5, sizeof(wire));
    const size_t cap = 64, prefix = 16;
    n = add_channel_tlvs_cap(wire, prefix, 0, cap);
    assert(n == SIZE_MAX);
    for (size_t i = cap; i < sizeof(wire); i++) assert(wire[i] == 0xa5);
}

static void check_dfs_and_malformed(void)
{
    parse_text(" Band 1:\n\tHE Iftypes: AP\n"
               "\t* 5260 MHz [52] (20.0 dBm) (radar detection)\n"
               "\t* 5280 MHz [56] (20.0 dBm) (radar detection)\n"
               "\t* 5300 MHz [60] (20.0 dBm) (no IR)\n"
               "\t* 5180 MHz [36] (20.0 dBm)\n");
    assert(phy_has_freq(&fixture_bands, 5260));
    assert(phy_has_freq(&fixture_bands, 5280));
    assert(!phy_has_freq(&fixture_bands, 5300));
    assert(!ax_channel_ok(&fixture_bands, &fixture_caps, 5260, 1, 0));
    uint8_t wire[BODY_MAX];
    size_t n = add_channel_tlvs(wire, 0, 0);
    assert(count_channel(wire, n, 5260, 0x03, 1, 0) == 1);
    assert(count_channel(wire, n, 5260, 0x04, 1, 0) == 0);

    parse_text(" Band 1:\n\tHE Iftypes: AP\n"
               "\t* 5180. MHz [36] (20.0 dBm)\n"
               "\t* 5200.0x MHz [40] (20.0 dBm)\n"
               "\t* 5220.00. MHz [44] (20.0 dBm)\n"
               "\t* 5240 MHz [48] (20.0 dBm) junk\n"
               "\t* 5240 MHz [48] (20.0 dBm) (unknown flag)\n"
               "\t* 4294967296 MHz [36] (20.0 dBm)\n"
               "\t* 5180 MHz [36 (20.0 dBm)\n"
               "\t* 5200 MHz [40] (20.0 dBm) (no IR) junk\n");
    assert(fixture_bands.nfreq == 0 && !fixture_bands.he5);
    parse_text(" Band 1:\n\tHE Iftypes: AP\n"
               "\t* 5180 MHz [36] (20.0 dBm) (NO-OUTDOOR)\n"
               "\t* 5200 MHz [40] (20.0 dBm) (no IR, radar detection)\n");
    assert(fixture_bands.nfreq == 0 && !fixture_bands.he5);
}

static void check_start_descriptor(void)
{
    uint8_t body[128], desc[80], x[4], band = 0x04, width = 1;
    struct start_channel ch;
    reset_fixture(1);
    fixture_bands.freq[fixture_bands.nfreq++] = 5180;
    size_t d = 0;
    put32(x, 5180);
    d += put_el(desc + d, 0x0b, x, 4);
    d += put_el(desc + d, 0x0c, &width, 1);
    d += put_el(desc + d, 0x10, &band, 1);
    size_t n = put_el(body, 0x0a, desc, (uint16_t)d);
    assert(start_channel_validate(body, n, &fixture_bands, &fixture_caps, &ch));
    assert(ch.freq == 5180 && ch.width == 1 && ch.band == 0x04);
    /* Duplicate outer descriptors and conflicting inner fields fail closed. */
    memcpy(body + n, body, n);
    assert(!start_channel_validate(body, 2 * n, &fixture_bands, &fixture_caps, &ch));
    d += put_el(desc + d, 0x10, &band, 1);
    n = put_el(body, 0x0a, desc, (uint16_t)d);
    assert(!start_channel_validate(body, n, &fixture_bands, &fixture_caps, &ch));
    d -= 5;
    d += put_el(desc + d, 0x0b, x, 4);
    n = put_el(body, 0x0a, desc, (uint16_t)d);
    assert(!start_channel_validate(body, n, &fixture_bands, &fixture_caps, &ch));
    d -= 8;
    d += put_el(desc + d, 0x0c, &width, 1);
    n = put_el(body, 0x0a, desc, (uint16_t)d);
    assert(!start_channel_validate(body, n, &fixture_bands, &fixture_caps, &ch));
    d -= 5;
    width = 2;
    desc[12] = width; /* 0x0c TLV payload after 0x0b (8) + header (4) */
    n = put_el(body, 0x0a, desc, (uint16_t)d);
    assert(!start_channel_validate(body, n, &fixture_bands, &fixture_caps, &ch));
    assert(!start_channel_validate(body, n - 1, &fixture_bands, &fixture_caps, &ch));
    width = 1;
    desc[12] = width;
    put32(x, 5200);
    d += put_el(desc + d, 0x0d, x, 4);
    n = put_el(body, 0x0a, desc, (uint16_t)d);
    assert(!start_channel_validate(body, n, &fixture_bands, &fixture_caps, &ch));
    /* The upper 5 GHz block used to be advertised as VHT80 although
     * vap_write_channel forces channel 165 and above back to HT20. */
    reset_fixture(0);
    for (uint32_t f = 5825; f <= 5885; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    assert(!legacy_channel_ok(&fixture_bands, 5825, 0x03, 2, 5835));
    assert(!legacy_channel_ok(&fixture_bands, 5825, 0x03, 3, 5855));
    assert(legacy_channel_ok(&fixture_bands, 5825, 0x03, 1, 0));
    fixture_bands.nfreq = 0;
    for (uint32_t f = 5180; f <= 5240; f += 20)
        fixture_bands.freq[fixture_bands.nfreq++] = f;
    assert(legacy_channel_ok(&fixture_bands, 5180, 0x03, 3, 5210));
    assert(!legacy_channel_ok(&fixture_bands, 5180, 0x03, 3, 5190));
    assert(!legacy_channel_ok(&fixture_bands, 5180, 0x03, 2, 5210));
    assert(!legacy_channel_ok(&fixture_bands, 5190, 0x03, 3, 5210));
    fixture_bands.nfreq--; /* missing final 20 MHz component */
    assert(!legacy_channel_ok(&fixture_bands, 5180, 0x03, 3, 5210));
    reset_fixture(0);
    fixture_bands.freq[fixture_bands.nfreq++] = 2442;
    fixture_bands.freq[fixture_bands.nfreq++] = 2462;
    assert(legacy_channel_ok(&fixture_bands, 2442, 0x82, 2, 2452));
    assert(!legacy_channel_ok(&fixture_bands, 2442, 0x82, 2, 2432));
    fixture_bands.freq[fixture_bands.nfreq++] = 2484;
    assert(legacy_channel_ok(&fixture_bands, 2484, 0x81, 1, 0));
    assert(!legacy_channel_ok(&fixture_bands, 2484, 0x82, 1, 0));
}

/* 0xE016 decision table for every ownership mode, and repeated-START
 * comparison against the BSS on air. */
static void check_start_policy(void)
{
    /* observer, netdev, managed, started */
    assert(start_should_ack(1, 0, 0, 0));   /* legacy / --no-vap-auto */
    assert(start_should_ack(1, 1, 1, 0));
    assert(start_should_ack(0, 1, 0, 0));   /* netifd/foreign owner */
    assert(!start_should_ack(0, 0, 1, 0));  /* own mode, no AP netdev */
    assert(!start_should_ack(0, 0, 0, 0));
    assert(!start_should_ack(0, 1, 1, 0));  /* hostapd/MLME failed */
    assert(start_should_ack(0, 1, 1, 1));   /* AP running */

    struct start_channel ax = {5180, 0, 1, 0x04}, ac = {5180, 0, 1, 0x03};
    struct start_channel vht80 = {5180, 5210, 3, 0x03};
    assert(!start_conflicts_running(&ax, 5180, 20, 1));
    assert(!start_conflicts_running(&ax, 0, 0, -1));  /* nothing known */
    assert(start_conflicts_running(&ax, 5200, 20, 1));
    assert(start_conflicts_running(&ax, 5180, 80, 1));
    assert(start_conflicts_running(&ax, 5180, 20, 0)); /* not HE on air */
    assert(start_conflicts_running(&ac, 5180, 20, 1));
    assert(!start_conflicts_running(&vht80, 5180, 80, 0));
    assert(start_conflicts_running(&vht80, 5180, 20, 0));
}

int main(int argc, char **argv)
{
    check_small(0);
    check_small(1);
    check_mixed_phy();
    check_ax20_only();
    check_captured_start_channel();
    check_hwsim_frequency_inventory();
    check_limits();
    check_band_scope_and_bounds();
    check_dfs_and_malformed();
    check_start_descriptor();
    check_start_policy();
    check_reg_he20("tests/fixtures/ua-reg-he20.txt");
    if (argc == 3) check_real_iw(argv[1], argv[2]);
    puts("channel wire: captured 2.4 GHz, hwsim HE, ordering and limits PASS");
    return 0;
}
