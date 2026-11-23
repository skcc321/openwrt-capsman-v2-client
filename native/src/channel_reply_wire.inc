/* CREATEVAP channel and trailing TLV builders; included from channels.inc. */
static uint32_t ccfi80(uint32_t f)
{
    if (f >= 5180 && f <= 5240) return 5210;
    if (f >= 5260 && f <= 5320) return 5290;
    if (f >= 5500 && f <= 5560) return 5530;
    if (f >= 5580 && f <= 5640) return 5610;
    if (f >= 5660 && f <= 5720) return 5690;
    if (f >= 5745 && f <= 5805) return 5775;
    return f;
}

/* 0x000A channel-descriptor TLVs for the CREATEVAP-response (0xD00B) body.
   The manager keeps one row per (frequency, band, width) and echoes the
   chosen descriptor verbatim in 0x6016.  A profile channel is available
   only when a descriptor with the profile's band and frequency exists at
   the requested width. AX is limited to eligible HE20; legacy widths
   require every constituent AP-eligible channel.
   Widths: 1 = 20, 2 = 40, 3 = 80 MHz; 0x0d is the centre
   frequency and is required for widths > 20 MHz. */
static size_t add_chan_desc(uint8_t *b, size_t n, uint32_t freq,
                            uint8_t width, uint8_t band, uint32_t ccfi)
{
    uint8_t sub[48], f[4], c[4];
    size_t sn = 0;
    put32(f, freq);
    sn += put_el(sub + sn, 0x0b, f, 4);
    sn += put_el(sub + sn, 0x0c, &width, 1);
    if (width > 1) {
        put32(c, ccfi);
        sn += put_el(sub + sn, 0x0d, c, 4);
    }
    sn += put_el(sub + sn, 0x10, &band, 1);
    return n + put_el(b + n, 0x0a, sub, (uint16_t)sn);
}

/* Centre of the 40 MHz block that contains a 20 MHz primary. */
static uint32_t c40_for(uint32_t f)
{
    if (f < 3000) {
        return f <= 2442 ? f + 10 : f - 10;
    }
    uint32_t ch = (f - 5000) / 5;
    return (((ch - 36) % 8) < 4) ? f + 10 : f - 10;
}

static int phy_has_freq(const struct phy_bands *pb, uint32_t f)
{
    for (int i = 0; i < pb->nfreq; i++)
        if (pb->freq[i] == f) return 1;
    return 0;
}

static int supported_primary(uint32_t f)
{
    if (f < 3000)
        return (f >= 2412 && f <= 2472 && (f - 2412) % 5 == 0) ||
               f == 2484;
    if (f >= 5180 && f <= 5720)
        return (f - 5180) % 20 == 0;
    return f >= 5745 && f <= 5885 && (f - 5745) % 20 == 0;
}

/* Keep advertisement aligned with vap_write_channel's HT40 direction and
 * VHT80 centre. Ch165 and above are HT20-only in that backend. */
static int legacy_channel_ok(const struct phy_bands *pb, uint32_t f,
                             uint8_t band, uint8_t w, uint32_t centre)
{
    if (!supported_primary(f) || !phy_has_freq(pb, f)) return 0;
    if (f < 3000) {
        if (band != 0x81 && band != 0x82) return 0;
        if (f == 2484 && band == 0x82) return 0; /* ch14 has no HT */
        if (w == 1) return centre == 0 || centre == f;
        return band == 0x82 && w == 2 && f >= 2412 && f <= 2472 &&
               centre == c40_for(f) && phy_has_freq(pb, 2 * centre - f);
    }
    if (f < 5180 || f >= 5925 || (band != 0x01 && band != 0x02 &&
        band != 0x03)) return 0;
    if (w == 1) return centre == 0 || centre == f;
    if (band == 0x01 || f >= 5825) return 0;
    if (w == 2 && f <= 5805) {
        uint32_t c = c40_for(f);
        return centre == c && phy_has_freq(pb, 2 * c - f);
    }
    if (w == 3 && band == 0x03 && f <= 5805) {
        uint32_t c = ccfi80(f);
        return c != f && centre == c &&
               phy_has_freq(pb, c - 30) && phy_has_freq(pb, c - 10) &&
               phy_has_freq(pb, c + 10) && phy_has_freq(pb, c + 30);
    }
    return 0;
}

/* Shared advertisement/START gate: PR #2 supports HE20 only. */
static int ax_channel_ok(const struct phy_bands *pb, const struct phy_caps *pc,
                         uint32_t f, uint8_t w, uint32_t centre)
{
    if (!pb->he5 || !pc->has_he || !supported_primary(f) ||
        f < 5180 || f >= 5925 ||
        w != 1 || (centre != 0 && centre != f)) return 0;
    for (int i = 0; i < pb->nfreq; i++)
        if (pb->freq[i] == f && pb->he5freq[i]) return 1;
    return 0;
}

static size_t append_chan_bounded(uint8_t *b, size_t n, size_t limit,
                                  uint32_t f, uint8_t w, uint8_t band,
                                  uint32_t centre)
{
    /* Nested record: 4 outer + 8 frequency + 5 width + optional 8 centre
     * + 5 band. Never emit a partial TLV. */
    size_t size = w > 1 ? 30 : 22;
    if (n > limit || size > limit - n) return SIZE_MAX;
    return add_chan_desc(b, n, f, w, band, centre);
}

static size_t add_channel_tlvs_cap(uint8_t *b, size_t n, int phy, size_t cap)
{
    struct phy_bands pb;
    struct phy_caps pc;
    read_phy_bands(phy, &pb);
    read_phy_caps(phy, &pc);
    /* The tail reader samples iw again. Reserve the maximum 0x61/0xB7
     * inventory so a regulatory update cannot overrun the response. */
    size_t tail = 8 + 4 + PHY_MAX_FREQ * 4;
    if (cap > BODY_MAX) cap = BODY_MAX;
    if (cap < tail || n > cap - tail) return SIZE_MAX;
    size_t limit = cap - tail;
#define APPEND(f, w, band, centre) do { \
    n = append_chan_bounded(b, n, limit, (f), (w), (band), (centre)); \
    if (n == SIZE_MAX) return SIZE_MAX; \
} while (0)
    for (int i = 0; i < pb.nfreq; i++) {
        uint32_t f = pb.freq[i];
        if (!supported_primary(f)) continue;
        if (f < 3000) {                                   /* 2.4 GHz */
            APPEND(f, 1, 0x81, f);
            if (f != 2484) APPEND(f, 1, 0x82, f);
            if (legacy_channel_ok(&pb, f, 0x82, 2, c40_for(f)))
                APPEND(f, 2, 0x82, c40_for(f));
        } else if (f < 5925) {                            /* 5 GHz */
            APPEND(f, 1, 0x01, f);
            APPEND(f, 1, 0x02, f);
            APPEND(f, 1, 0x03, f);
            if (ax_channel_ok(&pb, &pc, f, 1, f))
                APPEND(f, 1, 0x04, f);
            if (legacy_channel_ok(&pb, f, 0x02, 2, c40_for(f))) {
                APPEND(f, 2, 0x02, c40_for(f));
                APPEND(f, 2, 0x03, c40_for(f));
            }
            uint32_t centre = ccfi80(f);
            if (legacy_channel_ok(&pb, f, 0x03, 3, centre))
                APPEND(f, 3, 0x03, centre);
        } else {                                          /* 6 GHz */
            /* No validated 6 GHz hostapd/manager provisioning path. */
        }
    }
#undef APPEND
    return n;
}

static size_t add_channel_tlvs(uint8_t *b, size_t n, int phy)
{
    return add_channel_tlvs_cap(b, n, phy, BODY_MAX);
}

static size_t add_current_frequency_tlv(uint8_t *body, size_t n,
                                         uint32_t curfreq)
{
    uint8_t cf[4];
    if (curfreq) {
        put32(cf, curfreq);
        n += put_el(body + n, 0x61, cf, 4);
    }
    return n;
}

static size_t add_channel_number_tlv(uint8_t *body, size_t n, int phy)
{
    struct phy_bands pb;
    uint8_t list[PHY_MAX_FREQ * 4];
    read_phy_bands(phy, &pb);
    for (int i = 0; i < pb.nfreq; i++) {
        uint32_t ch = (pb.freq[i] - chan_base_for_freq(pb.freq[i])) / 5;
        put32(list + i * 4, ch);
    }
    return n + put_el(body + n, 0xb7, list, (uint16_t)(pb.nfreq * 4));
}
