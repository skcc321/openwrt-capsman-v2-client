/* NEWPHY wire builder; included from util.inc after the PHY readers. */
static int ax_channel_ok(const struct phy_bands *, const struct phy_caps *,
                         uint32_t, uint8_t, uint32_t);
static void build_newphy(uint8_t *b, const uint8_t mac[6], int phy, size_t *out)
{
    uint8_t v16[2], v32[4];
    /* Do not infer AP modes from a PHY-wide HE flag or raw frequency inventory. */
    struct phy_caps pc;
    struct phy_bands pb;
    uint8_t fbuf[PHY_MAX_FREQ * 4];
    const char *hw = phy_hwtype(phy);
    size_t n = 0;

    read_phy_bands(phy, &pb);
    read_phy_caps(phy, &pc);
    for (int i = 0; i < pb.nfreq; i++)
        put32(fbuf + i * 4, pb.freq[i]);

    n += put_el(b+n, 0x08, mac, 6);

    /* Interface/peer limits: 8 is the manager-side ceiling we advertise;
       the driver still enforces its own limit. */
    if (pc.max_ap > 0) {
        put16(v16, (uint16_t)pc.max_ap);
        n += put_el(b+n, 0x7e, v16, 2);
        n += put_el(b+n, 0x7f, v16, 2);
        n += put_el(b+n, 0x80, v16, 2);
    }

    /* 0x83 is a string (hw-type), not the old 8-byte capability blob. */
    n += put_el(b+n, 0x83, hw, (uint16_t)strlen(hw));

    put32(v32, 1);
    n += put_el(b+n, 0x8a, v32, 4);

    if (pc.nciphers > 0)
        n += put_el(b+n, 0x5e, pc.ciphers, (uint16_t)(pc.nciphers * 4));
    n += put_el(b+n, 0x05, fbuf, (uint16_t)(pb.nfreq * 4));

    if (pc.tx_chain) {
        put32(v32, pc.tx_chain);
        n += put_el(b+n, 0x4b, v32, 4);   /* tx chains */
    }
    if (pc.rx_chain) {
        put32(v32, pc.rx_chain);
        n += put_el(b+n, 0x4c, v32, 4);   /* rx chains */
    }
    for (int i = 0; i < pb.nband; i++) {
        uint8_t bd[5] = { pb.band[i], 0, 0, 0, 0x01 };
        if (pb.band[i] == 0x82 || pb.band[i] == 0x03) bd[4] = 0x03;
        if (pb.band[i] == 0x03 || pb.band[i] == 0x06) bd[4] = 0x07;
        n += put_el(b+n, 0x4d, bd, 5);
    }

    /* Wi-Fi 6 5 GHz only; neither EHT nor 6 GHz is provisioned. */
    {
        int have5 = 0;
        for (int i = 0; i < pb.nfreq; i++) {
            if (pb.freq[i] >= 4900 && pb.freq[i] < 5925) have5 = 1;
        }
        if (have5 && pb.he5 && pc.has_he) {
            uint8_t mask = 1;
            /* Derive the band mask from the very same START/descriptor
             * predicate, never from a PHY-wide HE capability alone. */
            for (int i = 0; i < pb.nfreq; i++) {
                uint32_t f = pb.freq[i], c40, c80;
                if (!he_wide_centers(f, &c40, &c80)) continue;
                if (ax_channel_ok(&pb, &pc, f, 2, c40)) mask |= 2;
                if (ax_channel_ok(&pb, &pc, f, 3, c80)) mask |= 4;
            }
            uint8_t bd[5] = { 0x04, 0, 0, 0, mask };
            n += put_el(b+n, 0x4d, bd, 5);
        }
    }

    /* 0x84 = little-endian capability bitset.  Bit 6 (0x40) tells the
       manager the CAP supports the data channel; without it a
       datapath.traffic-processing=on-capsman VAP is refused with
       "data channel not supported".  Keep bit 7 (MLO) clear. */
    {
        uint8_t caps84[4] = { 0x40, 0x00, 0x00, 0x00 };
        n += put_el(b+n, 0x84, caps84, sizeof(caps84));
    }
    *out = n;
}
