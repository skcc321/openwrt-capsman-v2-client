/* Decode exactly one START 0x0A descriptor before touching the VAP or
 * acknowledging the manager. Unknown unrelated TLVs remain extensible. */
struct start_channel {
    uint32_t freq, centre;
    uint8_t width, band;
};

static int start_channel_validate(const uint8_t *body, size_t len,
                                  const struct phy_bands *pb,
                                  const struct phy_caps *pc,
                                  struct start_channel *out)
{
    size_t p = 0;
    int found = 0;
    struct start_channel ch = {0};
    while (p + 4 <= len) {
        uint16_t t = rd16(body + p), l = rd16(body + p + 2);
        p += 4;
        if (l > len - p) return 0;
        if (t == 0x0a) {
            if (found++) return 0;
            size_t q = 0;
            unsigned seen = 0;
            while (q + 4 <= l) {
                uint16_t id = rd16(body + p + q);
                uint16_t sz = rd16(body + p + q + 2);
                q += 4;
                if (sz > l - q) return 0;
                const uint8_t *v = body + p + q;
                unsigned bit = 0;
                if (id == 0x0b) {
                    bit = 1;
                    if (sz != 4) return 0;
                    ch.freq = rd32(v);
                } else if (id == 0x0c) {
                    bit = 2;
                    if (sz != 1) return 0;
                    ch.width = v[0];
                } else if (id == 0x0d) {
                    bit = 4;
                    if (sz != 4) return 0;
                    ch.centre = rd32(v);
                } else if (id == 0x10) {
                    bit = 8;
                    if (sz != 1) return 0;
                    ch.band = v[0];
                }
                if (bit && (seen & bit)) return 0;
                seen |= bit;
                q += sz;
            }
            if (q != l || (seen & 11) != 11 || !ch.freq ||
                (ch.width > 1 && !(seen & 4))) return 0;
        }
        p += l;
    }
    if (p != len || !found) return 0;
    if (ch.band == 0x04) {
        if (!ax_channel_ok(pb, pc, ch.freq, ch.width, ch.centre)) return 0;
    } else if (!legacy_channel_ok(pb, ch.freq, ch.band, ch.width,
                                  ch.centre)) return 0;
    *out = ch;
    return 1;
}

/* 0xE016 policy per ownership mode; only the empty success reply is known on
 * the wire, so a failure sends nothing. Observer modes (legacy/netifd-owned
 * Wi-Fi, --no-vap-auto) never start a BSS here and keep upstream's ACK, as
 * does a netdev another owner runs. A BSS this agent owns is acknowledged
 * only once its AP is running. */
static int start_should_ack(int observer, int have_netdev, int managed,
                            int started)
{
    if (observer) return 1;
    if (!have_netdev) return 0;
    if (!managed) return 1;
    return started;
}

/* A running BSS ignores a repeated START, so acknowledge it only when the
 * request matches what is on air. Unknown running values (0, or ax < 0) are
 * not compared. Legacy bands share one hostapd configuration. */
static int start_conflicts_running(const struct start_channel *ch,
                                   unsigned freq, unsigned width_mhz, int ax)
{
    static const unsigned mhz[] = {0, 20, 40, 80};
    if (freq && freq != ch->freq) return 1;
    if (width_mhz && ch->width <= 3 && width_mhz != mhz[ch->width]) return 1;
    return ax >= 0 && ax != (ch->band == 0x04);
}
