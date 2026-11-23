/* Lab-only injection of a manager-shaped START into production provisioning.
 * No TLS, router, certs or captured secrets. Requires an isolated hwsim VM. */
#define main capagent_unused_main
#include "../capagent.c"
#undef main

#define TEST_IFNAME "heagent0"

int main(int argc, char **argv)
{
    if (argc != 5 || geteuid() != 0) {
        fprintf(stderr, "usage: offline_ax_start FREQ WIDTH CENTER SSID (root)\n");
        return 2;
    }
    unsigned freq = (unsigned)strtoul(argv[1], NULL, 0);
    unsigned width = (unsigned)strtoul(argv[2], NULL, 0);
    unsigned centre = (unsigned)strtoul(argv[3], NULL, 0);
    if (width > 255 || centre > 65535 || strlen(argv[4]) > 32) return 2;
    if (access("/sys/class/net/" TEST_IFNAME, F_OK) == 0 ||
        access("/tmp/vap-" TEST_IFNAME ".conf", F_OK) == 0 ||
        access("/var/run/vap-" TEST_IFNAME ".pid", F_OK) == 0)
        return 3;
    const char *journal = getenv("CAPAGENT_TEST_JOURNAL");
    if (!journal || access(journal, F_OK) == 0) return 3;
    uint8_t mac[6] = {0x02, 0xca, 0x50, 0x11, 0x22, 0x21};
    struct cfg c;
    memset(&c, 0, sizeof(c));
    c.vap_auto = 1;
    c.vap_teardown = 1;
    c.nradios = 1;
    memcpy(c.macs[0], mac, 6);
    snprintf(c.ifnames[0], sizeof(c.ifnames[0]), "%s", TEST_IFNAME);
    g_ax_indoor = 1; /* the supervisor must independently verify indoor UA */
    g_phy_map[0] = 0;
    g_own_path = journal;
    struct own_entry *e = own_alloc(0, TEST_IFNAME);
    if (!e) return 3;
    e->owner = OWN_CAPAGENT;
    struct vap *vp = &g_vap[0][0];
    memcpy(vp->bssid, mac, 6);
    vp->freq = freq;
    vp->l2fd = vp->extfd = -1;
    uint8_t body[256], chan[48], b[4], w = (uint8_t)width, band = 0x04;
    size_t n = 0, cn = 0;
    n += put_el(body + n, 0x03, argv[4], (uint16_t)strlen(argv[4]));
    put32(b, freq);
    cn += put_el(chan + cn, 0x0b, b, 4);
    cn += put_el(chan + cn, 0x0c, &w, 1);
    if (width > 1) {
        put32(b, centre);
        cn += put_el(chan + cn, 0x0d, b, 4);
    }
    cn += put_el(chan + cn, 0x10, &band, 1);
    n += put_el(body + n, 0x0a, chan, (uint16_t)cn);
    /* START parser and managed hostapd path; no CAP socket is opened. */
    struct phy_bands pb;
    struct phy_caps pc;
    struct start_channel ch;
    read_phy_bands(0, &pb);
    read_phy_caps(0, &pc);
    if (start_channel_validate(body, (uint16_t)n, &pb, &pc, &ch))
        vap_provision(0, body, (uint16_t)n, &c, &ch);
    else
        fprintf(stderr, "offline START rejected unsupported channel\n");
    int pid = vap_hostapd_pid(TEST_IFNAME);
    if (pid <= 0) pid = vap_find_hostapd(TEST_IFNAME);
    printf("OFFLINE START width=%u centre=%u hostapd-pid=%d\n",
           width, centre, pid);
    fflush(stdout);
    if (pid > 0) {
        const char *s = getenv("CAPAGENT_OFFLINE_HOLD_SEC");
        long seconds = s ? strtol(s, NULL, 10) : 5;
        if (seconds < 1 || seconds > 30) seconds = 5;
        sleep((unsigned)seconds);
    }
    vap_destroy(0, &c);
    unlink(journal);
    return pid > 0 ? 0 : 1;
}
