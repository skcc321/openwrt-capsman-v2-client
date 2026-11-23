/* Offline production regulatory bootstrap and START dispatch test (Linux).
 * PHY and regulatory data come from a mock `iw` in a temporary directory
 * whose name contains shell metacharacters; the country request is injected
 * and the hostapd start lock lives in that directory. No CAP/TLS session,
 * netdev creation, root, mac80211_hwsim state or RF operation is used. */
#include <assert.h>
#include <signal.h>
static int test_req_set_reg(const char *cc);
static int ax_scan_prepares;
static int test_ax_scan_prepare(const char *ifname)
{
    (void)ifname;           /* "lo" stands in for the AP: never touch it */
    ax_scan_prepares++;
    return 0;
}
static char g_lock[128], g_dir[64];
#define CAP_REQ_SET_REG test_req_set_reg
#define VAP_AX_SCAN_PREPARE test_ax_scan_prepare
#define VAP_START_LOCK g_lock
#define VAP_RUN_DIR g_dir
#define main capagent_unused_main
#include "../capagent.c"
#undef main

static char g_fail_if[16];
static pid_t g_mock_ap;              /* the "running hostapd" of the retry */
static int responses, provisions, provision_result, reg_requests;
static struct start_channel last_ch;
static int last_ch_set;

static void dir_file(char *out, size_t n, const char *name)
{
    snprintf(out, n, "%s/%s", g_dir, name);
}

static void put_file(const char *name, const char *text)
{
    char path[128];
    dir_file(path, sizeof(path), name);
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}

/* Remove everything the test may have created, also after a failed assert. */
static void cleanup(void)
{
    static const char *const files[] = {"iw", "phy.txt", "reg.txt", "events.log",
        "start.lock", "pwned", "hostapd", "hcount", "vap-lo.pid",
        "vaps.state", "vaps.state.tmp"};
    char path[128];
    for (size_t i = 0; i < sizeof(g_vap_children) /
                            sizeof(g_vap_children[0]); i++)
        if (g_vap_children[i].pid)
            vap_child_stop(&g_vap_children[i]);
    if (g_mock_ap > 0) kill(g_mock_ap, SIGKILL);
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        dir_file(path, sizeof(path), files[i]);
        unlink(path);
    }
    const char *ifs[] = {g_fail_if, "lo"};
    for (size_t i = 0; i < 2; i++) {
        if (!ifs[i][0]) continue;
        snprintf(path, sizeof(path), VAP_CONF_DIR "/vap-%s.conf", ifs[i]);
        unlink(path);
        snprintf(path, sizeof(path), "/tmp/vap-%s.log", ifs[i]);
        unlink(path);
    }
    rmdir(g_dir);
}

static void on_abort(int sig)
{
    cleanup();
    signal(sig, SIG_DFL);
    raise(sig);
}

static const char phy_world[] =
    "Wiphy phy0\n\tAvailable Antennas: TX 0x3 RX 0x3\n"
    "\tSupported Ciphers:\n\t\t* CCMP-128 (00-0f-ac:4)\n"
    "\tvalid interface combinations:\n\t\t * #{ AP } <= 8,\n"
    "\tBand 1:\n\t\tHE Iftypes: AP\n\t\tFrequencies:\n"
    "\t\t\t* 2412.0 MHz [1] (20.0 dBm)\n"
    "\tBand 2:\n\t\tHE Iftypes: AP\n\t\tFrequencies:\n"
    "\t\t\t* 5180.0 MHz [36] (20.0 dBm) (no IR)\n"
    "\t\t\t* 5200.0 MHz [40] (20.0 dBm) (no IR)\n"
    "\t\t\t* 5260.0 MHz [52] (20.0 dBm) (no IR, radar detection)\n";
static const char phy_ua[] =
    "Wiphy phy0\n\tAvailable Antennas: TX 0x3 RX 0x3\n"
    "\tSupported Ciphers:\n\t\t* CCMP-128 (00-0f-ac:4)\n"
    "\tvalid interface combinations:\n\t\t * #{ AP } <= 8,\n"
    "\tBand 1:\n\t\tHE Iftypes: AP\n\t\tFrequencies:\n"
    "\t\t\t* 2412.0 MHz [1] (20.0 dBm)\n"
    "\tBand 2:\n\t\tHE Iftypes: AP\n\t\tFrequencies:\n"
    "\t\t\t* 5180.0 MHz [36] (20.0 dBm)\n"
    "\t\t\t* 5200.0 MHz [40] (20.0 dBm)\n"
    "\t\t\t* 5260.0 MHz [52] (20.0 dBm) (radar detection)\n";
static const char phy_ua_wide[] =
    "Wiphy phy0\n\tAvailable Antennas: TX 0x3 RX 0x3\n"
    "\tBand 1:\n\t\tHE Iftypes: AP\n"
    "\t\t\t* 2412.0 MHz [1] (20.0 dBm)\n"
    "\tBand 2:\n\t\tCapabilities: 0x1234\n\t\t\tHT20/HT40\n"
    "\t\tVHT Capabilities (0x1234):\n"
    "\t\tHE Iftypes: AP\n\t\t\tHE PHY Capabilities: (0x1cbfce)\n"
    "\t\t\t* 5180.0 MHz [36] (20.0 dBm)\n"
    "\t\t\t* 5200.0 MHz [40] (20.0 dBm)\n"
    "\t\t\t* 5220.0 MHz [44] (20.0 dBm)\n"
    "\t\t\t* 5240.0 MHz [48] (20.0 dBm)\n"
    "\t\t\t* 5260.0 MHz [52] (20.0 dBm) (radar detection)\n";
static const char reg_world[] =
    "global\ncountry 00: DFS-UNSET\n"
    "\t(2402 - 2472 @ 40), (N/A, 20), (N/A)\n"
    "\t(5170 - 5250 @ 80), (N/A, 20), (N/A), NO-IR, AUTO-BW\n"
    "\t(5250 - 5330 @ 80), (N/A, 20), (0 ms), DFS, NO-IR, AUTO-BW\n";
/* Captured UA rules, plus a second radio's own domain that must not apply. */
static const char reg_ua[] =
    "global\ncountry UA: DFS-ETSI\n"
    "\t(2400 - 2483 @ 40), (N/A, 20), (N/A), NO-OUTDOOR\n"
    "\t(5150 - 5250 @ 80), (N/A, 20), (N/A), NO-OUTDOOR, AUTO-BW\n"
    "\t(5250 - 5350 @ 80), (N/A, 20), (0 ms), NO-OUTDOOR, DFS, AUTO-BW\n"
    "\nphy#1 (self-managed)\ncountry US: DFS-FCC\n"
    "\t(5150 - 5250 @ 80), (N/A, 23), (N/A), NO-HE\n";

/* cfg80211 applies a user hint asynchronously; the mock applies it at once. */
static int test_req_set_reg(const char *cc)
{
    assert(!strcmp(cc, "UA"));
    reg_requests++;
    put_file("phy.txt", phy_ua);
    put_file("reg.txt", reg_ua);
    return 0;
}

static void capture_reply(mbedtls_ssl_context *ssl, uint16_t type,
                          const uint8_t hdr[10], const uint8_t *body,
                          uint16_t len)
{
    (void)ssl; (void)hdr;
    assert(type == TYPE_START_RESP && !body && !len);
    responses++;
}

static int controlled_provision(int port, const uint8_t *body, uint16_t len,
                                const struct cfg *c,
                                const struct start_channel *ch)
{
    (void)port; (void)body; (void)len; (void)c;
    provisions++;
    last_ch_set = ch != NULL;
    if (ch) last_ch = *ch;
    return provision_result;
}

/* A BSS already on air: vap_provision's repeated-START gate, fed with the
 * running channel it reads from the kernel and the hostapd config. */
static unsigned run_freq, run_width;
static int run_ax;
static int running_bss_provision(int port, const uint8_t *body, uint16_t len,
                                 const struct cfg *c,
                                 const struct start_channel *ch)
{
    (void)port; (void)body; (void)len; (void)c;
    provisions++;
    return ch && !start_conflicts_running(ch, run_freq, run_width, run_ax);
}

static int failing_hostapd_provision(int port, const uint8_t *body,
                                     uint16_t len, const struct cfg *c,
                                     const struct start_channel *ch)
{
    (void)ch;
    return vap_hostapd_start(port, g_fail_if, 0, 0, body, len, NULL, c) > 0;
}

/* vap_provision's managed tail: journal via own_note_start (which starts
 * hostapd through own_try_start), then report whether the AP is running. */
static int journal_provision(int port, const uint8_t *body, uint16_t len,
                             const struct cfg *c,
                             const struct start_channel *ch)
{
    (void)ch;
    own_note_start(c, port, body, len, NULL, (int)if_nametoindex("lo"), 1);
    return vap_hostapd_pid("lo") > 0;
}

static int newphy_ax_mask(void)
{
    uint8_t b[BODY_MAX], mac[6] = {0x02};
    size_t n, i = 0;
    build_newphy(b, mac, 0, &n);
    while (i + 4 <= n) {
        uint16_t t = rd16(b + i), l = rd16(b + i + 2);
        if (t == 0x4d && l == 5 && b[i + 4] == 0x04) return b[i + 8];
        i += 4 + (size_t)l;
    }
    return 0;
}

static int has_desc(uint32_t freq, uint8_t band, uint8_t width)
{
    uint8_t b[BODY_MAX];
    size_t n = add_channel_tlvs(b, 0, 0), i = 0;
    assert(n != SIZE_MAX);
    while (i + 4 <= n) {
        uint16_t l = rd16(b + i + 2);
        const uint8_t *v = NULL; uint16_t vl = 0;
        uint32_t f = 0; uint8_t bd = 0, w = 0;
        if (find_el(b + i + 4, l, 0x0b, &v, &vl) && vl == 4) f = rd32(v);
        if (find_el(b + i + 4, l, 0x10, &v, &vl) && vl == 1) bd = v[0];
        if (find_el(b + i + 4, l, 0x0c, &v, &vl) && vl == 1) w = v[0];
        if (f == freq && bd == band && w == width) return 1;
        i += 4 + (size_t)l;
    }
    return 0;
}

/* START body: SSID + one 0x0A {freq, width, [centre], band}. */
static size_t start_body(uint8_t *body, uint32_t freq, uint8_t width,
                         uint32_t centre, uint8_t band)
{
    uint8_t desc[40], x[4];
    size_t d = 0, n = 0;
    n += put_el(body + n, 0x03, "PR2-OFFLINE", 11);
    put32(x, freq);
    d += put_el(desc + d, 0x0b, x, 4);
    d += put_el(desc + d, 0x0c, &width, 1);
    if (centre) {
        put32(x, centre);
        d += put_el(desc + d, 0x0d, x, 4);
    }
    d += put_el(desc + d, 0x10, &band, 1);
    return n + put_el(body + n, 0x0a, desc, (uint16_t)d);
}

typedef int (*provision_fn)(int, const uint8_t *, uint16_t, const struct cfg *,
                            const struct start_channel *);
static int start_with(const struct cfg *c, provision_fn p,
                      const uint8_t *body, size_t n)
{
    uint8_t hdr[10] = {0};
    return cap_handle_start(NULL, hdr, 0, body, (uint16_t)n, c, p,
                            capture_reply);
}
static int start(const struct cfg *c, const uint8_t *body, size_t n)
{
    return start_with(c, controlled_provision, body, n);
}

/* The channel the relay/MLME report for port 0 must be exactly this. */
static void assert_chan(uint32_t freq, uint8_t width, uint8_t band)
{
    uint32_t f = 0;
    uint8_t w = 0, b = 0;
    assert(vchan_get(0, &f, &w, &b));
    assert(f == freq && w == width && b == band);
}

static void check_hostapd_log_states(void)
{
    char path[128];
    dir_file(path, sizeof(path), "events.log");
    put_file("events.log", "heagent0: AP-DISABLED\n"
                           "heagent0: AP-ENABLED\n");
    assert(vap_wait_ap_enabled(path, 100, 1) == 1);
    /* The same log can change *after* a successful readiness check.
     * A fresh read detects the later disable; this is not a watchdog
     * or automatic recovery test. */
    put_file("events.log", "heagent0: AP-ENABLED\n");
    assert(vap_wait_ap_enabled(path, 100, 1) == 1);
    FILE *later_disable = fopen(path, "a");
    assert(later_disable);
    assert(fputs("heagent0: AP-DISABLED\n", later_disable) >= 0);
    assert(fclose(later_disable) == 0);
    assert(vap_wait_ap_enabled(path, 100, 1) == 0);
    put_file("events.log", "driver initialization failed\n"
                           "heagent0: AP-ENABLED\n");
    assert(vap_wait_ap_enabled(path, 100, 1) == 1);
    put_file("events.log", "heagent0: AP-DISABLED\n"
                           "heagent0: DFS-CAC-START\n");
    assert(vap_wait_ap_enabled(path, 100, 0) == 1);
    assert(vap_wait_ap_enabled(path, 100, 1) == 0);
    put_file("events.log", "heagent0: AP-ENABLED\n"
                           "heagent0: AP-DISABLED"); /* partial final line */
    assert(vap_wait_ap_enabled(path, 100, 1) == 1);
    FILE *f = fopen(path, "w");
    assert(f);
    for (int i = 0; i < 600; i++) fputs("unrelated verbose message\n", f);
    fputs("heagent0: AP-DISABLED\nheagent0: AP-ENABLED\n", f);
    fclose(f);
    assert(vap_wait_ap_enabled(path, 100, 1) == 1);
    put_file("events.log", "heagent0: AP-DISABLED\n");
    pid_t writer = fork();
    assert(writer >= 0);
    if (!writer) {
        usleep(150000);
        FILE *later = fopen(path, "a");
        if (!later) _exit(1);
        fputs("heagent0: AP-ENABLED\n", later);
        if (fclose(later)) _exit(1);
        _exit(0);
    }
    assert(vap_wait_ap_enabled(path, 500, 1) == 1);
    int status;
    assert(waitpid(writer, &status, 0) == writer);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    put_file("events.log", "heagent0: AP-DISABLED\n");
    assert(vap_wait_ap_enabled(path, 200, 1) == 0);
    put_file("events.log", "waiting for a real event\n");
    assert(vap_wait_ap_enabled(path, 100, 1) == -1);
}

static void assert_child_reaped(pid_t pid)
{
    int status;
    assert(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD);
}

static void check_hostapd_children(void)
{
    int status;
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        for (;;) pause();        /* successful foreground startup */
    }
    assert(vap_child_track("test-success", pid) == 0);
    assert(vap_child_slot("test-success")->pid == pid);
    assert(vap_child_stop(vap_child_slot("test-success")));
    assert(!vap_child_slot("test-success"));
    assert_child_reaped(pid);

    pid = fork();
    assert(pid >= 0);
    if (!pid) _exit(3);          /* early hostapd failure */
    assert(vap_child_track("test-early", pid) == 0);
    int got = 0;
    for (int i = 0; i < 100 && !got; i++) {
        got = vap_child_poll(pid, &status);
        usleep(1000);
    }
    assert(got == 1 && WIFEXITED(status) && WEXITSTATUS(status) == 3);
    vap_child_forget(vap_child_slot("test-early"));
    assert(!vap_child_slot("test-early"));
    assert_child_reaped(pid);

    int pipefd[2];
    assert(pipe(pipefd) == 0);
    pid = fork();
    assert(pid >= 0);
    if (!pid) {
        close(pipefd[0]);
        signal(SIGTERM, SIG_IGN);
        assert(write(pipefd[1], "R", 1) == 1);
        for (;;) pause();        /* timeout: ignores TERM, requires KILL */
    }
    close(pipefd[1]);
    char ready;
    assert(read(pipefd[0], &ready, 1) == 1 && ready == 'R');
    close(pipefd[0]);
    assert(vap_child_track("test-timeout", pid) == 0);
    assert(vap_child_stop(vap_child_slot("test-timeout")));
    assert(!vap_child_slot("test-timeout"));
    assert_child_reaped(pid);

    pid = fork();
    assert(pid >= 0);
    if (!pid) _exit(0);          /* exit after startup: watchdog sweep */
    assert(vap_child_track("test-late", pid) == 0);
    for (int i = 0; i < 100 && vap_child_slot("test-late"); i++) {
        vap_children_sweep();
        usleep(1000);
    }
    assert(!vap_child_slot("test-late"));
    assert_child_reaped(pid);
}

int main(void)
{
    char path[128], script[512];
    /* Space, ';' and '$(...)' would split or run commands under popen(). */
    snprintf(g_dir, sizeof(g_dir), "/tmp/capagent start;$(touch pwned)-XXXXXX");
    assert(mkdtemp(g_dir));
    signal(SIGABRT, on_abort);
    dir_file(g_lock, sizeof(g_lock), "start.lock");
    snprintf(script, sizeof(script),
             "#!/bin/sh\ncase \"$1 $2\" in\n"
             "\"reg get\") exec cat '%s/reg.txt' ;;\n"
             "phy*) exec cat '%s/phy.txt' ;;\nesac\nexit 1\n", g_dir, g_dir);
    put_file("iw", script);
    dir_file(path, sizeof(path), "iw");
    assert(chmod(path, 0700) == 0);
    assert(setenv("CAPAGENT_IW", path, 1) == 0);
    check_hostapd_log_states();
    check_hostapd_children();
    put_file("phy.txt", phy_world);
    put_file("reg.txt", reg_world);

    struct cfg c = {0};
    c.nradios = 1;
    c.vap_auto = 1;
    g_vap_country = "UA";
    g_ax_indoor = 1;

    /* World-domain boot: 5 GHz is no-IR, so nothing 5 GHz is advertised. */
    assert(newphy_ax_mask() == 0);
    assert(!has_desc(5180, 0x03, 1) && !has_desc(5180, 0x04, 1));
    assert(has_desc(2412, 0x81, 1));
    g_wl_legacy = 1;                 /* legacy Wi-Fi: never set a country */
    assert(vap_regulatory_bootstrap() == 0 && reg_requests == 0);
    g_wl_legacy = 0;

    /* Own mode applies the CAP country before NEWPHY samples the PHY. */
    assert(vap_regulatory_bootstrap() == 0 && reg_requests == 1);
    assert(newphy_ax_mask() == 0x01);
    assert(has_desc(5180, 0x04, 1) && has_desc(5180, 0x03, 1));
    assert(has_desc(5260, 0x03, 1) && !has_desc(5260, 0x04, 1)); /* DFS */
    assert(vap_regulatory_bootstrap() == 0 && reg_requests == 1);

    /* A first START with no recorded channel that fails leaves none. */
    uint8_t body[128];
    size_t n = start_body(body, 5180, 1, 0, 0x04);
    provision_result = 0;
    assert(!start(&c, body, n) && responses == 0);
    assert(!vchan_get(0, NULL, NULL, NULL));
    provision_result = 1;
    assert(start(&c, body, n) && responses == 1 && provisions == 2);
    assert(last_ch_set && last_ch.freq == 5180 && last_ch.band == 0x04);
    assert_chan(5180, 1, 0x04);

    /* The BSS now runs HE20 on 5180. Conflicting repeats are refused and
     * the recorded channel stays that of the running BSS. */
    run_freq = 5180; run_width = 20; run_ax = 1;
    n = start_body(body, 5200, 1, 0, 0x04);           /* frequency */
    assert(!start_with(&c, running_bss_provision, body, n));
    assert_chan(5180, 1, 0x04);
    n = start_body(body, 5180, 1, 0, 0x03);           /* HE mode */
    assert(!start_with(&c, running_bss_provision, body, n));
    assert_chan(5180, 1, 0x04);
    n = start_body(body, 5180, 2, 5190, 0x03);        /* width (and HE) */
    assert(!start_with(&c, running_bss_provision, body, n));
    assert_chan(5180, 1, 0x04);
    run_ax = 0;                                       /* width alone */
    vchan_set(0, 5180, 1, 0x03);
    assert(!start_with(&c, running_bss_provision, body, n));
    assert_chan(5180, 1, 0x03);
    run_ax = 1;
    vchan_set(0, 5180, 1, 0x04);
    assert(responses == 1);
    n = start_body(body, 5180, 1, 0, 0x04);           /* identical repeat */
    assert(start_with(&c, running_bss_provision, body, n) && responses == 2);
    assert_chan(5180, 1, 0x04);

    /* Startup failure: no ACK, recorded channel unchanged. */
    provision_result = 0;
    n = start_body(body, 5200, 1, 0, 0x04);
    assert(!start(&c, body, n) && responses == 2);
    assert_chan(5180, 1, 0x04);

    /* HE20-only PHY: wide AX refused; DFS AX and bad TLVs also refused. */
    int before = provisions;
    provision_result = 1;
    n = start_body(body, 5180, 2, 5190, 0x04);
    assert(!start(&c, body, n));
    n = start_body(body, 5180, 3, 5210, 0x04);
    assert(!start(&c, body, n));
    n = start_body(body, 5260, 1, 0, 0x04);
    assert(!start(&c, body, n));
    n = start_body(body, 5180, 1, 0, 0x04);
    body[4 + 11 + 4 + 11] = 2;       /* width TLV length 1 -> 2 */
    assert(!start(&c, body, n));
    n = start_body(body, 5180, 1, 0, 0x04);
    size_t dup = n + put_el(body + n, 0x0a, body + 4 + 11 + 4, 18);
    assert(!start(&c, body, dup));
    assert(responses == 2 && provisions == before);
    assert_chan(5180, 1, 0x04);
    n = start_body(body, 5260, 1, 0, 0x03);   /* legacy DFS via hostapd CAC */
    assert(start(&c, body, n) && responses == 3);
    assert_chan(5260, 1, 0x03);

    /* NO-OUTDOOR without --indoor: AX refused, legacy unchanged. */
    g_ax_indoor = 0;
    n = start_body(body, 5180, 1, 0, 0x04);
    assert(!start(&c, body, n) && responses == 3);
    n = start_body(body, 5180, 1, 0, 0x03);
    assert(start(&c, body, n) && responses == 4);
    g_ax_indoor = 1;

    /* Observer modes keep upstream's lenient channel record and ACK. */
    c.vap_auto = 0;
    n = start_body(body, 5180, 2, 5190, 0x04);
    assert(start(&c, body, n) && responses == 5 && !last_ch_set);
    assert_chan(5180, 2, 0x04);
    c.vap_auto = 1;
    g_wl_legacy = 1;
    assert(start_with(&c, vap_provision, body, n) && responses == 6);
    g_wl_legacy = 0;

    /* Production hostapd entry (start lock included) with a hostapd that
     * fails: no ACK, recorded channel restored, nothing left behind. */
    vchan_set(0, 5180, 1, 0x04);
    snprintf(g_fail_if, sizeof(g_fail_if), "pr2t%u",
             (unsigned)getpid() % 100000);
    char conf[128];
    snprintf(conf, sizeof(conf), VAP_CONF_DIR "/vap-%s.conf", g_fail_if);
    assert(access(conf, F_OK) != 0);
    assert(setenv("CAPAGENT_HOSTAPD", "/bin/false", 1) == 0);
    n = start_body(body, 5200, 1, 0, 0x04);
    assert(!start_with(&c, failing_hostapd_provision, body, n));
    assert(responses == 6);
    assert_chan(5180, 1, 0x04);
    assert(access(g_lock, F_OK) == 0);   /* the lock really was used */

    /* Automatic retry through the production ownership path. "lo" stands in
     * for the AP netdev (it exists unprivileged; nothing is created). The
     * mock hostapd fails once, then daemonizes a process whose cmdline holds
     * the config path, writes the pid file and logs AP-ENABLED. */
    assert(access(OWN_RUN_DIR "/vap-lo.pid", F_OK) != 0);
    assert(access(VAP_CONF_DIR "/vap-lo.conf", F_OK) != 0);
    snprintf(script, sizeof(script),
             "#!/bin/sh\nc='%s/hcount'\nn=$(cat \"$c\" 2>/dev/null || echo 0)\n"
             "echo $((n + 1)) > \"$c\"\n[ \"$n\" -eq 0 ] && exit 1\n"
             "tail -f /dev/null \"$4\" </dev/null >/dev/null 2>&1 &\n"
             "echo $! > \"$3\"\necho AP-ENABLED\n", g_dir);
    put_file("hostapd", script);
    dir_file(path, sizeof(path), "hostapd");
    assert(chmod(path, 0700) == 0);
    assert(setenv("CAPAGENT_HOSTAPD", path, 1) == 0);
    dir_file(path, sizeof(path), "absent-netifd.json");  /* probe: unknown */
    assert(setenv("CAPAGENT_NETIFD_STATUS", path, 1) == 0);
    static char state[128];
    dir_file(state, sizeof(state), "vaps.state");
    g_own_path = state;
    struct own_entry *e = own_alloc(0, "lo");
    assert(e);
    e->owner = OWN_CAPAGENT;
    e->ifindex = (int)if_nametoindex("lo");

    vchan_set(0, 5180, 1, 0x04);                       /* channel A */
    n = start_body(body, 5200, 1, 0, 0x04);            /* channel B */
    assert(!start_with(&c, journal_provision, body, n));
    assert(responses == 6 && e->fail_count == 1 && e->retry_at && !e->pid);
    assert_chan(5180, 1, 0x04);         /* first start failed: A preserved */
    usleep(2100 * 1000);                /* the real 2 s backoff */
    own_service(&c);                    /* own_reconcile_soft -> retry */
    assert(e->pid > 0 && e->fail_count == 0);
    g_mock_ap = e->pid;
    assert(vap_hostapd_pid("lo") == e->pid);
    assert_chan(5200, 1, 0x04);         /* retry succeeded on B: recorded */
    assert(responses == 6);             /* no invented late 0xE016 */
    assert(start_with(&c, journal_provision, body, n));  /* repeat of B */
    assert(responses == 7 && e->pid == g_mock_ap);
    assert_chan(5200, 1, 0x04);
    dir_file(path, sizeof(path), "hcount");
    FILE *hc = fopen(path, "r");
    int launches = 0;
    assert(hc && fscanf(hc, "%d", &launches) == 1);
    fclose(hc);
    assert(launches == 2);              /* no second daemon on the repeat */

    /* Switch only the mock inventory to a HE40/HE80-capable PHY. The
     * production NEWPHY, CREATEVAP and START readers must agree. */
    put_file("phy.txt", phy_ua_wide);
    assert(newphy_ax_mask() == 7);
    assert(has_desc(5180, 0x04, 1) &&
           has_desc(5180, 0x04, 2) && has_desc(5180, 0x04, 3));
    assert(!has_desc(5260, 0x04, 2)); /* no DFS/CAC bypass */
    before = provisions;
    n = start_body(body, 5180, 2, 5210, 0x04);
    assert(!start(&c, body, n));      /* wrong HE40 center */
    n = start_body(body, 5180, 3, 5190, 0x04);
    assert(!start(&c, body, n));      /* wrong HE80 center */
    n = start_body(body, 5180, 4, 5210, 0x04);
    assert(!start(&c, body, n));      /* HE160 unsupported */
    assert(provisions == before && responses == 7);
    n = start_body(body, 5180, 2, 5190, 0x04);
    provision_result = 0;
    assert(!start(&c, body, n) && responses == 7);
    assert_chan(5200, 1, 0x04);     /* failed width change cannot overwrite */
    provision_result = 1;
    assert(start(&c, body, n) && responses == 8);
    assert_chan(5180, 2, 0x04);
    n = start_body(body, 5180, 3, 5210, 0x04);
    assert(start(&c, body, n) && responses == 9);
    assert_chan(5180, 3, 0x04);
    run_freq = 5180; run_width = 80; run_ax = 1;
    n = start_body(body, 5180, 2, 5190, 0x04);
    assert(!start_with(&c, running_bss_provision, body, n));
    assert_chan(5180, 3, 0x04);

    /* Live RouterOS HE40 regression: wide AX runs hostapd in the foreground
     * (no -B), and hostapd then writes no -P pid file. The production START
     * tail (vap_hostapd_pid) must still see the running BSS and ACK. The
     * mock never writes the pid file in foreground mode, like hostapd. */
    kill(g_mock_ap, SIGKILL);                       /* retire the HE20 daemon */
    g_mock_ap = 0;
    dir_file(path, sizeof(path), "vap-lo.pid");     /* VAP_RUN_DIR, temp dir */
    unlink(path);
    e->pid = 0;
    snprintf(script, sizeof(script),
             "#!/bin/sh\nc='%s/hcount'\nn=$(cat \"$c\" 2>/dev/null || echo 0)\n"
             "echo $((n + 1)) > \"$c\"\n"
             "[ \"$1\" = -B ] && exit 9\n"          /* wide AX must not daemonize */
             "echo AP-ENABLED\nexec tail -f /dev/null \"$3\" </dev/null\n",
             g_dir);
    put_file("hostapd", script);
    dir_file(path, sizeof(path), "hostapd");
    assert(chmod(path, 0700) == 0);
    int prepares = ax_scan_prepares, before_resp = responses;
    n = start_body(body, 5180, 2, 5190, 0x04);
    assert(start_with(&c, journal_provision, body, n));
    assert(responses == before_resp + 1);           /* 0xE016 sent */
    assert(ax_scan_prepares == prepares + 1);
    assert_chan(5180, 2, 0x04);
    struct vap_child *fg = vap_child_slot("lo");
    assert(fg && fg->pid == e->pid);                /* tracked foreground */
    pid_t fg_pid = fg->pid;
    assert(vap_pidfile_value("lo") == fg_pid);      /* written by the agent */
    assert(vap_hostapd_pid("lo") == fg_pid && vap_hostapd_running("lo"));
    dir_file(path, sizeof(path), "hcount");
    hc = fopen(path, "r");
    assert(hc && fscanf(hc, "%d", &launches) == 1);
    fclose(hc);
    assert(launches == 3);
    /* An identical repeat and the reconcile tick reuse the live child. */
    assert(start_with(&c, journal_provision, body, n));
    assert(responses == before_resp + 2);
    own_service(&c);
    assert(e->pid == fg_pid && vap_child_slot("lo") == fg);
    hc = fopen(path, "r");
    assert(hc && fscanf(hc, "%d", &launches) == 1);
    fclose(hc);
    assert(launches == 3);                          /* no duplicate daemon */
    /* Ownership teardown reaps the child (bounded) and drops its pid file. */
    own_stop_pid(fg_pid);
    assert(!vap_child_slot("lo"));
    assert_child_reaped(fg_pid);
    assert(vap_pidfile_value("lo") == 0 && !vap_hostapd_running("lo"));
    e->pid = 0;

    /* A foreground hostapd that dies after a successful START: the sweep
     * reaps it and removes the agent-written pid file, so nothing mistakes
     * a recycled pid for this BSS and the journal can restart it. */
    unlink(VAP_CONF_DIR "/vap-lo.conf");
    n = start_body(body, 5180, 2, 5190, 0x04);
    body[4 + 2] ^= 1;                    /* SSID byte: a new profile body */
    assert(start_with(&c, journal_provision, body, n));
    fg = vap_child_slot("lo");
    assert(fg && vap_pidfile_value("lo") == fg->pid);
    fg_pid = fg->pid;
    kill(fg_pid, SIGKILL);
    for (int i = 0; i < 100 && vap_child_slot("lo"); i++) {
        vap_children_sweep();
        usleep(10000);
    }
    assert(!vap_child_slot("lo"));
    assert_child_reaped(fg_pid);
    assert(vap_pidfile_value("lo") == 0 && !vap_hostapd_running("lo"));
    e->pid = 0;

    /* A foreground child that exits right after logging AP-ENABLED is a
     * failed start: no pid file, no ACK, no zombie. */
    snprintf(script, sizeof(script),
             "#!/bin/sh\necho AP-ENABLED\nsleep 1\nexit 0\n");
    put_file("hostapd", script);
    before_resp = responses;
    body[4 + 2] ^= 2;
    assert(!start_with(&c, journal_provision, body, n));
    assert(responses == before_resp);
    assert(!vap_child_slot("lo") && vap_pidfile_value("lo") == 0);
    assert(waitpid(-1, NULL, WNOHANG) <= 0);        /* nothing left to reap */

    dir_file(path, sizeof(path), "pwned");
    assert(access(path, F_OK) != 0 && access("pwned", F_OK) != 0);
    cleanup();
    assert(access(g_dir, F_OK) != 0 && access(conf, F_OK) != 0);
    puts("offline START: world->UA bootstrap, multi-radio rules, ownership "
         "modes, conflicting repeats and failed START keep the running "
         "channel, automatic retry records it, no false 0xE016; ordered "
         "hostapd logs, bounded child reaping and foreground HE40 0xE016 "
         "PASS");
    return 0;
}
