#!/usr/bin/env python3
import sys, os, json, time, queue, threading, subprocess, tempfile, shlex

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import analyzer
    HAVE_ANALYZER = True
except Exception as _e:
    analyzer = None
    HAVE_ANALYZER = False
    ANALYZER_ERR = str(_e)

HERE = os.path.dirname(os.path.abspath(__file__))
SH = os.path.join(HERE, "netdeep.sh")
DB = getattr(analyzer, "DEFAULT_DB", os.path.expanduser("~/.netdeep/netdeep.db")) if HAVE_ANALYZER else os.path.expanduser("~/.netdeep/netdeep.db")

PORT_CHOICES = ["infra", "web", "proxmox", "fast", "top", "top100", "all", "custom"]
SEV_RANK = {"crit": 3, "critical": 3, "high": 2, "med": 1, "medium": 1, "low": 0, "info": 0}

# fields: key, kind, label, needs_root
FIELDS = [
    ("target", "text", "Target", False),
    ("ports", "choice", "Ports", False),
    ("custom", "text", "Custom", False),
    ("timeout", "text", "Timeout", False),
    ("arp", "bool", "L2 ARP", True),
    ("osdetect", "bool", "OS detect", True),
    ("scripts", "bool", "NSE scripts", False),
    ("deep", "bool", "Deep vuln", True),
    ("ssdp", "bool", "SSDP", False),
    ("mdns", "bool", "mDNS", False),
    ("netbios", "bool", "NetBIOS", False),
    ("masscan", "bool", "masscan-fast", True),
    ("skipdisc", "bool", "Skip discovery", False),
]


def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def default_target():
    try:
        out = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
        iface = None
        for ln in out.splitlines():
            ln = ln.strip()
            if ln.startswith("interface:"):
                iface = ln.split(":", 1)[1].strip()
        if iface:
            ic = subprocess.check_output(["ifconfig", iface], text=True, stderr=subprocess.DEVNULL)
            for ln in ic.splitlines():
                ln = ln.strip()
                if ln.startswith("inet "):
                    ip = ln.split()[1]
                    o = ip.split(".")
                    if len(o) == 4:
                        return "%s.%s.%s.0/24" % (o[0], o[1], o[2])
    except Exception:
        pass
    return "192.168.1.0/24"


def default_config():
    return {
        "target": default_target(),
        "ports": "infra",
        "custom": "",
        "timeout": "2",
        "arp": True, "osdetect": False, "scripts": False, "deep": False,
        "ssdp": True, "mdns": True, "netbios": False, "masscan": False, "skipdisc": False,
    }


def ports_spec(cfg):
    if cfg["ports"] == "custom":
        return cfg["custom"].strip() or "top"
    return cfg["ports"]


def build_argv(cfg):
    a = [SH, cfg["target"], "--ports", ports_spec(cfg), "--timeout", str(cfg["timeout"]).strip() or "2"]
    if not cfg["arp"]: a.append("--no-l2")   # l2 is on by default in the engine
    if cfg["osdetect"]: a.append("--os")
    if cfg["scripts"]: a.append("--scripts")
    if cfg["deep"]: a.append("--deep")
    if cfg["ssdp"]: a.append("--ssdp")
    if cfg["mdns"]: a.append("--mdns")
    if cfg["netbios"]: a.append("--netbios")
    if cfg["masscan"]: a.append("--fast")
    if cfg["skipdisc"]: a.append("--no-discovery")
    return a


import curses

C_RED = C_YEL = C_GRN = C_CYN = C_DIM = 0


def init_colors():
    global C_RED, C_YEL, C_GRN, C_CYN, C_DIM
    try:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        C_RED = curses.color_pair(1)
        C_YEL = curses.color_pair(2)
        C_GRN = curses.color_pair(3)
        C_CYN = curses.color_pair(4)
        C_DIM = curses.A_DIM
    except curses.error:
        pass


def aw(win, y, x, s, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    s = str(s)
    if x < 0:
        s = s[-x:]
        x = 0
    s = s[:max(0, w - x - 1)]
    try:
        win.addstr(y, x, s, attr)
    except curses.error:
        pass


def highest_sev(host):
    best = None
    br = -1
    for r in host.get("risks", []):
        rk = SEV_RANK.get(str(r.get("sev", "")).lower(), 0)
        if rk > br:
            br = rk
            best = str(r.get("sev", ""))
    return best or ""


def sev_attr(sev):
    rk = SEV_RANK.get(str(sev).lower(), 0)
    if rk >= 3:
        return C_RED
    if rk == 2:
        return C_YEL
    return 0


def ip_key(h):
    try:
        return tuple(int(x) for x in h.get("ip", "").split("."))
    except Exception:
        return (999, 999, 999, 999)


def sort_hosts(hosts, mode):
    if mode == "type":
        return sorted(hosts, key=lambda h: (h.get("device_type", "") or "~", ip_key(h)))
    if mode == "vendor":
        return sorted(hosts, key=lambda h: (h.get("vendor", "") or "~", ip_key(h)))
    if mode == "risk":
        return sorted(hosts, key=lambda h: (-SEV_RANK.get(highest_sev(h).lower(), -1), ip_key(h)))
    if mode == "ports":
        return sorted(hosts, key=lambda h: (-len(h.get("ports", [])), ip_key(h)))
    return sorted(hosts, key=ip_key)


def draw_scan(stdscr, log, spin, elapsed, cfg):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    aw(stdscr, 0, 0, " scanning %s  %s  %5.1fs " % (cfg["target"], spin, elapsed), curses.A_REVERSE)
    top = 2
    rows = h - 4
    tail = log[-rows:] if len(log) > rows else log
    y = top
    for ln in tail:
        low = ln.lower()
        at = 0
        if "l2" in low or "arp" in low:
            at = C_CYN
        elif "l3" in low or "discover" in low or "ping" in low:
            at = C_GRN
        elif "l4" in low or "port" in low or "nmap" in low:
            at = C_YEL
        aw(stdscr, y, 1, ln, at)
        y += 1
    aw(stdscr, h - 1, 0, " [q] abort ", curses.A_REVERSE)
    stdscr.refresh()


def run_scan(stdscr, cfg):
    fd, tmp = tempfile.mkstemp(prefix="netdeep-", suffix=".json")
    os.close(fd)
    argv = build_argv(cfg) + ["--json", tmp]
    try:
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except OSError as e:
        return {"_error": "spawn: %s" % e}
    q = queue.Queue()

    def pump():
        try:
            for ln in p.stderr:
                q.put(ln.rstrip("\n"))
        finally:
            try:
                p.stderr.close()
            except Exception:
                pass

    th = threading.Thread(target=pump, daemon=True)
    th.start()
    log = []
    spin = "|/-\\"
    si = 0
    t0 = time.time()
    stdscr.nodelay(True)
    aborted = False
    while True:
        try:
            while True:
                log.append(q.get_nowait())
        except queue.Empty:
            pass
        draw_scan(stdscr, log, spin[si % 4], time.time() - t0, cfg)
        si += 1
        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            p.terminate()
            aborted = True
            break
        if p.poll() is not None and not th.is_alive() and q.empty():
            break
        time.sleep(0.1)
    stdscr.nodelay(False)
    if aborted:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return None
    try:
        with open(tmp) as f:
            data = json.load(f)
    except Exception as e:
        data = {"_error": "json load: %s" % e, "_log": log[-30:]}
    try:
        os.unlink(tmp)
    except OSError:
        pass
    return data


def prompt_line(stdscr, label, init=""):
    h, w = stdscr.getmaxyx()
    curses.curs_set(1)
    buf = list(init)
    while True:
        stdscr.move(h - 1, 0)
        stdscr.clrtoeol()
        aw(stdscr, h - 1, 0, label + "".join(buf), curses.A_REVERSE)
        try:
            stdscr.move(h - 1, min(w - 1, len(label) + len(buf)))
        except curses.error:
            pass
        ch = stdscr.getch()
        if ch in (10, 13, curses.KEY_ENTER):
            curses.curs_set(0)
            return "".join(buf)
        if ch == 27:
            curses.curs_set(0)
            return None
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop()
        elif 32 <= ch <= 126:
            buf.append(chr(ch))


def menu_overlay(stdscr, title, items):
    sel = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        aw(stdscr, 0, 0, " " + title + " ", curses.A_REVERSE)
        for i, it in enumerate(items):
            at = curses.A_REVERSE if i == sel else 0
            aw(stdscr, 2 + i, 2, ("> " if i == sel else "  ") + it, at)
        aw(stdscr, h - 1, 0, " up/down select  enter ok  esc cancel ", C_DIM)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (curses.KEY_UP,) and sel > 0:
            sel -= 1
        elif ch in (curses.KEY_DOWN,) and sel < len(items) - 1:
            sel += 1
        elif ch in (10, 13, curses.KEY_ENTER):
            return sel
        elif ch in (27, ord("q")):
            return -1


def config_screen(stdscr, cfg):
    root = is_root()
    idx = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        rb = "root: yes" if root else "root: NO (root-only checks skipped by engine)"
        aw(stdscr, 0, 0, " netdeep ", curses.A_REVERSE)
        aw(stdscr, 0, 10, rb, C_GRN if root else C_YEL)
        y = 2
        for i, (k, kind, label, nr) in enumerate(FIELDS):
            cur = i == idx
            marker = "> " if cur else "  "
            lab = label
            if nr:
                lab += " *"
            aw(stdscr, y, 1, marker + lab.ljust(16), curses.A_REVERSE if cur else 0)
            v = cfg[k]
            if kind == "bool":
                vs = "[x]" if v else "[ ]"
                va = C_GRN if v else C_DIM
                if nr and not root and v:
                    vs += " will skip"
                    va = C_YEL
                aw(stdscr, y, 20, vs, va)
            elif kind == "choice":
                aw(stdscr, y, 20, "< %s >" % v, C_CYN)
            else:
                aw(stdscr, y, 20, str(v) if v else "-", C_CYN)
            y += 1
        y += 1
        aw(stdscr, y, 1, "cmd: " + " ".join(shlex.quote(x) for x in build_argv(cfg)), C_DIM)
        if not HAVE_ANALYZER:
            aw(stdscr, y + 1, 1, "note: analyzer import failed - WoL/label/export-helper disabled", C_YEL)
        aw(stdscr, h - 1, 0, " up/down field  left/right/space change  type edit  enter/F5 start  q quit ", curses.A_REVERSE)
        stdscr.refresh()
        ch = stdscr.getch()
        k, kind, label, nr = FIELDS[idx]
        if ch == curses.KEY_UP:
            idx = (idx - 1) % len(FIELDS)
        elif ch == curses.KEY_DOWN:
            idx = (idx + 1) % len(FIELDS)
        elif ch in (curses.KEY_ENTER, 10, 13) or ch == curses.KEY_F5:
            return "start"
        elif ch in (ord("q"), ord("Q")):
            return "quit"
        elif kind == "bool" and ch in (curses.KEY_LEFT, curses.KEY_RIGHT, ord(" ")):
            cfg[k] = not cfg[k]
        elif kind == "choice" and ch in (curses.KEY_LEFT, curses.KEY_RIGHT):
            ci = PORT_CHOICES.index(cfg[k])
            ci = (ci + (1 if ch == curses.KEY_RIGHT else -1)) % len(PORT_CHOICES)
            cfg[k] = PORT_CHOICES[ci]
        elif kind == "text":
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                cfg[k] = cfg[k][:-1]
            elif 32 <= ch <= 126:
                cfg[k] = cfg[k] + chr(ch)


def host_display(h):
    return h.get("label") or h.get("rdns") or h.get("ip", "")


def ports_brief(h):
    ps = h.get("ports", [])
    if not ps:
        return "-"
    nums = [str(p.get("port")) for p in ps]
    return "%d: %s" % (len(nums), ",".join(nums))


def detail_lines(host, changes):
    L = []
    def add(s, a=0):
        L.append((s, a))
    g = lambda k: host.get(k) or "-"
    add("== %s ==" % host.get("ip", ""), curses.A_BOLD)
    add("rdns   %s" % g("rdns"))
    add("mac    %s  %s" % (g("mac"), g("vendor")))
    add("state  %s   rtt %s" % (g("state"), g("rtt")))
    add("os     %s" % g("os"))
    dt = host.get("device_type", "")
    tc = host.get("type_confidence", "")
    add("type   %s (%s)" % (dt, tc), C_CYN)
    sig = host.get("type_signals", [])
    if sig:
        add("       signals: " + ", ".join(str(x) for x in sig), C_DIM)
    add("seen   first %s  last %s" % (host.get("first_seen", ""), host.get("last_seen", "")))
    ch = host.get("changes", [])
    if ch:
        add("changes:", C_YEL)
        for c in ch:
            add("   - %s" % c, C_YEL)
    app = host.get("app", {})
    if app:
        add("app:", C_GRN)
        for kk, vv in app.items():
            add("   %s: %s" % (kk, vv), C_GRN)
    risks = host.get("risks", [])
    if risks:
        add("risks:")
        for r in risks:
            add("   [%s] %s %s" % (r.get("sev", ""), ("p%s " % r.get("port")) if r.get("port") else "", r.get("msg", "")), sev_attr(r.get("sev")))
    add("ports:")
    for p in host.get("ports", []):
        pv = " ".join(x for x in [p.get("product", ""), p.get("version", ""), p.get("extra", "")] if x)
        add("   %s/%s %s  %s" % (p.get("port"), p.get("proto", ""), p.get("service", ""), pv))
        scr = p.get("scripts", {})
        for sk, sv in (scr or {}).items():
            first = str(sv).splitlines()[0] if sv else ""
            add("      %s: %s" % (sk, first), C_DIM)
    return L


def show_detail(stdscr, host, changes):
    lines = detail_lines(host, changes)
    off = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        rows = h - 2
        for i, (s, a) in enumerate(lines[off:off + rows]):
            aw(stdscr, 1 + i, 1, s, a)
        aw(stdscr, h - 1, 0, " up/down scroll  q/enter close ", curses.A_REVERSE)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (ord("q"), 27, 10, 13, curses.KEY_ENTER):
            return
        elif ch == curses.KEY_UP and off > 0:
            off -= 1
        elif ch == curses.KEY_DOWN and off < max(0, len(lines) - rows):
            off += 1
        elif ch == curses.KEY_NPAGE:
            off = min(off + rows, max(0, len(lines) - rows))
        elif ch == curses.KEY_PPAGE:
            off = max(0, off - rows)


def show_stats(stdscr, data):
    s = data.get("summary", {})
    ch = data.get("changes", {})
    L = []
    L.append(("hosts %s  up %s" % (s.get("hosts", 0), s.get("up", 0)), curses.A_BOLD))
    L.append(("", 0))
    L.append(("by type:", C_CYN))
    for k, v in sorted(s.get("by_type", {}).items(), key=lambda x: -x[1]):
        L.append(("   %-16s %s" % (k, v), 0))
    L.append(("by vendor (top):", C_CYN))
    for k, v in sorted(s.get("by_vendor", {}).items(), key=lambda x: -x[1])[:10]:
        L.append(("   %-16s %s" % (k, v), 0))
    L.append(("risks:", C_CYN))
    for k, v in s.get("risks", {}).items():
        L.append(("   %-16s %s" % (k, v), sev_attr(k)))
    px = s.get("proxmox", [])
    if px:
        L.append(("proxmox: " + ", ".join(px), C_GRN))
    L.append(("", 0))
    L.append(("changes: new %d gone %d new_ports %d closed_ports %d" % (
        len(ch.get("new_hosts", [])), len(ch.get("gone_hosts", [])),
        len(ch.get("new_ports", [])), len(ch.get("closed_ports", []))), C_YEL))
    off = 0
    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        aw(stdscr, 0, 0, " stats ", curses.A_REVERSE)
        for i, (t, a) in enumerate(L[off:off + h - 2]):
            aw(stdscr, 1 + i, 1, t, a)
        aw(stdscr, h - 1, 0, " q/enter close ", curses.A_REVERSE)
        stdscr.refresh()
        c = stdscr.getch()
        if c in (ord("q"), 27, 10, 13, curses.KEY_ENTER):
            return
        elif c == curses.KEY_DOWN and off < max(0, len(L) - (h - 2)):
            off += 1
        elif c == curses.KEY_UP and off > 0:
            off -= 1


def suspend_run(stdscr, cmd, wait=True):
    # os.system so the child gets the real tty (ssh/ping/traceroute); ip is shlex.quoted by callers
    curses.endwin()
    try:
        os.system(cmd)
    except Exception:
        pass
    if wait:
        try:
            input("\n[enter to return] ")
        except EOFError:
            pass
    stdscr.clear()
    stdscr.refresh()


def web_port(host):
    ps = {p.get("port") for p in host.get("ports", [])}
    if 8006 in ps:
        return 8006
    if 8007 in ps:
        return 8007
    return 443


def do_export(stdscr, data, fmt, ext):
    path = os.path.expanduser("~/netdeep-report.%s" % ext)
    try:
        r = subprocess.run(["python3", os.path.join(HERE, "analyzer.py"), "export",
                            "--format", fmt, "--out", path],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode == 0 and os.path.exists(path):
            return "exported %s" % path
    except Exception:
        pass
    # fallback: write from memory
    try:
        if ext == "json":
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            return "exported (mem) %s" % path
        if ext == "csv":
            import csv
            with open(path, "w", newline="") as f:
                wtr = csv.writer(f)
                wtr.writerow(["ip", "host", "mac", "vendor", "type", "state", "ports", "risk"])
                for hh in data.get("hosts", []):
                    wtr.writerow([hh.get("ip", ""), host_display(hh), hh.get("mac", ""),
                                  hh.get("vendor", ""), hh.get("device_type", ""), hh.get("state", ""),
                                  ";".join(str(p.get("port")) for p in hh.get("ports", [])),
                                  highest_sev(hh)])
            return "exported (mem) %s" % path
    except Exception as e:
        return "export failed: %s" % e
    return "export failed (helper needed for %s)" % fmt


def results_screen(stdscr, data, cfg):
    if "_error" in data:
        stdscr.erase()
        aw(stdscr, 1, 1, "scan error: %s" % data["_error"], C_RED)
        for i, ln in enumerate(data.get("_log", [])):
            aw(stdscr, 3 + i, 2, ln, C_DIM)
        aw(stdscr, 0, 0, " press r rescan / q quit ", curses.A_REVERSE)
        stdscr.refresh()
        while True:
            c = stdscr.getch()
            if c in (ord("q"),):
                return "quit"
            if c in (ord("r"),):
                return "rescan"

    changes = data.get("changes", {})
    new_hosts = set(changes.get("new_hosts", []))
    master = data.get("hosts", [])
    sort_mode = "ip"
    flt = ""
    status = "%d hosts, %d up  scan %s" % (
        data.get("summary", {}).get("hosts", len(master)),
        data.get("summary", {}).get("up", 0),
        data.get("meta", {}).get("scan_id", ""))

    def current_list():
        hs = master
        if flt:
            f = flt.lower()
            hs = [h for h in hs if f in json.dumps(h, default=str).lower()]
        return sort_hosts(hs, sort_mode)

    hosts = current_list()
    sel = 0
    off = 0

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        hdr = " netdeep  sort:%s  %s%s" % (sort_mode, ("filter:%s " % flt) if flt else "", status)
        aw(stdscr, 0, 0, hdr.ljust(w), curses.A_REVERSE)
        # column header
        aw(stdscr, 1, 0, "  %-15s %-20s %-14s %-12s %-14s %-6s %s" %
           ("IP", "HOST", "VENDOR", "TYPE", "PORTS", "RISK", "CHG"), C_DIM)
        rows = h - 4
        if sel < off:
            off = sel
        if sel >= off + rows:
            off = sel - rows + 1
        for i in range(off, min(len(hosts), off + rows)):
            host = hosts[i]
            y = 2 + (i - off)
            new = host.get("ip") in new_hosts
            base = curses.A_REVERSE if i == sel else (C_GRN if new else 0)
            mk = ">" if i == sel else " "
            sev = highest_sev(host)
            chg = "NEW" if new else ("+" if host.get("changes") else "")
            line = "%s %-15s %-20s %-14s %-12s %-14s %-6s %s" % (
                mk, host.get("ip", ""), host_display(host)[:20],
                (host.get("vendor", "") or "")[:14], (host.get("device_type", "") or "")[:12],
                ports_brief(host)[:14], sev[:6], chg)
            aw(stdscr, y, 0, line, base)
            if i != sel and sev:
                sa = sev_attr(sev)
                if sa:
                    aw(stdscr, y, 80, sev[:6], sa)  # recolor risk cell if visible
        aw(stdscr, h - 2, 0, status.ljust(w), C_DIM)
        foot = " enter detail  s sort  / filter  o web  w wol  p ping  t trace  g ssh  c copy  n label  V stats  e export  r rescan  q quit "
        aw(stdscr, h - 1, 0, foot, curses.A_REVERSE)
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q")):
            return "quit"
        elif ch in (ord("r"),):
            return "rescan"
        elif ch == curses.KEY_UP and sel > 0:
            sel -= 1
        elif ch == curses.KEY_DOWN and sel < len(hosts) - 1:
            sel += 1
        elif ch == curses.KEY_NPAGE:
            sel = min(len(hosts) - 1, sel + rows)
        elif ch == curses.KEY_PPAGE:
            sel = max(0, sel - rows)
        elif ch == curses.KEY_HOME:
            sel = 0
        elif ch == curses.KEY_END:
            sel = max(0, len(hosts) - 1)
        elif not hosts:
            continue
        elif ch in (10, 13, curses.KEY_ENTER):
            show_detail(stdscr, hosts[sel], changes)
        elif ch == ord("s"):
            order = ["ip", "type", "vendor", "risk", "ports"]
            sort_mode = order[(order.index(sort_mode) + 1) % len(order)]
            cur_ip = hosts[sel].get("ip")
            hosts = current_list()
            sel = next((i for i, x in enumerate(hosts) if x.get("ip") == cur_ip), 0)
        elif ch == ord("/"):
            r = prompt_line(stdscr, "filter: ", flt)
            if r is not None:
                flt = r
                hosts = current_list()
                sel = 0
                off = 0
        elif ch == ord("V"):
            show_stats(stdscr, data)
        elif ch == ord("o"):
            host = hosts[sel]
            port = web_port(host)
            url = "https://%s" % host.get("ip") if port == 443 else "https://%s:%d" % (host.get("ip"), port)
            subprocess.Popen(["open", url])
            status = "opened %s" % url
        elif ch == ord("w"):
            host = hosts[sel]
            mac = host.get("mac")
            if not HAVE_ANALYZER:
                status = "analyzer unavailable"
            elif not mac:
                status = "no mac for %s" % host.get("ip")
            else:
                try:
                    analyzer.wol(mac)
                    status = "WoL sent to %s" % mac
                except Exception as e:
                    status = "wol failed: %s" % e
        elif ch == ord("p"):
            suspend_run(stdscr, "ping -c 4 %s" % shlex.quote(hosts[sel].get("ip", "")))
        elif ch == ord("t"):
            suspend_run(stdscr, "traceroute %s" % shlex.quote(hosts[sel].get("ip", "")))
        elif ch in (ord("g"), ord("S")):
            suspend_run(stdscr, "ssh %s" % shlex.quote(hosts[sel].get("ip", "")), wait=False)
        elif ch == ord("c"):
            ip = hosts[sel].get("ip", "")
            try:
                pb = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE, text=True)
                pb.communicate(ip)
                status = "copied %s" % ip
            except Exception as e:
                status = "copy failed: %s" % e
        elif ch == ord("n"):
            if not HAVE_ANALYZER:
                status = "analyzer unavailable"
            else:
                host = hosts[sel]
                r = prompt_line(stdscr, "label: ", host.get("label", ""))
                if r is not None:
                    key = host.get("mac") or host.get("ip")
                    try:
                        analyzer.set_label(DB, key, r)
                        host["label"] = r
                        status = "labeled %s" % key
                    except Exception as e:
                        status = "label failed: %s" % e
        elif ch == ord("e"):
            opts = ["CSV", "JSON", "HTML", "Markdown", "Prometheus"]
            fmts = [("csv", "csv"), ("json", "json"), ("html", "html"),
                    ("markdown", "md"), ("prometheus", "prom")]
            i = menu_overlay(stdscr, "export format", opts)
            if i >= 0:
                fmt, ext = fmts[i]
                status = do_export(stdscr, data, fmt, ext)


def tui_main(stdscr):
    curses.curs_set(0)
    stdscr.keypad(True)
    init_colors()
    cfg = default_config()
    while True:
        if config_screen(stdscr, cfg) == "quit":
            return
        data = run_scan(stdscr, cfg)
        if data is None:
            continue
        if results_screen(stdscr, data, cfg) == "quit":
            return


SAMPLE = {
    "meta": {"target": "192.168.1.0/24", "elapsed": 12.3, "scan_id": "s1", "ts": "2026-01-01", "root": True},
    "hosts": [{
        "ip": "192.168.1.10", "rdns": "pve.lan", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "Proxmox",
        "state": "up", "rtt": "1.2ms", "os": "Linux", "device_type": "hypervisor",
        "type_confidence": "high", "type_signals": ["port:8006", "banner:pve"],
        "ports": [{"port": 8006, "proto": "tcp", "service": "https", "product": "pve-api",
                   "version": "8.1", "extra": "", "scripts": {"http-title": "Proxmox VE\nx"}}],
        "app": {"pve-manager": "8.1.4"}, "risks": [{"sev": "high", "id": "R1", "msg": "self-signed", "port": 8006}],
        "sources": ["arp"], "label": "", "first_seen": "2026-01-01", "last_seen": "2026-01-02", "changes": []}],
    "summary": {"hosts": 1, "up": 1, "by_type": {"hypervisor": 1}, "by_vendor": {"Proxmox": 1},
                "risks": {"high": 1}, "proxmox": ["192.168.1.10"]},
    "changes": {"new_hosts": ["192.168.1.10"], "gone_hosts": [], "new_ports": [{"ip": "192.168.1.10", "port": 8006}],
                "closed_ports": [], "prev_scan_id": "s0"},
}


def main():
    if "--print-cmd" in sys.argv:
        cfg = default_config()
        argv = build_argv(cfg) + ["--json", "/tmp/netdeep.json"]
        print(" ".join(shlex.quote(x) for x in argv))
        return
    if "--selftest" in sys.argv:
        blob = json.dumps(SAMPLE)
        rec = json.loads(blob)
        host = rec["hosts"][0]
        assert host["ip"] and "ports" in host and "risks" in host
        assert rec["summary"]["by_type"] and rec["changes"]["new_hosts"]
        assert highest_sev(host) == "high"
        assert ports_brief(host).startswith("1:")
        return
    curses.wrapper(tui_main)


if __name__ == "__main__":
    main()
