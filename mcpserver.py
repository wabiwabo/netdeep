#!/usr/bin/env python3
import sys, os, time, sqlite3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import analyzer
    HAVE_ANALYZER = True
except Exception:
    HAVE_ANALYZER = False

try:
    import query
    HAVE_QUERY = True
except Exception:
    HAVE_QUERY = False

try:
    from mcp.server.fastmcp import FastMCP
    HAVE_MCP = True
except Exception:
    HAVE_MCP = False

# well-known ports that usually mean no-auth-by-default / juicy
RISKY = {2375: "docker", 6379: "redis", 27017: "mongo", 9200: "es",
         23: "telnet", 3389: "rdp", 445: "smb", 5900: "vnc"}


def _db():
    p = os.environ.get("NETDEEP_DB")
    if p:
        return p
    if HAVE_ANALYZER:
        return analyzer.DEFAULT_DB
    return os.path.expanduser("~/.netdeep/history.db")


def _dur(v):
    if not v:
        return None
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    u = v[-1].lower()
    if u in mult:
        body = v[:-1]
    else:
        body, u = v, "d"  # bare number -> days
    try:
        return float(body) * mult[u]
    except Exception:
        return None


def _seen_ok(h, v):
    ls = h.get("last_seen")
    if not ls:
        return False
    op = "<"
    if v[:1] in "<>":
        op, v = v[0], v[1:]
    secs = _dur(v)
    if secs is None:
        return False
    age = time.time() - ls
    return age <= secs if op == "<" else age >= secs


def _blob(h):
    parts = [str(h.get(k) or "") for k in
             ("ip", "mac", "vendor", "device_type", "hostname", "label", "state", "os")]
    for p in h.get("ports") or []:
        parts += [str(p.get("port")), str(p.get("service") or ""), str(p.get("product") or "")]
    return " ".join(parts).lower()


def _tok_ok(h, tok):
    if ":" in tok:
        k, v = tok.split(":", 1)
        k = k.lower()
        if k == "port":
            return any(str(p.get("port")) == v for p in h.get("ports") or [])
        if k in ("type", "devtype"):
            return v.lower() in (h.get("device_type") or "").lower()
        if k == "vendor":
            return v.lower() in (h.get("vendor") or "").lower()
        if k == "ip":
            return v in (h.get("ip") or "")
        if k in ("host", "hostname"):
            return v.lower() in (h.get("hostname") or "").lower()
        if k == "mac":
            return v.lower() in (h.get("mac") or "").lower()
        if k == "os":
            return v.lower() in (h.get("os") or "").lower()
        if k == "state":
            return v.lower() in (h.get("state") or "").lower()
        if k == "label":
            return v.lower() in (h.get("label") or "").lower()
        if k in ("svc", "service"):
            return any(v.lower() in str(p.get("service") or "").lower() for p in h.get("ports") or [])
        if k == "seen":
            return _seen_ok(h, v)
        # unknown key -> just substring the whole token
    return tok.lower() in _blob(h)


def _naive_match(h, q):
    q = (q or "").strip()
    if not q:
        return True
    return all(_tok_ok(h, t) for t in q.split())


def _matches(h, q):
    if HAVE_QUERY:
        try:
            return query.match(h, q)
        except Exception:
            pass
    return _naive_match(h, q)


def _scan_rows(db):
    analyzer.ensure_db(db)
    con = sqlite3.connect(db)
    rows = con.execute("SELECT id, started_at, target FROM scan ORDER BY id").fetchall()
    con.close()
    return rows


# --- tool bodies (plain, so --selftest can hit them without the sdk) ---

def _search_hosts(db, q):
    return [h for h in analyzer.load_scan(db) if _matches(h, q)]


def _get_host(db, ip):
    for h in analyzer.load_scan(db):
        if h.get("ip") == ip:
            return h
    return {}


def _whats_new(db, since=1):
    ids = [r[0] for r in _scan_rows(db)]
    if not ids:
        return {"latest_scan": None, "base_scan": None, "new_hosts": [], "new_ports": []}
    s = since if isinstance(since, int) and since > 0 else 1
    latest = ids[-1]
    idx = len(ids) - 1 - s
    base = ids[idx] if idx >= 0 else None
    cur = analyzer.load_scan(db, latest)
    prev = analyzer.load_scan(db, base) if base else []
    prev_ips = {h["ip"] for h in prev}
    prev_pp = {(h["ip"], p["port"]) for h in prev for p in h.get("ports") or []}
    new_hosts = [h["ip"] for h in cur if h["ip"] not in prev_ips]
    new_ports = [{"ip": h["ip"], "port": p["port"], "service": p.get("service")}
                 for h in cur for p in (h.get("ports") or [])
                 if (h["ip"], p["port"]) not in prev_pp]
    return {"latest_scan": latest, "base_scan": base,
            "new_hosts": new_hosts, "new_ports": new_ports}


def _exposed(db):
    out = []
    for h in analyzer.load_scan(db):
        hits = [{"port": p["port"], "service": RISKY[p["port"]]}
                for p in (h.get("ports") or []) if p.get("port") in RISKY]
        if hits:
            out.append({"ip": h["ip"], "hostname": h.get("hostname"),
                        "device_type": h.get("device_type"), "exposed": hits})
    return out


def _list_scans(db):
    return [{"id": r[0], "started_at": r[1], "target": r[2]} for r in _scan_rows(db)]


def _diff_scans(db, a, b):
    d = analyzer.diff_scans(db, a, b)
    d.pop("_per", None)
    return d


def _latest_summary(db):
    hosts = analyzer.load_scan(db)
    by_type = {}
    for h in hosts:
        t = h.get("device_type") or "unknown"
        by_type[t] = by_type.get(t, 0) + 1
    return {"scan_id": analyzer.latest_scan(db), "hosts": len(hosts), "by_device_type": by_type}


if HAVE_MCP:
    mcp = FastMCP("netdeep")

    @mcp.tool()
    def search_hosts(query: str) -> list:
        """Find hosts matching a filter like 'port:8006 type:proxmox seen:<7d'. Use for
        any 'which hosts / find the hosts / how many hosts' question about the LAN. Keys:
        port, type, vendor, ip, host, mac, os, state, label, service, seen:<Nd / seen:>Nd;
        bare words match anything. Returns host records from the latest scan."""
        return _search_hosts(_db(), query)

    @mcp.tool()
    def get_host(ip: str) -> dict:
        """Full record for one host by IP (ports, os, vendor, first/last seen). Use when
        the user names or points at a single machine. Empty dict if not in the latest scan."""
        return _get_host(_db(), ip)

    @mcp.tool()
    def whats_new(since_scans: int = 1) -> dict:
        """Hosts and ports present in the latest scan but absent `since_scans` scans back
        (default the previous scan). Use for 'what is new / what showed up / anything new on
        the network'. Returns {latest_scan, base_scan, new_hosts, new_ports}."""
        return _whats_new(_db(), since_scans)

    @mcp.tool()
    def exposed_services() -> list:
        """Hosts running well-known risky / no-auth-by-default services (docker 2375,
        redis 6379, mongo 27017, es 9200, telnet 23, rdp 3389, smb 445, vnc 5900). Use for
        'what is exposed / attack surface / anything risky'. Derived from open ports; the
        history keeps no risk scores."""
        return _exposed(_db())

    @mcp.tool()
    def list_scans() -> list:
        """Every scan in history as {id, started_at, target}, oldest first. Use to show the
        scan timeline or to get the ids that diff_scans needs."""
        return _list_scans(_db())

    @mcp.tool()
    def diff_scans(a: int, b: int) -> dict:
        """Compare two scans by id: new/gone hosts and new/closed ports between them. Use for
        'what changed between scan X and Y'. Get ids from list_scans. Returns
        {new_hosts, gone_hosts, new_ports, closed_ports}."""
        return _diff_scans(_db(), a, b)

    @mcp.resource("scan://latest")
    def scan_latest() -> dict:
        """Latest scan summary: total host count and counts by device_type."""
        return _latest_summary(_db())


def _selftest():
    print("mcp sdk:", "present" if HAVE_MCP else "missing (pip install mcp)")
    print("analyzer:", "present" if HAVE_ANALYZER else "missing")
    print("query:", "present" if HAVE_QUERY else "absent (naive match)")
    if not HAVE_ANALYZER:
        print("analyzer missing, skipping data checks")
        print("OK")
        return 0
    import tempfile
    db = os.path.join(tempfile.mkdtemp(prefix="netdeep-selftest-"), "t.db")
    analyzer.ensure_db(db)
    checks = [("search_hosts", lambda: _search_hosts(db, "port:8006 type:proxmox seen:<7d"), list),
              ("get_host", lambda: _get_host(db, "10.0.0.1"), dict),
              ("whats_new", lambda: _whats_new(db, 1), dict),
              ("exposed_services", lambda: _exposed(db), list),
              ("list_scans", lambda: _list_scans(db), list),
              ("diff_scans", lambda: _diff_scans(db, 1, 2), dict),
              ("scan_latest", lambda: _latest_summary(db), dict)]
    for name, fn, typ in checks:
        r = fn()
        assert isinstance(r, typ), "%s -> %r" % (name, type(r))
        print("  %-16s -> %s ok" % (name, typ.__name__))
    h = {"ip": "10.0.0.9", "device_type": "proxmox", "vendor": "dell", "hostname": "pve1",
         "last_seen": time.time(), "ports": [{"port": 8006, "service": "pve"}]}
    assert _naive_match(h, "port:8006 type:proxmox seen:<7d")
    assert not _naive_match(h, "port:22")
    assert not _naive_match(h, "seen:>7d")
    print("OK")
    return 0


def main():
    if "--selftest" in sys.argv:
        return _selftest()
    if HAVE_MCP:
        mcp.run()  # stdio transport, what claude code launches
        return 0
    print("mcp sdk not installed; run: pip install mcp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
