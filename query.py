#!/usr/bin/env python3
# tiny filter dsl over host dicts. one matcher shared by tui / web / mcp.
import shlex, re, argparse, json, time, datetime, os

# info<low<med<high<crit. long forms show up in cve-sourced risks.
SEVR = {"info": 0, "low": 1, "med": 2, "medium": 2, "high": 3, "crit": 4, "critical": 4}
UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# string fields -> which host keys to substring against
STRF = {"ip": ("ip",), "vendor": ("vendor",), "os": ("os",), "label": ("label",),
        "type": ("device_type",), "host": ("rdns", "hostname")}
FIELDS = set(STRF) | {"mac", "port", "risk", "seen", "score"}
BARE = ("ip", "rdns", "hostname", "vendor", "label", "device_type")
OPS = (">=", "<=", ">", "<", "~")   # order matters: 2-char before 1-char


def parse(expr):
    out = []
    try:
        toks = shlex.split(expr or "")
    except ValueError:
        toks = (expr or "").split()   # unbalanced quote -> dumb split
    for t in toks:
        if not t:
            continue
        neg = t[0] == "!"
        if neg:
            t = t[1:]
        if not t:
            continue
        if ":" in t:
            f, v = t.split(":", 1)
            f = f.strip().lower()
        else:
            f, v = None, t
        op = ":"
        if f is not None:
            for o in OPS:
                if v.startswith(o):
                    op, v = o, v[len(o):]
                    break
        out.append({"neg": neg, "field": f, "op": op, "val": v})
    return out


def _cmp(op, a, b):
    if op in (":", "~", "="):
        return a == b
    if op == ">":
        return a > b
    if op == "<":
        return a < b
    if op == ">=":
        return a >= b
    if op == "<=":
        return a <= b
    return False


def _epoch(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if not s:
        return None
    try:
        return float(s)   # numeric string -> epoch
    except ValueError:
        pass
    try:
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.timestamp()   # naive -> local, close enough at day scale


def _dur(v):
    m = re.match(r"^(\d+(?:\.\d+)?)([smhdw]?)$", v.strip(), re.I)
    if not m:
        return None
    return float(m.group(1)) * UNIT[(m.group(2) or "d").lower()]


def _contains(h, keys, needle):
    n = needle.lower()
    for k in keys:
        x = h.get(k)
        if x and n in str(x).lower():
            return True
    return False


def _matcher(t):
    f, op, val = t["field"], t["op"], t["val"]

    if f is None:
        return lambda h: _contains(h, BARE, val)

    if f in STRF:
        keys = STRF[f]
        return lambda h: _contains(h, keys, val)   # op ignored, always substring

    if f == "mac":
        q = re.sub(r"[^0-9a-f]", "", val.lower())
        if not q:
            return None
        return lambda h: q in re.sub(r"[^0-9a-f]", "", str(h.get("mac") or "").lower())

    if f == "port":
        try:
            n = int(val)
        except ValueError:
            return None

        def m(h):
            for p in h.get("ports") or []:
                pn = p.get("port")
                if isinstance(pn, int) and _cmp(op, pn, n):
                    return True
            return False
        return m

    if f == "risk":
        r = SEVR.get(val.lower())
        if r is None:
            return None
        o = ">=" if op in (":", "~") else op   # risk:high means >= high

        def m(h):
            for rk in h.get("risks") or []:   # risks absent from history -> []
                rr = SEVR.get(str(rk.get("sev")).lower())
                if rr is not None and _cmp(o, rr, r):
                    return True
            return False
        return m

    if f == "score":
        r = SEVR.get(val.lower())
        if r is None:
            return None
        o = ">=" if op in (":", "~") else op

        def m(h):
            b = SEVR.get(str((h.get("risk_score") or {}).get("band")).lower())
            return b is not None and _cmp(o, b, r)
        return m

    if f == "seen":
        secs = _dur(val)
        if secs is None:
            return None
        o = "<=" if op in (":", "~") else op   # bare seen:7d -> within 7d

        def m(h):
            e = _epoch(h.get("last_seen"))
            if e is None:
                return False
            return _cmp(o, time.time() - e, secs)
        return m

    return None   # unknown field -> caller drops it


def compile_predicate(expr):
    ms = []
    for t in parse(expr):
        try:
            fn = _matcher(t)
        except Exception:
            fn = None
        if fn is not None:
            ms.append((t["neg"], fn))

    def pred(h):
        for neg, fn in ms:   # AND across terms
            try:
                ok = bool(fn(h))
            except Exception:
                ok = False
            if neg:
                ok = not ok
            if not ok:
                return False
        return True
    return pred


def match(host, expr):
    return compile_predicate(expr)(host)


def filt(hosts, expr):
    pred = compile_predicate(expr)
    return [h for h in hosts if pred(h)]


def _load(path):
    with open(os.path.expanduser(path)) as f:
        obj = json.load(f)
    hosts = obj.get("hosts") if isinstance(obj, dict) else obj
    return hosts or []


def _selftest():
    now = time.time()
    H = [
        {"ip": "10.0.0.5", "rdns": "pve1.lan", "hostname": None, "vendor": "Dell",
         "device_type": "Proxmox-VE", "mac": "bc:24:11:c1:2e:67", "os": "linux",
         "label": None, "ports": [{"port": 8006}, {"port": 22}],
         "risks": [{"sev": "crit", "id": "x"}], "risk_score": {"band": "crit"},
         "last_seen": now - 3600},
        {"ip": "10.0.0.9", "rdns": "nas.lan", "hostname": None, "vendor": "Synology",
         "device_type": "nas", "mac": "00:11:32:aa:bb:cc", "os": None, "label": None,
         "ports": [{"port": 5000}, {"port": 445}], "risks": [{"sev": "low", "id": "y"}],
         "last_seen": now - 40 * 86400},
        {"ip": "192.168.1.2", "rdns": None, "hostname": "printer", "vendor": "HP",
         "device_type": "printer", "mac": "aa:bb:cc:dd:ee:ff", "os": None, "label": None,
         "ports": [{"port": 9100}], "last_seen": now - 86400},   # no risks key on purpose
    ]

    def ips(e):
        return sorted(h["ip"] for h in filt(H, e))

    # parse shape + quoted values via shlex
    p = parse('port:>8000 !vendor:synology type:proxmox')
    assert p[0] == {"neg": False, "field": "port", "op": ">", "val": "8000"}, p[0]
    assert p[1] == {"neg": True, "field": "vendor", "op": ":", "val": "synology"}, p[1]

    assert ips("port:8006") == ["10.0.0.5"], ips("port:8006")
    assert ips("port:>8000") == ["10.0.0.5", "192.168.1.2"], ips("port:>8000")
    assert ips("risk:high") == ["10.0.0.5"], ips("risk:high")     # crit>=high, low/none out
    assert ips("risk:>=med") == ["10.0.0.5"], ips("risk:>=med")
    assert ips("type:proxmox") == ["10.0.0.5"], ips("type:proxmox")   # case-insensitive
    assert ips("score:high") == ["10.0.0.5"], ips("score:high")

    s = set(ips("seen:<7d"))
    assert "10.0.0.5" in s and "10.0.0.9" not in s, s
    assert ips("seen:>30d") == ["10.0.0.9"], ips("seen:>30d")

    s = set(ips("!vendor:synology"))
    assert "10.0.0.5" in s and "10.0.0.9" not in s, s

    assert ips("10.0.0") == ["10.0.0.5", "10.0.0.9"], ips("10.0.0")   # bare substr on ip
    assert ips("port:8006 type:proxmox") == ["10.0.0.5"], "AND"       # and semantics
    print("OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("test")
    p.add_argument("--expr", required=True)
    p.add_argument("--scan-json")
    a = ap.parse_args()

    if a.selftest:
        _selftest()
        return
    if a.cmd == "test":
        if a.scan_json:
            for h in filt(_load(a.scan_json), a.expr):
                print(h.get("ip"))
        else:
            for t in parse(a.expr):
                print(json.dumps(t))
        return
    ap.print_help()
    raise SystemExit(2)


if __name__ == "__main__":
    main()
