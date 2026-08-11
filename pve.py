#!/usr/bin/env python3
import argparse, hashlib, json, os, re, ssl, sys
import http.client

MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
NET_RE = re.compile(r"net\d+$")
PINS = os.path.expanduser("~/.netdeep/pve_pins.json")
_warned = set()


def norm_mac(s):
    if not s:
        return ""
    return "".join(p.zfill(2) for p in re.split(r"[:\-.]", s.strip().lower()))


def _pins():
    try:
        with open(PINS) as f:
            return json.load(f)
    except Exception:
        return {}


# trust-on-first-use: record the cert sha on first sight, refuse to send the token
# if it ever changes. rotated the cert on purpose? use --cacert or delete the pin.
def _pin_ok(node, der):
    sha = hashlib.sha256(der).hexdigest()
    d = _pins()
    cur = d.get(node)
    if cur == sha:
        return True
    if cur:
        if node not in _warned:
            sys.stderr.write("pve: cert pin MISMATCH for %s — refusing to send token "
                             "(rotated? --cacert, or delete it from %s)\n" % (node, PINS))
            _warned.add(node)
        return False
    d[node] = sha
    try:
        os.makedirs(os.path.dirname(PINS), exist_ok=True)
        tmp = PINS + ".tmp"
        with open(tmp, "w") as f:
            json.dump(d, f)
        os.replace(tmp, PINS)
    except Exception:
        pass
    return True


# PVEAuditor is a built-in read-only role, so this token can enumerate but never mutate.
# the token is a credential, so we never hand it to an unverified peer: with --cacert the
# handshake is verified against the ca; otherwise we pin the leaf cert (tofu) before sending.
def api_get(node, token, path, cacert=None, timeout=6):
    try:
        if cacert:
            ctx = ssl.create_default_context(cafile=cacert)
            c = http.client.HTTPSConnection(node, 8006, timeout=timeout, context=ctx)
            c.connect()
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(node, 8006, timeout=timeout, context=ctx)
            c.connect()
            if not _pin_ok(node, c.sock.getpeercert(binary_form=True)):
                c.close()
                return None
        c.request("GET", "/api2/json" + path,
                  headers={"Authorization": "PVEAPIToken=" + token.strip()})
        r = c.getresponse()
        body = r.read()
        c.close()
        if r.status != 200:
            return None
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None


def _usable_ip(ip):
    if not ip:
        return False
    low = ip.lower()
    if ip.startswith("127.") or low == "::1":
        return False
    if ip.startswith("169.254.") or low.startswith("fe80"):
        return False
    return True


def _nic(val):
    d = {}
    for part in val.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            d[k.strip().lower()] = v.strip()
    mac = d.get("hwaddr") or d.get("macaddr")
    if not mac:
        for v in d.values():        # qemu writes model=MAC (virtio=.., e1000=.., ..)
            if MAC_RE.match(v):
                mac = v
                break
    ip = d.get("ip")
    if ip and ip.lower() in ("dhcp", "manual", "auto"):
        ip = None
    if ip:
        ip = ip.split("/")[0]
    return mac, d.get("bridge"), d.get("tag"), ip


def _parse_cfg(cfg, g):
    for k in sorted(cfg):
        if not NET_RE.match(k) or not isinstance(cfg[k], str):
            continue
        mac, bridge, tag, ip = _nic(cfg[k])
        if mac and mac not in g["macs"]:
            g["macs"].append(mac)
        if bridge and g["bridge"] is None:
            g["bridge"] = bridge
        if tag is not None and g["vlan"] is None:
            try:
                g["vlan"] = int(tag)
            except ValueError:
                g["vlan"] = tag
        if ip and ip not in g["ips"]:
            g["ips"].append(ip)


def _add_ips(g, ips):
    for ip in ips:
        if _usable_ip(ip) and ip not in g["ips"]:
            g["ips"].append(ip)


def _agent_ips(resp):
    out = []
    if not resp:
        return out
    data = resp.get("data")
    ifaces = data.get("result") if isinstance(data, dict) else data
    for iface in ifaces or []:
        if not isinstance(iface, dict):
            continue
        for a in iface.get("ip-addresses") or []:
            out.append(a.get("ip-address"))
    return out


def _lxc_ips(resp):
    out = []
    if not resp:
        return out
    for iface in resp.get("data") or []:
        if not isinstance(iface, dict):
            continue
        for key in ("inet", "inet6"):
            v = iface.get(key)
            if v:
                out.append(v.split("/")[0])
    return out


def collect(node, token, cacert=None):
    guests = []
    res = api_get(node, token, "/cluster/resources?type=vm", cacert) or {}
    for r in res.get("data") or []:
        typ = r.get("type")
        vmid = r.get("vmid")
        gnode = r.get("node")
        if typ not in ("qemu", "lxc") or vmid is None or not gnode:
            continue
        g = {"vmid": vmid, "name": r.get("name"), "node": gnode, "type": typ,
             "status": r.get("status"), "macs": [], "ips": [], "bridge": None, "vlan": None}
        cfg = (api_get(node, token, "/nodes/%s/%s/%s/config" % (gnode, typ, vmid), cacert) or {}).get("data") or {}
        _parse_cfg(cfg, g)
        if typ == "qemu":
            # live ips via guest-agent. PVEAuditor has no VM.Monitor/VM.GuestAgent, so this
            # usually 403s or returns nothing -> api_get gives None and we move on.
            _add_ips(g, _agent_ips(api_get(node, token,
                     "/nodes/%s/qemu/%s/agent/network-get-interfaces" % (gnode, vmid), cacert)))
        else:
            _add_ips(g, _lxc_ips(api_get(node, token,
                     "/nodes/%s/lxc/%s/interfaces" % (gnode, vmid), cacert)))
        guests.append(g)

    cl = {"quorate": False, "nodes": [], "ha": []}
    for item in (api_get(node, token, "/cluster/status", cacert) or {}).get("data") or []:
        t = item.get("type")
        if t == "cluster":
            cl["quorate"] = bool(item.get("quorate"))
        elif t == "node":
            cl["nodes"].append({"node": item.get("name"),
                                "online": bool(item.get("online")),
                                "ip": item.get("ip")})
    cl["ha"] = (api_get(node, token, "/cluster/ha/status/current", cacert) or {}).get("data") or []
    return {"guests": guests, "cluster": cl}


def reconcile(collected, scan_hosts):
    guests = collected.get("guests") or []
    cluster = collected.get("cluster") or {}
    node_ips = set(n.get("ip") for n in cluster.get("nodes") or [] if n.get("ip"))

    mac2g, ip2g = {}, {}
    for g in guests:
        for m in g["macs"]:
            k = norm_mac(m)
            if k:
                mac2g[k] = g
        for ip in g["ips"]:
            if ip:
                ip2g[ip] = g

    scan_macs = set(norm_mac(h.get("mac")) for h in scan_hosts if h.get("mac"))
    scan_ips = set(h.get("ip") for h in scan_hosts if h.get("ip"))

    matched, done = [], set()
    for h in scan_hosts:
        ip, mac = h.get("ip"), h.get("mac")
        g = mac2g.get(norm_mac(mac)) if mac else None
        if g is None and ip:
            g = ip2g.get(ip)
        if g is None or ip in done:
            continue
        matched.append({"ip": ip, "vmid": g["vmid"], "name": g["name"], "node": g["node"]})
        done.add(ip)

    invisible = []
    for g in guests:
        if g.get("status") != "running":
            continue
        gmacs = set(norm_mac(m) for m in g["macs"] if m)
        gips = set(g["ips"])
        if not (gmacs & scan_macs) and not (gips & scan_ips):
            invisible.append({"vmid": g["vmid"], "name": g["name"], "node": g["node"],
                              "macs": g["macs"], "ips": g["ips"],
                              "bridge": g["bridge"], "vlan": g["vlan"]})

    # only a scanned ip can be rogue. a running guest on a nat/host-only bridge has an
    # ip the sweep can't reach -> it lands in invisible, never here.
    unmanaged = []
    for h in scan_hosts:
        ip, mac = h.get("ip"), h.get("mac")
        if not ip or ip in unmanaged or ip in node_ips:
            continue
        g = mac2g.get(norm_mac(mac)) if mac else None
        if g is None:
            g = ip2g.get(ip)
        if g is None:
            unmanaged.append(ip)

    return {"matched": matched, "invisible_guests": invisible, "unmanaged_ips": unmanaged}


def _selftest():
    assert norm_mac("BC-24-11-C1-2E-67") == norm_mac("bc:24:11:c1:2e:67")
    assert norm_mac("8:0:27:0:0:1") == "080027000001"

    collected = {
        "cluster": {"quorate": True, "ha": [],
                    "nodes": [{"node": "pve1", "online": True, "ip": "192.168.1.2"},
                              {"node": "pve2", "online": True, "ip": "192.168.1.3"}]},
        "guests": [
            {"vmid": 101, "name": "web", "node": "pve1", "type": "qemu", "status": "running",
             "macs": ["BC:24:11:C1:2E:67"], "ips": ["192.168.1.10"], "bridge": "vmbr0", "vlan": 10},
            {"vmid": 102, "name": "db", "node": "pve1", "type": "lxc", "status": "running",
             "macs": ["52:54:00:AA:BB:CC"], "ips": ["192.168.1.11"], "bridge": "vmbr0", "vlan": None},
            {"vmid": 103, "name": "ghost", "node": "pve2", "type": "qemu", "status": "running",
             "macs": ["52:54:00:DE:AD:00"], "ips": [], "bridge": "vmbr0", "vlan": 20},
            {"vmid": 104, "name": "archived", "node": "pve2", "type": "lxc", "status": "stopped",
             "macs": ["52:54:00:FF:FF:FF"], "ips": [], "bridge": "vmbr0", "vlan": None},
        ],
    }
    scan = [
        {"ip": "192.168.1.10", "mac": "bc-24-11-c1-2e-67"},   # web, matched by mac (dash form)
        {"ip": "192.168.1.11", "mac": None},                  # db, matched by ip
        {"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:ff"},    # node mgmt ip -> not rogue
        {"ip": "192.168.1.50", "mac": "00:11:22:33:44:55"},   # rogue / bare-metal
    ]
    r = reconcile(collected, scan)
    m = dict((x["ip"], x) for x in r["matched"])
    assert sorted(m) == ["192.168.1.10", "192.168.1.11"], r["matched"]
    assert m["192.168.1.10"]["name"] == "web" and m["192.168.1.10"]["vmid"] == 101
    assert m["192.168.1.11"]["name"] == "db"
    assert sorted(g["vmid"] for g in r["invisible_guests"]) == [103], r["invisible_guests"]
    assert r["unmanaged_ips"] == ["192.168.1.50"], r["unmanaged_ips"]
    print("OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("reconcile")
    p.add_argument("--node", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--cacert")
    p.add_argument("--scan-json")
    a = ap.parse_args()

    if a.selftest:
        _selftest()
        return
    if a.cmd != "reconcile":
        ap.print_help()
        raise SystemExit(2)

    scan = []
    if a.scan_json:
        with open(os.path.expanduser(a.scan_json)) as f:
            obj = json.load(f)
        hosts = obj.get("hosts") if isinstance(obj, dict) else obj
        for h in hosts or []:
            if isinstance(h, dict) and h.get("ip"):
                scan.append({"ip": h.get("ip"), "mac": h.get("mac")})

    c = collect(a.node, a.token, cacert=a.cacert)
    out = {"cluster": c["cluster"], "guests": c["guests"], "reconcile": reconcile(c, scan)}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
