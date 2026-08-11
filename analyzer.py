#!/usr/bin/env python3
import argparse, csv, html, json, os, re, socket, sqlite3, ssl, struct, sys, tempfile, time
import http.client
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

try:
    from defusedxml.ElementTree import parse as xml_parse
except Exception:
    from xml.etree.ElementTree import parse as xml_parse

DEFAULT_DB = os.path.expanduser("~/.netdeep/history.db")

SEV_ORDER = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}

# {ports all-open} OR {vendor substring} OR {mdns service} -> type. highest weight wins.
RULES = [
    {"type": "proxmox-ve", "ports": {8006}, "weight": 95, "sig": "8006 (pve api)"},
    {"type": "proxmox-backup", "ports": {8007}, "weight": 95, "sig": "8007 (pbs api)"},
    {"type": "hypervisor", "ports": {5900, 3128}, "weight": 70, "sig": "spice/vnc console"},
    {"type": "windows", "ports": {445, 139}, "weight": 80, "sig": "smb+netbios"},
    {"type": "nas", "ports": {445, 2049, 111}, "weight": 85, "sig": "smb+nfs"},
    {"type": "nas", "vendor": ["synology", "qnap"], "weight": 85, "sig": "nas vendor"},
    {"type": "nas", "mdns": ["_smb", "_afpovertcp", "_adisk"], "weight": 75, "sig": "mdns file share"},
    {"type": "printer", "ports": {9100}, "weight": 78, "sig": "jetdirect 9100"},
    {"type": "printer", "ports": {631}, "weight": 78, "sig": "ipp 631"},
    {"type": "printer", "mdns": ["_ipp", "_pdl-datastream", "_printer"], "weight": 74, "sig": "mdns print"},
    {"type": "camera", "ports": {554}, "weight": 72, "sig": "rtsp 554"},
    {"type": "camera", "vendor": ["hikvision", "dahua", "axis"], "weight": 82, "sig": "camera vendor"},
    {"type": "router", "ports": {53, 80, 443}, "weight": 60, "sig": "dns+web"},
    {"type": "router", "vendor": ["mikrotik", "ubiquiti", "tp-link", "tplink"], "weight": 82, "sig": "router vendor"},
    {"type": "monitoring", "ports": {3000}, "weight": 55, "sig": "grafana 3000"},
    {"type": "monitoring", "ports": {9090}, "weight": 55, "sig": "prometheus/cockpit 9090"},
]

TLS_PORTS = (443, 8006, 8007, 8443, 9090)


def ip_key(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0


def norm_mac(m):
    return ":".join(p.zfill(2) for p in m.split(":")).lower()


def mk(sev, id_, msg, port):
    return {"sev": sev, "id": id_, "msg": msg, "port": port}


def new_rec(ip):
    return {"ip": ip, "rdns": None, "mac": None, "vendor": None, "state": None,
            "rtt": None, "os": None, "hostname": None, "device_type": None,
            "type_confidence": 0, "type_signals": [], "ports": [], "app": {},
            "risks": [], "sources": [], "ssdp": None, "netbios": None,
            "mdns_services": [], "label": None, "first_seen": None,
            "last_seen": None, "changes": []}


def getrec(records, ip):
    if ip not in records:
        records[ip] = new_rec(ip)
    return records[ip]


def add_source(r, s):
    if s not in r["sources"]:
        r["sources"].append(s)


def safe(fn, *a):
    try:
        fn(*a)
    except Exception:
        pass


# --- nmap / arp ---

def parse_nmap(path, records):
    root = xml_parse(path).getroot()
    for host in root.findall("host"):
        ip = mac = vendor = None
        for addr in host.findall("address"):
            t = addr.get("addrtype")
            if t == "ipv4":
                ip = addr.get("addr")
            elif t == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        if not ip:
            continue
        r = getrec(records, ip)
        add_source(r, "nmap")
        st = host.find("status")
        if st is not None:
            r["state"] = st.get("state")
        if mac:
            r["mac"] = norm_mac(mac)
        if vendor:
            r["vendor"] = vendor
        hn = host.find("hostnames")
        if hn is not None:
            h = hn.find("hostname")
            if h is not None:
                r["hostname"] = h.get("name")
        times = host.find("times")
        if times is not None and times.get("srtt"):
            try:
                r["rtt"] = round(int(times.get("srtt")) / 1000.0, 2)
            except Exception:
                pass
        ose = host.find("os")
        if ose is not None:
            best, ba = None, -1
            for om in ose.findall("osmatch"):
                try:
                    acc = int(om.get("accuracy") or 0)
                except Exception:
                    acc = 0
                if acc > ba:
                    ba, best = acc, om.get("name")
            if best:
                r["os"] = best
        ports = host.find("ports")
        if ports is not None:
            for p in ports.findall("port"):
                stt = p.find("state")
                if stt is None or stt.get("state") != "open":
                    continue
                svc = p.find("service")
                scripts = {}
                for sc in p.findall("script"):
                    scripts[sc.get("id")] = sc.get("output") or ""
                r["ports"].append({
                    "port": int(p.get("portid")),
                    "proto": p.get("protocol"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extra": svc.get("extrainfo") if svc is not None else None,
                    "scripts": scripts})


def merge_arp(path, records):
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("\t") if "\t" in line else line.split(None, 2)
            if len(parts) < 2:
                continue
            ip = parts[0].strip()
            if ip.count(".") != 3:
                continue
            mac = parts[1].strip()
            vendor = parts[2].strip() if len(parts) > 2 else None
            r = getrec(records, ip)
            add_source(r, "arp")
            if not r["mac"]:
                r["mac"] = norm_mac(mac)
            if vendor and not r["vendor"]:
                r["vendor"] = vendor


# --- passive discovery ---

def arp_cache(records):
    import subprocess
    out = subprocess.run(["arp", "-an"], capture_output=True, text=True, timeout=10).stdout
    ip_macs, mac_ips = {}, {}
    for line in out.splitlines():
        if "incomplete" in line:
            continue
        m = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]+)", line)
        if not m:
            continue
        ip, mac = m.group(1), norm_mac(m.group(2))
        o = ip.split(".")
        first = int(o[0]) if o and o[0].isdigit() else 0
        if first >= 224 or ip == "255.255.255.255" or ip.startswith("169.254."):
            continue  # multicast / broadcast / link-local, not real hosts
        if mac.startswith(("01:00:5e", "33:33", "ff:ff:ff")):
            continue
        r = getrec(records, ip)
        add_source(r, "arpcache")
        if not r["mac"]:
            r["mac"] = mac
        ip_macs.setdefault(ip, set()).add(mac)
        mac_ips.setdefault(mac, set()).add(ip)
    for mac, ips in mac_ips.items():
        if len(ips) > 1:
            for ip in ips:
                records[ip]["risks"].append(
                    mk("high", "arp-conflict", "mac %s claims multiple ips: %s" % (mac, ", ".join(sorted(ips))), 0))
    for ip, macs in ip_macs.items():
        if len(macs) > 1:
            records[ip]["risks"].append(
                mk("high", "arp-conflict", "ip %s maps to multiple macs: %s" % (ip, ", ".join(sorted(macs))), 0))


def parse_http_headers(data):
    hdrs = {}
    for line in data.decode("latin1", "replace").split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    return hdrs


def ssdp(records):
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(3)
    try:
        s.sendto(msg, ("239.255.255.250", 1900))
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                break
            r = getrec(records, addr[0])
            add_source(r, "ssdp")
            h = parse_http_headers(data)
            if h.get("server"):
                r["ssdp"] = h["server"]
    finally:
        s.close()


def enc_name(name):
    out = b""
    for lbl in name.split("."):
        if not lbl:
            continue
        b = lbl.encode()
        out += bytes([len(b)]) + b
    return out + b"\x00"


def dns_query(name, qtype, qclass):
    return os.urandom(2) + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + enc_name(name) + struct.pack(">HH", qtype, qclass)


def parse_name(data, off):
    labels, jumped, start = [], False, off
    while True:
        l = data[off]
        if l == 0:
            off += 1
            break
        if l & 0xC0 == 0xC0:
            ptr = ((l & 0x3F) << 8) | data[off + 1]
            if not jumped:
                start = off + 2
            off, jumped = ptr, True
            continue
        off += 1
        labels.append(data[off:off + l].decode("ascii", "replace"))
        off += l
    return ".".join(labels), (start if jumped else off)


def parse_ptr(data):
    out = []
    try:
        qd = struct.unpack(">H", data[4:6])[0]
        an = struct.unpack(">H", data[6:8])[0]
        off = 12
        for _ in range(qd):
            _, off = parse_name(data, off)
            off += 4
        for _ in range(an):
            _, off = parse_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype == 12:
                tgt, _ = parse_name(data, off)
                out.append(tgt)
            off += rdlen
    except Exception:
        pass
    return out


def mdns(records):
    # macos: mDNSResponder holds 5353, so set QU bit (qclass 0x8001) and take unicast replies here
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    found = {}
    try:
        s.sendto(dns_query("_services._dns-sd._udp.local", 12, 0x8001), ("224.0.0.251", 5353))
        types = set()
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                break
            svcs = parse_ptr(data)
            found.setdefault(addr[0], set()).update(svcs)
            types.update(svcs)
        for t in list(types)[:15]:
            try:
                s.sendto(dns_query(t, 12, 0x8001), ("224.0.0.251", 5353))
            except Exception:
                pass
        while True:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                break
            found.setdefault(addr[0], set()).update(parse_ptr(data))
    finally:
        s.close()
    for ip, svcs in found.items():
        r = getrec(records, ip)
        add_source(r, "mdns")
        r["mdns_services"] = sorted(set(r["mdns_services"]) | svcs)


def nbstat(ip):
    name = b"*" + b"\x00" * 15
    enc = b""
    for byte in name:
        enc += bytes([(byte >> 4) + 0x41, (byte & 0x0F) + 0x41])
    q = os.urandom(2) + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += bytes([0x20]) + enc + b"\x00" + struct.pack(">HH", 0x21, 0x01)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.sendto(q, (ip, 137))
        data, _ = s.recvfrom(65535)
    except Exception:
        return None
    finally:
        s.close()
    try:
        off = 12
        _, off = parse_name(data, off)
        off += 4
        _, off = parse_name(data, off)
        off += 10  # type,class,ttl,rdlen
        num = data[off]
        off += 1
        for _ in range(num):
            nm = data[off:off + 15].decode("ascii", "replace").rstrip()
            suffix = data[off + 15]
            flags = struct.unpack(">H", data[off + 16:off + 18])[0]
            off += 18
            if suffix == 0x00 and not (flags & 0x8000):
                return nm
    except Exception:
        pass
    return None


def netbios(records):
    for ip in list(records.keys()):
        nm = nbstat(ip)
        if nm:
            r = records[ip]
            r["netbios"] = nm
            add_source(r, "netbios")
            if not r["hostname"]:
                r["hostname"] = nm


# --- enrich / classify / risk ---

def proxmox_version(ip, port):
    ctx = ssl._create_unverified_context()
    c = http.client.HTTPSConnection(ip, port, timeout=4, context=ctx)
    try:
        c.request("GET", "/api2/json/version")
        body = c.getresponse().read()
        return json.loads(body)["data"]["version"]
    finally:
        c.close()


def enrich(records, do_proxmox):
    def work(r):
        socket.setdefaulttimeout(2)
        try:
            r["rdns"] = socket.gethostbyaddr(r["ip"])[0]
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(None)
        if do_proxmox:
            open_p = [p["port"] for p in r["ports"]]
            for p in (8006, 8007):
                if p in open_p:
                    try:
                        v = proxmox_version(r["ip"], p)
                        if v:
                            r["app"]["PVE 8006" if p == 8006 else "PBS 8007"] = v
                    except Exception:
                        pass
    if not records:
        return
    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(work, list(records.values())))


def classify(r):
    ports = set(p["port"] for p in r["ports"])
    vendor = (r.get("vendor") or "").lower()
    md = [s.lower() for s in r.get("mdns_services", [])]
    signals, best = [], None
    for rule in RULES:
        hit, why = False, None
        rp = rule.get("ports")
        if rp and rp.issubset(ports):
            hit, why = True, rule["sig"]
        for vs in rule.get("vendor", []):
            if vs in vendor:
                hit, why = True, "vendor " + vs
        for m in rule.get("mdns", []):
            if any(m in x for x in md):
                hit, why = True, "mdns " + m
        if hit:
            signals.append("%s: %s" % (rule["type"], why))
            if best is None or rule["weight"] > best["weight"]:
                best = {"type": rule["type"], "weight": rule["weight"]}
    if 3389 in ports and best and best["type"] == "windows":
        signals.append("windows: +rdp")
    if r.get("netbios") and (best is None or best["weight"] < 70):
        best = {"type": "windows", "weight": 70}
        signals.append("windows: netbios name")
    if best is None:
        osl = (r.get("os") or "").lower()
        if ports and ports.issubset({22}) and "linux" in osl:
            best = {"type": "linux-server", "weight": 60}
            signals.append("linux-server: 22 + linux os")
    if r.get("ssdp"):
        signals.append("ssdp: " + r["ssdp"][:48])
    if best:
        r["device_type"] = best["type"]
        r["type_confidence"] = min(100, best["weight"])
    else:
        r["device_type"] = "host"
        r["type_confidence"] = 0
    r["type_signals"] = signals


def redis_open(ip):
    try:
        s = socket.create_connection((ip, 6379), timeout=2)
        s.sendall(b"INFO\r\n")
        data = s.recv(4096)
        s.close()
        return b"redis_version" in data and b"NOAUTH" not in data and b"WRONGPASS" not in data
    except Exception:
        return False


def http_get(ip, port, path):
    c = http.client.HTTPConnection(ip, port, timeout=3)
    try:
        c.request("GET", path)
        resp = c.getresponse()
        return resp.status, resp.read()
    finally:
        c.close()


def es_open(ip):
    try:
        st, body = http_get(ip, 9200, "/")
        return st != 401 and b"cluster_name" in body
    except Exception:
        return False


def docker_open(ip):
    try:
        st, body = http_get(ip, 2375, "/version")
        return st == 200 and b"ApiVersion" in body
    except Exception:
        return False


def cert_info(ip, port):
    try:
        socket.setdefaulttimeout(3)
        pem = ssl.get_server_certificate((ip, port))
    except Exception:
        socket.setdefaulttimeout(None)
        return None
    socket.setdefaulttimeout(None)
    try:
        f = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        f.write(pem)
        f.close()
        d = ssl._ssl._test_decode_cert(f.name)
        os.unlink(f.name)
    except Exception:
        return None
    out = {"self_signed": d.get("subject") == d.get("issuer")}
    na = d.get("notAfter")
    if na:
        try:
            t = time.mktime(time.strptime(na, "%b %d %H:%M:%S %Y %Z"))
            out["expiring"] = 0 <= (t - time.time()) <= 21 * 86400
        except Exception:
            pass
    return out


def risk_flags(r):
    pm = {p["port"]: p for p in r["ports"]}
    ip = r["ip"]
    risks = []
    if 23 in pm:
        risks.append(mk("med", "telnet", "telnet exposed", 23))
    if 6379 in pm and redis_open(ip):
        risks.append(mk("crit", "redis", "unauth redis", 6379))
    if 27017 in pm:
        risks.append(mk("high", "mongodb", "mongodb exposed (verify auth)", 27017))
    if 9200 in pm and es_open(ip):
        risks.append(mk("high", "elasticsearch", "elasticsearch exposed", 9200))
    if 2375 in pm and docker_open(ip):
        risks.append(mk("crit", "docker", "unauth docker api (root-equiv)", 2375))
    for vp in range(5900, 5907):
        if vp in pm:
            risks.append(mk("med", "vnc", "vnc exposed", vp))
            break
    if 445 in pm:
        risks.append(mk("low", "smb", "smb exposed", 445))
        for k, v in pm[445].get("scripts", {}).items():
            if "smb-vuln-ms17-010" in (k or "") and "VULNERABLE" in v:
                risks.append(mk("crit", "ms17-010", "smb ms17-010 vulnerable", 445))
    if 3389 in pm:
        risks.append(mk("med", "rdp", "rdp exposed", 3389))
    if 21 in pm:
        for k, v in pm[21].get("scripts", {}).items():
            if "ftp-anon" in (k or "") and "Anonymous" in v:
                risks.append(mk("high", "ftp-anon", "anon ftp", 21))
    for tp in TLS_PORTS:
        if tp in pm:
            info = cert_info(ip, tp)
            if info:
                if info.get("self_signed"):
                    risks.append(mk("info", "self-signed", "self-signed cert", tp))
                if info.get("expiring"):
                    risks.append(mk("med", "cert-exp", "cert expiring", tp))
    r["risks"] += risks


# --- sqlite ---

def ensure_db(db):
    d = os.path.dirname(db)
    if d:
        os.makedirs(d, exist_ok=True)
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS scan(id INTEGER PRIMARY KEY, started_at REAL, target TEXT, args TEXT);
    CREATE TABLE IF NOT EXISTS host(id INTEGER PRIMARY KEY, ident TEXT UNIQUE, mac TEXT, ip TEXT,
        vendor TEXT, device_type TEXT, hostname TEXT, label TEXT, first_seen REAL, last_seen REAL);
    CREATE TABLE IF NOT EXISTS host_seen(scan_id INTEGER, host_id INTEGER, ip TEXT, state TEXT, rtt REAL, os TEXT);
    CREATE TABLE IF NOT EXISTS port(id INTEGER PRIMARY KEY, host_id INTEGER, port INTEGER, proto TEXT,
        first_seen REAL, last_seen REAL, UNIQUE(host_id, port, proto));
    CREATE TABLE IF NOT EXISTS port_seen(scan_id INTEGER, port_id INTEGER, service TEXT, product TEXT,
        version TEXT, scripts_json TEXT);
    CREATE INDEX IF NOT EXISTS idx_host_ident ON host(ident);
    CREATE INDEX IF NOT EXISTS idx_hostseen_scan ON host_seen(scan_id);
    CREATE INDEX IF NOT EXISTS idx_port_host ON port(host_id);
    """)
    con.commit()
    con.close()


def latest_scan(db):
    con = sqlite3.connect(db)
    row = con.execute("SELECT max(id) FROM scan").fetchone()
    con.close()
    return row[0]


def load_scan(db, scan_id=None):
    ensure_db(db)
    con = sqlite3.connect(db)
    if scan_id is None:
        scan_id = con.execute("SELECT max(id) FROM scan").fetchone()[0]
    hosts = []
    if scan_id is None:
        con.close()
        return hosts
    rows = con.execute("""SELECT h.ip,h.mac,h.vendor,h.device_type,h.hostname,h.label,h.first_seen,
        h.last_seen,hs.state,hs.rtt,hs.os,h.id FROM host_seen hs JOIN host h ON h.id=hs.host_id
        WHERE hs.scan_id=?""", (scan_id,)).fetchall()
    for x in rows:
        pr = con.execute("""SELECT p.port,p.proto,ps.service,ps.product,ps.version,ps.scripts_json
            FROM port_seen ps JOIN port p ON p.id=ps.port_id WHERE ps.scan_id=? AND p.host_id=?""",
            (scan_id, x[11])).fetchall()
        ports = []
        for p in pr:
            try:
                scripts = json.loads(p[5]) if p[5] else {}
            except Exception:
                scripts = {}
            ports.append({"port": p[0], "proto": p[1], "service": p[2], "product": p[3],
                          "version": p[4], "scripts": scripts})
        hosts.append({"ip": x[0], "mac": x[1], "vendor": x[2], "device_type": x[3],
                      "hostname": x[4], "label": x[5], "first_seen": x[6], "last_seen": x[7],
                      "state": x[8], "rtt": x[9], "os": x[10], "ports": ports})
    con.close()
    hosts.sort(key=lambda h: ip_key(h["ip"]))
    return hosts


def empty_changes():
    return {"new_hosts": [], "gone_hosts": [], "new_ports": [], "closed_ports": [], "prev_scan_id": None}


def diff_scans(db, a, b):
    la = {h["ip"]: h for h in load_scan(db, a)} if a else {}
    lb = {h["ip"]: h for h in load_scan(db, b)}
    new_hosts = [ip for ip in lb if ip not in la]
    gone_hosts = [ip for ip in la if ip not in lb]
    new_ports, closed_ports, per = [], [], {}
    for ip, h in lb.items():
        ch = []
        if ip in new_hosts:
            ch.append("new host")
        ap = la.get(ip)
        bp = {(p["port"], p["proto"]): p for p in h["ports"]}
        aps = {(p["port"], p["proto"]): p for p in ap["ports"]} if ap else {}
        for k, p in bp.items():
            if k not in aps:
                new_ports.append({"ip": ip, "port": p["port"]})
                if ip not in new_hosts:
                    ch.append("port %d opened" % p["port"])
            else:
                ov, nv = aps[k].get("version"), p.get("version")
                if ov and nv and ov != nv:
                    ch.append("%s %s->%s" % (p.get("service") or "svc", ov, nv))
        for k, p in aps.items():
            if k not in bp:
                closed_ports.append({"ip": ip, "port": p["port"]})
                ch.append("closed %d" % p["port"])
        if ch:
            per[ip] = ch
    for ip in gone_hosts:
        for p in la[ip]["ports"]:
            closed_ports.append({"ip": ip, "port": p["port"]})
    return {"new_hosts": new_hosts, "gone_hosts": gone_hosts, "new_ports": new_ports,
            "closed_ports": closed_ports, "prev_scan_id": a, "_per": per}


def store_and_diff(db, target, argv, records, nmap_xml):
    ensure_db(db)
    con = sqlite3.connect(db)
    now = time.time()
    xmlpath = os.path.abspath(nmap_xml) if nmap_xml and os.path.exists(nmap_xml) else None
    args_json = json.dumps({"argv": argv, "nmap_xml": xmlpath})
    scan_id = con.execute("INSERT INTO scan(started_at,target,args) VALUES(?,?,?)",
                          (now, target, args_json)).lastrowid
    for r in records.values():
        ident = r["mac"] or r["ip"]
        con.execute("""INSERT INTO host(ident,mac,ip,vendor,device_type,hostname,label,first_seen,last_seen)
            VALUES(?,?,?,?,?,?,NULL,?,?)
            ON CONFLICT(ident) DO UPDATE SET mac=excluded.mac, ip=excluded.ip, vendor=excluded.vendor,
            device_type=excluded.device_type, hostname=excluded.hostname, last_seen=excluded.last_seen""",
            (ident, r["mac"], r["ip"], r["vendor"], r["device_type"], r["hostname"], now, now))
        hid, fs, ls, lbl = con.execute(
            "SELECT id,first_seen,last_seen,label FROM host WHERE ident=?", (ident,)).fetchone()
        r["first_seen"], r["last_seen"], r["label"] = fs, ls, lbl
        con.execute("INSERT INTO host_seen(scan_id,host_id,ip,state,rtt,os) VALUES(?,?,?,?,?,?)",
                    (scan_id, hid, r["ip"], r["state"], r["rtt"], r["os"]))
        for p in r["ports"]:
            con.execute("""INSERT INTO port(host_id,port,proto,first_seen,last_seen) VALUES(?,?,?,?,?)
                ON CONFLICT(host_id,port,proto) DO UPDATE SET last_seen=excluded.last_seen""",
                (hid, p["port"], p["proto"], now, now))
            pid = con.execute("SELECT id FROM port WHERE host_id=? AND port=? AND proto=?",
                              (hid, p["port"], p["proto"])).fetchone()[0]
            con.execute("""INSERT INTO port_seen(scan_id,port_id,service,product,version,scripts_json)
                VALUES(?,?,?,?,?,?)""", (scan_id, pid, p["service"], p["product"], p["version"],
                json.dumps(p.get("scripts", {}))))
    con.commit()
    prev = con.execute("SELECT max(id) FROM scan WHERE target=? AND id<?", (target, scan_id)).fetchone()[0]
    con.close()
    if prev:
        changes = diff_scans(db, prev, scan_id)
        for ip, ch in changes.pop("_per").items():
            if ip in records:
                records[ip]["changes"] = ch
    else:
        changes = empty_changes()
    return scan_id, changes


# --- output ---

def build_output(records, meta, changes):
    hosts = []
    for ip in sorted(records, key=ip_key):
        r = records[ip]
        hosts.append({
            "ip": r["ip"], "rdns": r["rdns"] or r["hostname"], "mac": r["mac"],
            "vendor": r["vendor"], "state": r["state"], "rtt": r["rtt"], "os": r["os"],
            "device_type": r["device_type"], "type_confidence": r["type_confidence"],
            "type_signals": r["type_signals"], "ports": r["ports"], "app": r["app"],
            "risks": r["risks"], "sources": r["sources"], "label": r["label"],
            "first_seen": r["first_seen"], "last_seen": r["last_seen"], "changes": r["changes"],
            "fingerprints": r.get("fingerprints"), "risk_score": r.get("risk_score")})
    up = sum(1 for r in records.values() if r["state"] == "up")
    by_type = Counter(r["device_type"] for r in records.values())
    by_vendor = Counter(r["vendor"] for r in records.values() if r["vendor"])
    risks = Counter()
    for r in records.values():
        for rk in r["risks"]:
            risks[rk["sev"]] += 1
    proxmox = [r["ip"] for r in records.values()
               if (r["device_type"] or "").startswith("proxmox") or r["app"]]
    summary = {"hosts": len(records), "up": up, "by_type": dict(by_type),
               "by_vendor": dict(by_vendor), "risks": dict(risks), "proxmox": proxmox}
    return {"meta": meta, "hosts": hosts, "summary": summary, "changes": changes}


def col(s, code, tty):
    return "\x1b[%sm%s\x1b[0m" % (code, s) if tty else str(s)


def print_summary(out):
    tty = sys.stdout.isatty()
    m, s = out["meta"], out["summary"]
    print(col("netdeep", "1;36", tty), m["target"], "  %d hosts, %d up, %.1fs" %
          (s["hosts"], s["up"], m.get("elapsed") or 0))
    for h in out["hosts"]:
        if h["state"] and h["state"] != "up":
            continue
        ports = ",".join(str(p["port"]) for p in h["ports"])
        rk = ""
        if h["risks"]:
            worst = min(h["risks"], key=lambda x: SEV_ORDER.get(x["sev"], 9))["sev"]
            code = {"crit": "1;31", "high": "31", "med": "33", "low": "37", "info": "90"}.get(worst, "37")
            rk = col("[%d %s]" % (len(h["risks"]), worst), code, tty)
        name = h["rdns"] or h["label"] or ""
        print("  %-15s %-16s %-14s %s %s" % (
            h["ip"], (h["vendor"] or "")[:16], col(h["device_type"] or "", "36", tty), ports, rk), name)
    if s["risks"]:
        print("  risks:", ", ".join("%s=%d" % (k, v) for k, v in
              sorted(s["risks"].items(), key=lambda kv: SEV_ORDER.get(kv[0], 9))))
    if s["proxmox"]:
        print("  proxmox:", ", ".join(s["proxmox"]))
    c = out["changes"]
    if c["new_hosts"] or c["gone_hosts"] or c["new_ports"] or c["closed_ports"]:
        print("  changes: +%dh -%dh +%dp -%dp" % (
            len(c["new_hosts"]), len(c["gone_hosts"]), len(c["new_ports"]), len(c["closed_ports"])))


# --- subcommands ---

def fp_value(v):
    if isinstance(v, dict):
        if "sha256" in v:
            return v["sha256"]
        if any(k in ("rsa", "ecdsa", "ed25519", "dsa") for k in v):
            return ";".join("%s=%s" % (k, v[k]) for k in sorted(v))
        prods = v.get("products") or []
        s = "|".join([v.get("server") or ""] + sorted(prods))
        return s or None
    return v


def add_fingerprints(records, db):
    import fingerprint as fp
    for ip, r in records.items():
        ports = [p["port"] for p in r.get("ports", [])]
        if not ports:
            continue
        try:
            fps = fp.scan_host(ip, ports)
        except Exception:
            continue
        if not fps:
            continue
        r["fingerprints"] = fps
        for port, kinds in fps.items():
            for t, v in kinds.items():
                val = fp_value(v)
                if not val:
                    continue
                d = fp.baseline_diff(ip, int(port), t, str(val), db)
                if d.get("changed"):
                    r["changes"].append("%s %s drift" % (port, t))
                    r["risks"].append(mk("high", "fp-drift", "%s fingerprint changed" % t, int(port)))


def default_gateway():
    import subprocess
    try:
        out = subprocess.check_output(["route", "-n", "get", "default"],
                                      text=True, stderr=subprocess.DEVNULL)
        for ln in out.splitlines():
            if "gateway:" in ln:
                return ln.split(":", 1)[1].strip()
    except Exception:
        pass
    try:
        out = subprocess.check_output(["ip", "route"], text=True, stderr=subprocess.DEVNULL)
        for ln in out.splitlines():
            if ln.startswith("default"):
                return ln.split()[2]
    except Exception:
        pass
    return None


def add_rogue(records, db):
    import passive
    scan_hosts = [{"ip": ip, "mac": r.get("mac")} for ip, r in records.items()]
    try:
        arp = passive.arp_cache() or []
    except Exception:
        arp = []
    gw = default_gateway()
    gwmac = next((e["mac"] for e in arp if e.get("ip") == gw), None)
    try:
        risks = passive.detect_rogue(scan_hosts, arp, None, gw, gwmac, db) or []
    except Exception:
        risks = []
    for rk in risks:
        ip = rk.get("ip")
        item = {"sev": rk["sev"], "id": rk["id"], "msg": rk["msg"], "port": None}
        if ip and ip in records:
            records[ip]["risks"].append(item)
        elif ip:
            r = getrec(records, ip)
            add_source(r, "arpcache")
            if rk.get("mac"):
                r["mac"] = rk["mac"]
            r["risks"].append(item)


def dedup_risks(risks):
    seen, out = set(), []
    for x in risks:
        k = (x.get("id"), x.get("port"))
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out


def add_probes(records):
    import probes
    cports = {2375, 2376, 2379, 10250, 10255, 6443, 8443, 4646, 8500, 9000, 9443}
    for ip, r in records.items():
        ports = [p["port"] for p in r.get("ports", [])]
        pset = set(ports)
        found = []
        if pset & cports:
            try:
                found += probes.container_probe(ip, ports) or []
            except Exception:
                pass
        if pset & {443, 623, 8443}:
            try:
                b = probes.bmc_probe(ip) or {}
                found += b.get("findings", [])
                if b.get("redfish"):
                    r["type_signals"].append("bmc:redfish")
            except Exception:
                pass
        for rk in found:
            r["risks"].append({"sev": rk["sev"], "id": rk["id"],
                               "msg": rk["msg"], "port": rk.get("port")})


def add_scores(records, db):
    import vulns
    for r in records.values():
        try:
            r["risk_score"] = vulns.score_host(r, db)
        except Exception:
            pass


def cmd_consolidate(a):
    records = {}
    if a.nmap_xml and os.path.exists(a.nmap_xml) and os.path.getsize(a.nmap_xml) > 0:
        safe(parse_nmap, a.nmap_xml, records)
    if a.arp and os.path.exists(a.arp) and os.path.getsize(a.arp) > 0:
        safe(merge_arp, a.arp, records)
    if a.arp_cache:
        safe(arp_cache, records)
    if a.ssdp:
        safe(ssdp, records)
    if a.netbios:
        safe(netbios, records)
    if a.mdns:
        safe(mdns, records)
    enrich(records, a.proxmox)
    for r in records.values():
        classify(r)
        safe(risk_flags, r)
    if getattr(a, "fingerprint", False):
        safe(add_fingerprints, records, a.db)
    if getattr(a, "rogue", False):
        safe(add_rogue, records, a.db)
    if getattr(a, "vuln", False):
        safe(add_probes, records)
    for r in records.values():
        r["risks"] = dedup_risks(r["risks"])
    if getattr(a, "vuln", False):
        safe(add_scores, records, a.db)
    scan_id, changes = None, empty_changes()
    if not a.no_store:
        scan_id, changes = store_and_diff(a.db, a.target, sys.argv, records, a.nmap_xml)
    meta = {"target": a.target, "elapsed": a.elapsed, "scan_id": scan_id,
            "ts": int(time.time()), "root": a.root}
    out = build_output(records, meta, changes)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    if a.terminal:
        print_summary(out)


def static_risks(ports):
    ps = set(ports)
    r = []
    if 23 in ps: r.append(mk("med", "telnet", "telnet exposed", 23))
    if 6379 in ps: r.append(mk("high", "redis", "redis exposed", 6379))
    if 27017 in ps: r.append(mk("high", "mongodb", "mongodb exposed", 27017))
    if 9200 in ps: r.append(mk("med", "elasticsearch", "elasticsearch exposed", 9200))
    if 2375 in ps: r.append(mk("high", "docker", "docker api exposed", 2375))
    for vp in range(5900, 5907):
        if vp in ps:
            r.append(mk("med", "vnc", "vnc exposed", vp)); break
    if 445 in ps: r.append(mk("low", "smb", "smb exposed", 445))
    if 3389 in ps: r.append(mk("med", "rdp", "rdp exposed", 3389))
    if 21 in ps: r.append(mk("low", "ftp", "ftp exposed", 21))
    return r


def export_rows(hosts):
    rows = []
    for h in hosts:
        ports = [p["port"] for p in h["ports"]]
        rows.append({
            "ip": h["ip"], "reverse_dns": h.get("hostname") or "", "mac": h.get("mac") or "",
            "vendor": h.get("vendor") or "", "device_type": h.get("device_type") or "",
            "state": h.get("state") or "", "rtt": h.get("rtt"),
            "ports": ports,
            "services": ["%d/%s" % (p["port"], p["service"] or "?") for p in h["ports"]],
            "risks": static_risks(ports), "label": h.get("label") or ""})
    return rows


def cmd_export(a):
    ensure_db(a.db)
    scan_id = a.scan_id or latest_scan(a.db)
    hosts = load_scan(a.db, scan_id)
    rows = export_rows(hosts)
    fmt = a.format
    if fmt == "csv":
        with open(a.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "reverse_dns", "mac", "vendor", "device_type", "state",
                        "rtt_ms", "open_ports", "services", "risks", "label"])
            for r in rows:
                w.writerow([r["ip"], r["reverse_dns"], r["mac"], r["vendor"], r["device_type"],
                            r["state"], r["rtt"] if r["rtt"] is not None else "",
                            ",".join(str(p) for p in r["ports"]), ",".join(r["services"]),
                            ";".join("%s:%s" % (x["sev"], x["id"]) for x in r["risks"]), r["label"]])
    elif fmt == "json":
        with open(a.out, "w") as f:
            json.dump(hosts, f, indent=2)
    elif fmt == "html":
        write_html(a.out, rows, scan_id)
    elif fmt == "md":
        write_md(a.db, a.out, rows, scan_id)
    elif fmt == "prometheus":
        write_prom(a.db, a.out, rows, scan_id)
    elif fmt == "xml":
        write_xml(a.db, a.out, scan_id)
    print("wrote", a.out)


def write_html(path, rows, scan_id):
    e = html.escape
    parts = ["<meta charset=utf-8><style>",
             "body{background:#111;color:#ddd;font:13px monospace;margin:1.5rem}",
             "table{border-collapse:collapse;width:100%}",
             "th,td{border:1px solid #333;padding:4px 8px;text-align:left}",
             "th{background:#1c1c1c}tr:nth-child(even){background:#161616}",
             "a{color:#4ea1ff}.crit{color:#ff5555}.high{color:#ff8844}.med{color:#e6c34a}.low{color:#888}",
             "</style>", "<h2>netdeep scan %s</h2>" % scan_id,
             "<table><tr><th>ip</th><th>host</th><th>vendor</th><th>type</th><th>ports</th><th>risk</th></tr>"]
    for r in rows:
        worst = ""
        if r["risks"]:
            worst = min(r["risks"], key=lambda x: SEV_ORDER.get(x["sev"], 9))["sev"]
        rk = '<span class=%s>%s</span>' % (worst, e(worst)) if worst else ""
        parts.append("<tr><td><a href='https://%s:8006'>%s</a></td><td>%s</td><td>%s</td>"
                     "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
                         e(r["ip"]), e(r["ip"]), e(r["reverse_dns"]), e(r["vendor"]),
                         e(r["device_type"]), e(",".join(str(p) for p in r["ports"])), rk))
    parts.append("</table>")
    with open(path, "w") as f:
        f.write("\n".join(parts))


def write_md(db, path, rows, scan_id):
    con = sqlite3.connect(db)
    row = con.execute("SELECT target FROM scan WHERE id=?", (scan_id,)).fetchone()
    target = row[0] if row else "?"
    prev = None
    if row:
        prev = con.execute("SELECT max(id) FROM scan WHERE target=? AND id<?", (target, scan_id)).fetchone()[0]
    con.close()
    groups = {}
    for r in rows:
        groups.setdefault(r["device_type"] or "host", []).append(r)
    out = ["# netdeep report — scan %s (%s)\n" % (scan_id, target)]
    for t in sorted(groups):
        out.append("## %s\n" % t)
        for r in groups[t]:
            out.append("- **%s** %s %s — ports %s" % (
                r["ip"], r["reverse_dns"], r["vendor"],
                ", ".join(str(p) for p in r["ports"]) or "-"))
        out.append("")
    allr = []
    for r in rows:
        for x in r["risks"]:
            allr.append((r["ip"], x))
    out.append("## Risks\n")
    if allr:
        for ip, x in sorted(allr, key=lambda z: SEV_ORDER.get(z[1]["sev"], 9)):
            out.append("- `%s` %s **%s** — %s" % (x["sev"], ip, x["id"], x["msg"]))
    else:
        out.append("_none_")
    out.append("\n## Changes\n")
    if prev:
        d = diff_scans(db, prev, scan_id)
        out.append("new hosts: %s" % (", ".join(d["new_hosts"]) or "-"))
        out.append("gone hosts: %s" % (", ".join(d["gone_hosts"]) or "-"))
        out.append("new ports: %s" % (", ".join("%s:%d" % (p["ip"], p["port"]) for p in d["new_ports"]) or "-"))
        out.append("closed ports: %s" % (", ".join("%s:%d" % (p["ip"], p["port"]) for p in d["closed_ports"]) or "-"))
    else:
        out.append("_no previous scan_")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def prom_label(v):
    return str(v).replace("\\", "\\\\").replace('"', '\\"')


def write_prom(db, path, rows, scan_id):
    con = sqlite3.connect(db)
    r = con.execute("SELECT started_at FROM scan WHERE id=?", (scan_id,)).fetchone()
    con.close()
    ts = int(r[0]) if r else int(time.time())
    L = []
    L.append("# HELP netscan_host_up host seen up in last scan")
    L.append("# TYPE netscan_host_up gauge")
    for h in rows:
        L.append('netscan_host_up{ip="%s",mac="%s",vendor="%s",device_type="%s"} 1' % (
            prom_label(h["ip"]), prom_label(h["mac"]), prom_label(h["vendor"]), prom_label(h["device_type"])))
    L.append("# HELP netscan_open_ports open port count per host")
    L.append("# TYPE netscan_open_ports gauge")
    for h in rows:
        L.append('netscan_open_ports{ip="%s"} %d' % (prom_label(h["ip"]), len(h["ports"])))
    L.append("# HELP netscan_risk_flags risk flags per host by severity")
    L.append("# TYPE netscan_risk_flags gauge")
    for h in rows:
        by = Counter(x["sev"] for x in h["risks"])
        for sev, n in by.items():
            L.append('netscan_risk_flags{ip="%s",severity="%s"} %d' % (prom_label(h["ip"]), prom_label(sev), n))
    L.append("# HELP netscan_last_scan_timestamp_seconds unix ts of last scan")
    L.append("# TYPE netscan_last_scan_timestamp_seconds gauge")
    L.append("netscan_last_scan_timestamp_seconds %d" % ts)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(L) + "\n")
    os.rename(tmp, path)


def write_xml(db, path, scan_id):
    con = sqlite3.connect(db)
    row = con.execute("SELECT args FROM scan WHERE id=?", (scan_id,)).fetchone()
    con.close()
    src = None
    if row and row[0]:
        try:
            src = json.loads(row[0]).get("nmap_xml")
        except Exception:
            pass
    if src and os.path.exists(src):
        with open(src, "rb") as a, open(path, "wb") as b:
            b.write(a.read())
    else:
        with open(path, "w") as f:
            f.write("<!-- raw nmap xml not available for scan %s -->\n" % scan_id)


def cmd_diff(a):
    ensure_db(a.db)
    con = sqlite3.connect(a.db)
    if a.scan_a and a.scan_b:
        sa, sb = a.scan_a, a.scan_b
    else:
        ids = [r[0] for r in con.execute(
            "SELECT id FROM scan WHERE target=? ORDER BY id DESC LIMIT 2", (a.target,)).fetchall()]
        con.close()
        if len(ids) < 2:
            print("need at least two scans for", a.target)
            return
        sb, sa = ids[0], ids[1]
        con = sqlite3.connect(a.db)
    con.close()
    d = diff_scans(a.db, sa, sb)
    per = d.pop("_per")
    if a.json:
        print(json.dumps(d, indent=2))
        return
    print("diff %s -> %s" % (sa, sb))
    print("  new hosts:", ", ".join(d["new_hosts"]) or "-")
    print("  gone hosts:", ", ".join(d["gone_hosts"]) or "-")
    print("  new ports:", ", ".join("%s:%d" % (p["ip"], p["port"]) for p in d["new_ports"]) or "-")
    print("  closed ports:", ", ".join("%s:%d" % (p["ip"], p["port"]) for p in d["closed_ports"]) or "-")
    for ip, ch in per.items():
        print("  %s: %s" % (ip, "; ".join(ch)))


def cmd_label(a):
    ensure_db(a.db)
    if a.set:
        if "=" not in a.set:
            print("use --set ip_or_mac=text")
            return
        k, v = a.set.split("=", 1)
        set_label(a.db, k.strip(), v.strip())
        print("labeled", k.strip())
    elif a.get:
        print(get_label(a.db, a.get) or "")
    elif a.list:
        for k, v in sorted(all_labels(a.db).items()):
            print("%-20s %s" % (k, v))


# --- module helpers (used by a tui) ---

def wol(mac, broadcast="255.255.255.255", port=9):
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        return "bad mac"
    packet = b"\xff" * 6 + bytes.fromhex(clean) * 16
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, (broadcast, port))
        s.close()
        return True
    except Exception as e:
        return str(e)


def set_label(db, key, text):
    ensure_db(db)
    con = sqlite3.connect(db)
    now = time.time()
    cur = con.execute("UPDATE host SET label=? WHERE ident=?", (text, key))
    if cur.rowcount == 0:
        con.execute("INSERT INTO host(ident,label,first_seen,last_seen) VALUES(?,?,?,?)",
                    (key, text, now, now))
    con.commit()
    con.close()


def get_label(db, key):
    ensure_db(db)
    con = sqlite3.connect(db)
    row = con.execute("SELECT label FROM host WHERE ident=?", (key,)).fetchone()
    con.close()
    return row[0] if row else None


def all_labels(db):
    ensure_db(db)
    con = sqlite3.connect(db)
    rows = con.execute("SELECT ident,label FROM host WHERE label IS NOT NULL").fetchall()
    con.close()
    return {k: v for k, v in rows}


def main():
    ap = argparse.ArgumentParser(prog="analyzer")
    sub = ap.add_subparsers(dest="cmd")

    c = sub.add_parser("consolidate")
    c.add_argument("--nmap-xml")
    c.add_argument("--arp")
    c.add_argument("--target", required=True)
    c.add_argument("--elapsed", type=float, default=0)
    c.add_argument("--db", default=DEFAULT_DB)
    c.add_argument("--out", required=True)
    c.add_argument("--root", action="store_true")
    c.add_argument("--arp-cache", dest="arp_cache", action="store_true")
    c.add_argument("--ssdp", action="store_true")
    c.add_argument("--netbios", action="store_true")
    c.add_argument("--mdns", action="store_true")
    c.add_argument("--proxmox", action="store_true")
    c.add_argument("--fingerprint", action="store_true")
    c.add_argument("--rogue", action="store_true")
    c.add_argument("--vuln", action="store_true")
    c.add_argument("--no-store", dest="no_store", action="store_true")
    c.add_argument("--terminal", action="store_true")
    c.set_defaults(fn=cmd_consolidate)

    e = sub.add_parser("export")
    e.add_argument("--db", default=DEFAULT_DB)
    e.add_argument("--format", choices=["csv", "json", "html", "md", "prometheus", "xml"], required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--scan-id", dest="scan_id", type=int)
    e.set_defaults(fn=cmd_export)

    d = sub.add_parser("diff")
    d.add_argument("--db", default=DEFAULT_DB)
    d.add_argument("--target", required=True)
    d.add_argument("--scan-a", dest="scan_a", type=int)
    d.add_argument("--scan-b", dest="scan_b", type=int)
    d.add_argument("--json", action="store_true")
    d.set_defaults(fn=cmd_diff)

    l = sub.add_parser("label")
    l.add_argument("--db", default=DEFAULT_DB)
    l.add_argument("--set")
    l.add_argument("--get")
    l.add_argument("--list", action="store_true")
    l.set_defaults(fn=cmd_label)

    a = ap.parse_args()
    if not getattr(a, "cmd", None):
        ap.print_help()
        return
    a.fn(a)


if __name__ == "__main__":
    main()
