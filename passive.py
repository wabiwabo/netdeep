#!/usr/bin/env python3
import socket, struct, subprocess, sqlite3, argparse, os, re, time, uuid, sys, json
import urllib.request
import xml.etree.ElementTree as ET

DEFAULT_DB = os.path.expanduser("~/.netdeep/history.db")

ARP_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)")
IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")

HV = {
    "bc:24:11": "Proxmox",
    "52:54:00": "QEMU/KVM",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "00:15:5d": "Hyper-V",
    "08:00:27": "VirtualBox",
    "00:1c:42": "Parallels",
}

SEV = {"crit": 0, "high": 1, "med": 2, "low": 3}

MDNS = ("224.0.0.251", 5353)
SSDP = ("239.255.255.250", 1900)
WSD = ("239.255.255.250", 3702)


def _run(cmd, timeout=10):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return (p.stdout or b"").decode("utf-8", "replace")
    except Exception:
        return ""


def _mac(s):
    if not s:
        return ""
    parts = re.split(r"[:\-.]", s.strip().lower())
    if len(parts) != 6:
        return ""
    try:
        return ":".join("%02x" % int(p, 16) for p in parts)   # zero-pad; macos arp prints 1:0:5e:0:0:fb
    except ValueError:
        return ""


def _isip(s):
    return bool(s) and IP_RE.match(s) is not None


def _skip_ip(ip):
    try:
        o = int(ip.split(".")[0])
    except (ValueError, AttributeError):
        return True
    if o >= 224:                       # multicast + limited broadcast
        return True
    if ip == "255.255.255.255":
        return True
    if ip.startswith("169.254."):      # link-local, not a real neighbor
        return True
    return False


def _skip_mac(m):
    return m.startswith("01:00:5e") or m.startswith("33:33") or m.startswith("ff:ff:ff")


def hypervisor_oui(mac):
    m = _mac(mac)
    if not m:
        return None
    if m[:8] in HV:
        return HV[m[:8]]
    if m.startswith("02:42"):          # docker bridge/veth
        return "Docker"
    return None


def is_randomized(mac):
    m = _mac(mac)
    if not m:
        return False
    return m[1] in "26ae"              # locally-administered bit lives in the 2nd nibble


def arp_cache():
    out = _run(["arp", "-an"])
    res, seen = [], set()
    for ln in out.splitlines():
        if "incomplete" in ln:
            continue
        m = ARP_RE.search(ln)
        if not m:
            continue
        ip = m.group(1)
        mac = _mac(m.group(2))
        if not mac or _skip_ip(ip) or _skip_mac(mac):
            continue
        k = (ip, mac)
        if k in seen:
            continue
        seen.add(k)
        res.append({"ip": ip, "mac": mac})
    return res


def _db(path=DEFAULT_DB):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
    c = sqlite3.connect(path)
    try:
        c.execute("pragma journal_mode=wal")
    except sqlite3.Error:
        pass
    c.execute("create table if not exists passive_known_mac(mac text primary key, label text, added real)")
    c.execute("create table if not exists passive_gateway(ip text primary key, mac text, seen real)")
    c.execute("create table if not exists passive_dhcp(ip text primary key, seen real, approved integer default 0)")
    c.execute("create table if not exists passive_sightings(mac text, ip text, proto text, name text, ts real)")
    c.commit()
    return c


def known_add(mac, label="", db=DEFAULT_DB):
    m = _mac(mac)
    if not m:
        return False
    c = _db(db)
    try:
        c.execute("insert or replace into passive_known_mac(mac,label,added) values(?,?,?)",
                  (m, label or "", time.time()))
        c.commit()
        return True
    except sqlite3.Error:
        return False
    finally:
        try:
            c.close()
        except sqlite3.Error:
            pass


def known_all(db=DEFAULT_DB):
    c = _db(db)
    try:
        return [{"mac": r[0], "label": r[1], "added": r[2]}
                for r in c.execute("select mac,label,added from passive_known_mac order by added")]
    except sqlite3.Error:
        return []
    finally:
        try:
            c.close()
        except sqlite3.Error:
            pass


# responses here are attacker-controllable, so kill dtd/entities before parsing.
def _xml(data):
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    try:
        import defusedxml.ElementTree as DET
        return DET.fromstring(data)
    except ImportError:
        pass
    except Exception:
        return None
    try:
        p = ET.XMLParser()
        ep = getattr(p, "parser", None)     # cpython expat handle
        if ep is not None:
            def _no(*a, **k):
                raise ValueError("entities off")
            for h in ("EntityDeclHandler", "UnparsedEntityDeclHandler", "StartDoctypeDeclHandler"):
                try:
                    setattr(ep, h, _no)
                except Exception:
                    pass
            try:
                ep.ExternalEntityRefHandler = lambda *a, **k: False
            except Exception:
                pass
        return ET.fromstring(data, parser=p)
    except Exception:
        return None


def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else tag


def _hdr(t, name):
    m = re.search(r"(?im)^%s:\s*(.+?)\s*$" % re.escape(name), t)
    return m.group(1) if m else None


def _mdns_name(data):
    # read the first name (question, or first RR when there are no questions)
    try:
        i, labels, steps = 12, [], 0
        while i < len(data) and steps < 40:
            steps += 1
            n = data[i]
            if n == 0 or n & 0xc0:      # end, or a compression pointer we won't chase
                break
            i += 1
            if i + n > len(data):
                break
            labels.append(data[i:i + n].decode("ascii", "replace"))
            i += n
        return ".".join(labels) or None
    except Exception:
        return None


def _ssdp_name(data):
    try:
        t = data.decode("utf-8", "replace")
    except Exception:
        return None
    return _hdr(t, "SERVER") or _hdr(t, "USN") or _hdr(t, "NT")


def _banner(proto, data):
    try:
        return _mdns_name(data) if proto == "mdns" else _ssdp_name(data)
    except Exception:
        return None


def _mcast_sock(group, port, iface=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return None
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError:
        pass
    if hasattr(socket, "SO_REUSEPORT"):     # macos needs this to co-bind 5353 alongside mDNSResponder
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    try:
        s.bind(("", port))
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return None
    ifaddr = socket.inet_aton(iface) if _isip(iface) else socket.inet_aton("0.0.0.0")
    try:
        mreq = struct.pack("4s4s", socket.inet_aton(group), ifaddr)   # ip_mreq is 8 bytes, "4sl" would pad wrong
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    return s


def _tcpdump_start(duration, iface):
    n = max(50, int(duration) * 25)
    cmd = ["tcpdump", "-l", "-n", "-e", "-c", str(n)]
    if iface:
        cmd += ["-i", iface]
    cmd += ["arp or udp port 67 or udp port 68"]
    try:
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except Exception:
        return None


def _tcpdump_collect(proc):
    if not proc:
        return [], []
    try:
        if proc.poll() is None:
            proc.terminate()
    except Exception:
        pass
    try:
        out, _ = proc.communicate(timeout=3)
    except Exception:
        try:
            proc.kill()
            out, _ = proc.communicate(timeout=2)
        except Exception:
            return [], []
    if not out:
        return [], []
    return _parse_tcpdump(out.decode("utf-8", "replace"))


def _parse_tcpdump(text):
    arp, dhcp = [], []
    for ln in text.splitlines():
        mr = re.search(r"Reply (\d+\.\d+\.\d+\.\d+) is-at ([0-9a-fA-F:]+)", ln)
        if mr:
            ip, mac = mr.group(1), _mac(mr.group(2))
            if mac and not _skip_ip(ip) and not _skip_mac(mac):
                arp.append((ip, mac))
            continue
        # server->client bootp reply: source ip on port 67 is the dhcp server
        md = re.search(r"(\d+\.\d+\.\d+\.\d+)\.67 > \d+\.\d+\.\d+\.\d+\.68: BOOTP/DHCP, Reply", ln)
        if md and not _skip_ip(md.group(1)):
            dhcp.append(md.group(1))
    return arp, dhcp


def _log_listen(hosts, dhcp):
    try:
        c = _db(DEFAULT_DB)
    except Exception:
        return
    try:
        now = time.time()
        for h in hosts:
            try:
                c.execute("insert into passive_sightings(mac,ip,proto,name,ts) values(?,?,?,?,?)",
                          (h.get("mac"), h.get("ip"), h.get("proto"), h.get("name"), now))
            except sqlite3.Error:
                pass
        for d in dhcp:
            try:
                row = c.execute("select count(*) from passive_dhcp where approved=1").fetchone()
                appr = 1 if (row and row[0] == 0) else 0     # first server ever seen becomes the baseline
                c.execute("insert or ignore into passive_dhcp(ip,seen,approved) values(?,?,?)", (d, now, appr))
                c.execute("update passive_dhcp set seen=? where ip=?", (now, d))
            except sqlite3.Error:
                pass
        c.commit()
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


def listen(duration=15, iface=None):
    hosts, events, dhcp = {}, [], set()
    socks = []
    proc = None
    try:
        for grp, port, proto in ((MDNS[0], MDNS[1], "mdns"), (SSDP[0], SSDP[1], "ssdp")):
            s = _mcast_sock(grp, port, iface)
            if s:
                socks.append((s, proto))
        proc = _tcpdump_start(duration, iface)      # root path, runs alongside; no-ops without bpf access
        deadline = time.time() + max(1, int(duration))
        if socks:
            while time.time() < deadline:
                for s, proto in socks:
                    rem = deadline - time.time()
                    if rem <= 0:
                        break
                    s.settimeout(min(0.5, rem))
                    try:
                        data, addr = s.recvfrom(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        continue
                    ip = addr[0]
                    if _skip_ip(ip):
                        continue
                    name = _banner(proto, data)
                    events.append({"proto": proto, "ip": ip, "name": name})
                    h = hosts.setdefault(ip, {"ip": ip, "mac": None, "proto": proto, "name": name})
                    if name and not h.get("name"):
                        h["name"] = name
        elif proc:
            try:
                proc.wait(timeout=max(1, int(duration)))
            except Exception:
                pass
        for s, _ in socks:
            try:
                s.close()
            except OSError:
                pass
        arp_pairs, dhcp_srv = _tcpdump_collect(proc)
        for ip, mac in arp_pairs:
            h = hosts.setdefault(ip, {"ip": ip, "mac": None, "proto": "arp", "name": None})
            if not h.get("mac"):
                h["mac"] = mac
        for d in dhcp_srv:
            dhcp.add(d)
    except Exception:
        pass
    out = {"hosts": list(hosts.values()), "dhcp_servers": sorted(dhcp), "raw_events": events}
    _log_listen(out["hosts"], out["dhcp_servers"])
    return out


def ssdp_search(timeout=3):
    msg = ("M-SEARCH * HTTP/1.1\r\n"
           "HOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\n'
           "MX: 2\r\n"
           "ST: ssdp:all\r\n\r\n").encode()
    res = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return []
    try:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except OSError:
            pass
        try:
            s.sendto(msg, SSDP)
        except OSError:
            return []
        deadline = time.time() + timeout
        while True:
            rem = deadline - time.time()
            if rem <= 0:
                break
            s.settimeout(rem)
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                break
            except OSError:
                break
            t = data.decode("utf-8", "replace")
            ip = addr[0]
            loc = _hdr(t, "LOCATION")
            key = (ip, loc)
            if key not in res:
                res[key] = {"ip": ip, "server": _hdr(t, "SERVER"), "location": loc}
    finally:
        try:
            s.close()
        except OSError:
            pass
    return list(res.values())


def ws_discovery(timeout=3):
    mid = "urn:uuid:" + str(uuid.uuid4())
    env = ('<?xml version="1.0" encoding="utf-8"?>'
           '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
           'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
           'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
           '<s:Header><a:MessageID>%s</a:MessageID>'
           '<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>'
           '<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action></s:Header>'
           '<s:Body><d:Probe/></s:Body></s:Envelope>' % mid).encode()
    res = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return []
    try:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        except OSError:
            pass
        try:
            s.sendto(env, WSD)
        except OSError:
            return []
        deadline = time.time() + timeout
        while True:
            rem = deadline - time.time()
            if rem <= 0:
                break
            s.settimeout(rem)
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                break
            except OSError:
                break
            types, xaddrs = _probematch(data)
            key = (addr[0], xaddrs)
            if key not in res:
                res[key] = {"ip": addr[0], "types": types, "xaddrs": xaddrs}
    finally:
        try:
            s.close()
        except OSError:
            pass
    return list(res.values())


def _probematch(data):
    root = _xml(data)
    if root is None:
        return None, None
    types = xaddrs = None
    for el in root.iter():
        t = _local(el.tag)
        if t == "Types" and el.text:
            types = el.text.strip()
        elif t == "XAddrs" and el.text:
            xaddrs = el.text.strip()
    return types, xaddrs


# ssrf-adjacent: only feed this LOCATION urls that came back from ssdp_search.
def upnp_describe(location_url, timeout=3):
    if not location_url or not re.match(r"https?://", location_url):
        return {}
    try:
        req = urllib.request.Request(location_url, headers={"User-Agent": "netdeep"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(65536)               # cap it; device xml is tiny, hostile xml is not
    except Exception:
        return {}
    root = _xml(data)
    if root is None:
        return {}
    out, want = {}, ("friendlyName", "manufacturer", "modelName", "modelNumber")
    for el in root.iter():
        t = _local(el.tag)
        if t in want and t not in out and el.text:
            out[t] = el.text.strip()
    return out


def detect_rogue(scan_hosts, arp_entries=None, known_macs=None,
                 gateway_ip=None, gateway_mac=None, db=DEFAULT_DB):
    risks = []
    try:
        c = _db(db)
    except Exception:
        return risks
    try:
        allow = set(_mac(m) for m in (known_macs or []) if m)
        try:
            for r in c.execute("select mac from passive_known_mac"):
                allow.add(r[0])
        except sqlite3.Error:
            pass

        pairs = []
        for h in (scan_hosts or []):
            ip, mac = h.get("ip"), _mac(h.get("mac") or "")
            if ip and mac:
                pairs.append((ip, mac))
        for e in (arp_entries or []):
            ip, mac = e.get("ip"), _mac(e.get("mac") or "")
            if ip and mac:
                pairs.append((ip, mac))

        # gateway mac pin: first sighting is trusted, a later mismatch smells like arp-spoof
        if gateway_ip and gateway_mac:
            gm = _mac(gateway_mac)
            row = c.execute("select mac from passive_gateway where ip=?", (gateway_ip,)).fetchone()
            if row is None:
                c.execute("insert into passive_gateway(ip,mac,seen) values(?,?,?)",
                          (gateway_ip, gm, time.time()))
                c.commit()
            elif gm and row[0] != gm:
                risks.append({"sev": "crit", "id": "gw_mac_changed",
                              "msg": "gateway mac changed (possible MITM), was %s" % row[0],
                              "ip": gateway_ip, "mac": gm})
                c.execute("update passive_gateway set mac=?, seen=? where ip=?",
                          (gm, time.time(), gateway_ip))
                c.commit()

        ip2macs, mac2ips = {}, {}
        for ip, mac in pairs:
            ip2macs.setdefault(ip, set()).add(mac)
            mac2ips.setdefault(mac, set()).add(ip)
        for ip, macs in ip2macs.items():
            if len(macs) > 1:
                risks.append({"sev": "high", "id": "arp_conflict_ip",
                              "msg": "ip %s claimed by %d macs: %s" % (ip, len(macs), ", ".join(sorted(macs))),
                              "ip": ip, "mac": None})
        for mac, ips in mac2ips.items():
            if len(ips) > 1:
                risks.append({"sev": "high", "id": "arp_conflict_mac",
                              "msg": "mac %s on %d ips: %s" % (mac, len(ips), ", ".join(sorted(ips))),
                              "ip": None, "mac": mac})

        checked = set()
        for ip, mac in pairs:
            if mac in checked:
                continue
            checked.add(mac)
            try:
                c.execute("insert into passive_sightings(mac,ip,proto,name,ts) values(?,?,?,?,?)",
                          (mac, ip, "scan", None, time.time()))
            except sqlite3.Error:
                pass
            if mac in allow:
                continue
            hv = hypervisor_oui(mac)
            if hv:
                risks.append({"sev": "high", "id": "rogue_vm",
                              "msg": "possible rogue VM (%s)" % hv, "ip": ip, "mac": mac})
            elif is_randomized(mac):
                risks.append({"sev": "low", "id": "randomized_mac",
                              "msg": "randomized/private mac", "ip": ip, "mac": mac})
            else:
                risks.append({"sev": "med", "id": "new_device", "msg": "new device", "ip": ip, "mac": mac})
        c.commit()

        # rogue dhcp, sourced from what listen() persisted
        try:
            rows = c.execute("select ip, approved from passive_dhcp").fetchall()
        except sqlite3.Error:
            rows = []
        if rows:
            seen = set(r[0] for r in rows)
            appr = set(r[0] for r in rows if r[1])
            if len(seen) > 1:
                risks.append({"sev": "crit", "id": "rogue_dhcp",
                              "msg": "multiple dhcp servers seen: %s" % ", ".join(sorted(seen)),
                              "ip": None, "mac": None})
            unappr = (seen - appr) if appr else set()
            if unappr:
                risks.append({"sev": "crit", "id": "rogue_dhcp_unapproved",
                              "msg": "unapproved dhcp server: %s" % ", ".join(sorted(unappr)),
                              "ip": None, "mac": None})
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass
    risks.sort(key=lambda r: SEV.get(r.get("sev"), 9))
    return risks


def _selftest():
    assert hypervisor_oui("bc:24:11:aa:bb:cc") == "Proxmox"
    assert hypervisor_oui("52:54:00:12:34:56") == "QEMU/KVM"
    assert hypervisor_oui("00:0c:29:11:22:33") == "VMware"
    assert hypervisor_oui("02:42:ac:11:00:02") == "Docker"
    assert hypervisor_oui("a1:b2:c3:d4:e5:f6") is None

    assert is_randomized("02:11:22:33:44:55") is True
    assert is_randomized("06:00:00:00:00:01") is True
    assert is_randomized("0a:00:00:00:00:01") is True
    assert is_randomized("0e:00:00:00:00:01") is True
    assert is_randomized("bc:24:11:aa:bb:cc") is False    # 2nd nibble 'c' -> not local
    assert is_randomized("00:15:5d:00:00:01") is False

    assert _mac("1:0:5e:0:0:fb") == "01:00:5e:00:00:fb"   # macos-style short octets

    p = os.path.join(os.environ.get("TMPDIR") or "/tmp", "netdeep-selftest-%s.db" % uuid.uuid4().hex)
    try:
        hosts = [
            {"ip": "192.168.1.10", "mac": "aa:aa:aa:aa:aa:aa"},
            {"ip": "192.168.1.11", "mac": "aa:aa:aa:aa:aa:aa"},   # same mac, two ips
            {"ip": "192.168.1.10", "mac": "bb:bb:bb:bb:bb:bb"},   # same ip, two macs
            {"ip": "192.168.1.20", "mac": "bc:24:11:00:00:01"},   # proxmox oui -> rogue vm
            {"ip": "192.168.1.21", "mac": "02:aa:bb:cc:dd:ee"},   # locally-administered -> randomized
        ]
        risks = detect_rogue(hosts, db=p)
        ids = [r["id"] for r in risks]
        assert "arp_conflict_ip" in ids, ids
        assert "arp_conflict_mac" in ids, ids
        assert any(r["id"] == "rogue_vm" and r["sev"] == "high" for r in risks), risks
        assert any(r["id"] == "randomized_mac" and r["sev"] == "low" for r in risks), risks
        assert any(r["id"] == "new_device" for r in risks), risks

        known_add("aa:aa:aa:aa:aa:aa", "printer", db=p)
        assert any(x["mac"] == "aa:aa:aa:aa:aa:aa" for x in known_all(db=p))

        detect_rogue([], gateway_ip="192.168.1.1", gateway_mac="11:11:11:11:11:11", db=p)
        r2 = detect_rogue([], gateway_ip="192.168.1.1", gateway_mac="99:99:99:99:99:99", db=p)
        assert any(x["id"] == "gw_mac_changed" and x["sev"] == "crit" for x in r2), r2
    finally:
        for suf in ("", "-wal", "-shm"):
            try:
                os.remove(p + suf)
            except OSError:
                pass
    print("OK")


def _load_scan(path):
    try:
        with open(os.path.expanduser(path)) as f:
            obj = json.load(f)
    except Exception:
        return []
    hosts = obj.get("hosts") if isinstance(obj, dict) else obj
    out = []
    for h in hosts or []:
        if isinstance(h, dict) and h.get("ip"):
            out.append({"ip": h.get("ip"), "mac": h.get("mac")})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    pl = sub.add_parser("listen")
    pl.add_argument("--for", dest="dur", type=int, default=15)
    pl.add_argument("--iface")

    sub.add_parser("ssdp")
    sub.add_parser("wsd")

    pr = sub.add_parser("rogue")
    pr.add_argument("--scan-json", required=True)
    pr.add_argument("--gw-ip")
    pr.add_argument("--gw-mac")
    pr.add_argument("--db", default=DEFAULT_DB)

    pk = sub.add_parser("known")
    pk.add_argument("--add")
    pk.add_argument("--label", default="")
    pk.add_argument("--db", default=DEFAULT_DB)

    a = ap.parse_args()

    if a.selftest:
        _selftest()
        return
    if a.cmd == "listen":
        print(json.dumps(listen(a.dur, a.iface), indent=2))
    elif a.cmd == "ssdp":
        print(json.dumps(ssdp_search(), indent=2))
    elif a.cmd == "wsd":
        print(json.dumps(ws_discovery(), indent=2))
    elif a.cmd == "rogue":
        risks = detect_rogue(_load_scan(a.scan_json), gateway_ip=a.gw_ip, gateway_mac=a.gw_mac, db=a.db)
        print(json.dumps(risks, indent=2))
    elif a.cmd == "known":
        if a.add:
            known_add(a.add, a.label, a.db)
            print(json.dumps({"added": _mac(a.add), "label": a.label}))
        else:
            print(json.dumps(known_all(a.db), indent=2))
    else:
        ap.print_help()
        raise SystemExit(2)


if __name__ == "__main__":
    main()
