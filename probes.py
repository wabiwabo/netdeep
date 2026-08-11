#!/usr/bin/env python3
# read-only recon: one GET per probe, self-signed tls is fine here. a 401/403 is the secure result, a 200 json body is the finding. never mutate, never range/dump.
import argparse, json, re, socket, ssl, struct
import http.client

SEV = {"crit": 0, "high": 1, "med": 2, "low": 3, "info": 4}

# port -> (scheme, paths). scheme https falls back to http inside http_get.
CPORTS = {
    2375:  ("http",  ["/version", "/info"]),
    2379:  ("https", ["/version"]),          # /version only. detect, never touch /v2/keys or v3 range
    10250: ("https", ["/pods"]),
    10255: ("http",  ["/pods"]),
    6443:  ("https", ["/version"]),
    8443:  ("https", ["/version"]),
    4646:  ("http",  ["/v1/agent/self"]),
    8500:  ("http",  ["/v1/status/leader"]),
    9000:  ("http",  ["/api/status"]),
    9443:  ("https", ["/api/status"]),
}


def mk(sev, id_, msg, port):
    return {"sev": sev, "id": id_, "msg": msg, "port": port}


def _get_once(host, port, path, scheme, timeout):
    c = None
    try:
        if scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)   # self-signed is the norm on this gear
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            c = http.client.HTTPConnection(host, port, timeout=timeout)
        c.request("GET", path, headers={"User-Agent": "netdeep", "Accept": "*/*"})
        r = c.getresponse()
        body = r.read(8192)                     # cap it; the finding lives in the first few kb
        hdrs = {}
        for k, v in r.getheaders():
            hdrs[k.lower()] = v
        return r.status, hdrs, body
    except Exception:
        return None
    finally:
        if c is not None:
            try:
                c.close()
            except Exception:
                pass


def http_get(host, port, path, scheme="https", timeout=3):
    order = ["https", "http"] if scheme == "https" else [scheme]
    for sch in order:
        r = _get_once(host, port, path, sch, timeout)
        if r is not None:
            return r
    return None


def _json(body):
    if not body:
        return None
    try:
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        return json.loads(body)
    except Exception:
        return None


# identity by response SHAPE, not just an open port
def _is_podlist(b):
    return isinstance(b, dict) and (b.get("kind") == "PodList" or "items" in b)


def _is_k8s_ver(b):
    return isinstance(b, dict) and ("gitVersion" in b or ("major" in b and "minor" in b))


def _is_nomad_self(b):
    return isinstance(b, dict) and any(str(k).lower() in ("member", "config", "stats") for k in b)


def _is_consul_leader(b):
    return isinstance(b, str)   # /v1/status/leader is a bare json string ("ip:port" or "")


def classify_container(port, status, body):
    if port == 2375:
        if status == 200 and isinstance(body, dict) and ("ApiVersion" in body or "GitCommit" in body):
            return mk("crit", "docker", "unauth docker api (root-equiv)", 2375)
        return None
    if port == 2379:
        if status == 200 and isinstance(body, dict) and "etcdserver" in body:
            return mk("crit", "etcd", "etcd exposed (holds k8s secrets)", 2379)
        return None
    if port == 10250:
        if status == 200 and _is_podlist(body):
            return mk("crit", "kubelet", "kubelet anonymous exec", 10250)
        return None
    if port == 10255:
        if status == 200 and _is_podlist(body):
            return mk("high", "kubelet_ro", "read-only kubelet", 10255)
        return None
    if port in (6443, 8443):
        # anonymous 200 is the problem. 401/403 = secured, not our business
        if status == 200 and _is_k8s_ver(body):
            return mk("high", "k8s_api", "k8s api anonymous", port)
        return None
    if port == 4646:
        if status == 200 and _is_nomad_self(body):
            return mk("high", "nomad", "nomad acl disabled", 4646)
        return None
    if port == 8500:
        if status == 200 and _is_consul_leader(body):
            return mk("high", "consul", "consul acl disabled", 8500)
        return None
    if port in (9000, 9443):
        if status == 200 and isinstance(body, dict) and "Version" in body:
            v = body.get("Version")
            msg = "portainer %s (version leak)" % v if v else "portainer exposed (version leak)"
            return mk("info", "portainer", msg, port)
        return None
    return None


def container_probe(ip, ports):
    have = set()
    for p in ports or []:
        try:
            have.add(int(p))
        except (ValueError, TypeError):
            pass
    risks = []
    for port in sorted(have):
        if port == 2376:
            risks.append(mk("info", "docker_tls", "docker api tls (client-cert)", 2376))
            continue
        spec = CPORTS.get(port)
        if not spec:
            continue
        scheme, paths = spec
        for path in paths:
            r = http_get(ip, port, path, scheme=scheme)
            if r is None:
                continue
            status, _, body = r
            risk = classify_container(port, status, _json(body))
            if risk:
                risks.append(risk)
                break                            # one hit per port, don't hammer
    risks.sort(key=lambda x: SEV.get(x["sev"], 9))
    return risks


def classify_bmc(root, headers):
    out = {"redfish": False, "vendor": None, "firmware": None, "findings": []}
    srv = ((headers or {}).get("server") or "").lower()
    bmc = False
    # redfish service root is spec-mandated UNAUTH; valid json here is a reliable bmc signal
    if isinstance(root, dict) and any(k in root for k in ("RedfishVersion", "Vendor", "UUID")):
        out["redfish"] = True
        bmc = True
        if root.get("Vendor"):
            out["vendor"] = root.get("Vendor")
        if root.get("FirmwareVersion"):
            out["firmware"] = str(root.get("FirmwareVersion"))
    if "ilo" in srv:                             # HP-iLO-Server header
        out["vendor"] = out["vendor"] or "HPE iLO"
        bmc = True
    if bmc:
        out["findings"].append(mk("crit", "bmc_lan", "bmc reachable from LAN", 443))
    return out


def _peer_cert(ip, port, timeout):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.create_connection((ip, port), timeout=timeout)
        try:
            ss = ctx.wrap_socket(s, server_hostname=str(ip))
            der = ss.getpeercert(binary_form=True)   # binary form works even with verify off
            try:
                ss.close()
            except Exception:
                pass
            return der
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        return None


def _vendor_from_cert(der):
    if not der:
        return None
    # org/cn sit in the der as readable ascii; cheap substring beats an asn.1 parser
    for needle, name in ((b"Dell Inc", "Dell iDRAC"), (b"iDRAC", "Dell iDRAC"),
                         (b"ATEN", "Supermicro"), (b"Super Micro", "Supermicro"),
                         (b"iLO", "HPE iLO"), (b"Hewlett", "HPE iLO")):
        if needle in der:
            return name
    return None


def _ipmi_pkt():
    # asf/rmcp presence-ping: rmcp hdr (ver6, seq ff, class asf=0x06) + asf iana 4542, msgtype 0x80
    return struct.pack("!BBBB", 0x06, 0x00, 0xff, 0x06) + \
        struct.pack("!IBBBB", 4542, 0x80, 0x00, 0x00, 0x00)


def _ipmi_ping(ip, timeout):
    # any pong back means a bmc is listening on 623/udp. unprivileged udp, no root needed.
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_ipmi_pkt(), (ip, 623))
        data, _ = s.recvfrom(1024)
        return bool(data)
    except Exception:
        return False
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def _has(findings, id_):
    return any(f.get("id") == id_ for f in findings)


def bmc_probe(ip, timeout=3):
    root, headers = None, {}
    r = http_get(ip, 443, "/redfish/v1/", scheme="https", timeout=timeout)
    if r:
        _, headers, body = r
        root = _json(body)
    out = classify_bmc(root, headers)
    out["ipmi"] = False

    if not out["vendor"]:                        # cert fingerprint fallback (iDRAC/ATEN/iLO)
        v = _vendor_from_cert(_peer_cert(ip, 443, timeout))
        if v:
            out["vendor"] = v

    # ilo leaks firmware rev unauthenticated via /xmldata
    if out["vendor"] and "ilo" in out["vendor"].lower() and not out["firmware"]:
        rr = http_get(ip, 443, "/xmldata?item=all", scheme="https", timeout=timeout)
        if rr:
            m = re.search(rb"<FWRI>([^<]+)</FWRI>", rr[2] or b"")
            if m:
                out["firmware"] = m.group(1).decode("ascii", "replace").strip()

    if _ipmi_ping(ip, timeout):
        out["ipmi"] = True
        out["findings"].append(mk("info", "ipmi", "ipmi 623 open", 623))

    # a management controller reachable at all from the LAN is the finding
    if (out["vendor"] or out["ipmi"]) and not _has(out["findings"], "bmc_lan"):
        out["findings"].append(mk("crit", "bmc_lan", "bmc reachable from LAN", 443))

    out["findings"].sort(key=lambda x: SEV.get(x["sev"], 9))
    return out


def _ports(s):
    out = []
    for tok in (s or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            out.append(int(tok))
        except ValueError:
            pass
    return out


def _selftest():
    # docker: 200 json with ApiVersion -> crit; no body / 401 -> nothing
    r = classify_container(2375, 200, {"ApiVersion": "1.41", "GitCommit": "459d0df"})
    assert r and r["sev"] == "crit" and r["port"] == 2375, r
    assert classify_container(2375, 200, None) is None
    assert classify_container(2375, 401, {"message": "x"}) is None

    r = classify_container(2379, 200, {"etcdserver": "3.5.9", "etcdcluster": "3.5.0"})
    assert r and r["sev"] == "crit" and "etcd" in r["msg"], r

    pods = {"kind": "PodList", "apiVersion": "v1", "items": []}
    assert classify_container(10250, 200, pods)["sev"] == "crit"
    assert classify_container(10255, 200, pods)["sev"] == "high"
    assert classify_container(10250, 200, {"nope": 1}) is None

    ver = {"major": "1", "minor": "27", "gitVersion": "v1.27.3"}
    assert classify_container(6443, 200, ver)["sev"] == "high"
    assert classify_container(6443, 401, None) is None       # secured, not flagged
    assert classify_container(8443, 403, ver) is None

    assert classify_container(4646, 200, {"config": {}, "member": {}, "stats": {}})["sev"] == "high"
    assert classify_container(8500, 200, "10.0.0.1:8300")["sev"] == "high"
    assert classify_container(8500, 200, {"not": "consul"}) is None

    r = classify_container(9000, 200, {"Version": "2.19.4"})
    assert r and r["sev"] == "info" and "2.19.4" in r["msg"], r

    # bmc: redfish service root -> redfish True + finding
    b = classify_bmc({"RedfishVersion": "1.6.0", "UUID": "abc"}, {"server": "Apache"})
    assert b["redfish"] is True and any(x["sev"] == "crit" for x in b["findings"]), b
    assert classify_bmc({"RedfishVersion": "1.11", "Vendor": "Dell"}, {})["vendor"] == "Dell"
    b = classify_bmc(None, {"server": "HP-iLO-Server/1.30"})
    assert b["vendor"] and "iLO" in b["vendor"] and b["findings"], b
    b = classify_bmc(None, {})
    assert b["redfish"] is False and not b["findings"], b

    assert _vendor_from_cert(b"...O=Dell Inc.,CN=idrac...") == "Dell iDRAC"
    assert _vendor_from_cert(b"CN=ATEN") == "Supermicro"
    assert _vendor_from_cert(None) is None

    assert _ports("2375, 6443 ,2379,,x") == [2375, 6443, 2379]
    assert _json(b'{"a":1}') == {"a": 1}
    assert _json(b"<html>nope") is None
    pkt = _ipmi_pkt()
    assert pkt[:4] == b"\x06\x00\xff\x06" and pkt[4:8] == struct.pack("!I", 4542), pkt
    print("OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    pc = sub.add_parser("containers")
    pc.add_argument("--host", required=True)
    pc.add_argument("--ports", required=True)

    pb = sub.add_parser("bmc")
    pb.add_argument("--host", required=True)

    a = ap.parse_args()

    if a.selftest:
        _selftest()
        return
    if a.cmd == "containers":
        print(json.dumps(container_probe(a.host, _ports(a.ports)), indent=2))
    elif a.cmd == "bmc":
        print(json.dumps(bmc_probe(a.host), indent=2))
    else:
        ap.print_help()
        raise SystemExit(2)


if __name__ == "__main__":
    main()
