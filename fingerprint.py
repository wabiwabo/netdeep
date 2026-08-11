#!/usr/bin/env python3
# host/service fingerprinting + drift for netdeep. stdlib only.

import argparse
import base64
import hashlib
import http.client
import os
import re
import socket
import sqlite3
import ssl
import struct
import subprocess

UA = "netdeep/1"
DEFAULT_DB = os.path.expanduser("~/.netdeep/history.db")

# ports that speak tls
TLS_PORTS = (443, 8006, 8007, 8443)


def murmur3_32(data, seed=0):
    # murmurhash3 x86_32. matches mmh3.hash (signed).
    if isinstance(data, str):
        data = data.encode()
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    n = len(data)
    h = seed & 0xFFFFFFFF
    nb = n & ~3
    for i in range(0, nb, 4):
        k = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    k = 0
    t = n & 3
    if t == 3:
        k ^= data[nb + 2] << 16
    if t >= 2:
        k ^= data[nb + 1] << 8
    if t >= 1:
        k ^= data[nb]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= n
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return struct.unpack("<i", struct.pack("<I", h))[0]


# --- tiny json (avoid importing json) ---

def _jstr(s):
    o = ['"']
    for ch in s:
        if ch == '"':
            o.append('\\"')
        elif ch == '\\':
            o.append('\\\\')
        elif ch == '\n':
            o.append('\\n')
        elif ch == '\r':
            o.append('\\r')
        elif ch == '\t':
            o.append('\\t')
        elif ord(ch) < 0x20:
            o.append('\\u%04x' % ord(ch))
        else:
            o.append(ch)
    o.append('"')
    return "".join(o)


def _js(o):
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, int):
        return str(o)
    if isinstance(o, float):
        return repr(o)
    if isinstance(o, str):
        return _jstr(o)
    if isinstance(o, dict):
        return "{" + ",".join(_jstr(str(k)) + ":" + _js(v) for k, v in o.items()) + "}"
    if isinstance(o, (list, tuple)):
        return "[" + ",".join(_js(v) for v in o) + "]"
    return _jstr(str(o))


# --- fs helpers ---

def _netdeep_dir():
    d = os.path.dirname(DEFAULT_DB) or "."
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        pass
    return d


def _netdeep_path(name):
    return os.path.join(_netdeep_dir(), name)


# --- http ---

def _conn(host, port, scheme, timeout):
    if scheme == "https":
        ctx = ssl._create_unverified_context()
        return http.client.HTTPSConnection(host, int(port), timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, int(port), timeout=timeout)


def _split_url(u):
    m = re.match(r'^(https?)://([^/:]+)(?::(\d+))?(/.*)?$', u, re.I)
    if not m:
        return None
    sch = m.group(1).lower()
    h = m.group(2)
    p = int(m.group(3)) if m.group(3) else (443 if sch == "https" else 80)
    return sch, h, p, m.group(4) or "/"


def _http_get_raw(host, port, scheme, path, timeout=4, depth=0):
    c = None
    try:
        c = _conn(host, port, scheme, timeout)
        c.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*"})
        r = c.getresponse()
        st = r.status
        loc = r.getheader("Location")
        body = r.read()
        if st in (301, 302, 303, 307, 308) and loc and depth < 3:
            if loc[:7].lower() == "http://" or loc[:8].lower() == "https://":
                parts = _split_url(loc)
                if not parts:
                    return None
                sch, h, p, pth = parts
            else:
                sch, h, p, pth = scheme, host, port, loc if loc.startswith("/") else "/" + loc
            return _http_get_raw(h, p, sch, pth, timeout, depth + 1)
        if st >= 400:
            return None
        return body
    except Exception:
        return None
    finally:
        try:
            if c:
                c.close()
        except Exception:
            pass


def favicon_hash(host, port, scheme="https"):
    # shodan-style: mmh3 of base64.encodebytes(raw). the 76-col newlines matter.
    try:
        body = _http_get_raw(host, port, scheme, "/favicon.ico", timeout=4)
        if not body:
            return None
        return murmur3_32(base64.encodebytes(body), 0)
    except Exception:
        return None


_COOKIE_STARTS = (
    ("pveauthcookie", "Proxmox VE"),
    ("grafana_session", "Grafana"),
    ("laravel_session", "Laravel"),
    ("wordpress_logged_in", "WordPress"),
)
_COOKIE_EXACT = (
    ("jsessionid", "Java/Tomcat"),
    ("connect.sid", "Node/Express"),
)


def _products(hd, cookies, body):
    p = set()
    low = [c.lower() for c in cookies]
    for c in low:
        for pre, name in _COOKIE_STARTS:
            if c.startswith(pre):
                p.add(name)
        for ex, name in _COOKIE_EXACT:
            if c == ex:
                p.add(name)
    if "csrftoken" in low and "sessionid" in low:
        p.add("Django")
    for hk in ("server", "x-powered-by", "x-generator"):
        v = hd.get(hk)
        if v:
            p.add(v)
    wa = hd.get("www-authenticate")
    if wa:
        m = re.search(r'realm="([^"]*)"', wa)
        if m:
            p.add("realm:" + m.group(1))
    if body:
        try:
            t = body.decode("latin-1", "ignore")
            m = re.search(r'<meta[^>]+name=["\']?generator["\']?[^>]+content=["\']([^"\'>]+)', t, re.I)
            if m:
                p.add("generator:" + m.group(1).strip())
        except Exception:
            pass
    return sorted(p)


def http_fingerprint(host, port, scheme="http"):
    c = None
    try:
        c = _conn(host, port, scheme, 4)
        c.request("GET", "/", headers={"User-Agent": UA, "Accept": "*/*"})
        r = c.getresponse()
        raw = r.getheaders()
        try:
            body = r.read(65536)  # first ~64k only
        except Exception:
            body = b""
        hd = {}
        cookies = []
        for k, v in raw:
            lk = k.lower()
            if lk == "set-cookie":
                cookies.append(v.split("=", 1)[0].strip())
            else:
                hd[lk] = v
        return {"server": hd.get("server"), "cookies": cookies, "products": _products(hd, cookies, body)}
    except Exception:
        return None
    finally:
        try:
            if c:
                c.close()
        except Exception:
            pass


# --- cert ---

def _rdn(seq):
    if not seq:
        return None
    out = []
    for rdn in seq:
        for kv in rdn:
            try:
                out.append(kv[0] + "=" + kv[1])
            except Exception:
                pass
    return ",".join(out)


def _cert_meta(der):
    # notAfter + self-signed via ssl's private decoder (needs a file). best-effort.
    out = {}
    p = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        p = _netdeep_path(".cert_%d.pem" % os.getpid())
        with open(p, "w") as f:
            f.write(pem)
        d = ssl._ssl._test_decode_cert(p)
        na = d.get("notAfter")
        if na:
            out["notAfter"] = na
        subj = _rdn(d.get("subject"))
        iss = _rdn(d.get("issuer"))
        if subj is not None and iss is not None:
            out["self_signed"] = subj == iss
    except Exception:
        pass
    finally:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    return out


def cert_sha(host, port=443, timeout=4):
    # CERT_NONE: we want the leaf cert even if self-signed / expired.
    s = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, int(port)), timeout=timeout)
        raw.settimeout(timeout)
        try:
            s = ctx.wrap_socket(raw, server_hostname=host)
        except Exception:
            try:
                raw.close()
            except Exception:
                pass
            raw = socket.create_connection((host, int(port)), timeout=timeout)
            raw.settimeout(timeout)
            s = ctx.wrap_socket(raw)  # some stacks reject ip in SNI
        der = s.getpeercert(binary_form=True)
        if not der:
            return None
        out = {"sha256": hashlib.sha256(der).hexdigest()}
        out.update(_cert_meta(der))
        return out
    except Exception:
        return None
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


# --- ssh ---

def _ktname(t):
    t = t.lower()
    if "ed25519" in t:
        return "ed25519"
    if "ecdsa" in t:
        return "ecdsa"
    if "rsa" in t:
        return "rsa"
    if "dss" in t or "dsa" in t:
        return "dsa"
    return t


def ssh_hostkey(host, port=22, timeout=4):
    txt = ""
    out = {}
    try:
        p = subprocess.run(
            ["ssh-keyscan", "-T", str(timeout), "-p", str(int(port)),
             "-t", "rsa,ecdsa,ed25519", host],
            capture_output=True, timeout=timeout + 3)
        txt = p.stdout.decode("utf-8", "ignore")
    except Exception:
        txt = ""
    # primary: sha256 fp straight off the raw key blob (matches openssh SHA256:..)
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split()
        if len(parts) < 3:
            continue
        ktype, b64 = parts[1], parts[2]
        try:
            raw = base64.b64decode(b64)
            dig = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
            out[_ktname(ktype)] = "SHA256:" + dig
        except Exception:
            continue
    if out:
        return out
    # fallback: let ssh-keygen fingerprint whatever keyscan returned
    if txt.strip():
        fp = None
        try:
            fp = _netdeep_path(".hk_%d" % os.getpid())
            with open(fp, "w") as f:
                f.write(txt)
            k = subprocess.run(["ssh-keygen", "-lf", fp], capture_output=True, timeout=timeout)
            for ln in k.stdout.decode("utf-8", "ignore").splitlines():
                m = re.search(r'(SHA256:\S+).*\(([A-Za-z0-9]+)\)', ln)
                if m:
                    out[_ktname(m.group(2))] = m.group(1)
        except Exception:
            pass
        finally:
            try:
                if fp and os.path.exists(fp):
                    os.remove(fp)
            except Exception:
                pass
    return out or None


# --- jarm (vendored salesforce algorithm) ---
# jarm is a RESPONSE fingerprint: spoofable. good for grouping/drift, not a trust anchor.

_CIPHERS_ALL = [
    b"\x00\x16", b"\x00\x33", b"\x00\x67", b"\xc0\x9e", b"\xc0\xa2", b"\x00\x9e",
    b"\x00\x39", b"\x00\x6b", b"\xc0\x9f", b"\xc0\xa3", b"\x00\x9f", b"\x00\x45",
    b"\x00\xbe", b"\x00\x88", b"\x00\xc4", b"\x00\x9a", b"\xc0\x08", b"\xc0\x09",
    b"\xc0\x23", b"\xc0\xac", b"\xc0\xae", b"\xc0\x2b", b"\xc0\x0a", b"\xc0\x24",
    b"\xc0\xad", b"\xc0\xaf", b"\xc0\x2c", b"\xc0\x72", b"\xc0\x73", b"\xcc\xa9",
    b"\x13\x02", b"\x13\x01", b"\xcc\x14", b"\xc0\x07", b"\xc0\x12", b"\xc0\x13",
    b"\xc0\x27", b"\xc0\x2f", b"\xc0\x14", b"\xc0\x28", b"\xc0\x30", b"\xc0\x60",
    b"\xc0\x61", b"\xc0\x76", b"\xc0\x77", b"\xcc\xa8", b"\x13\x05", b"\x13\x04",
    b"\x13\x03", b"\xcc\x13", b"\xc0\x11", b"\x00\x0a", b"\x00\x2f", b"\x00\x3c",
    b"\xc0\x9c", b"\xc0\xa0", b"\x00\x9c", b"\x00\x35", b"\x00\x3d", b"\xc0\x9d",
    b"\xc0\xa1", b"\x00\x9d", b"\x00\x41", b"\x00\xba", b"\x00\x84", b"\x00\xc0",
    b"\x00\x07", b"\x00\x04", b"\x00\x05",
]
_CIPHERS_NO13 = [c for c in _CIPHERS_ALL if c[0:1] != b"\x13"]

# lookup table -> jarm cipher byte (index, 1-based)
_CIPHER_TABLE = [
    b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f",
    b"\x00\x33", b"\x00\x35", b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41",
    b"\x00\x45", b"\x00\x67", b"\x00\x6b", b"\x00\x84", b"\x00\x88", b"\x00\x9a",
    b"\x00\x9c", b"\x00\x9d", b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe",
    b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a",
    b"\xc0\x11", b"\xc0\x12", b"\xc0\x13", b"\xc0\x14", b"\xc0\x23", b"\xc0\x24",
    b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c", b"\xc0\x2f", b"\xc0\x30",
    b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77",
    b"\xc0\x9c", b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1",
    b"\xc0\xa2", b"\xc0\xa3", b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf",
    b"\xcc\x13", b"\xcc\x14", b"\xcc\xa8", b"\xcc\xa9", b"\x13\x01", b"\x13\x02",
    b"\x13\x03", b"\x13\x04", b"\x13\x05",
]

_GREASE = [
    b"\x0a\x0a", b"\x1a\x1a", b"\x2a\x2a", b"\x3a\x3a", b"\x4a\x4a", b"\x5a\x5a",
    b"\x6a\x6a", b"\x7a\x7a", b"\x8a\x8a", b"\x9a\x9a", b"\xaa\xaa", b"\xba\xba",
    b"\xca\xca", b"\xda\xda", b"\xea\xea", b"\xfa\xfa",
]


def _grease():
    return _GREASE[os.urandom(1)[0] % len(_GREASE)]


def _mung(a, req):
    out = []
    n = len(a)
    if req == "REVERSE":
        out = a[::-1]
    elif req == "BOTTOM_HALF":
        out = a[n // 2 + 1:] if n % 2 == 1 else a[n // 2:]
    elif req == "TOP_HALF":
        if n % 2 == 1:
            out.append(a[n // 2])
        out = out + _mung(_mung(a, "BOTTOM_HALF"), "REVERSE")
    elif req == "MIDDLE_OUT":
        mid = n // 2
        if n % 2 == 1:
            out.append(a[mid])
            for i in range(1, mid + 1):
                out.append(a[mid + i])
                out.append(a[mid - i])
        else:
            for i in range(1, mid + 1):
                out.append(a[mid - 1 + i])
                out.append(a[mid - i])
    return out


def _jarm_probes(host, port):
    port = int(port)
    return [
        [host, port, "TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"],
        [host, port, "TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"],
        [host, port, "TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
        [host, port, "TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
        [host, port, "TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
    ]


def _jarm_ciphers(d):
    lst = list(_CIPHERS_ALL if d[3] == "ALL" else _CIPHERS_NO13)
    if d[4] != "FORWARD":
        lst = _mung(lst, d[4])
    if d[5] == "GREASE":
        lst = [_grease()] + lst
    return b"".join(lst)


def _sni(host):
    h = host.encode() if isinstance(host, str) else host
    ext = b"\x00\x00"
    ext += struct.pack(">H", len(h) + 5)
    ext += struct.pack(">H", len(h) + 3)
    ext += b"\x00"
    ext += struct.pack(">H", len(h))
    ext += h
    return ext


def _alpn(d):
    if d[6] == "RARE_APLN":
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
                 b"\x06\x73\x70\x64\x79\x2f\x31", b"\x08\x73\x70\x64\x79\x2f\x32\x2e\x30",
                 b"\x08\x73\x70\x64\x79\x2f\x33\x2e\x30", b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    else:
        alpns = [b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39", b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30",
                 b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31", b"\x06\x73\x70\x64\x79\x2f\x31",
                 b"\x08\x73\x70\x64\x79\x2f\x32\x2e\x30", b"\x08\x73\x70\x64\x79\x2f\x33\x2e\x30",
                 b"\x02\x68\x32", b"\x03\x68\x32\x63", b"\x02\x68\x71"]
    if d[4] != "FORWARD":
        alpns = _mung(alpns, d[4])
    blob = b"".join(alpns)
    return b"\x00\x10" + struct.pack(">H", len(blob) + 2) + struct.pack(">H", len(blob)) + blob


def _key_share(d):
    ks = b"\x00\x1d" + b"\x00\x20" + os.urandom(32)
    return b"\x00\x33" + struct.pack(">H", len(ks) + 2) + struct.pack(">H", len(ks)) + ks


def _supported_versions(d, grease):
    if d[7] == "1.2_SUPPORT":
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03"]
    else:
        tls = [b"\x03\x01", b"\x03\x02", b"\x03\x03", b"\x03\x04"]
    if d[8] == "REVERSE":
        tls = tls[::-1]
    vers = _grease() if grease else b""
    for v in tls:
        vers += v
    return b"\x00\x2b" + struct.pack(">H", len(vers) + 1) + struct.pack(">B", len(vers)) + vers


def _jarm_extensions(d):
    grease = d[5] == "GREASE"
    x = b""
    if grease:
        x += _grease() + b"\x00\x00"
    x += _sni(d[0])
    x += b"\x00\x17\x00\x00"                                              # extended_master_secret
    x += b"\x00\x01\x00\x01\x01"                                          # max_fragment_length
    x += b"\xff\x01\x00\x01\x00"                                          # renegotiation_info
    x += b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"      # supported_groups
    x += b"\x00\x0b\x00\x02\x01\x00"                                      # ec_point_formats
    x += b"\x00\x23\x00\x00"                                              # session_ticket
    x += _alpn(d)
    x += (b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03"
          b"\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01")                    # signature_algorithms
    x += _key_share(d)
    x += b"\x00\x2d\x00\x02\x01\x01"                                      # psk_key_exchange_modes
    if d[7] in ("1.2_SUPPORT", "1.3_SUPPORT"):
        x += _supported_versions(d, grease)
    return struct.pack(">H", len(x)) + x


def _jarm_packet(d):
    v = d[2]
    pay = b"\x16"
    if v == "TLS_1.3":
        pay += b"\x03\x01"; ch = b"\x03\x03"
    elif v == "SSLv3":
        pay += b"\x03\x00"; ch = b"\x03\x00"
    elif v == "TLS_1":
        pay += b"\x03\x01"; ch = b"\x03\x01"
    elif v == "TLS_1.1":
        pay += b"\x03\x02"; ch = b"\x03\x02"
    else:
        pay += b"\x03\x03"; ch = b"\x03\x03"
    ch += os.urandom(32)
    sid = os.urandom(32)
    ch += struct.pack(">B", len(sid)) + sid
    ciphers = _jarm_ciphers(d)
    ch += struct.pack(">H", len(ciphers)) + ciphers
    ch += b"\x01\x00"  # compression: len=1, null
    ch += _jarm_extensions(d)
    hs = b"\x01" + b"\x00" + struct.pack(">H", len(ch)) + ch
    return pay + struct.pack(">H", len(hs)) + hs


def _jarm_send(host, port, payload, timeout):
    s = None
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(payload)
        buf = b""
        while len(buf) < 1484:
            try:
                chunk = s.recv(1484 - len(buf))
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) >= 5:
                need = int.from_bytes(buf[3:5], "big") + 5
                if len(buf) >= need:
                    break
        return buf or None
    except Exception:
        return None
    finally:
        try:
            if s:
                s.close()
        except Exception:
            pass


def _find_ext(ext_type, types, values):
    i = 0
    if ext_type == b"\x00\x10":
        while i < len(types):
            if types[i] == ext_type and isinstance(values[i], (bytes, bytearray)):
                return values[i][3:].decode("latin-1", "ignore")
            i += 1
    else:
        while i < len(types):
            if types[i] == ext_type and isinstance(values[i], (bytes, bytearray)):
                return values[i].hex()
            i += 1
    return ""


def _extract_ext(data, counter):
    try:
        if data[counter + 47] == 11:
            return "|"
        if data[counter + 50:counter + 53] == b"\x0e\xac\x0b" or data[82:85] == b"\x0f\xf0\x0b":
            return "|"
        if counter + 42 >= len(data):
            return "|"
        count = 49 + counter
        length = int.from_bytes(data[counter + 47:counter + 49], "big")
        maximum = length + (count - 1)
        types = []
        values = []
        while count < maximum:
            types.append(data[count:count + 2])
            el = int.from_bytes(data[count + 2:count + 4], "big")
            if el == 0:
                count += 4
                values.append("")
            else:
                values.append(data[count + 4:count + 4 + el])
                count += el + 4
        result = str(_find_ext(b"\x00\x10", types, values)) + "|"
        j = 0
        while j < len(types):
            result += types[j].hex()
            j += 1
            if j != len(types):
                result += "-"
        return result
    except IndexError:
        return "|"


def _jarm_read(data):
    try:
        if data is None:
            return "|||"
        if data[0] == 21:  # alert
            return "|||"
        if data[0] == 22 and data[5] == 2:  # handshake / server hello
            counter = data[43]
            selected = data[counter + 44:counter + 46]
            version = data[9:11]
            return selected.hex() + "|" + version.hex() + "|" + _extract_ext(data, counter)
        return "|||"
    except Exception:
        return "|||"


def _cipher_byte(cipher):
    if cipher == "":
        return "00"
    count = 1
    for b in _CIPHER_TABLE:
        if cipher == b.hex():
            break
        count += 1
    hv = hex(count)[2:]
    return hv if len(hv) >= 2 else "0" + hv


def _version_byte(version):
    if version == "":
        return "0"
    return "abcdef"[int(version[3:4])]


def _jarm_hash(raw):
    if raw == ",".join(["|||"] * 10):
        return "0" * 62
    fuzzy = ""
    ext_acc = ""
    for hs in raw.split(","):
        c = hs.split("|")
        while len(c) < 4:
            c.append("")
        fuzzy += _cipher_byte(c[0])
        fuzzy += _version_byte(c[1])
        ext_acc += c[2] + c[3]
    fuzzy += hashlib.sha256(ext_acc.encode()).hexdigest()[0:32]
    return fuzzy


def jarm(host, port=443, timeout=4):
    # spoofable response fp -> use for grouping/drift, never as a trust anchor.
    try:
        res = []
        for d in _jarm_probes(host, port):
            res.append(_jarm_read(_jarm_send(host, port, _jarm_packet(d), timeout)))
        if all(x == "|||" for x in res):
            return None  # no tls
        return _jarm_hash(",".join(res))
    except Exception:
        return None


# --- scan ---

def scan_host(host, ports):
    out = {}
    for p in ports:
        try:
            p = int(p)
        except Exception:
            continue
        f = {}
        if p in TLS_PORTS:
            j = jarm(host, p)
            if j:
                f["jarm"] = j
            c = cert_sha(host, p)
            if c:
                f["cert"] = c
            fv = favicon_hash(host, p, "https")
            if fv is not None:
                f["favicon"] = fv
            h = http_fingerprint(host, p, "https")
            if h:
                f["http"] = h
        elif p in (80, 8080):
            fv = favicon_hash(host, p, "http")
            if fv is not None:
                f["favicon"] = fv
            h = http_fingerprint(host, p, "http")
            if h:
                f["http"] = h
        elif p == 22:
            k = ssh_hostkey(host, p)
            if k:
                f["ssh"] = k
        else:
            h = http_fingerprint(host, p, "https") or http_fingerprint(host, p, "http")
            if h:
                f["http"] = h
        if f:
            out[p] = f
    return out


# --- baseline / drift ---

def _db(path):
    d = os.path.dirname(path)
    if d:
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute(
        "CREATE TABLE IF NOT EXISTS fp_baseline("
        "host TEXT, port INTEGER, fp_type TEXT, value TEXT, "
        "first_seen INTEGER, last_seen INTEGER, accepted INTEGER DEFAULT 0, "
        "PRIMARY KEY(host,port,fp_type))")
    con.commit()
    return con


def _sval(value):
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def baseline_diff(host, port, fp_type, value, db=DEFAULT_DB):
    port = int(port)
    val = _sval(value)
    con = _db(db)
    try:
        row = con.execute(
            "SELECT value,first_seen FROM fp_baseline WHERE host=? AND port=? AND fp_type=?",
            (host, port, fp_type)).fetchone()
        if row is None:
            con.execute(
                "INSERT INTO fp_baseline(host,port,fp_type,value,first_seen,last_seen,accepted) "
                "VALUES(?,?,?,?,strftime('%s','now'),strftime('%s','now'),0)",
                (host, port, fp_type, val))
            con.commit()
            fs = con.execute(
                "SELECT first_seen FROM fp_baseline WHERE host=? AND port=? AND fp_type=?",
                (host, port, fp_type)).fetchone()[0]
            return {"changed": False, "old": None, "new": val, "first_seen": fs}
        old, fs = row[0], row[1]
        if old == val:
            con.execute(
                "UPDATE fp_baseline SET last_seen=strftime('%s','now') "
                "WHERE host=? AND port=? AND fp_type=?", (host, port, fp_type))
            con.commit()
            return {"changed": False, "old": old, "new": val, "first_seen": fs}
        # drift: record new value, un-bless it
        con.execute(
            "UPDATE fp_baseline SET value=?, last_seen=strftime('%s','now'), accepted=0 "
            "WHERE host=? AND port=? AND fp_type=?", (val, host, port, fp_type))
        con.commit()
        return {"changed": True, "old": old, "new": val, "first_seen": fs}
    finally:
        con.close()


def accept_baseline(host, port, fp_type, db=DEFAULT_DB):
    port = int(port)
    con = _db(db)
    try:
        con.execute(
            "UPDATE fp_baseline SET accepted=1, last_seen=strftime('%s','now') "
            "WHERE host=? AND port=? AND fp_type=?", (host, port, fp_type))
        con.commit()
        r = con.execute(
            "SELECT value,accepted,first_seen,last_seen FROM fp_baseline "
            "WHERE host=? AND port=? AND fp_type=?", (host, port, fp_type)).fetchone()
        if not r:
            return None
        return {"host": host, "port": port, "fp_type": fp_type,
                "value": r[0], "accepted": r[1], "first_seen": r[2], "last_seen": r[3]}
    finally:
        con.close()


# --- selftest (offline) ---

def _selftest():
    assert murmur3_32(b"") == 0, "empty vector"
    try:
        import mmh3
        assert murmur3_32(b"hello") == mmh3.hash(b"hello"), "hello vs mmh3"
        assert murmur3_32(b"foo") == mmh3.hash(b"foo"), "foo vs mmh3"
        assert murmur3_32(b"the quick brown fox", 42) == mmh3.hash(b"the quick brown fox", 42), "seed vs mmh3"
    except ImportError:
        # authoritative mmh3 vectors, baked in
        assert murmur3_32(b"hello") == 613153351, "hello vector"
        assert murmur3_32(b"foo") == -156908512, "foo vector"
        assert murmur3_32(b"", 1) == 1364076727, "seed vector"
    # baseline drift on a throwaway db
    tdb = _netdeep_path(".selftest_%d.db" % os.getpid())
    for ext in ("", "-wal", "-shm"):
        try:
            os.remove(tdb + ext)
        except Exception:
            pass
    try:
        r1 = baseline_diff("h", 1, "t", "v1", tdb)
        assert r1["changed"] is False, "first insert"
        r2 = baseline_diff("h", 1, "t", "v2", tdb)
        assert r2["changed"] is True and r2["old"] == "v1" and r2["new"] == "v2", "drift"
        r3 = baseline_diff("h", 1, "t", "v2", tdb)
        assert r3["changed"] is False, "stable"
    finally:
        for ext in ("", "-wal", "-shm"):
            try:
                os.remove(tdb + ext)
            except Exception:
                pass
    # jarm packet builder smoke, no socket
    pkt = _jarm_packet(_jarm_probes("example.com", 443)[0])
    assert isinstance(pkt, (bytes, bytearray)) and len(pkt) > 0, "jarm packet"
    assert pkt[0] == 0x16, "jarm record type"
    print("OK")
    return 0


def _scheme_for(port, scheme):
    if scheme:
        return scheme
    return "https" if int(port) in TLS_PORTS else "http"


def main():
    ap = argparse.ArgumentParser(prog="fingerprint.py")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan")
    sp.add_argument("--host", required=True)
    sp.add_argument("--ports", default="22,80,443,8006")

    pdef = {"favicon": 443, "jarm": 443, "cert": 443, "http": 443, "ssh": 22}
    for name in ("favicon", "jarm", "cert", "http", "ssh"):
        q = sub.add_parser(name)
        q.add_argument("--host", required=True)
        q.add_argument("--port", type=int, default=pdef[name])
        q.add_argument("--scheme", default=None)

    for name in ("diff", "accept"):
        d = sub.add_parser(name)
        d.add_argument("--host", required=True)
        d.add_argument("--port", type=int, required=True)
        d.add_argument("--type", required=True, dest="fptype")
        d.add_argument("--db", default=DEFAULT_DB)
        if name == "diff":
            d.add_argument("--value", required=True)

    args = ap.parse_args()
    if args.selftest:
        raise SystemExit(_selftest())
    if not args.cmd:
        ap.print_help()
        raise SystemExit(2)

    if args.cmd == "scan":
        ports = [x.strip() for x in args.ports.split(",") if x.strip()]
        print(_js(scan_host(args.host, ports)))
    elif args.cmd == "favicon":
        print(_js(favicon_hash(args.host, args.port, _scheme_for(args.port, args.scheme))))
    elif args.cmd == "jarm":
        print(_js(jarm(args.host, args.port)))
    elif args.cmd == "cert":
        print(_js(cert_sha(args.host, args.port)))
    elif args.cmd == "http":
        print(_js(http_fingerprint(args.host, args.port, _scheme_for(args.port, args.scheme))))
    elif args.cmd == "ssh":
        print(_js(ssh_hostkey(args.host, args.port)))
    elif args.cmd == "diff":
        print(_js(baseline_diff(args.host, args.port, args.fptype, args.value, args.db)))
    elif args.cmd == "accept":
        print(_js(accept_baseline(args.host, args.port, args.fptype, args.db)))


if __name__ == "__main__":
    main()
