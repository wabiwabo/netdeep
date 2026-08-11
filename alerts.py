#!/usr/bin/env python3
# netdeep alerts: notify fan-out + zabbix/grafana/ansible/prom exports
# usage: alerts.py {test,grafana,ansible,lld} ... | alerts.py --selftest

import argparse, json, os, subprocess, sys, tempfile
import urllib.request

CFG = "~/.netdeep/alerts.json"
HTTP_TIMEOUT = 6

PRIO = {"crit": "5", "high": "4", "med": "3", "low": "2", "info": "1"}
TAGS = {"crit": "skull", "high": "warning", "med": "bell",
        "low": "speech_balloon", "info": "information_source"}


def load_config(path=None):
    # file wins, then env
    p = os.path.expanduser(path or CFG)
    if os.path.isfile(p):
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            pass
    return _env_config()


def _env_config():
    g = os.environ.get
    c = {}
    if g("NETDEEP_NTFY_TOPIC"):
        c["ntfy"] = {"server": g("NETDEEP_NTFY_SERVER", "https://ntfy.sh"),
                     "topic": g("NETDEEP_NTFY_TOPIC"),
                     "token": g("NETDEEP_NTFY_TOKEN", "")}
    if g("NETDEEP_TG_TOKEN") and g("NETDEEP_TG_CHAT"):
        c["telegram"] = {"token": g("NETDEEP_TG_TOKEN"), "chat_id": g("NETDEEP_TG_CHAT")}
    if g("NETDEEP_SLACK_WEBHOOK"):
        c["slack"] = {"webhook": g("NETDEEP_SLACK_WEBHOOK")}
    if g("NETDEEP_DISCORD_WEBHOOK"):
        c["discord"] = {"webhook": g("NETDEEP_DISCORD_WEBHOOK")}
    if g("NETDEEP_WEBHOOK"):
        c["webhook"] = {"url": g("NETDEEP_WEBHOOK")}
    if g("NETDEEP_MACOS"):
        c["macos"] = g("NETDEEP_MACOS").lower() not in ("0", "false", "no", "")
    if g("NETDEEP_ZBX_SERVER"):
        c["zabbix"] = {"server": g("NETDEEP_ZBX_SERVER"),
                       "port": int(g("NETDEEP_ZBX_PORT", "10051")),
                       "host": g("NETDEEP_ZBX_HOST", "netdeep-collector")}
    return c


def _b(x):
    return ("" if x is None else str(x)).encode()


def _h(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _ntfy_req(cfg, sev, title, body, url):
    base = (cfg.get("server") or "https://ntfy.sh").rstrip("/")
    u = base + "/" + (cfg.get("topic") or "")
    req = urllib.request.Request(u, data=_b(body), method="POST")
    req.add_header("Title", str(title or "").replace("\n", " "))  # ntfy Title is single-line
    req.add_header("Priority", PRIO.get(sev, "3"))
    req.add_header("Tags", TAGS.get(sev, "bell"))
    if url:
        req.add_header("Click", url)
    tok = cfg.get("token")
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    return req


def _telegram_req(cfg, title, body):
    u = "https://api.telegram.org/bot" + (cfg.get("token") or "") + "/sendMessage"
    text = "<b>" + _h(title) + "</b>\n" + _h(body)
    payload = {"chat_id": cfg.get("chat_id"), "text": text, "parse_mode": "HTML"}
    req = urllib.request.Request(u, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    return req


def _slack_req(cfg, sev, title, body, url):
    txt = "*[%s]* %s\n%s" % (sev.upper(), title, body)
    if url:
        txt += "\n" + url
    req = urllib.request.Request(cfg.get("webhook"), data=json.dumps({"text": txt}).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    return req


def _discord_req(cfg, sev, title, body, url):
    txt = "**[%s]** %s\n%s" % (sev.upper(), title, body)
    if url:
        txt += "\n" + url
    req = urllib.request.Request(cfg.get("webhook"), data=json.dumps({"content": txt}).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    return req


def _webhook_req(cfg, sev, title, body, url):
    payload = {"severity": sev, "title": title, "body": body, "url": url}
    req = urllib.request.Request(cfg.get("url"), data=json.dumps(payload).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    return req


def _post(req):
    try:
        r = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
        try:
            r.read()
        finally:
            r.close()
        return (True, None)
    except Exception as e:
        return (False, str(e))


def _osa(s):
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _macos_notify(title, body):
    try:
        s = "display notification %s with title %s" % (_osa(body), _osa(title))
        subprocess.run(["osascript", "-e", s], timeout=HTTP_TIMEOUT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return (True, None)
    except Exception as e:
        return (False, str(e))


def notify(severity, title, body, url=None, config=None):
    cfg = config or load_config()
    out = []
    n = cfg.get("ntfy") or {}
    if n.get("topic"):
        out.append(("ntfy",) + _post(_ntfy_req(n, severity, title, body, url)))
    tg = cfg.get("telegram") or {}
    if tg.get("token") and tg.get("chat_id"):
        out.append(("telegram",) + _post(_telegram_req(tg, title, body)))
    sl = cfg.get("slack") or {}
    if sl.get("webhook"):
        out.append(("slack",) + _post(_slack_req(sl, severity, title, body, url)))
    dc = cfg.get("discord") or {}
    if dc.get("webhook"):
        out.append(("discord",) + _post(_discord_req(dc, severity, title, body, url)))
    wh = cfg.get("webhook") or {}
    if wh.get("url"):
        out.append(("webhook",) + _post(_webhook_req(wh, severity, title, body, url)))
    if cfg.get("macos") and sys.platform == "darwin":  # osascript only on darwin
        out.append(("macos",) + _macos_notify(title, body))
    return out


def zabbix_lld(hosts):
    out = []
    for h in hosts or []:
        out.append({
            "{#IP}": h.get("ip", ""),
            "{#MAC}": h.get("mac", ""),
            "{#DNS}": h.get("dns") or h.get("hostname") or "",
            "{#VENDOR}": h.get("vendor", ""),
            "{#TYPE}": h.get("device_type") or h.get("type") or "",
        })
    return out


def zabbix_send(config, key, value):
    zbx = (config or {}).get("zabbix") or {}
    sender = _which("zabbix_sender")
    if not sender:
        return (None, "no zabbix_sender")
    cmd = [sender, "-z", zbx.get("server", ""), "-p", str(zbx.get("port", 10051)),
           "-s", zbx.get("host", "netdeep-collector"), "-k", key, "-o", str(value)]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=15)
        if p.returncode == 0:
            return (True, None)
        return (False, (p.stderr or b"").decode("utf-8", "replace").strip())
    except Exception as e:
        return (False, str(e))


def _which(name):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        f = os.path.join(d, name)
        if os.path.isfile(f) and os.access(f, os.X_OK):
            return f
    return None


def _grafana_model():
    ds = {"type": "prometheus", "uid": "${DS_PROM}"}
    panels = [
        {"id": 1, "type": "stat", "title": "hosts up / total", "datasource": ds,
         "gridPos": {"h": 5, "w": 6, "x": 0, "y": 0},
         "targets": [
             {"refId": "A", "datasource": ds, "expr": "sum(netscan_host_up)", "legendFormat": "up"},
             {"refId": "B", "datasource": ds, "expr": "count(netscan_host_up)", "legendFormat": "total"}],
         "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "none"},
         "fieldConfig": {"defaults": {"unit": "short"}, "overrides": []}},
        {"id": 2, "type": "stat", "title": "scan freshness", "datasource": ds,
         "gridPos": {"h": 5, "w": 6, "x": 6, "y": 0},
         "targets": [
             {"refId": "A", "datasource": ds, "expr": "time() - max(netscan_last_scan_timestamp_seconds)"}],
         "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "background", "graphMode": "none"},
         "fieldConfig": {"defaults": {"unit": "s", "thresholds": {"mode": "absolute", "steps": [
             {"color": "green", "value": None}, {"color": "yellow", "value": 900},
             {"color": "red", "value": 3600}]}}, "overrides": []}},
        {"id": 3, "type": "state-timeline", "title": "open ports", "datasource": ds,
         "gridPos": {"h": 10, "w": 12, "x": 12, "y": 0},
         "targets": [
             {"refId": "A", "datasource": ds, "expr": "netscan_port_open", "legendFormat": "{{ip}}:{{port}}"}],
         "options": {"showValue": "never", "mergeValues": True, "alignValue": "left"},
         "fieldConfig": {"defaults": {"custom": {"fillOpacity": 80, "lineWidth": 0}}, "overrides": []}},
        {"id": 4, "type": "table", "title": "inventory", "datasource": ds,
         "gridPos": {"h": 12, "w": 24, "x": 0, "y": 10},
         "targets": [
             {"refId": "A", "datasource": ds, "expr": "netscan_host_info", "format": "table", "instant": True}],
         "transformations": [
             {"id": "labelsToFields", "options": {"mode": "columns"}},
             {"id": "organize", "options": {"excludeByName": {
                 "Time": True, "Value": True, "__name__": True, "job": True, "instance": True}}}],
         "options": {"showHeader": True}},
    ]
    return {
        "id": None,
        "uid": "netdeep-netscan",
        "title": "netdeep / netscan",
        "tags": ["netdeep", "netscan"],
        "schemaVersion": 39,
        "version": 0,
        "editable": True,
        "graphTooltip": 0,
        "refresh": "1m",
        "timezone": "",
        "time": {"from": "now-24h", "to": "now"},
        "annotations": {"list": []},
        "templating": {"list": [
            {"name": "DS_PROM", "label": "Prometheus", "type": "datasource",
             "query": "prometheus", "refresh": 1, "hide": 0, "current": {}, "options": []}]},
        "panels": panels,
    }


def grafana_dashboard(path):
    with open(path, "w") as f:
        json.dump(_grafana_model(), f, indent=2)
        f.write("\n")
    return path


def _slug(s):
    s = str(s).strip().lower()
    out = "".join(c if (c.isalnum() or c in "-_.") else "-" for c in s)
    return out or "unknown"


def _hostkey(h):
    return _slug(h.get("hostname") or h.get("dns") or h.get("ip") or "host")


def _yq(s):
    s = "" if s is None else str(s)
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _yaml_inv(hosts):
    groups = {}
    for h in hosts or []:
        g = _slug(h.get("device_type") or h.get("type") or "unknown")
        groups.setdefault(g, []).append(h)
    lines = ["all:", "  children:"]
    for g in sorted(groups):
        lines.append("    %s:" % g)
        lines.append("      hosts:")
        for h in groups[g]:
            lines.append("        %s:" % _hostkey(h))
            lines.append("          ansible_host: %s" % _yq(h.get("ip", "")))
            lines.append("          netdeep_mac: %s" % _yq(h.get("mac", "")))
            lines.append("          netdeep_vendor: %s" % _yq(h.get("vendor", "")))
            lines.append("          netdeep_type: %s" % _yq(h.get("device_type") or h.get("type") or ""))
    return "\n".join(lines) + "\n"


def _json_inv(hosts):
    groups = {}
    meta = {}
    for h in hosts or []:
        g = _slug(h.get("device_type") or h.get("type") or "unknown")
        name = _hostkey(h)
        groups.setdefault(g, {"hosts": []})["hosts"].append(name)
        meta[name] = {
            "ansible_host": h.get("ip", ""),
            "netdeep_mac": h.get("mac", ""),
            "netdeep_vendor": h.get("vendor", ""),
            "netdeep_type": h.get("device_type") or h.get("type") or "",
        }
    groups["_meta"] = {"hostvars": meta}
    return groups


def ansible_inventory(hosts, path, fmt="yaml"):
    if fmt == "json":
        data = json.dumps(_json_inv(hosts), indent=2) + "\n"
    else:
        data = _yaml_inv(hosts)
    _write_private(path, data)  # 0600: inventory leaks topology + hostnames
    return path


def _write_private(path, data):
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, 0o700)
        except Exception:
            pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data.encode())
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)  # force it, umask may have clipped the create mode
    except Exception:
        pass


def _pq(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _pnum(v):
    try:
        return "%g" % float(v)
    except Exception:
        return "1"


def prom_alert_textfile(events, path):
    lines = ["# HELP netscan_alert active netdeep scan alert (1=firing)",
             "# TYPE netscan_alert gauge"]
    for e in events or []:
        lines.append('netscan_alert{ip="%s",severity="%s"} %s' % (
            _pq(e.get("ip", "")), _pq(e.get("severity", "info")), _pnum(e.get("value", 1))))
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)  # atomic: collector must never read a half-written file
    return path


def _load_scan(path):
    with open(path) as f:
        d = json.load(f)
    if isinstance(d, dict):
        return d.get("hosts") or d.get("results") or []
    return d


def _selftest():
    nreq = _ntfy_req({"server": "https://ntfy.example/", "topic": "netdeep", "token": "tok123"},
                     "crit", "host down", "gw 192.168.1.1 unreachable", "https://grafana/d/x")
    assert nreq.get_full_url() == "https://ntfy.example/netdeep", nreq.get_full_url()
    assert nreq.get_method() == "POST"
    nh = {k.lower(): v for k, v in nreq.header_items()}
    assert nh["title"] == "host down", nh
    assert nh["priority"] == "5", nh
    assert nh["tags"] == "skull", nh
    assert nh["click"] == "https://grafana/d/x", nh
    assert nh["authorization"] == "Bearer tok123", nh
    assert nreq.data == b"gw 192.168.1.1 unreachable"

    treq = _telegram_req({"token": "123456:AA-BB", "chat_id": "987"}, "host down", "gw down")
    assert treq.get_full_url() == "https://api.telegram.org/bot123456:AA-BB/sendMessage", treq.get_full_url()
    assert treq.get_method() == "POST"
    th = {k.lower(): v for k, v in treq.header_items()}
    assert th["content-type"] == "application/json", th
    tp = json.loads(treq.data.decode())
    assert tp["chat_id"] == "987", tp
    assert tp["parse_mode"] == "HTML", tp
    assert "host down" in tp["text"], tp

    d = tempfile.mkdtemp(prefix="netdeep-selftest-")
    hosts = [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:00:11:22", "vendor": "MikroTik",
         "device_type": "router", "hostname": "gw"},
        {"ip": "192.168.1.20", "mac": "de:ad:be:ef:00:01", "vendor": "Ubiquiti",
         "device_type": "switch"},
    ]

    gp = os.path.join(d, "dash.json")
    grafana_dashboard(gp)
    with open(gp) as f:
        m = json.load(f)
    assert m["id"] is None
    assert m["uid"] == "netdeep-netscan"
    assert "DS_PROM" in [v["name"] for v in m["templating"]["list"]]
    exprs = " ".join(t.get("expr", "") for p in m["panels"] for t in p.get("targets", []))
    for k in ("netscan_host_info", "netscan_host_up", "netscan_last_scan_timestamp_seconds"):
        assert k in exprs, k

    yp = os.path.join(d, "hosts.yml")
    ansible_inventory(hosts, yp, fmt="yaml")
    assert (os.stat(yp).st_mode & 0o777) == 0o600, oct(os.stat(yp).st_mode)
    y = open(yp).read()
    assert 'ansible_host: "192.168.1.1"' in y, y
    assert "router:" in y and "switch:" in y
    assert 'netdeep_vendor: "MikroTik"' in y

    jp = os.path.join(d, "hosts.json")
    ansible_inventory(hosts, jp, fmt="json")
    with open(jp) as f:
        ji = json.load(f)
    assert "_meta" in ji and "hostvars" in ji["_meta"]
    assert "router" in ji and "switch" in ji

    lld = zabbix_lld(hosts)
    assert isinstance(lld, list) and lld and lld[0]["{#IP}"] == "192.168.1.1"

    pp = os.path.join(d, "alerts.prom")
    prom_alert_textfile([{"ip": "192.168.1.1", "severity": "crit"}], pp)
    pt = open(pp).read()
    assert 'netscan_alert{ip="192.168.1.1",severity="crit"} 1' in pt, pt

    print("OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="alerts.py")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    ptest = sub.add_parser("test")
    ptest.add_argument("--config")

    pgraf = sub.add_parser("grafana")
    pgraf.add_argument("--out", required=True)

    pans = sub.add_parser("ansible")
    pans.add_argument("--scan-json", required=True)
    pans.add_argument("--out", required=True)
    pans.add_argument("--format", default="yaml", choices=["yaml", "json"])

    plld = sub.add_parser("lld")
    plld.add_argument("--scan-json", required=True)

    pfs = sub.add_parser("fromscan")
    pfs.add_argument("--scan-json", required=True)
    pfs.add_argument("--config")
    pfs.add_argument("--min-sev", default="high")

    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()

    if args.cmd == "test":
        cfg = load_config(args.config) if args.config else None
        res = notify("high", "netdeep test", "test alert from alerts.py",
                     url="https://ntfy.sh", config=cfg)
        if not res:
            print("no transports configured (check ~/.netdeep/alerts.json or env)")
            return 1
        for name, ok, err in res:
            print("%-9s %-4s %s" % (name, "ok" if ok else "FAIL", err or ""))
        return 0 if all(ok for _, ok, _ in res) else 1

    if args.cmd == "grafana":
        grafana_dashboard(args.out)
        print("wrote", args.out)
        return 0

    if args.cmd == "ansible":
        hosts = _load_scan(args.scan_json)
        ansible_inventory(hosts, args.out, fmt=args.format)
        print("wrote %s (%d hosts, %s)" % (args.out, len(hosts), args.format))
        return 0

    if args.cmd == "lld":
        hosts = _load_scan(args.scan_json)
        print(json.dumps(zabbix_lld(hosts), indent=2))
        return 0

    if args.cmd == "fromscan":
        with open(args.scan_json) as f:
            data = json.load(f)
        hosts = data.get("hosts", data if isinstance(data, list) else [])
        ch = data.get("changes", {}) if isinstance(data, dict) else {}
        new_hosts = ch.get("new_hosts", [])
        order = {"crit": 4, "high": 3, "med": 2, "low": 1, "info": 0}
        thr = order.get(args.min_sev, 3)
        hot = [(rk.get("sev"), h.get("ip"), rk.get("msg"))
               for h in hosts for rk in h.get("risks", [])
               if order.get(rk.get("sev"), 0) >= thr]
        if not new_hosts and not hot:
            print("nothing to alert")
            return 0
        lines = []
        if new_hosts:
            lines.append("new hosts: " + ", ".join(new_hosts))
        lines += ["[%s] %s %s" % (s, ip, m) for s, ip, m in hot]
        sev = "crit" if any(s == "crit" for s, _, _ in hot) else "high"
        tgt = data.get("meta", {}).get("target", "") if isinstance(data, dict) else ""
        cfg = load_config(args.config) if args.config else None
        res = notify(sev, "netdeep: %d finding(s) on %s" % (len(hot), tgt),
                     "\n".join(lines), config=cfg)
        if not res:
            print("no transports configured")
            return 0
        for name, ok, err in res:
            print("%-9s %-4s %s" % (name, "ok" if ok else "FAIL", err or ""))
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
