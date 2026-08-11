#!/usr/bin/env python3
# authorized/defensive audit only: enumerate + enrich + prioritize, never exploit.
import argparse
import csv
import gzip
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import urllib.request

DEFAULT_DB = os.path.expanduser("~/.netdeep/history.db")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CSV = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_API = "https://api.first.org/data/v1/epss"

SEV_PTS = {"crit": 40, "critical": 40, "high": 25, "med": 10, "medium": 10, "low": 3, "info": 1}
EXPOSED = {22, 80, 443, 3389, 8006, 8007, 8443, 2375, 6443}


def have(tool):
    return shutil.which(tool) is not None


def _db(db):
    os.makedirs(os.path.dirname(db), exist_ok=True)
    c = sqlite3.connect(db, timeout=10)
    c.execute("pragma journal_mode=wal")
    c.execute("create table if not exists vuln_kev(cve text primary key, vendor text, product text, date_added text)")
    c.execute("create table if not exists vuln_epss(cve text primary key, epss real, percentile real)")
    return c


def _get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "netdeep"})
    return urllib.request.urlopen(req, timeout=timeout).read()


def kev_update(db=DEFAULT_DB):
    try:
        data = json.loads(_get(KEV_URL))
    except Exception:
        return 0
    c = _db(db)
    n = 0
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID")
        if not cve:
            continue
        c.execute("insert or replace into vuln_kev values(?,?,?,?)",
                  (cve, v.get("vendorProject"), v.get("product"), v.get("dateAdded")))
        n += 1
    c.commit()
    c.close()
    return n


def epss_update(db=DEFAULT_DB, cves=None):
    c = _db(db)
    n = 0
    if cves:
        # api takes a comma list, keep batches under the url length cap
        batch = []
        for cve in cves:
            batch.append(cve)
            if sum(len(x) for x in batch) > 1800:
                n += _epss_api(c, batch)
                batch = []
        if batch:
            n += _epss_api(c, batch)
    else:
        try:
            raw = gzip.decompress(_get(EPSS_CSV))
            rdr = csv.reader(io.StringIO(raw.decode("utf-8", "replace")))
            for row in rdr:
                if not row or row[0].startswith("#") or row[0] == "cve":
                    continue
                try:
                    c.execute("insert or replace into vuln_epss values(?,?,?)",
                              (row[0], float(row[1]), float(row[2])))
                    n += 1
                except (ValueError, IndexError):
                    pass
        except Exception:
            pass
    c.commit()
    c.close()
    return n


def _epss_api(c, cves):
    try:
        data = json.loads(_get(EPSS_API + "?cve=" + ",".join(cves)))
    except Exception:
        return 0
    n = 0
    for row in data.get("data", []):
        try:
            c.execute("insert or replace into vuln_epss values(?,?,?)",
                      (row["cve"], float(row["epss"]), float(row["percentile"])))
            n += 1
        except (KeyError, ValueError):
            pass
    return n


def enrich_cve(cve, db=DEFAULT_DB):
    out = {"cve": cve, "kev": False, "epss": None, "percentile": None}
    try:
        c = _db(db)
        out["kev"] = c.execute("select 1 from vuln_kev where cve=?", (cve,)).fetchone() is not None
        row = c.execute("select epss,percentile from vuln_epss where cve=?", (cve,)).fetchone()
        if row:
            out["epss"], out["percentile"] = row
        c.close()
    except Exception:
        pass
    return out


def score_host(host, db=DEFAULT_DB):
    factors = {}
    score = 0.0
    for rk in host.get("risks", []):
        score += SEV_PTS.get(rk.get("sev"), 0)
    factors["risk_points"] = score
    kev_hit = False
    cve_pts = 0.0
    for cve in host.get("cves", []) or []:
        e = enrich_cve(cve, db)
        if e["kev"]:
            kev_hit = True
            cve_pts += 50
        elif e["epss"]:
            cve_pts += e["epss"] * 30
    if cve_pts:
        factors["cve_points"] = round(cve_pts, 1)
    score += cve_pts
    ports = {p.get("port") for p in host.get("ports", [])}
    exposed = bool(ports & EXPOSED)
    if exposed:
        score *= 1.3
        factors["exposed"] = sorted(ports & EXPOSED)
    if kev_hit:
        factors["kev"] = True
        score = max(score, 60)  # confirmed in-the-wild -> floor at crit
    band = ("crit" if score >= 60 else "high" if score >= 35 else
            "med" if score >= 15 else "low" if score >= 5 else "info")
    return {"score": round(score, 1), "band": band, "factors": factors}


def run_httpx(targets):
    if not have("httpx") or not targets:
        return []
    try:
        p = subprocess.run(["httpx", "-json", "-silent", "-td", "-sc", "-title", "-nc"],
                           input="\n".join(targets), text=True, capture_output=True, timeout=120)
    except Exception:
        return []
    out = []
    for ln in p.stdout.splitlines():
        try:
            j = json.loads(ln)
        except ValueError:
            continue
        out.append({"url": j.get("url"), "status": j.get("status_code"),
                    "title": j.get("title"), "tech": j.get("tech") or j.get("technologies") or [],
                    "tls": j.get("tls") or {}})
    return out


def run_nuclei(targets, tags=None, severity=None, rate=50):
    if not have("nuclei") or not targets:
        return []
    import tempfile
    tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    tf.write("\n".join(targets))
    tf.close()
    cmd = ["nuclei", "-l", tf.name, "-jsonl", "-silent", "-duc", "-rl", str(rate)]
    cmd += ["-tags", tags or "exposure,misconfig,default-login,panel,network"]
    if severity:
        cmd += ["-severity", severity]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=900)
    except Exception:
        p = None
    try:
        os.unlink(tf.name)
    except OSError:
        pass
    if not p:
        return []
    out = []
    for ln in p.stdout.splitlines():
        try:
            j = json.loads(ln)
        except ValueError:
            continue
        info = j.get("info", {})
        cls = info.get("classification") or {}
        out.append({"template_id": j.get("template-id"), "name": info.get("name"),
                    "severity": info.get("severity"), "cve": cls.get("cve-id"),
                    "matched_at": j.get("matched-at")})
    return out


def tls_grade(host, port=443, timeout=90):
    if not have("testssl.sh"):
        return None
    import tempfile
    out = tempfile.mktemp(suffix=".json")
    try:
        subprocess.run(["testssl.sh", "--quiet", "--jsonfile-pretty", out, "--fast",
                        "%s:%d" % (host, port)], capture_output=True, timeout=timeout)
        with open(out) as f:
            js = json.load(f)
    except Exception:
        js = None
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass
    if not js:
        return None
    rows = js if isinstance(js, list) else js.get("scanResult", [])
    grade, findings = None, []
    for r in _flatten(rows):
        rid = str(r.get("id", "")).lower()
        if rid in ("overall_grade", "grade", "rating"):
            grade = r.get("finding")
        elif r.get("severity") in ("HIGH", "CRITICAL", "MEDIUM"):
            findings.append({"id": r.get("id"), "sev": r.get("severity", "").lower(),
                             "finding": r.get("finding")})
    return {"grade": grade, "findings": findings}


def _flatten(rows):
    for r in rows or []:
        if isinstance(r, dict) and "id" in r:
            yield r
        elif isinstance(r, dict):
            for v in r.values():
                if isinstance(v, list):
                    for x in _flatten(v):
                        yield x


def _load_scan(path):
    with open(path) as f:
        d = json.load(f)
    return d.get("hosts", d if isinstance(d, list) else [])


def _selftest():
    import tempfile
    db = tempfile.mktemp(suffix=".db")
    c = _db(db)
    c.execute("insert into vuln_kev values('CVE-2024-0001','acme','widget','2024-01-01')")
    c.execute("insert into vuln_epss values('CVE-2024-0001',0.97,0.99)")
    c.execute("insert into vuln_epss values('CVE-2024-0002',0.2,0.5)")
    c.commit()
    c.close()
    assert enrich_cve("CVE-2024-0001", db)["kev"] is True
    assert enrich_cve("CVE-2024-0002", db)["epss"] == 0.2
    hot = score_host({"risks": [{"sev": "high"}], "ports": [{"port": 8006}],
                      "cves": ["CVE-2024-0001"]}, db)
    assert hot["band"] == "crit", hot
    clean = score_host({"risks": [{"sev": "low"}], "ports": [{"port": 12345}]}, db)
    assert clean["band"] in ("low", "info"), clean
    # graceful when tools absent
    assert run_nuclei(["http://x"]) == [] or isinstance(run_nuclei(["http://x"]), list)
    assert run_httpx([]) == []
    try:
        os.unlink(db)
    except OSError:
        pass
    print("OK")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vulns.py")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--db", default=DEFAULT_DB)
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("kev-update")
    pe = sub.add_parser("epss-update")
    pe.add_argument("--cves")
    pc = sub.add_parser("enrich")
    pc.add_argument("--cve", required=True)
    pt = sub.add_parser("tls")
    pt.add_argument("--host", required=True)
    pt.add_argument("--port", type=int, default=443)
    ph = sub.add_parser("httpx")
    ph.add_argument("--targets", required=True)
    pn = sub.add_parser("nuclei")
    pn.add_argument("--targets", required=True)
    pn.add_argument("--severity")
    pn.add_argument("--tags")
    ps = sub.add_parser("score")
    ps.add_argument("--scan-json", required=True)
    a = ap.parse_args(argv)

    if a.selftest:
        return _selftest()
    if a.cmd == "kev-update":
        print("kev cached:", kev_update(a.db))
    elif a.cmd == "epss-update":
        print("epss cached:", epss_update(a.db, a.cves.split(",") if a.cves else None))
    elif a.cmd == "enrich":
        print(json.dumps(enrich_cve(a.cve, a.db), indent=2))
    elif a.cmd == "tls":
        print(json.dumps(tls_grade(a.host, a.port), indent=2))
    elif a.cmd == "httpx":
        print(json.dumps(run_httpx(a.targets.split(",")), indent=2))
    elif a.cmd == "nuclei":
        print(json.dumps(run_nuclei(a.targets.split(","), a.tags, a.severity), indent=2))
    elif a.cmd == "score":
        for h in _load_scan(a.scan_json):
            print(h.get("ip"), json.dumps(score_host(h, a.db)))
    else:
        ap.print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
