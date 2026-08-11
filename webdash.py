#!/usr/bin/env python3
import argparse, json, os, sqlite3, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# guard the sibling imports; a missing one just degrades a feature
try:
    import analyzer
except Exception:
    analyzer = None
try:
    import query
except Exception:
    query = None
try:
    import topology
except Exception:
    topology = None

DEFAULT_DB = os.path.expanduser("~/.netdeep/history.db")


def load(db, sid):
    if not analyzer:
        return []
    try:
        return analyzer.load_scan(db, sid)
    except Exception:
        return []


def scans(db):
    # read scan table straight; query_only so we never race the scanner's writes
    try:
        con = sqlite3.connect(db, check_same_thread=False)
    except Exception:
        return []
    try:
        con.execute("PRAGMA query_only=1")
        rows = con.execute("SELECT id,started_at,target FROM scan ORDER BY id DESC").fetchall()
        return [{"id": r[0], "started_at": r[1], "target": r[2]} for r in rows]
    except Exception:
        return []  # fresh db: no such table yet
    finally:
        con.close()


def graph(db, sid):
    if not topology:
        return {"nodes": [], "edges": []}
    try:
        return topology.build_graph(load(db, sid))
    except Exception:
        return {"nodes": [], "edges": []}


def filt(hosts, q):
    if not q or not query:
        return hosts
    try:
        cp = getattr(query, "compile_predicate", None)
        if cp:
            f = cp(q)
            return [h for h in hosts if f(h)]
        return [h for h in hosts if query.match(h, q)]
    except Exception:
        return hosts  # bad expr -> don't blank the table


def sid_of(qs):
    v = qs.get("scan", [None])[0]
    if v in (None, "", "latest"):
        return None
    try:
        return int(v)
    except Exception:
        return None


def make_handler(db):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass

        def _json(self, obj, code=200):
            self._send(code, "application/json; charset=utf-8",
                       json.dumps(obj).encode("utf-8"))

        def do_GET(self):
            u = urlparse(self.path)
            p = u.path
            qs = parse_qs(u.query)
            if p == "/":
                self._send(200, "text/html; charset=utf-8", PAGE.encode("utf-8"))
            elif p == "/api/scans.json":
                self._json(scans(db))
            elif p == "/api/hosts.json":
                hosts = load(db, sid_of(qs))
                self._json(filt(hosts, qs.get("q", [""])[0].strip()))
            elif p == "/api/graph.json":
                self._json(graph(db, sid_of(qs)))
            elif p.startswith("/api/host/") and p.endswith(".json"):
                ip = unquote(p[len("/api/host/"):-len(".json")])
                for h in load(db, sid_of(qs)):
                    if h.get("ip") == ip:
                        return self._json(h)
                self._json({"error": "not found"}, 404)
            else:
                self._json({"error": "not found"}, 404)
    return H


def serve(db, host="127.0.0.1", port=8787):
    srv = ThreadingHTTPServer((host, port), make_handler(db))
    print("netdeep webdash -> http://%s:%d  (db %s)" % (host, port, db))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


def selftest():
    import tempfile, urllib.request
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(db))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        for path in ("/api/scans.json", "/api/hosts.json"):
            r = urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=5)
            assert r.status == 200, "%s -> %s" % (path, r.status)
            json.loads(r.read())  # must parse; empty list is fine
    finally:
        srv.shutdown()  # gotcha: must come from a thread other than serve_forever's
        srv.server_close()
        t.join(timeout=5)
    print("OK")


PAGE = """<!doctype html>
<title>netdeep webdash</title>
<style>
:root{--bg:#0b0f0d;--pan:#11161400;--fg:#c9d6cf;--dim:#5f7a6d;--acc:#3fd07a;--warn:#e0603a;--line:#1c2a24;}
*{box-sizing:border-box}
body{margin:0;background:#0b0f0d;color:var(--fg);font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}
header{display:flex;gap:14px;align-items:center;padding:10px 14px;border-bottom:1px solid var(--line);position:sticky;top:0;background:#0b0f0d}
header b{color:var(--acc);letter-spacing:1px}
header .sp{flex:1}
select,input{background:#0f1512;color:var(--fg);border:1px solid var(--line);padding:5px 8px;font:inherit;border-radius:3px}
input{width:240px}
input::placeholder{color:var(--dim)}
#count{color:var(--dim);font-size:12px}
main{display:grid;grid-template-columns:1fr 380px;gap:0}
@media(max-width:820px){main{grid-template-columns:1fr}}
.tbl{overflow:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px}
th{color:var(--dim);font-weight:400;position:sticky;top:0;background:#0b0f0d;border-bottom:1px solid var(--line)}
tbody tr{cursor:pointer}
tbody tr:hover{background:#0f1512}
tr.warn td:first-child{border-left:2px solid var(--warn)}
.ports{color:var(--dim)}
aside{border-left:1px solid var(--line);min-height:calc(100vh - 46px)}
@media(max-width:820px){aside{border-left:none;border-top:1px solid var(--line)}}
svg{width:100%;height:360px;display:block}
.edge{stroke:#243b31;stroke-width:1}
.node{fill:var(--acc);stroke:#0b0f0d;stroke-width:1.5}
.node.gateway{fill:#e0b93a}
.node.switch,.node.uplink,.node.switchport{fill:#4aa3e0}
.node.pvenode,.node.bridge,.node.guest{fill:#b07de0}
.glabel{fill:var(--dim);font:10px ui-monospace,monospace}
#detail{padding:10px 12px;color:var(--dim);font-size:12px;white-space:pre-wrap;word-break:break-word;border-top:1px solid var(--line);max-height:40vh;overflow:auto}
</style>
<header>
  <b>netdeep</b>
  <select id="scan"></select>
  <input id="q" placeholder="filter ( q -> /api/hosts.json?q= )" spellcheck="false">
  <span class="sp"></span>
  <span id="count"></span>
</header>
<main>
  <div class="tbl">
    <table>
      <thead><tr><th>ip</th><th>host</th><th>vendor</th><th>type</th><th>ports</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
  <aside>
    <svg id="g" viewBox="0 0 360 360" preserveAspectRatio="xMidYMid meet"></svg>
    <div id="detail">click a host for detail</div>
  </aside>
</main>
<script>
var scan="", q="", tim=null, scansSig="";
var NS="http://www.w3.org/2000/svg";
// risky/plaintext services -> flag row. purely a client-side hint, no server risk data.
var RISKY={21:1,23:1,25:1,111:1,135:1,139:1,445:1,512:1,513:1,514:1,1433:1,1521:1,3306:1,3389:1,5432:1,5900:1,5901:1,6379:1,9200:1,11211:1,27017:1};

function el(t,txt){var e=document.createElement(t);if(txt!=null)e.textContent=txt;return e;}
function getJSON(u,cb){fetch(u).then(function(r){return r.json();}).then(cb).catch(function(){});}
function fmt(ts){if(!ts)return "";try{return new Date(ts*1000).toLocaleString();}catch(e){return "";}}
function exposed(h){return (h.ports||[]).some(function(p){return RISKY[p.port];});}

function loadScans(){
  getJSON("/api/scans.json",function(rows){
    var sig=rows.map(function(r){return r.id;}).join(",");
    if(sig===scansSig)return;   // dropdown only rebuilds when the set changes
    scansSig=sig;
    var s=document.getElementById("scan"), cur=s.value;
    s.innerHTML="";
    var o=el("option","latest");o.value="";s.appendChild(o);
    rows.forEach(function(r){
      var t="#"+r.id+" "+(r.target||"")+" "+fmt(r.started_at);
      var op=el("option",t);op.value=String(r.id);s.appendChild(op);
    });
    s.value=cur;
  });
}

function loadHosts(){
  var u="/api/hosts.json?scan="+encodeURIComponent(scan)+"&q="+encodeURIComponent(q);
  getJSON(u,function(hosts){
    var tb=document.getElementById("rows");
    tb.innerHTML="";
    document.getElementById("count").textContent=hosts.length+" hosts";
    hosts.forEach(function(h){
      var tr=el("tr");
      tr.appendChild(el("td",h.ip||""));
      tr.appendChild(el("td",h.hostname||""));
      tr.appendChild(el("td",h.vendor||""));
      tr.appendChild(el("td",h.device_type||""));
      var ps=(h.ports||[]).map(function(p){return p.port+"/"+(p.proto||"tcp")+(p.service?" "+p.service:"");}).join("  ");
      var td=el("td",ps);td.className="ports";tr.appendChild(td);
      if(exposed(h))tr.className="warn";
      tr.addEventListener("click",function(){showHost(h.ip);});
      tb.appendChild(tr);
    });
  });
}

function showHost(ip){
  if(!ip)return;
  getJSON("/api/host/"+encodeURIComponent(ip)+".json?scan="+encodeURIComponent(scan),function(h){
    document.getElementById("detail").textContent=JSON.stringify(h,null,2);  // textContent, never innerHTML
  });
}

function drawGraph(nodes,edges){
  var svg=document.getElementById("g");
  while(svg.firstChild)svg.removeChild(svg.firstChild);
  var W=360,H=360,cx=W/2,cy=H/2,R=Math.min(W,H)/2-34,n=nodes.length||1,pos={};
  nodes.forEach(function(nd,i){var a=2*Math.PI*i/n;pos[nd.id]={x:cx+R*Math.cos(a),y:cy+R*Math.sin(a)};});
  edges.forEach(function(e){
    var s=pos[e.src],d=pos[e.dst];if(!s||!d)return;
    var ln=document.createElementNS(NS,"line");
    ln.setAttribute("x1",s.x);ln.setAttribute("y1",s.y);
    ln.setAttribute("x2",d.x);ln.setAttribute("y2",d.y);
    ln.setAttribute("class","edge");svg.appendChild(ln);
  });
  nodes.forEach(function(nd){
    var p=pos[nd.id];if(!p)return;
    var c=document.createElementNS(NS,"circle");
    c.setAttribute("cx",p.x);c.setAttribute("cy",p.y);c.setAttribute("r",6);
    c.setAttribute("class","node "+(nd.type||"host"));svg.appendChild(c);
    var t=document.createElementNS(NS,"text");
    t.setAttribute("x",p.x+8);t.setAttribute("y",p.y+3);t.setAttribute("class","glabel");
    t.textContent=nd.label||nd.id;svg.appendChild(t);
  });
}
function loadGraph(){getJSON("/api/graph.json?scan="+encodeURIComponent(scan),function(g){drawGraph(g.nodes||[],g.edges||[]);});}

function refresh(){loadHosts();loadGraph();}

document.getElementById("scan").addEventListener("change",function(e){scan=e.target.value;refresh();});
document.getElementById("q").addEventListener("input",function(e){
  q=e.target.value;clearTimeout(tim);tim=setTimeout(loadHosts,250);
});

loadScans();refresh();
setInterval(function(){loadScans();refresh();},5000);   // live-ish poll
</script>
"""


def main():
    ap = argparse.ArgumentParser(prog="webdash")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve")
    s.add_argument("--db", default=DEFAULT_DB)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.cmd == "serve":
        return serve(a.db, a.host, a.port)
    ap.print_help()


if __name__ == "__main__":
    main()
