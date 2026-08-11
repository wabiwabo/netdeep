#!/usr/bin/env python3
import argparse, json, os, re, subprocess, tempfile

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOP_RE = re.compile(r"^\s*(\d+)\s")

# q-bridge carries vlan in the index; bridge-mib doesn't. try the richer one first.
OID_QFDB = "1.3.6.1.2.1.17.7.1.2.2.1.2"     # dot1qTpFdbPort  (index = fdbid/vlan + 6 mac octets)
OID_DFDB = "1.3.6.1.2.1.17.4.3.1.2"         # dot1dTpFdbPort  (index = 6 mac octets)
OID_BPORT = "1.3.6.1.2.1.17.1.4.1.2"        # dot1dBasePortIfIndex (bridgeport -> ifindex)
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"       # ifName
OID_IFALIAS = "1.3.6.1.2.1.31.1.1.1.18"     # ifAlias

UPLINK_MIN = 4                              # >=this many macs behind one port = trunk/uplink, not an edge port


def _run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return (p.stdout or b"").decode("utf-8", "replace")
    except Exception:
        return ""


def _which(name):
    dirs = (os.environ.get("PATH") or "").split(os.pathsep)
    for d in dirs + ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]:      # sbin often missing from a gui PATH
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def _mac(s):
    if not s:
        return ""
    parts = re.split(r"[:\-.]", str(s).strip().lower())
    if len(parts) != 6:
        return ""
    try:
        return ":".join("%02x" % int(p, 16) for p in parts)
    except ValueError:
        return ""


# --- snmp fdb ---

def _snmp_tool():
    return _which("snmpbulkwalk") or _which("snmpwalk")


def _walk(tool, host, base, community, timeout):
    base = base.lstrip(".")
    cmd = [tool, "-v2c", "-c", community, "-On", "-Oq", "-t", str(int(timeout)), "-r", "1", host, base]
    out = _run(cmd, timeout=max(10, int(timeout) * 8))
    res = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        parts = ln.split(None, 1)
        oid = parts[0].lstrip(".")
        val = parts[1].strip() if len(parts) > 1 else ""
        if not oid.startswith(base + "."):      # skip banners / error lines
            continue
        try:
            ints = [int(x) for x in oid[len(base) + 1:].split(".")]
        except ValueError:
            continue
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        res.append((ints, val))
    return res


def _bridgeport_map(tool, host, community, timeout):
    m = {}
    for sfx, val in _walk(tool, host, OID_BPORT, community, timeout):
        try:
            m[sfx[-1]] = int(val)
        except (ValueError, IndexError):
            pass
    return m


def _ifnames(tool, host, community, timeout):
    name, alias = {}, {}
    for sfx, val in _walk(tool, host, OID_IFNAME, community, timeout):
        if sfx and val:
            name[sfx[-1]] = val
    for sfx, val in _walk(tool, host, OID_IFALIAS, community, timeout):
        if sfx and val:
            alias[sfx[-1]] = val
    return name, alias


def snmp_fdb(switch, community="public", timeout=2):
    out = []
    tool = _snmp_tool()
    if not tool:
        return out
    try:
        rows = _walk(tool, switch, OID_QFDB, community, timeout)
        qbridge = True
        if not rows:
            rows = _walk(tool, switch, OID_DFDB, community, timeout)
            qbridge = False
        if not rows:
            return out
        b2if = _bridgeport_map(tool, switch, community, timeout)
        ifname, ifalias = _ifnames(tool, switch, community, timeout)
        tmp = []
        for sfx, val in rows:
            try:
                port = int(val)
            except ValueError:
                continue
            if len(sfx) < 6:
                continue
            # index tail is 6 decimal octets of the mac -> hex. q-bridge prefixes the vlan/fdbid.
            macb = sfx[-6:]
            vlan = sfx[0] if (qbridge and len(sfx) >= 7) else None
            mac = ":".join("%02x" % (b & 0xff) for b in macb)
            ifidx = b2if.get(port, port)        # bridge-port != ifindex; fall back to port if unmapped
            nm = ifname.get(ifidx) or ifalias.get(ifidx)
            tmp.append({"mac": mac, "port_ifindex": ifidx, "ifname": nm, "vlan": vlan})
        cnt = {}
        for e in tmp:
            cnt[e["port_ifindex"]] = cnt.get(e["port_ifindex"], 0) + 1
        for e in tmp:
            e["uplink"] = cnt.get(e["port_ifindex"], 0) >= UPLINK_MIN
        out = tmp
    except Exception:
        pass
    return out


# --- traceroute ---

def _parse_trace(out):
    hops = []
    for ln in out.splitlines():
        if not HOP_RE.match(ln):
            continue
        m = IPV4_RE.search(ln)
        hops.append(m.group(0) if m else None)      # '*' -> None, an unknown hop
    return hops


def traceroute_to(target, timeout=3, maxhops=15):
    hops = []
    try:
        if _which("traceroute"):
            cmd = ["traceroute", "-n", "-w1", "-q1", "-m", str(int(maxhops)), target]
        elif _which("tracert"):
            cmd = ["tracert", "-d", "-h", str(int(maxhops)), target]
        else:
            return hops
        out = _run(cmd, timeout=max(8, int(maxhops) + int(timeout) + 2))
        hops = _parse_trace(out)
    except Exception:
        pass
    return hops


# nmap xml is usually our own file, but parse_nmap_traces takes arbitrary input -> kill entities (xxe/billion-laughs).
def _fromstring(data):
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
        import xml.etree.ElementTree as ET
        p = ET.XMLParser()
        ep = getattr(p, "parser", None)         # cpython expat handle
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


def _xml_root(src):
    try:
        if isinstance(src, (bytes, bytearray)):
            return _fromstring(src)
        if isinstance(src, str):
            if "<" in src and ">" in src:
                return _fromstring(src)
            p = os.path.expanduser(src)
            if os.path.exists(p):
                with open(p, "rb") as f:
                    return _fromstring(f.read())
    except Exception:
        pass
    return None


def parse_nmap_traces(nmap_xml):
    res = {}
    root = _xml_root(nmap_xml)
    if root is None:
        return res
    try:
        for host in root.iter("host"):
            tgt = None
            for a in host.findall("address"):
                if a.get("addrtype") == "ipv4":
                    tgt = a.get("addr")
                    break
            if tgt is None:
                a = host.find("address")
                tgt = a.get("addr") if a is not None else None
            tr = host.find("trace")
            if not tgt or tr is None:
                continue
            byttl = {}
            for hop in tr.findall("hop"):
                try:
                    ttl = int(hop.get("ttl"))
                except (TypeError, ValueError):
                    continue
                byttl[ttl] = hop.get("ipaddr") or None
            if not byttl:
                continue
            hi = max(byttl)
            res[tgt] = [byttl.get(i) for i in range(1, hi + 1)]     # ttl gaps -> None, keeps hop distance honest
    except Exception:
        pass
    return res


# --- graph ---

def build_graph(scan_hosts, fdb=None, pve=None, traces=None):
    nodes, edges = {}, {}
    GW = "gateway"

    def node(nid, label, typ, **extra):
        if nid and nid not in nodes:
            d = {"id": nid, "label": label, "type": typ}
            for k, v in extra.items():
                if v:
                    d[k] = v
            nodes[nid] = d

    def edge(s, d, label=""):
        k = (s, d, label)
        if s and d and s != d and k not in edges:
            edges[k] = {"src": s, "dst": d, "label": label}

    node(GW, "gateway", "gateway")

    host_id = {}        # mac and ip -> node id
    hlist = []
    for h in scan_hosts or []:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip")
        mac = _mac(h.get("mac") or "")
        nid = ip or mac
        if not nid:
            continue
        label = ip or mac
        hn = h.get("hostname")
        if hn:
            label = "%s %s" % (label, hn)
        typ = h.get("device_type") or "host"
        node(nid, label, typ, ip=ip, mac=mac, vendor=h.get("vendor"))
        if mac:
            host_id[mac] = nid
        if ip:
            host_id[ip] = nid
        hlist.append(nid)

    attached = set()

    if fdb:
        fmap = fdb if isinstance(fdb, dict) else {"switch": fdb}
        for swid, entries in fmap.items():
            sid = "sw:" + str(swid)
            node(sid, str(swid), "switch")
            edge(GW, sid)
            groups = {}
            for e in entries or []:
                mac = _mac(e.get("mac") or "")
                if not mac:
                    continue
                key = e.get("port_ifindex")
                g = groups.setdefault(key, {"ifname": e.get("ifname"), "vlan": e.get("vlan"),
                                            "uplink": bool(e.get("uplink")), "macs": set()})
                g["macs"].add(mac)
                if e.get("uplink"):
                    g["uplink"] = True
            for key, g in groups.items():
                pid = "%s:p%s" % (sid, key)
                plabel = g["ifname"] or ("if%s" % key)
                if g["uplink"]:
                    # don't cram every mac behind a trunk -> it's another switch, not N edge hosts
                    node(pid, plabel + " (uplink)", "uplink")
                    edge(sid, pid, "trunk")
                    continue
                node(pid, plabel, "switchport")
                edge(sid, pid, g["ifname"] or "")
                vlbl = ("vlan %s" % g["vlan"]) if g["vlan"] not in (None, "") else ""
                for mac in g["macs"]:
                    hid = host_id.get(mac)
                    if hid:
                        edge(pid, hid, vlbl)
                        attached.add(hid)

    if isinstance(pve, dict):
        for cn in (pve.get("cluster") or {}).get("nodes") or []:
            nm = cn.get("node")
            if nm:
                node("pve:" + nm, nm, "pvenode")
                edge(GW, "pve:" + nm)
        for g in pve.get("guests") or []:
            if not isinstance(g, dict):
                continue
            pnid = "pve:" + str(g.get("node"))
            node(pnid, str(g.get("node")), "pvenode")
            edge(GW, pnid)
            br = g.get("bridge") or "vmbr?"
            bid = "%s:%s" % (pnid, br)
            node(bid, br, "bridge")
            edge(pnid, bid)
            gid = None
            for m in g.get("macs") or []:
                gid = host_id.get(_mac(m))
                if gid:
                    break
            if not gid:
                for ip in g.get("ips") or []:
                    gid = host_id.get(ip)
                    if gid:
                        break
            if not gid:
                gid = "vm:%s:%s" % (g.get("node"), g.get("vmid"))
                node(gid, g.get("name") or str(g.get("vmid")), "guest")
            vlbl = ("vlan %s" % g.get("vlan")) if g.get("vlan") not in (None, "") else ""
            edge(bid, gid, vlbl)
            attached.add(gid)

    if isinstance(traces, dict):
        for tgt, hops in traces.items():
            prev = GW
            for i, hop in enumerate(hops or []):
                if hop is None:
                    hid = "hop:%s:%d" % (tgt, i)     # unique per position; two Nones must never share a node
                    node(hid, "*", "unknown")
                else:
                    hid = host_id.get(hop) or ("router:" + hop)
                    if hid not in nodes:
                        node(hid, hop, "router")
                edge(prev, hid)
                prev = hid
            tid = host_id.get(tgt)
            if tid:
                edge(prev, tid)
                attached.add(tid)

    for nid in hlist:       # anything the sources didn't parent hangs straight off the gateway
        if nid not in attached:
            edge(GW, nid)

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


# --- renderers ---

DOT_COLOR = {"gateway": "#f0b0b0", "switch": "#a0c8f0", "switchport": "#b8e0a8",
             "uplink": "#d0b0e0", "pvenode": "#e0c0a0", "bridge": "#a0d8d8",
             "guest": "#e8d0a0", "router": "#d0b0e0", "unknown": "#c8c8c8", "host": "#e6e6e6"}


def _dot_esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _cluster_of(nid):
    if nid.startswith("sw:"):
        return nid.split(":p")[0]
    if nid.startswith("pve:"):
        return "pve:" + nid.split(":")[1]
    return None


def _dot_node(n):
    return '"%s" [label="%s", fillcolor="%s"]' % (
        _dot_esc(n["id"]), _dot_esc(n["label"]), DOT_COLOR.get(n["type"], "#e6e6e6"))


def to_dot(graph):
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    cl, top = {}, []
    for n in nodes:
        c = _cluster_of(n["id"])
        if c:
            cl.setdefault(c, []).append(n)
        else:
            top.append(n)
    out = ["digraph netdeep {", "  rankdir=LR;",
           '  node [shape=box, style="rounded,filled", fontname="monospace", fontsize=10];',
           '  edge [fontname="monospace", fontsize=8, color="#888888"];']
    for n in top:
        out.append("  %s;" % _dot_node(n))
    for i, (c, members) in enumerate(cl.items()):
        head = next((m for m in members if m["id"] == c), None)
        out.append("  subgraph cluster_%d {" % i)
        out.append('    label="%s"; color="#cccccc";' % _dot_esc(head["label"] if head else c))
        for n in members:
            out.append("    %s;" % _dot_node(n))
        out.append("  }")
    for e in edges:
        lbl = (' [label="%s"]' % _dot_esc(e["label"])) if e.get("label") else ""
        out.append('  "%s" -> "%s"%s;' % (_dot_esc(e["src"]), _dot_esc(e["dst"]), lbl))
    out.append("}")
    return "\n".join(out)


def _mm_esc(s):
    return str(s).replace('"', "'").replace("\n", " ").replace("[", "(").replace("]", ")").replace("|", "/")


def to_mermaid(graph):
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    idmap = {}

    def mid(nid):
        if nid not in idmap:
            idmap[nid] = "n%d" % (len(idmap) + 1)
        return idmap[nid]

    out = ["graph TD"]
    for n in nodes:
        out.append('  %s["%s"]' % (mid(n["id"]), _mm_esc(n["label"])))
    for e in edges:
        lbl = _mm_esc(e["label"])
        if lbl:
            out.append("  %s -->|%s| %s" % (mid(e["src"]), lbl, mid(e["dst"])))
        else:
            out.append("  %s --> %s" % (mid(e["src"]), mid(e["dst"])))
    return "\n".join(out)


_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>netdeep topology</title>
<style>
 html,body{margin:0;height:100%;background:#181a1f;color:#abb2bf;font-family:monospace}
 #g{width:100%;height:100vh;display:block}
 #d{position:fixed;top:10px;right:10px;min-width:200px;max-width:320px;background:#21252b;
    border:1px solid #3a3f4b;border-radius:6px;padding:10px;font-size:12px;display:none;word-break:break-all}
 #d b{color:#61afef}
 #h{position:fixed;top:10px;left:12px;font-size:12px;color:#5c6370}
</style></head><body>
<div id="h">netdeep topology &middot; drag nodes &middot; click for detail</div>
<svg id="g" xmlns="http://www.w3.org/2000/svg"></svg>
<div id="d"></div>
<script>
(function(){
 var G = __DATA__;
 var nodes=G.nodes||[], edges=G.edges||[], byId={};
 nodes.forEach(function(n){byId[n.id]=n;});
 var adj={}; nodes.forEach(function(n){adj[n.id]=[];});
 edges.forEach(function(e){ if(byId[e.src]&&byId[e.dst]){adj[e.src].push(e.dst);adj[e.dst].push(e.src);} });
 var indeg={}; nodes.forEach(function(n){indeg[n.id]=0;});
 edges.forEach(function(e){ if(byId[e.dst]) indeg[e.dst]++; });
 var roots=nodes.filter(function(n){return n.type=='gateway'||indeg[n.id]==0;}).map(function(n){return n.id;});
 if(!roots.length&&nodes.length) roots=[nodes[0].id];
 var depth={},q=[]; roots.forEach(function(r){depth[r]=0;q.push(r);});
 while(q.length){var u=q.shift();(adj[u]||[]).forEach(function(v){if(depth[v]==null){depth[v]=depth[u]+1;q.push(v);}});}
 nodes.forEach(function(n){if(depth[n.id]==null)depth[n.id]=0;});
 var layers={}; nodes.forEach(function(n){(layers[depth[n.id]]=layers[depth[n.id]]||[]).push(n);});
 var HG=210,VG=60,PX=90,PY=50,pos={};
 Object.keys(layers).forEach(function(d){layers[d].forEach(function(n,i){pos[n.id]={x:PX+d*HG,y:PY+i*VG};});});
 for(var it=0;it<60;it++){
  nodes.forEach(function(n){var nb=adj[n.id];if(!nb.length)return;var s=0;nb.forEach(function(m){s+=pos[m].y;});
   pos[n.id].y+=((s/nb.length)-pos[n.id].y)*0.25;});
  Object.keys(layers).forEach(function(d){
   var arr=layers[d].slice().sort(function(a,b){return pos[a.id].y-pos[b.id].y;});
   for(var i=1;i<arr.length;i++){if(pos[arr[i].id].y-pos[arr[i-1].id].y<VG)pos[arr[i].id].y=pos[arr[i-1].id].y+VG;}});
 }
 var maxX=0,maxY=0; nodes.forEach(function(n){maxX=Math.max(maxX,pos[n.id].x);maxY=Math.max(maxY,pos[n.id].y);});
 var svg=document.getElementById('g'); svg.setAttribute('viewBox','0 0 '+(maxX+240)+' '+(maxY+120));
 var COL={gateway:'#e06c75',switch:'#61afef',switchport:'#98c379',uplink:'#c678dd',pvenode:'#d19a66',
          bridge:'#56b6c2',guest:'#e5c07b',router:'#c678dd',unknown:'#5c6370',host:'#abb2bf'};
 function el(t){return document.createElementNS('http://www.w3.org/2000/svg',t);}
 var eg=el('g'); svg.appendChild(eg); var lines=[];
 edges.forEach(function(e){ if(!pos[e.src]||!pos[e.dst])return;
  var ln=el('line'); ln.setAttribute('stroke','#3e4451'); ln.setAttribute('stroke-width','1.4'); eg.appendChild(ln);
  var lt=null; if(e.label){lt=el('text');lt.setAttribute('font-size','9');lt.setAttribute('fill','#5c6370');lt.textContent=e.label;eg.appendChild(lt);}
  lines.push({e:e,ln:ln,lt:lt}); });
 function place(){ lines.forEach(function(o){var a=pos[o.e.src],b=pos[o.e.dst];
  o.ln.setAttribute('x1',a.x);o.ln.setAttribute('y1',a.y);o.ln.setAttribute('x2',b.x);o.ln.setAttribute('y2',b.y);
  if(o.lt){o.lt.setAttribute('x',(a.x+b.x)/2);o.lt.setAttribute('y',(a.y+b.y)/2-2);}}); }
 var ng=el('g'); svg.appendChild(ng); var drag=null;
 nodes.forEach(function(n){
  var g=el('g'); g.style.cursor='pointer';
  var w=Math.max(46,(n.label||n.id).length*7+16);
  var r=el('rect'); r.setAttribute('width',w); r.setAttribute('height',26); r.setAttribute('rx',5);
  r.setAttribute('fill',COL[n.type]||'#abb2bf'); r.setAttribute('opacity','0.92');
  var t=el('text'); t.setAttribute('font-size','11'); t.setAttribute('fill','#181a1f'); t.setAttribute('font-family','monospace');
  t.setAttribute('x',8); t.setAttribute('y',17); t.textContent=n.label||n.id;
  g.appendChild(r); g.appendChild(t); ng.appendChild(g);
  function pl(){var p=pos[n.id]; g.setAttribute('transform','translate('+(p.x-w/2)+','+(p.y-13)+')');}
  pl(); n._pl=pl; var moved=false;
  g.addEventListener('mousedown',function(ev){drag=n;moved=false;n._mv=function(){moved=true;};ev.preventDefault();});
  g.addEventListener('click',function(){if(!moved)detail(n);});
 });
 place();
 svg.addEventListener('mousemove',function(ev){ if(!drag)return; var vb=svg.viewBox.baseVal,pt=svg.getBoundingClientRect();
  pos[drag.id]={x:(ev.clientX-pt.left)*vb.width/pt.width,y:(ev.clientY-pt.top)*vb.height/pt.height};
  if(drag._mv)drag._mv(); drag._pl(); place(); });
 window.addEventListener('mouseup',function(){drag=null;});
 function detail(n){ var d=document.getElementById('d'); d.innerHTML='';
  [['id',n.id],['type',n.type],['ip',n.ip||''],['mac',n.mac||''],['vendor',n.vendor||''],['label',n.label||'']].forEach(function(kv){
   if(kv[1]===''&&kv[0]!='id')return; var p=document.createElement('div'); var b=document.createElement('b');
   b.textContent=kv[0]+': '; p.appendChild(b); p.appendChild(document.createTextNode(kv[1])); d.appendChild(p); });
  d.style.display='block'; }
})();
</script></body></html>"""


def _html_doc(graph):
    data = json.dumps(graph).replace("</", "<\\/")      # don't let a label close the script tag
    return _HTML.replace("__DATA__", data)


def to_html(graph, path):
    try:
        with open(os.path.expanduser(path), "w") as f:
            f.write(_html_doc(graph))
        return path
    except Exception:
        return None


# --- cli ---

def _load(path):
    try:
        with open(os.path.expanduser(path)) as f:
            return json.load(f)
    except Exception:
        return None


def _load_scan(path):
    obj = _load(path)
    hosts = obj.get("hosts") if isinstance(obj, dict) else obj
    return [h for h in (hosts or []) if isinstance(h, dict) and h.get("ip")]


def _selftest():
    assert _mac("AA-BB-CC-00-00-01") == "aa:bb:cc:00:00:01"
    assert _mac("1:0:5e:0:0:fb") == "01:00:5e:00:00:fb"

    assert _parse_trace(" 1  192.168.1.1  0.5 ms\n 2  * * *\n 3  8.8.8.8  10 ms\n") == \
        ["192.168.1.1", None, "8.8.8.8"]

    tr = parse_nmap_traces('<nmaprun><host><address addr="8.8.8.8" addrtype="ipv4"/>'
                           '<trace><hop ttl="1" ipaddr="192.168.1.1"/>'
                           '<hop ttl="3" ipaddr="8.8.8.8"/></trace></host></nmaprun>')
    assert tr.get("8.8.8.8") == ["192.168.1.1", None, "8.8.8.8"], tr

    scan = [
        {"ip": "192.168.1.10", "mac": "aa:bb:cc:00:00:01", "vendor": "Dell", "device_type": "server", "hostname": "web01"},
        {"ip": "192.168.1.11", "mac": "aa:bb:cc:00:00:02", "device_type": "printer"},
        {"ip": "192.168.1.12", "mac": "aa:bb:cc:00:00:03"},     # not in fdb -> hangs off gateway
    ]
    fdb = [
        {"mac": "aa:bb:cc:00:00:01", "port_ifindex": 10001, "ifname": "Gi0/1", "vlan": 10, "uplink": False},
        {"mac": "aa:bb:cc:00:00:02", "port_ifindex": 10002, "ifname": "Gi0/2", "vlan": 10, "uplink": False},
        {"mac": "de:ad:00:00:00:01", "port_ifindex": 10048, "ifname": "Gi0/48", "vlan": 1, "uplink": True},
    ]
    g = build_graph(scan, fdb=fdb)
    types = set(n["type"] for n in g["nodes"])
    assert "gateway" in types and "switch" in types and "switchport" in types and "uplink" in types, types
    es = set((e["src"], e["dst"]) for e in g["edges"])
    assert ("gateway", "192.168.1.12") in es, "unmatched host should attach to gateway"
    assert any(s == "sw:switch:p10001" and d == "192.168.1.10" for s, d in es), es

    dot = to_dot(g)
    assert dot and "digraph netdeep" in dot and "192.168.1.10" in dot and "Gi0/1" in dot, "dot"
    mm = to_mermaid(g)
    assert mm and "graph TD" in mm and "192.168.1.10" in mm and "Gi0/1" in mm, "mermaid"

    pve = {"cluster": {"nodes": [{"node": "pve1", "ip": "192.168.1.2"}]},
           "guests": [{"vmid": 101, "name": "web", "node": "pve1", "type": "qemu", "status": "running",
                       "macs": ["aa:bb:cc:00:00:01"], "ips": ["192.168.1.10"], "bridge": "vmbr0", "vlan": 10}]}
    g2 = build_graph(scan, pve=pve)
    assert any(n["type"] == "bridge" for n in g2["nodes"]), "pve bridge"

    g3 = build_graph([], traces={"9.9.9.9": [None, None, "9.9.9.9"]})
    unk = [n for n in g3["nodes"] if n["type"] == "unknown"]
    assert len(unk) == 2, unk       # two None hops must not collapse into one node

    fd, tmp = tempfile.mkstemp(suffix=".html", prefix="netdeep-topo-")
    os.close(fd)
    try:
        assert to_html(g, tmp) == tmp
        with open(tmp) as f:
            doc = f.read()
        assert doc and "<svg" in doc and "</html>" in doc and "192.168.1.10" in doc, "html"
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    print("OK")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    pf = sub.add_parser("fdb")
    pf.add_argument("--switch", required=True)
    pf.add_argument("--community", default="public")

    pg = sub.add_parser("graph")
    pg.add_argument("--scan-json", required=True)
    pg.add_argument("--fdb-json")
    pg.add_argument("--pve-json")
    pg.add_argument("--format", choices=["dot", "mermaid", "html"], default="dot")
    pg.add_argument("--out")

    a = ap.parse_args()

    if a.selftest:
        _selftest()
        return
    if a.cmd == "fdb":
        print(json.dumps(snmp_fdb(a.switch, a.community), indent=2))
    elif a.cmd == "graph":
        scan = _load_scan(a.scan_json)
        fdb = _load(a.fdb_json) if a.fdb_json else None
        pve = _load(a.pve_json) if a.pve_json else None
        g = build_graph(scan, fdb=fdb, pve=pve)
        if a.format == "dot":
            out = to_dot(g)
        elif a.format == "mermaid":
            out = to_mermaid(g)
        else:
            out = _html_doc(g)
        if a.out:
            with open(os.path.expanduser(a.out), "w") as f:
                f.write(out)
            print(a.out)
        else:
            print(out)
    else:
        ap.print_help()
        raise SystemExit(2)


if __name__ == "__main__":
    main()
