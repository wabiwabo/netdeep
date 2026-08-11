# roadmap

Where netdeep is going. Grounded in what's actually buildable on macOS/Linux with
python stdlib first, shelling out to `nmap`/`arp-scan`/`snmpwalk`/`nuclei` when they
buy something, degrading when they're absent. Everything here is for networks you own.

Two primitives underpin most of it — build once, reuse everywhere:

- **fingerprint baseline + diff.** JARM, SSH host-key, cert SHA, favicon, HTTP-tech are
  all stable strings keyed by `(host, port)`. One table, one diff pass → drift alarms.
  A host whose SSH key or TLS stack changes when you didn't touch it is the loudest
  "something is wrong" signal an infra box can give you.
- **query dsl → sql.** `port:8006 seen:<7d type:proxmox risk:high` compiled to
  parameterised SQL. Same compiler feeds the TUI filter, the web dashboard, and MCP.

## shipped

- L2 ARP (mac+vendor) + ARP-cache read + ARP-conflict detection
- L3 discovery, port + service/version (SYN/connect), OS, NSE bundle
- passive: SSDP/UPnP, mDNS, NetBIOS nbstat
- device classification (OUI + port signature), risk flags, CVE hints (`--deep`)
- sqlite history + diff (new/gone hosts, new/closed ports, version drift, first/last seen)
- exports: json / csv / html / markdown / prometheus textfile
- curses TUI: config, live scan, results, detail, stats, sort/filter, WoL, ssh/ping/traceroute, labels
- **wave 1** — proxmox reconciliation (`pve.py`), passive + rogue/ARP-spoof/rogue-DHCP
  detection (`passive.py`), fingerprint drift (`fingerprint.py`), alert fan-out (`alerts.py`)
- **wave 2** — topology map (`topology.py`), vuln scoring + KEV/EPSS + nuclei (`vulns.py`),
  container/BMC probes (`probes.py`)
- **wave 3** — query DSL (`query.py`), web dashboard (`webdash.py`), MCP server (`mcpserver.py`),
  TUI watch mode + sparkline-ready + mouse + DSL filter

## wave 1 — infra-native killers  (shipped)

Zero/near-zero new deps. Aimed straight at the rogue-VM / ARP-conflict class of incident.

- **proxmox reconciliation** (`pve.py`). read-only PVEAuditor token → walk the cluster,
  pull each guest's vNIC mac + live ip, join against the LAN scan. answers:
  which vm owns this ip · which running guest is invisible to the scan · which live ip
  belongs to no guest (rogue / bare-metal). plus quorum/HA/node health. stdlib http.
- **passive + rogue detection** (`passive.py`). bounded listen on ARP/DHCP/mDNS/SSDP to
  catch silent hosts; gateway-mac pin + arp-spoof detection; rogue-DHCP detection;
  new-mac alerting with hypervisor-OUI tagging (`bc:24:11` proxmox, `52:54:00` kvm,
  `00:0c:29`/`00:50:56` vmware). stdlib sockets for the no-root path, tcpdump for L2.
- **fingerprint drift** (`fingerprint.py`). JARM (vendored, stdlib), ssh host-key SHA256,
  cert SHA256. baseline + alert on change. this is the compromise/reimage tripwire.
- **alerting** (`alerts.py`). one `notify()` → ntfy / telegram / slack / discord / webhook /
  macOS `osascript`, and into the prometheus + zabbix you already run. stdlib urllib.

## wave 2 — fleet map & vuln depth  (shipped)

- **topology** (`topology.py`). snmp switch FDB (mac→port→vlan) + merged traceroutes +
  proxmox virtual-L2 → DOT + mermaid (optional self-contained html graph). flat list → map.
- **vuln orchestration** (`vulns.py`). `httpx → nuclei` against discovered web/services,
  local CISA-KEV + EPSS cache joined to every CVE, risk score = cvss×epss×kev×exposure,
  testssl.sh A–F per TLS endpoint. a ranked worklist, not a CVE dump. also: unauth
  container control-plane (docker 2375 / k8s / etcd — root-equiv = critical) and
  BMC/Redfish/IPMI discovery for physical hosts.
- **richer identification.** favicon mmh3 hash + HTTP header/cookie fingerprint
  (`PVEAuthCookie`→proxmox) landed in `fingerprint.py`; WS-Discovery / UPnP / mDNS-TXT
  deep-parse in `passive.py`. still todo: feed those signals back into `classify()` so the
  device_type column gets them for free.

## wave 3 — claude-native + ux  (shipped)

- **query dsl** (`query.py`). the foundational compiler above.
- **mcp server** (`mcpserver.py`). expose the sqlite over MCP so Claude Code answers
  "what changed on the lan today / which hosts expose unauth services / find the new device".
- **web dashboard** (`webdash.py`). `serve` mode on stdlib http.server: inventory, timeline,
  topology graph, off the existing db. leave it open on a second monitor.
- **tui next** watch/live mode, per-host latency sparklines, fuzzy search, mouse sort.
- **exports+** grafana dashboard json, ansible inventory, launchd watch daemon, VHS demo gif.

## deps, honestly

killer tier is cheap: pve/passive/fingerprint/alerts/topology/containers/bmc/grafana/ansible
need only what's already installed (`curl`/`socket`/`snmpwalk`/`tcpdump`). the only real
adds are `nuclei`+`httpx` (brew) for wave 2 vuln depth and the `mcp` sdk (pip) for wave 3.
passive L2 sniff and some snmp paths want root — same degrade-without-root contract as today.

## non-goals

no exploitation — enumerate and enrich, never fire exploits. default-cred checks stay
opt-in, rate-limited, curated (verify, don't brute). no DHCP passive snooping daemon
(needs a mirror port; low yield vs arp+mdns). no textual rewrite — curses stays.
