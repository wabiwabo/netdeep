# netdeep

Network recon for LANs you own — homelabs, Proxmox fleets, the rack in the closet.
Layer-2 + layer-3 host discovery, port/service/version scanning, device classification,
risk flags, and scan history you can diff over time. Wraps `nmap`/`arp-scan`/`masscan`
when they're around, degrades gracefully when they're not.

## what's here

- `netdeep.sh` — orchestrator. discovers hosts (ARP + ping/SYN), scans ports, grabs
  service/version, hands results to the analyzer.
- `analyzer.py` — consolidates a run: classification, risk flags, sqlite history + diff,
  and exports (json/csv/html/markdown/prometheus). stdlib only.
- `netdeep-tui.py` — curses front-end. config form, live scan, results table with
  drill-down, wake-on-lan, ssh/ping/traceroute, labels, watch mode, exports.
- `fingerprint.py` — JARM, ssh host-key, cert, favicon, http/cookie fingerprints, with
  baseline drift (a key or TLS stack that changes when you didn't touch it = red flag).
- `passive.py` — passive listen (arp/mdns/ssdp/ws-discovery), gateway-MAC pin, ARP-spoof,
  rogue-DHCP, new-MAC + hypervisor-OUI tagging (a stray `bc:24:11`/`52:54:00` = a new VM).
- `pve.py` — Proxmox reconciliation. which VM owns this IP, which guest is invisible,
  which live IP belongs to no guest at all.
- `probes.py` — read-only container (docker/k8s/etcd/nomad/consul) + BMC/redfish/ipmi checks.
- `vulns.py` — CISA-KEV + EPSS cache, risk scoring, nuclei/httpx/testssl orchestration.
- `topology.py` — SNMP switch FDB + traceroute merge → DOT / mermaid / self-contained html map.
- `alerts.py` — ntfy/telegram/slack/discord/webhook/macOS fan-out + zabbix/grafana/ansible.
- `query.py` — filter DSL (`port:8006 type:proxmox risk:high seen:<7d`) shared by TUI/dash/mcp.
- `webdash.py` — `serve` mode, a self-contained web dashboard off the sqlite history.
- `mcpserver.py` — MCP server so Claude can answer "what changed on the LAN today".
- `scan-8006.sh` — the dumb one-off. sweep a subnet for a single open port. no deps but `nc`.

## requirements

- macOS or Linux, `bash`, `python3` (stdlib only — no pip, no venv).
- for full depth: `brew install nmap arp-scan masscan` (or your distro's packages).
- **root**: arp-scan, SYN scans, OS detection, and masscan all need it — run under `sudo`.
  without root, netdeep falls back to a plain TCP connect scan and skips L2/OS.

## quickstart

```bash
sudo ./netdeep.sh              # auto-detect your /24, discover + scan
sudo ./netdeep-tui.py         # same power, curses UI
```

No sudo? It still runs, just shallower:

```bash
./netdeep.sh                  # TCP connect scan, no ARP/OS
```

## scanning specific ports

`-p` takes a single port, a list, a range, or a named preset. Give the target as a
trailing CIDR/host (defaults to your local /24).

```bash
./netdeep.sh -p 8006 192.168.1.0/24     # just Proxmox web UI across the subnet
./netdeep.sh -p 22,443                   # list
./netdeep.sh -p 8000-8100                # range
./netdeep.sh -p proxmox 10.0.0.0/24      # preset
```

presets:

| preset    | covers |
|-----------|--------|
| `fast`    | a handful of the usual suspects, quick sweep |
| `top`     | nmap top-1000 |
| `infra`   | ssh/dns/snmp/ntp/ipmi/redis/mongo/etc — infra ports |
| `web`     | 80/443/8080/8443 and friends |
| `proxmox` | 8006 + 22 + 3128 + ceph/corosync bits |
| `all`     | 1-65535. bring coffee. |

## options

| flag         | what |
|--------------|------|
| `-p PORTS`   | port, list (`22,443`), range (`8000-8100`), or preset |
| `--deep`     | CVE hints via nmap `vulners` (slow, needs nmap) |
| `--ssdp`     | passive: SSDP/UPnP discovery |
| `--mdns`     | passive: mDNS/Bonjour discovery |
| `--netbios`  | passive: NetBIOS name query |
| `--fingerprint` | JARM/ssh-key/cert/favicon/http fingerprints + drift alarms |
| `--rogue`    | ARP-spoof, rogue-DHCP, new-MAC + hypervisor-OUI detection |
| `--vuln`     | container/BMC probes + KEV/EPSS-weighted risk score per host |
| `--topo FMT` | write a topology map (`dot`/`mermaid`/`html`), with `--topo-out FILE` |
| `--pve NODE --pve-token T` | reconcile a Proxmox cluster against the scan |
| `--alert`    | fire ntfy/telegram/etc on new hosts + high/crit risks |
| `[target]`   | trailing CIDR or host. omit for auto /24. |

Passive discovery also reads the local ARP cache to surface silent hosts and flags
ARP conflicts (two MACs, one IP — someone's spoofing or you've got a dup).

## what it finds

- **L2 ARP** — MAC + vendor lookup, catches hosts that don't answer ping.
- **passive** — SSDP/mDNS/NetBIOS + ARP-cache read, ARP-conflict detection.
- **classification** — router, hypervisor, NAS, printer, camera, phone, etc.
- **risk flags** — unauth redis/mongo/docker/elasticsearch, telnet, open SMB /
  MS17-010 (EternalBlue), exposed RDP, self-signed / expired TLS certs.
- **CVE hints** — `--deep` runs nmap vulners against detected versions.
- **history** — every run lands in sqlite. `analyzer.py diff` shows what changed
  (new hosts, closed ports, new services) since last time.

## going deeper

```bash
# fingerprint drift — baseline the fleet, get told when an ssh key or TLS stack changes
sudo ./netdeep.sh -p infra --fingerprint 192.168.1.0/24

# rogue hunt — new/unknown MACs, ARP-spoof, rogue DHCP, stray VM MACs
sudo ./netdeep.sh --rogue

# risk scoring — container/BMC exposure + KEV/EPSS-weighted score per host
sudo ./netdeep.sh -p infra --vuln
./vulns.py kev-update && ./vulns.py epss-update      # refresh the intel cache (cron it)

# topology map straight out of the scan (+ SNMP FDB if you feed it a switch)
sudo ./netdeep.sh --topo mermaid --topo-out lan.mmd
./topology.py fdb --switch 192.168.1.1 --community public

# proxmox: which VM owns that mystery IP, which guest is invisible, which IP is nobody's
./pve.py reconcile --node 192.168.1.10 --token 'root@pam!scan=SECRET' --scan-json last.json
```

## ask claude (mcp)

Point Claude Code at the scan history and ask it things in plain english —
"what changed on the LAN today", "which hosts expose unauth services", "find the new device".

```bash
pip install mcp
claude mcp add netdeep -e NETDEEP_DB=$HOME/.netdeep/history.db -- python3 $PWD/mcpserver.py
```

## web dashboard

```bash
./webdash.py serve                   # http://127.0.0.1:8787, live off the sqlite
```

## alerts

Drop `~/.netdeep/alerts.json` (`ntfy`/`telegram`/`slack`/`discord`/`webhook`/`macos`/`zabbix`),
then `--alert` pushes on new hosts + high/crit findings. Feeds your existing Prometheus/Zabbix too.

```bash
./alerts.py test                     # verify your transports
sudo ./netdeep.sh -p infra --rogue --vuln --alert
```

## history + diff

```bash
sudo ./netdeep.sh -p infra          # run, results stored
./analyzer.py diff                   # what changed vs the previous run
./query.py test --expr "port:8006 type:proxmox risk:high" --scan-json last.json
```

## exports

```bash
./analyzer.py --export json  > net.json
./analyzer.py --export csv   > net.csv
./analyzer.py --export html  > net.html
./analyzer.py --export markdown > net.md
```

Prometheus textfile for node_exporter — drop it in the collector dir on a cron and
graph your attack surface:

```bash
*/15 * * * * cd /opt/netdeep && sudo ./netdeep.sh -p infra >/dev/null 2>&1 \
  && ./analyzer.py --export prometheus > /var/lib/node_exporter/textfile_collector/netdeep.prom
```

## TUI

```bash
sudo ./netdeep-tui.py
```

| key       | does |
|-----------|------|
| `c`       | open config form (target, ports, options) |
| `s`       | start scan |
| `x`       | stop scan |
| `↑ ↓`     | move in results table |
| `enter`   | drill into selected host |
| `/`       | filter |
| `l`       | label / rename host |
| `w`       | wake-on-lan the selected host |
| `p`       | ping |
| `t`       | traceroute |
| `g`       | ssh to host |
| `W`       | watch mode — auto-rescan on an interval |
| `V`       | stats panel |
| `e`       | export menu |
| `r`       | rescan |
| `q`       | quit |

Filter (`/`) understands the `query.py` DSL — `port:8006 type:proxmox risk:high` — and
falls back to plain substring. Mouse works too: click a row to select, click the header to sort.

## scan-8006.sh

No nmap, no python, just `nc`. Sweep one port across a subnet.

```bash
./scan-8006.sh                       # auto /24, port 8006
./scan-8006.sh 10.0.0.0/24           # that subnet
PORT=443 ./scan-8006.sh 192.168.1.0/24
PORT=22 TIMEOUT=2 CONCURRENCY=200 ./scan-8006.sh 10.0.0.0/16
```

Prints `ip<TAB>https://ip:PORT` for every hit, then a count. Env: `PORT` (8006),
`TIMEOUT` (1s), `CONCURRENCY` (100).

## don't be an idiot

Point this at your own network. Scanning hosts you don't own or have written
permission to test is how you end up explaining yourself to someone. RFC1918 targets
only unless you know exactly what you're doing.

## layout

```
netdeep.sh        orchestrator (discovery + scanning)
analyzer.py       consolidation, risk, classification, history/diff, exports
netdeep-tui.py    curses UI
fingerprint.py    JARM/ssh-key/cert/favicon/http fingerprints + drift
passive.py        passive discovery + rogue/ARP-spoof/rogue-DHCP detection
pve.py            proxmox cluster reconciliation
probes.py         container + BMC/redfish/ipmi checks
vulns.py          KEV/EPSS cache, risk scoring, nuclei/httpx/testssl
topology.py       switch FDB + traceroute → DOT/mermaid/html map
alerts.py         ntfy/telegram/slack/webhook + zabbix/grafana/ansible
query.py          filter DSL over hosts
webdash.py        local web dashboard
mcpserver.py      MCP server for Claude
scan-8006.sh      single-port subnet sweep
```

See `ROADMAP.md` for what's shipped and what's next.
