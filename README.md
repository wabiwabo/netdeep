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
  drill-down, wake-on-lan, ssh/ping/traceroute, labels, exports.
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

## history + diff

```bash
sudo ./netdeep.sh -p infra          # run, results stored
./analyzer.py diff                   # what changed vs the previous run
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
| `S`       | ssh to host |
| `e`       | export menu |
| `r`       | rescan |
| `q`       | quit |

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
analyzer.py       consolidation, risk, history/diff, exports
netdeep-tui.py    curses UI
scan-8006.sh      single-port subnet sweep
```
