# netdeep

Recon and drift-watch for LANs you actually own: homelabs, proxmox fleets, the rack in
the closet, the /24 where half the hosts are things you forgot you plugged in.

Most scanners hand you a port list and call it a day. This one builds an inventory,
figures out *what* each box is, fingerprints it, remembers it, and tells you when
something changes. A new MAC that shouldn't be there. An ssh host key that rotated when
you didn't touch the box. A VM answering on an IP that belongs to no guest.

It leans on the tools that already do their jobs well (`nmap`, `arp-scan`, `masscan`,
`snmpwalk`, `nuclei`) and does the thinking in python stdlib. No pip wall, no venv, no
daemon. If a tool isn't installed it degrades and keeps going. If you're not root it drops
to a connect scan and skips the parts that need raw sockets. It never stops working, it
just works shallower.

## why you'd run it

You're staring at a subnet. `nmap` says 41 hosts are up and 8006 is open on three of them.
Cool. But which of those three is the proxmox node you rebuilt last week, which is a VM you
forgot to shut down, and which one is *new*? Is that `bc:24:11` MAC a guest you spun up, or
did something start a VM on your network while you weren't looking? Did the cert on your PBS
box change because you renewed it, or because someone's sitting in the middle?

That's the gap. netdeep keeps a baseline and answers "what's different since last time."

## the layers

- **L2 / ARP.** `arp-scan` on the wire plus a read of the kernel ARP cache. MAC and vendor,
  and here's the point: it sees hosts that drop every ping and every SYN but still have to
  ARP to talk. A firewalled NAS is invisible to a port scan and loud on L2.
- **L3 discovery.** `nmap` ping/SYN sweep for the hosts that do answer, on- and off-link.
- **L4 ports + versions.** SYN scan as root, connect scan otherwise, `-sV` for
  service/version, the usual NSE bundle on `--scripts`.
- **passive.** mDNS/Bonjour, SSDP/UPnP, WS-Discovery, NetBIOS. Devices announce themselves
  on multicast whether or not they answer you directly: smart TVs, printers, cameras, cast
  targets, NAS boxes all shout their model and hostname if you bother to listen.
- **L7 / identity.** cookie and header fingerprints (`PVEAuthCookie` means proxmox, no
  guessing), favicon hashing the way shodan does it, JARM on the TLS stack, ssh host-key and
  cert fingerprints.

## install

```bash
git clone https://github.com/wabiwabo/netdeep && cd netdeep
brew install nmap arp-scan masscan          # or your distro's packages
```

python3 covers the code side. Stdlib only, nothing to install. Optional muscle: `nuclei` +
`httpx` (brew) for the vuln pass, `mcp` (pip) for the claude bridge.

`arp-scan`, SYN scans, OS detection and `masscan` need raw sockets, so run under `sudo`.
No root and it quietly falls back to a TCP connect scan and skips L2/OS. The rest works
either way.

## quickstart

```bash
sudo ./netdeep.sh                 # auto-detect your /24, full depth
sudo ./netdeep-tui.py             # same thing, curses cockpit
./netdeep.sh                      # no sudo: connect scan, no L2/OS, still useful
```

## ports

`-p` eats a single port, a list, a range, or a preset. Target is a trailing CIDR / IP /
hostname; leave it off and it takes your local /24.

```bash
./netdeep.sh -p 8006 192.168.1.0/24     # hunt proxmox web across the subnet
./netdeep.sh -p 22,443                    # a list
./netdeep.sh -p 8000-8100                 # a range
./netdeep.sh -p proxmox 10.0.0.0/24       # a preset
./netdeep.sh -p all 192.168.1.10          # every port on one host. bring coffee.
```

| preset    | what it covers |
|-----------|----------------|
| `fast`    | nmap `-F`, the quick-and-dirty top ports |
| `top`     | nmap top-1000 |
| `top100`  | top-100 |
| `infra`   | ssh, dns, snmp, ntp, ipmi, redis, mongo, vnc, rdp, proxmox, the mgmt-plane stuff |
| `web`     | 80/443/8000/8006/8007/8080/8443/9090 |
| `proxmox` | 22, 3128, 5900, 8006, 8007 |
| `all`     | 1-65535 |

## flags

| flag | what it does |
|------|--------------|
| `-p PORTS` | port / list / range / preset (above) |
| `-t SEC` | per-probe timeout (default 2) |
| `--no-l2` | skip the arp-scan sweep |
| `--no-discovery` | treat every host as up (`nmap -Pn`) |
| `--discovery-only` | find live hosts, don't port scan |
| `--os` | OS detection (`nmap -O`, needs root) |
| `--scripts` | the safe NSE bundle (banners, titles, tls, smb, rdp) |
| `--deep` | add vuln NSE + `vulners` CVE hints |
| `--fast` | `masscan` pre-pass, then `-sV` on only the open ports |
| `--ssdp --mdns --netbios` | passive discovery on/off |
| `--fingerprint` | JARM / ssh-key / cert / favicon / http fp + **drift alarms** |
| `--rogue` | ARP-spoof, rogue-DHCP, new-MAC + hypervisor-OUI detection |
| `--vuln` | container/BMC probes + KEV/EPSS-weighted risk score per host |
| `--topo FMT` | write a map (`dot` / `mermaid` / `html`); pair with `--topo-out FILE` |
| `--pve NODE --pve-token T` | reconcile a proxmox cluster against the scan |
| `--pve-cacert FILE` | verify the pve node cert against a CA (else it pins TOFU) |
| `--alert` | fire ntfy/telegram/etc on new hosts + high/crit findings |
| `--json / --csv / --md / --prom FILE` | write output as you go |
| `--db PATH` | history db (default `~/.netdeep/history.db`) |
| `--no-store` | don't touch history for this run |
| `-q` | shut up |
| `[target]` | trailing CIDR / IP / host, or nothing for auto /24 |

## fingerprint drift, the tripwire

Ports and versions change for boring reasons. Identity shouldn't. `--fingerprint` records,
per host+port, four things that stay stable until someone changes the box underneath them.

- **JARM.** an active fingerprint of the TLS *stack*. ten crafted ClientHellos, hash the
  responses. every pveproxy on the same build lands on the same JARM, so your nodes cluster
  together; a node that suddenly doesn't match its siblings, or grew a reverse proxy in front,
  stands out. it's a response fingerprint (forgeable), so it's for grouping and drift, not a
  trust anchor.
- **ssh host key.** SHA256 of the offered key. a key that changes on a box you *didn't*
  reinstall is MITM, compromise, or a device silently swapped at that IP. highest
  signal-to-noise alarm in the whole tool.
- **cert SHA256.** same idea for TLS. self-signed and expiring already get flagged; the
  fingerprint catches the quiet swap.
- **favicon + cookies/headers.** cheap product ID that survives header stripping.

First run baselines. Every run after, a change becomes a `*-drift` finding and lands in the
diff. Bless a change you made on purpose and it goes quiet again.

```bash
sudo ./netdeep.sh -p infra --fingerprint 192.168.1.0/24     # baseline the fleet
# ... a week later, same command. if pve3's ssh key moved, you hear about it.
```

## rogue hunting

`--rogue` is built for "something's on my network that I didn't put there."

- **new / unknown MAC.** anything not in your baseline. new MAC whose OUI is a hypervisor
  prefix (`bc:24:11` proxmox, `52:54:00` kvm, `00:0c:29`/`00:50:56` vmware, `08:00:27` vbox)
  means someone booted a VM on your LAN, and it gets flagged loud.
- **randomized MAC.** the U/L bit is set (2nd nibble is 2/6/a/e), so it's a privacy-randomized
  phone, not a real NIC. tagged so it doesn't pollute the vendor column.
- **gateway-MAC pin.** records your gateway's MAC once. if it changes, that's the classic MITM
  and you get a crit on the spot.
- **ARP conflict.** one IP on two MACs, or one MAC on two IPs. spoofing, or a dup you need to
  hunt down.
- **rogue DHCP.** a second box handing out leases, caught passively from any OFFER that isn't
  your known server.

## proxmox reconciliation

The one nothing else can do from outside the hypervisor. Point it at a node with a read-only
**PVEAuditor** token and it walks the cluster, pulls every guest's vNIC MAC and live IP, and
cross-references the LAN scan:

- which VM owns that mystery IP
- which running guest is invisible to the scan (isolated vlan, agent down, firewalled)
- which live IP on the wire belongs to **no** guest at all. rogue, or bare metal you forgot.

```bash
./pve.py reconcile --node 192.168.1.10 --token 'root@pam!scan=SECRET' --scan-json last.json
```

The token is a credential, so it never gets handed to an unverified peer. Pass
`--cacert /etc/pve/pve-root-ca.pem` to verify against the CA, or let it pin the leaf cert on
first contact (trust-on-first-use, like ssh known-hosts) and refuse to send the token if that
cert ever changes. Rotated on purpose? re-pin with `--cacert`, or delete the entry from
`~/.netdeep/pve_pins.json`.

## risk scoring, not CVE dumping

`--vuln` does two things. It runs read-only probes at the services that are dangerous when
left open: docker `2375` (unauth means root on the host), etcd `2379` (holds every k8s
secret), kubelet `10250`, nomad, consul, and BMCs (redfish/ipmi on your bare-metal). A `401`
is the *good* answer; a `200` with a JSON body is the finding.

Then it scores each host. CVSS alone is noise. A 9.8 on an unreachable box matters less than a
medium that's internet-adjacent and being exploited today, so the score folds in **EPSS**
(probability it gets popped) and **CISA KEV** (confirmed in-the-wild, hard-escalated to the
top), times an exposure multiplier. You get a ranked worklist, not 200 CVEs.

```bash
./vulns.py kev-update && ./vulns.py epss-update     # refresh the intel cache, cron it
sudo ./netdeep.sh -p infra --vuln
```

With `nuclei` + `httpx` installed the vuln path also runs the community template set
(exposures, default-logins, panels) and pulls the CVE IDs into the same score.

## topology map

Turn the flat list into a picture. Straight from the scan you get a gateway to host tree.
Feed it a managed switch over SNMP and it learns which MAC sits on which physical port and
VLAN, and spots the trunk (the port with a swarm of MACs behind it is your hypervisor or
uplink).

```bash
sudo ./netdeep.sh --topo mermaid --topo-out lan.mmd        # paste into anything
./topology.py graph --scan-json last.json --format html --out lan.html   # standalone, clickable
./topology.py fdb --switch 192.168.1.1 --community public  # mac -> switchport -> vlan
```

`dot` and `mermaid` are plain text with zero deps to produce. the html carries its own inline
svg + js, no CDN.

## history, diff, and the query language

Every run lands in sqlite. That's what makes drift possible.

```bash
sudo ./netdeep.sh -p infra                 # run N, stored
./analyzer.py diff                          # what moved since run N-1
```

Diff shows new and vanished hosts, newly-opened and closed ports, and service/version drift
(that ssh 8.9 to 9.6 you meant to do, or the one you didn't). Ask history questions with the
filter DSL, the same grammar the TUI and dashboard use:

```bash
./query.py test --expr "port:8006 type:proxmox risk:high seen:<7d" --scan-json last.json
```

fields: `ip host vendor type mac os label port risk seen score`. ops: `~` contains,
`< > >= <=` for port/seen/score, `!` negates. `seen:<7d` is last-seen inside a week. bare
words match across ip / hostname / vendor / label / type. terms AND together.

## exports

```bash
./analyzer.py export --format json  --out net.json
./analyzer.py export --format csv   --out net.csv
./analyzer.py export --format html  --out net.html
./analyzer.py export --format md    --out net.md
```

prometheus textfile for node_exporter. drop it in the collector dir on a cron and graph your
attack surface over time:

```bash
*/15 * * * * cd /opt/netdeep && sudo ./netdeep.sh -p infra --db ~/.netdeep/history.db -q \
  && ./analyzer.py export --format prometheus \
     --out /var/lib/node_exporter/textfile_collector/netdeep.prom
```

grafana dashboard json and an ansible inventory come out of `alerts.py` if you want them
wired into the stack you already run.

## alerts

Drop `~/.netdeep/alerts.json` with any of `ntfy` / `telegram` / `slack` / `discord` /
`webhook` / `macos` / `zabbix`, then `--alert` pushes on new hosts and high/crit findings.
Reuses the prometheus + zabbix you're already running instead of being one more thing to
babysit.

```bash
./alerts.py test                            # prove your transports work
sudo ./netdeep.sh -p infra --rogue --vuln --alert
```

## ask claude (mcp)

The history db behind an MCP server, so you can ask in plain english instead of writing
queries: "what changed on the LAN today", "which hosts expose unauth services", "find the new
device", "diff tonight vs last week".

```bash
pip install mcp
claude mcp add netdeep -e NETDEEP_DB=$HOME/.netdeep/history.db -- python3 $PWD/mcpserver.py
```

## the TUI

```bash
sudo ./netdeep-tui.py
```

A config form, a live scan with a rolling log, and a results table you drive with the keyboard
(or the mouse: click a row to select, click a header to sort).

| key | does |
|-----|------|
| `↑ ↓  pgup pgdn  home end` | move |
| `enter` | drill into the host: ports, versions, fingerprints, risks, score, changes |
| `s` | cycle sort (ip / type / vendor / risk / ports) |
| `/` | filter, understands the query DSL, falls back to substring |
| `o` | open the host's web UI in a browser |
| `w` | wake-on-lan the selected MAC |
| `p` / `t` / `g` | ping / traceroute / ssh (drops to a real shell, back on exit) |
| `c` | copy the IP to the clipboard |
| `n` | label / rename a host (sticks in history) |
| `V` | stats panel: counts by type, vendor, risk |
| `W` | watch mode, auto-rescan on an interval, table updates in place |
| `e` | export menu |
| `r` | rescan · `q` quit |

## scan-8006.sh

The dumb one, for when you don't want to think. No nmap, no python, just `nc`. Sweep one port
across a subnet.

```bash
./scan-8006.sh                              # auto /24, port 8006
./scan-8006.sh 10.0.0.0/24                   # that subnet
PORT=443 ./scan-8006.sh 192.168.1.0/24
PORT=22 TIMEOUT=2 CONCURRENCY=200 ./scan-8006.sh 10.0.0.0/16
```

Prints `ip<TAB>https://ip:PORT` per hit and a count. Tunables: `PORT` (8006), `TIMEOUT` (1s),
`CONCURRENCY` (100).

## authorization

Point this at your own network. Scanning hosts you don't own or don't have written permission
to test (never mind fingerprinting or probing them) is how you end up explaining yourself to
someone who isn't amused. RFC1918 targets only unless you know exactly what you're doing and
have it in writing. The tool warns when a target isn't private. That warning is for you.

## how it's built

Thin bash front-end (`netdeep.sh`) runs the scanners and hands raw output to the brain.
`analyzer.py` does consolidation, classification, risk, history and diff. Everything else is a
self-contained module the analyzer or the TUI pulls in when you ask for it, and each one runs
standalone too (`python3 pve.py --selftest`, `python3 fingerprint.py scan --host ...`). Stdlib
first, shell out to real tools when they earn it, degrade without root. One sqlite file is the
whole state.

```
netdeep.sh        orchestrator, discovery + scanning
analyzer.py       consolidation, classification, risk, history/diff, exports
netdeep-tui.py    curses cockpit
fingerprint.py    JARM / ssh-key / cert / favicon / http fp + drift
passive.py        passive discovery + rogue / ARP-spoof / rogue-DHCP
pve.py            proxmox cluster reconciliation (cert-pinned)
probes.py         container + BMC / redfish / ipmi checks
vulns.py          KEV/EPSS cache, risk scoring, nuclei/httpx/testssl
topology.py       switch FDB + traceroute -> dot / mermaid / html map
alerts.py         ntfy/telegram/slack/webhook + zabbix/grafana/ansible
query.py          the filter DSL
webdash.py        local web dashboard
mcpserver.py      MCP bridge
scan-8006.sh      single-port subnet sweep
```

`ROADMAP.md` is what's shipped and what's next.
