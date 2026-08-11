#!/usr/bin/env bash
# thin front-end: run the scanners, hand raw output to analyzer.py

DIR="$(cd "$(dirname "$0")" && pwd)"
ANALYZER="$DIR/analyzer.py"

PORTS=""
TIMEOUT=2
L2=1
NODISC=0
DISCOVERY_ONLY=0
OS=0
DO_SCRIPTS=0
DEEP=0
FAST=0
SSDP=0
NETBIOS=0
MDNS=0
PROXMOX=0
NOSTORE=0
QUIET=0
JSON=""
CSV=""
MD=""
PROM=""
DB=""
TARGETS=()

SCRIPTS="banner,http-title,http-server-header,ssl-cert,ssl-enum-ciphers,ssh-hostkey,smb-protocols,rdp-ntlm-info,vnc-info,ftp-anon"

usage() {
  cat >&2 <<'EOF'
usage: netdeep.sh [opts] [target ...]
  -p, --ports SPEC     preset (fast|top|top100|infra|web|proxmox|all) or raw nmap ports (22,443 / 8006 / 8000-8100)
  -t, --timeout SEC    default 2
      --no-l2          skip arp-scan
      --no-discovery   nmap -Pn
      --discovery-only nmap -sn
      --os             nmap -O (root)
      --scripts        default NSE bundle
      --deep           add vuln NSE (implies --scripts)
      --fast           masscan pre-pass, then nmap -sV on open ports (root)
      --ssdp --netbios --mdns  passive discovery
      --proxmox        probe pve api
      --json FILE      enriched json out
      --csv/--md/--prom FILE  export after scan
      --db PATH        sqlite history (default ~/.netdeep/history.db)
      --no-store       don't persist
  -q, --quiet   -h, --help
  target: CIDR / IP / a.b.c.d-e / host; default = local /24
EOF
}

log() { [ "$QUIET" = 1 ] || printf '%s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--ports) PORTS="$2"; shift 2;;
    -t|--timeout) TIMEOUT="$2"; shift 2;;
    --no-l2) L2=0; shift;;
    --no-discovery) NODISC=1; shift;;
    --discovery-only) DISCOVERY_ONLY=1; shift;;
    --os) OS=1; shift;;
    --scripts) DO_SCRIPTS=1; shift;;
    --deep) DEEP=1; DO_SCRIPTS=1; shift;;
    --fast) FAST=1; shift;;
    --ssdp) SSDP=1; shift;;
    --netbios) NETBIOS=1; shift;;
    --mdns) MDNS=1; shift;;
    --proxmox) PROXMOX=1; shift;;
    --json) JSON="$2"; shift 2;;
    --csv) CSV="$2"; shift 2;;
    --md) MD="$2"; shift 2;;
    --prom) PROM="$2"; shift 2;;
    --db) DB="$2"; shift 2;;
    --no-store) NOSTORE=1; shift;;
    -q|--quiet) QUIET=1; shift;;
    -h|--help) usage; exit 0;;
    --) shift; while [ $# -gt 0 ]; do TARGETS+=("$1"); shift; done;;
    -*) log "unknown option: $1"; usage; exit 1;;
    *) TARGETS+=("$1"); shift;;
  esac
done

[ "$DEEP" = 1 ] && SCRIPTS="$SCRIPTS,smb-vuln-ms17-010,vulners,vuln"

IS_ROOT=0; [ "$(id -u)" = 0 ] && IS_ROOT=1
SUDO=""
if [ "$IS_ROOT" = 0 ] && sudo -n true 2>/dev/null; then SUDO="sudo"; fi
PRIV=0; { [ "$IS_ROOT" = 1 ] || [ -n "$SUDO" ]; } && PRIV=1
[ "$PRIV" = 1 ] || log "[!] no root: connect scan (-sT), skipping arp-scan/masscan/-O"

# default route interface + our /24
if command -v ip >/dev/null 2>&1; then
  IFACE=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
  MYIP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2;exit}' | cut -d/ -f1)
else
  IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
  MYIP=$(ifconfig "$IFACE" 2>/dev/null | awk '/inet /{print $2;exit}')
fi

if [ ${#TARGETS[@]} -eq 0 ]; then
  [ -n "$MYIP" ] || { log "cannot auto-detect network, give a target"; exit 1; }
  TARGETS=("${MYIP%.*}.0/24")
  log "[*] auto target ${TARGETS[0]} via ${IFACE:-?}"
fi
TARGETSTR="${TARGETS[*]}"

# ports -> nmap argv
PORTARGS=()
case "$PORTS" in
  "") ;;
  fast) PORTARGS=(-F);;
  top) PORTARGS=(--top-ports 1000);;
  top100) PORTARGS=(--top-ports 100);;
  all) PORTARGS=(-p-);;
  proxmox) PORTARGS=(-p 22,3128,5900,8006,8007);;
  web) PORTARGS=(-p 80,443,8000,8006,8007,8080,8443,9090);;
  infra) PORTARGS=(-p 22,53,80,111,123,443,445,502,623,902,903,2049,3128,3260,3389,5432,5900,5901,6379,8000,8006,8007,8080,8443,9090,9100,27017);;
  *) PORTARGS=(-p "$PORTS");;
esac

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t netdeep)
XML="$TMP/scan.xml"
ARP="$TMP/arp.txt"
MASS="$TMP/mass.txt"
TMPJSON="$TMP/out.json"
trap 'rm -rf "$TMP"' EXIT
SECONDS=0

# L2 sweep
if [ "$L2" = 1 ] && [ "$PRIV" = 1 ] && command -v arp-scan >/dev/null 2>&1; then
  log "[*] arp-scan L2 sweep on ${IFACE:-auto}"
  ${SUDO} arp-scan --interface="$IFACE" --localnet --retry=2 --timeout=200 "${TARGETS[@]}" 2>/dev/null \
    | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/' > "$ARP"
elif [ "$L2" = 1 ]; then
  log "[!] arp-scan skipped (no root or not installed)"
fi

# masscan pre-pass
if [ "$FAST" = 1 ] && [ "$PRIV" = 1 ] && command -v masscan >/dev/null 2>&1; then
  case "$PORTS" in
    fast|top|top100|infra|web|proxmox|all|"") MPORTS="1-65535";;
    *) MPORTS="$PORTS";;
  esac
  log "[*] masscan pre-pass -p$MPORTS"
  ${SUDO} masscan "${TARGETS[@]}" -p"$MPORTS" --rate 1000 -oL "$MASS" 2>/dev/null
  OPEN=$(awk '/^open/{print $3}' "$MASS" 2>/dev/null | sort -un | paste -sd, -)
  if [ -n "$OPEN" ]; then
    PORTARGS=(-p "$OPEN")
    log "[*] masscan open ports: $OPEN"
  else
    log "[!] masscan found no open ports"
  fi
elif [ "$FAST" = 1 ]; then
  log "[!] --fast ignored (no root or masscan missing)"
fi

# nmap argv
NM=(nmap -T4 --max-retries 2 --host-timeout 90s -oX "$XML")
[ "$NODISC" = 1 ] && NM+=(-Pn)
if [ "$DISCOVERY_ONLY" = 1 ]; then
  NM+=(-sn)
else
  if [ "$PRIV" = 1 ]; then NM+=(-sS); else NM+=(-sT); fi
  NM+=(-sV --version-intensity 5)
  [ "$OS" = 1 ] && [ "$PRIV" = 1 ] && NM+=(-O)
  [ "$DO_SCRIPTS" = 1 ] && NM+=(-sC --script "$SCRIPTS")
  [ ${#PORTARGS[@]} -gt 0 ] && NM+=("${PORTARGS[@]}")
fi

log "[*] nmap ${TARGETSTR}"
${SUDO} "${NM[@]}" "${TARGETS[@]}" >/dev/null 2>&1

# proxmox default-on when pve ports in scope
PXSTR="${PORTARGS[*]}"
case "$PXSTR" in *8006*|*8007*) PROXMOX=1;; esac

# consolidate + analyze + report
AN=(consolidate --nmap-xml "$XML" --arp "$ARP" --target "$TARGETSTR" --elapsed "$SECONDS" --arp-cache)
[ "$PRIV" = 1 ] && AN+=(--root)
[ "$SSDP" = 1 ] && AN+=(--ssdp)
[ "$NETBIOS" = 1 ] && AN+=(--netbios)
[ "$MDNS" = 1 ] && AN+=(--mdns)
[ "$PROXMOX" = 1 ] && AN+=(--proxmox)
[ -n "$DB" ] && AN+=(--db "$DB")
[ "$NOSTORE" = 1 ] && AN+=(--no-store)
AN+=(--out "${JSON:-$TMPJSON}" --terminal)

log "[*] analyzer: python3 $ANALYZER ${AN[*]}"
python3 "$ANALYZER" "${AN[@]}"

# exports off the latest scan
for pair in "csv:$CSV" "md:$MD" "prom:$PROM"; do
  fmt="${pair%%:*}"; out="${pair#*:}"
  [ -n "$out" ] || continue
  EX=(export --format "$fmt" --out "$out")
  [ -n "$DB" ] && EX+=(--db "$DB")
  log "[*] export $fmt -> $out"
  python3 "$ANALYZER" "${EX[@]}"
done
