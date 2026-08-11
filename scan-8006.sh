#!/usr/bin/env bash
# scan-8006.sh — sweep a subnet for one open port. no nmap, just nc.
# usage: ./scan-8006.sh [CIDR]     env: PORT (8006) TIMEOUT (1) CONCURRENCY (100)
set -u

PORT="${PORT:-8006}"
TIMEOUT="${TIMEOUT:-1}"
CONCURRENCY="${CONCURRENCY:-100}"
export PORT TIMEOUT

# child worker: nc one host, print it if the port answers
if [ "${1:-}" = "__probe" ]; then
  h="${2:-}"
  [ -z "$h" ] && exit 0
  nc -z -w "$TIMEOUT" "$h" "$PORT" >/dev/null 2>&1 && printf '%s\n' "$h"
  exit 0
fi

ip2int() { local IFS=. ; set -- $1; echo $(( ($1<<24)+($2<<16)+($3<<8)+$4 )); }
int2ip() { local n=$1; echo "$(((n>>24)&255)).$(((n>>16)&255)).$(((n>>8)&255)).$((n&255))"; }

rfc1918() {
  local IFS=. ; set -- $1
  [ "$1" = "10" ] && return 0
  [ "$1" = "192" ] && [ "$2" = "168" ] && return 0
  [ "$1" = "172" ] && [ "$2" -ge 16 ] 2>/dev/null && [ "$2" -le 31 ] && return 0
  return 1
}

detect_cidr() {
  local ip="" dev
  if command -v route >/dev/null 2>&1; then          # macos
    dev=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
    [ -n "$dev" ] && ip=$(ifconfig "$dev" 2>/dev/null | awk '/inet /{print $2; exit}')
  fi
  if [ -z "$ip" ] && command -v ip >/dev/null 2>&1; then   # linux
    ip=$(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | head -n1 | cut -d/ -f1)
  fi
  [ -z "$ip" ] && return 1
  local IFS=. ; set -- $ip
  echo "$1.$2.$3.0/24"
}

CIDR="${1:-}"
if [ -z "$CIDR" ]; then
  CIDR=$(detect_cidr) || { echo "can't detect subnet — pass a CIDR" >&2; exit 1; }
  echo "auto: $CIDR" >&2
fi

case "$CIDR" in */*) : ;; *) CIDR="$CIDR/32" ;; esac
base="${CIDR%/*}"; mask="${CIDR#*/}"

case "$mask" in ''|*[!0-9]*) echo "bad mask" >&2; exit 1 ;; esac
if [ "$mask" -lt 16 ] || [ "$mask" -gt 32 ]; then
  echo "mask must be /16../32" >&2; exit 1
fi

rfc1918 "$base" || echo "warn: $CIDR isn't RFC1918. only scan what you own." >&2

baseint=$(ip2int "$base")
netsize=$(( 1 << (32 - mask) ))
netaddr=$(( baseint & (0xFFFFFFFF ^ (netsize - 1)) ))

if [ "$netsize" -le 2 ]; then
  start=$netaddr; end=$(( netaddr + netsize - 1 ))
else
  start=$(( netaddr + 1 )); end=$(( netaddr + netsize - 2 ))   # skip net + broadcast
fi

echo "sweeping $CIDR :$PORT ($(( end - start + 1 )) hosts, -P$CONCURRENCY)" >&2

hits=$(
  i=$start
  while [ "$i" -le "$end" ]; do int2ip "$i"; i=$(( i + 1 )); done \
    | xargs -P "$CONCURRENCY" -I{} "$0" __probe {}
)

if [ -n "$hits" ]; then
  printf '%s\n' "$hits" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | while IFS= read -r h; do
    printf '%s\thttps://%s:%s\n' "$h" "$h" "$PORT"
  done
  n=$(printf '%s\n' "$hits" | grep -c .)
else
  n=0
fi
echo "$n open on :$PORT" >&2
