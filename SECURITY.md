# security

## using this responsibly

netdeep is for networks you own or have written authorization to test. it discovers,
fingerprints, and probes hosts. pointing it at anything else is on you, not the project. it
flags non-RFC1918 targets on purpose so you don't do it by accident.

what it will not do: exploit, brute-force, or exfiltrate. default-credential checks are
opt-in and rate-limited. everything else is read-only enumeration.

## reporting a bug in netdeep itself

Found a problem in the tool (not in a host it scanned)? For anything sensitive, use GitHub's
private vulnerability reporting on the repo's Security tab, or ask for a private channel
before dropping a public PoC. Non-sensitive stuff, open an issue. Give it a few days before
public disclosure.

## how it handles secrets

- API tokens and SNMP community strings live in config under `~/.netdeep/`, never passed on
  argv where `ps` can read them, never written to the sqlite history, never in exports.
- the proxmox API token is cert-pinned (trust-on-first-use, or `--cacert`) and withheld if
  the node's certificate changes underneath it.
- keep `~/.netdeep/` at `0700`. the ansible inventory export is written `0600`.
