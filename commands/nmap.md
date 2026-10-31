# Nmap Command Reference

Nmap (Network Mapper) is an open-source tool for host discovery, port scanning, and service enumeration. Security teams use it to inventory assets, verify firewall rules, and map attack surface. This page is for authorized testing: scan only networks and hosts you own or have written permission to assess. Treat lab ranges and explicitly scoped engagements as the only valid targets.

## What it is and where it runs

Nmap sends crafted packets to target hosts and interprets the responses to report open ports, running services, and operating system hints. It runs on Linux, macOS, and Windows from the command line. Raw-packet scan types such as SYN scanning need root or administrator rights. The companion `ncat`, `nping`, and `ndiff` tools ship alongside it, and the Zenmap GUI wraps the same engine.

## Core commands

Host discovery finds live hosts before deeper scanning.

```bash
nmap -sn 10.0.0.0/24
```

Default scan probes the most common ports on one or more hosts.

```bash
nmap 10.0.0.5
nmap 10.0.0.5 10.0.0.6 scanme.nmap.org
```

Service and version detection identifies what listens on each open port.

```bash
nmap -sV 10.0.0.5
```

Script scan runs the default safe script set for extra detail.

```bash
nmap -sC 10.0.0.5
```

OS detection guesses the operating system from stack fingerprints.

```bash
nmap -O 10.0.0.5
```

| Task | Flag |
|------|------|
| Ping sweep, no port scan | `-sn` |
| TCP SYN scan (default as root) | `-sS` |
| TCP connect scan (no root) | `-sT` |
| UDP scan | `-sU` |
| TCP ACK scan (firewall mapping) | `-sA` |
| Service and version detection | `-sV` |
| Default scripts | `-sC` |
| OS detection | `-O` |

## Common workflows

Discover live hosts on an authorized subnet, then scan only responders.

```bash
nmap -sn 10.0.0.0/24 -oG live-hosts.gnmap
nmap -sS -sV -p- -iL live-hosts.txt -oA full-tcp
```

Quick triage of a single lab host with top ports and versions.

```bash
nmap -sS -sV --top-ports 100 -T4 10.0.0.5 -oN triage.txt
```

Enumerate web and TLS details on an authorized server with scripts.

```bash
nmap -sV -p 80,443,8080,8443 --script http-title,ssl-cert 10.0.0.5
```

UDP service check on common UDP ports in a lab, with version probes.

```bash
sudo nmap -sU -sV --top-ports 20 10.0.0.5 -oN udp-scan.txt
```

## Flags and options worth knowing

Port selection controls scope and speed.

```bash
nmap -p 22,80,443 10.0.0.5
nmap -p- 10.0.0.5
nmap --top-ports 1000 10.0.0.5
nmap -F 10.0.0.5
```

| Flag | Meaning |
|------|---------|
| `-p <ports>` | Scan named ports or ranges |
| `-p-` | Scan all 65535 TCP ports |
| `--top-ports <n>` | Scan the n most common ports |
| `-F` | Fast mode, top 100 ports |
| `-T0` to `-T5` | Timing from slow (`-T0`) to aggressive (`-T5`) |
| `--script <name>` | Run specific NSE scripts or categories |
| `-oN <file>` | Normal, human-readable output |
| `-oX <file>` | XML output for tooling |
| `-oG <file>` | Grepable output |
| `-oA <base>` | Write normal, XML, and grepable at once |

Timing templates balance speed against noise. `-T4` suits fast lab networks; `-T2` is quieter on sensitive links. Evasion options such as fragmentation (`-f`), decoys (`-D`), and source-port spoofing (`--source-port`) exist to test how detection controls respond. Use them only in authorized exercises to validate IDS and firewall coverage, never to hide activity from an asset owner.

## Detection and defense

Nmap supports authorized asset discovery and attack-surface management. Security teams run scheduled scans to inventory hosts, catch unexpected open ports, and confirm that decommissioned services are gone. Compare results over time with `ndiff` to flag drift.

Defenders detect scanning through pattern signatures. A single source touching many ports or many hosts in a short window triggers IDS and IPS rules in tools like Suricata, Snort, and Zeek. SYN scans leave half-open connections; firewall and flow logs show the fan-out. Aggressive timing (`-T4`, `-T5`) is loud and easy to spot, while slow scans evade thresholds but take far longer.

Mitigation reduces what a scan can find. Close unused ports, restrict services to required source ranges, and put management interfaces behind VPN or bastion hosts. Default-deny firewall rules limit response to probes. Rate limiting and connection throttling blunt fast scans. Keeping an accurate asset inventory means an unexpected open service stands out quickly. Exposed and unnecessary services map to weak access control; see /SECURE_CODING_REFERENCE.md for secure service configuration guidance.

## Resources

- Nmap Reference Guide (the official `man nmap` page)
- Nmap Network Scanning by Gordon Lyon (Fyodor), the project's official book
- Nmap Scripting Engine (NSE) documentation on nmap.org

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/networking-commands.md
- /commands/metasploit.md
- /commands/tshark.md
- /commands/ssh.md
