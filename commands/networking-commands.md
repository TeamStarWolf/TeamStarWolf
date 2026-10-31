# Networking Command Reference

This page collects the command-line tools for inspecting and testing networks on Linux and, where noted, other platforms. It covers interface and route configuration, socket listing, reachability, DNS lookups, and packet capture. Most tools are read-only diagnostics; a few change state or move data. Full packet analysis lives on the tshark page.

## What it is and where it runs

The `iproute2` suite (`ip`, `ss`) is standard on modern Linux and replaces the older `net-tools` commands (`ifconfig`, `route`, `netstat`). DNS tools (`dig`, `host`, `nslookup`) ship with BIND utilities or similar packages. `ping`, `traceroute`, `nc`, and `tcpdump` are near-universal on Unix-like systems. Windows provides `tracert`, `nslookup`, and `ping` with its own flag spellings.

```bash
ip -V            # iproute2 version
ss --version
```

## Core commands

### Interfaces and routes

```bash
ip addr show                 # list interfaces and addresses
ip -br link                  # brief link state
ip route show                # routing table
ip route get 8.8.8.8         # which route a destination takes
```

Legacy equivalents, still present on many systems:

```bash
ifconfig -a
route -n
```

| Command | Purpose |
|---------|---------|
| `ip addr` | Show or set interface addresses |
| `ip link` | Show or set link state (up, down, MTU) |
| `ip route` | Show or manage the routing table |
| `ip neigh` | Show the ARP/NDP neighbor table |

### Sockets and connections

```bash
ss -tulpn              # listening TCP/UDP sockets with process and port
ss -tanp state established
netstat -tulpn         # legacy equivalent
```

`ss` is the current tool and is faster than `netstat` on busy hosts. The flags map closely: `-t` TCP, `-u` UDP, `-l` listening, `-n` numeric, `-p` process.

### Reachability and path

```bash
ping -c 4 10.0.0.1
traceroute example.com        # Linux/macOS
tracert example.com           # Windows
mtr example.com               # continuous traceroute plus loss stats
```

`mtr` combines `ping` and `traceroute` into a live per-hop loss and latency view.

### DNS lookups

```bash
dig example.com A +short
dig @1.1.1.1 example.com MX
dig example.com ANY +noall +answer
host example.com
nslookup example.com 8.8.8.8
```

`dig` is the detailed resolver tool. `host` is terse. `nslookup` works on Windows and Unix.

| Command | Typical use |
|---------|-------------|
| `dig` | Scriptable, precise record queries and tracing |
| `host` | Quick forward or reverse lookup |
| `nslookup` | Cross-platform interactive lookup |

### ARP neighbors

```bash
ip neigh show
arp -a            # legacy / Windows
```

### Netcat

```bash
nc -zv host 22 80 443         # port scan a short list
nc -lvnp 4444                 # listen on a port
nc host 25                    # talk to a service by hand
```

`nc` reads and writes raw TCP or UDP. Use it to test ports, grab banners, or move data between two hosts.

### Packet capture (brief)

```bash
sudo tcpdump -i eth0 -nn port 53
sudo tcpdump -i eth0 -w capture.pcap host 10.0.0.5
```

`tcpdump` captures traffic to screen or to a `.pcap` file. For deep protocol decoding, see /commands/tshark.md.

### Transfers (brief)

```bash
curl -sS https://example.com/health
wget -q https://example.com/file.tar.gz
```

`curl` and `wget` fetch over HTTP(S) and other protocols. `curl` has its own page at /commands/curl.md.

## Common workflows

Find what is listening and tie it to a process:

```bash
sudo ss -tulpn | grep -E ':(80|443|22)\b'
```

Diagnose a slow or failing connection end to end:

```bash
ping -c 3 api.example.com          # is the host reachable
dig api.example.com +short         # does the name resolve
nc -zv api.example.com 443         # is the port open
mtr -rw api.example.com            # where does the path degrade
```

Capture only DNS queries for five seconds to a file for later analysis:

```bash
sudo timeout 5 tcpdump -i any -nn -w dns.pcap port 53
```

Add a temporary route and confirm it:

```bash
sudo ip route add 192.168.50.0/24 via 10.0.0.1
ip route get 192.168.50.10
```

## Flags and options worth knowing

| Flag | Command | Purpose |
|------|---------|---------|
| `-br` | `ip` | Brief one-line-per-item output |
| `-tulpn` | `ss`, `netstat` | TCP+UDP listeners, numeric, with PID |
| `-c N` | `ping` | Send N packets then stop |
| `-nn` | `tcpdump` | Do not resolve hosts or ports |
| `+short` | `dig` | Answer only, script-friendly |
| `-z`, `-v` | `nc` | Scan mode (no data) and verbose |
| `-w FILE` | `tcpdump` | Write raw packets to a pcap file |

## Security notes

`nc` is dual-use. Administrators test ports with it; attackers use it for bind and reverse shells, data exfiltration, and lateral movement. Alert on unexpected `nc` listeners and outbound connections. Some builds include the `-e` option to run a program on connect; its presence is a common backdoor primitive.

Packet capture with `tcpdump` requires root or the `CAP_NET_RAW` capability and exposes the content of every unencrypted packet on the segment. Capture only with authorization and a defined scope, and store `.pcap` files as sensitive data, since they can hold credentials and session tokens. Capturing on networks you do not own may be unlawful.

DNS tools support reconnaissance. Zone transfers (`dig AXFR`), bulk record enumeration, and reverse-lookup sweeps map an environment before an attack. Restrict zone transfers to known secondaries and monitor for `ANY` and `AXFR` queries.

Cleartext protocols leak. `nc host 25`, `ftp`, `telnet`, and plain HTTP expose credentials and data to anyone capturing the path; this is cleartext transmission of sensitive information (CWE-319). Prefer TLS-wrapped equivalents and segment management traffic. See /SECURE_CODING_REFERENCE.md for transport-security guidance.

## Resources

- man pages: `ip(8)`, `ss(8)`, `tcpdump(1)`, `dig(1)`, `nc(1)`, `ping(8)`, `traceroute(8)`, `mtr(8)`
- iproute2 project documentation
- "TCP/IP Illustrated, Volume 1" by W. Richard Stevens
- IANA service name and port registry

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/tshark.md
- /commands/nmap.md
- /commands/curl.md
- /commands/ssh.md
