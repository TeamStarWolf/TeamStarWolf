# tshark Command Reference

tshark is the command-line version of Wireshark. It captures and reads network traffic, applies filters, extracts fields, and prints protocol statistics, all without a graphical interface. Security teams use it for authorized network analysis, incident response, and protocol troubleshooting on networks they are permitted to monitor. Capturing traffic needs privilege and authorization, so confirm both before you start. This page covers capture, read, filtering, field extraction, and statistics, plus the handling rules for captured data.

## What it is and where it runs

tshark runs on Linux, Windows, and macOS and ships with the Wireshark distribution. It reads the same dissectors as Wireshark and the same capture file formats (`pcap`, `pcapng`). Live capture needs access to a network interface, which usually means root or membership in a capture group, plus packet-capture privileges on the host. Read and analysis of an existing capture file need only file access.

List the interfaces available for capture:

```
tshark -D
```

## Core commands

Capture on an interface with `-i`, and write to a file with `-w` so you analyze later rather than on the wire.

```
tshark -i eth0 -w capture.pcapng
```

Read a saved capture with `-r`.

```
tshark -r capture.pcapng
```

Capture filters use Berkeley Packet Filter (BPF) syntax and are applied with `-f` at capture time. They are cheap because the kernel drops unmatched packets before tshark sees them.

```
tshark -i eth0 -f "tcp port 80 or tcp port 443" -w web.pcapng
```

Display filters use Wireshark's own syntax and are applied with `-Y` after dissection. They are richer than BPF and work on read as well as capture.

```
tshark -r capture.pcapng -Y "http.request.method == \"POST\""
```

Extract specific fields as columns with `-T fields` and one `-e` per field. Add `-E header=y` for a header row and `-E separator=,` for CSV.

```
tshark -r capture.pcapng -T fields -e ip.src -e ip.dst -e tcp.dstport -E header=y
```

Print protocol statistics with `-z`. Combine with `-q` to suppress per-packet output.

```
tshark -r capture.pcapng -q -z conv,tcp
tshark -r capture.pcapng -q -z io,phs
tshark -r capture.pcapng -q -z endpoints,ip
```

Limit the number of packets with `-c`, and resolve or suppress name resolution with `-n`.

```
tshark -i eth0 -c 100
tshark -i eth0 -n -c 100
```

| Flag | Purpose |
| --- | --- |
| `-i` | Interface to capture on |
| `-w` | Write raw packets to a file |
| `-r` | Read packets from a file |
| `-f` | Capture filter (BPF syntax) |
| `-Y` | Display filter (Wireshark syntax) |
| `-T fields` | Output selected fields |
| `-e` | Field to include with `-T fields` |
| `-z` | Statistics module |
| `-c` | Stop after N packets |
| `-q` | Quiet, suppress per-packet lines |

Ring buffers cap disk use during long captures. `-b` sets the rotation condition and keeps a fixed number of files.

```
tshark -i eth0 -w rolling.pcapng -b filesize:102400 -b files:10
```

This keeps ten files of 100 MB each, overwriting the oldest as it goes.

## Common workflows

Capture only the traffic you are authorized to inspect, then analyze offline.

```
tshark -i eth0 -f "host 10.10.10.5" -w host5.pcapng
tshark -r host5.pcapng -q -z conv,tcp
```

Pull a flow summary as CSV for a report.

```
tshark -r capture.pcapng -T fields -e frame.time -e ip.src -e ip.dst -e _ws.col.Protocol -E header=y -E separator=, > flows.csv
```

Find cleartext credential exposure during an authorized review, so it can be reported and fixed.

```
tshark -r capture.pcapng -Y "http.authbasic or ftp.request.command == \"PASS\""
```

Run a long incident-response capture with a ring buffer so disk never fills.

```
tshark -i eth0 -w ir.pcapng -b duration:3600 -b files:24 -f "not port 22"
```

## Flags and options worth knowing

| Flag | Meaning |
| --- | --- |
| `-D` | List available capture interfaces |
| `-n` | Disable name resolution |
| `-N` | Enable selected name resolution layers |
| `-b` | Ring buffer condition |
| `-a` | Autostop condition, such as `duration:60` |
| `-E` | Field output formatting options |
| `-x` | Hex and ASCII dump of each packet |
| `-V` | Verbose, full protocol tree per packet |
| `-s` | Snap length, bytes captured per packet |

## Detection and defense

Capturing traffic is a privileged action, so the first control is access. Packet capture requires root or an equivalent capability, and on a managed network it requires authorization from the owner. Restrict who holds capture rights, log the use of capture tools, and watch for interfaces entering promiscuous mode on hosts that should not sniff. Network taps and SPAN ports should be inventoried, since a capture point is a sensitive asset.

Captures are a data-protection problem. A `pcap` can hold credentials, session tokens, personal data, and full message bodies for any cleartext protocol. Storing that without protection is CWE-312 (cleartext storage of sensitive information); transmitting it unprotected is CWE-319. Encrypt capture files at rest, limit retention, scope captures to the minimum hosts and ports, and delete them when the engagement closes. Treat extracted field files and CSVs with the same care as the raw capture.

The finding in a capture is usually cleartext traffic itself. HTTP, FTP, Telnet, SNMPv1/v2c, and unencrypted LDAP expose data a passive observer can read. The remediation is to move those services to TLS or SSH equivalents, disable the plaintext listeners, and enforce encryption in transit. Apply the transport-security and sensitive-data-handling guidance in /SECURE_CODING_REFERENCE.md when fixing the exposed services.

## Resources

- Wireshark and tshark official documentation
- tshark `man` page and Wireshark Display Filter Reference
- "Practical Packet Analysis" by Chris Sanders

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/networking-commands.md
- /commands/nmap.md
- /commands/ssh.md
