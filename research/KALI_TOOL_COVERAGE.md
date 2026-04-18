# Kali Linux Tool Coverage

> Maintained by [**@WolfenLabs**](https://x.com/WolfenLabs)
>
> A coverage analysis comparing the Kali Linux tool catalog against the [curated Stars Lists](CURATED_STARS_LISTS.md) and the broader [Starred GitHub Repositories index](../Starred%20GitHub%20Repositories.md). Surveyed against the full Kali tool index at <https://www.kali.org/tools/all-tools/>.

## Why this exists

Kali is the de-facto baseline reference distribution for offensive security. When a working catalogue claims "comprehensive coverage" of practitioner tooling, the honest test is: *how does it line up against the tools a Kali user already has on disk?*

This document answers that. It is **not** a recommendation to star every Kali tool — many are distro packages, GUI shells, or unmaintained forks with no useful upstream. It identifies the tools that **(a)** have a maintained upstream GitHub repository and **(b)** are not yet in the curated Stars Lists, so the gap can be closed deliberately rather than by reflex.

## Method

1. Extract the canonical tool list from the Kali tools index (655 tools surveyed in this pass — Kali rolls forward, expect drift).
2. Match by basename against the 1,076 starred repositories in the live `TeamStarWolf` profile.
3. Classify the remainder into four buckets:
   - **Already covered indirectly** — same upstream project, repo named differently (e.g., `impacket-scripts` → `fortra/impacket`).
   - **Out of scope: distro / OS** — system libraries, shells, editors, drivers (e.g., `apache2`, `bind9`, `curl`, `git`, `glibc`, `samba`, `postgresql`, `tmux`, `chromium`).
   - **Out of scope: deprecated or unmaintained** — projects with no commit activity in 5+ years and no active fork worth tracking.
   - **Worth adding** — actively maintained upstream repositories that fill a real gap.

## Coverage summary

| Bucket | Count | Notes |
|---|---|---|
| Direct-name matches in starred repos | 106 | Confirmed by `comm` of basenames |
| Covered indirectly (different repo name) | ~70 | Same upstream, e.g. `webacoo`/`weevely` → `epinna/weevely`; `impacket-scripts` → `fortra/impacket` |
| Out of scope: distro packages and OS components | ~180 | `apache2`, `bind9`, `bluez`, `chromium`, `curl`, `glibc`, `git`, `samba`, `postgresql`, `python3`, `tmux`, etc. |
| Out of scope: deprecated, unmaintained, or commercial-only | ~140 | `b374k`, `cisco7crack`, `copy-router-config`, `framework2`, `isr-evilgrade`, `maltego` (proprietary), `burpsuite` (proprietary), etc. |
| Worth adding (actively maintained upstream) | ~60 | Enumerated below |

The 106 direct matches plus the indirect coverage means roughly **~26%** of Kali's catalogue is already represented by upstream GitHub stars in the existing Lists. Once distro packages and dead projects are excluded from the denominator, effective coverage of the *trackable* Kali surface is closer to **~55%**.

## Worth-adding queue

Grouped by which existing Stars List the tool would join. Each entry is a tool that ships in Kali, has an actively maintained upstream GitHub repo, and is not yet starred.

### → Active Directory Offensive Operations
- `bloodyad` — [CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD) — AD privilege escalation framework
- `certipy-ad` — [ly4k/Certipy](https://github.com/ly4k/Certipy) — ADCS abuse toolkit (likely already starred under different basename — verify)
- `dploot` — [zblurx/dploot](https://github.com/zblurx/dploot) — DPAPI secret extraction at scale
- `linkedin2username` — [initstring/linkedin2username](https://github.com/initstring/linkedin2username) — usernames from LinkedIn for password spraying
- `shimit` — [cyberark/shimit](https://github.com/cyberark/shimit) — Golden ticket forging for Kerberos
- `windapsearch` / `ldeep` — verify both are starred

### → Bug Bounty and Web Application Reconnaissance
- `assetfinder` — [tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) — passive subdomain enumeration
- `crlfuzz` — [dwisiswant0/crlfuzz](https://github.com/dwisiswant0/crlfuzz) — CRLF injection scanner
- `dnsgen` — [ProjectAnte/dnsgen](https://github.com/ProjectAnte/dnsgen) — wordlist mutation for subdomain bruteforcing
- `feroxbuster` — [epi052/feroxbuster](https://github.com/epi052/feroxbuster) — Rust content discovery
- `findomain` — [Findomain/Findomain](https://github.com/Findomain/Findomain) — fast cross-platform subdomain enumerator
- `getallurls` (`gau`) — [lc/gau](https://github.com/lc/gau) — fetches URLs from AlienVault OTX, Wayback, Common Crawl
- `gospider` — [jaeles-project/gospider](https://github.com/jaeles-project/gospider) — fast web spider in Go
- `goshs` — [patrickhener/goshs](https://github.com/patrickhener/goshs) — replacement for SimpleHTTPServer with auth and TLS
- `hurl` — [Orange-Cyberdefense/hurl](https://github.com/Orange-Cyberdefense/hurl) — HTTP request sender
- `jsql-injection` — [ron190/jsql-injection](https://github.com/ron190/jsql-injection) — Java SQL injection tool
- `subzy` — [LukaSikic/subzy](https://github.com/LukaSikic/subzy) — subdomain takeover scanner
- `urlcrazy` — [urbanadventurer/urlcrazy](https://github.com/urbanadventurer/urlcrazy) — typo-domain generator
- `waybackurls` — [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) — Wayback Machine URL extraction
- `xsstrike` — [s0md3v/XSStrike](https://github.com/s0md3v/XSStrike) — XSS detection suite (verify — possibly starred)

### → Cloud and Container Security
- `cloudbrute` — [0xsha/CloudBrute](https://github.com/0xsha/CloudBrute) — multi-cloud asset enumeration
- `dufflebag` — [BishopFox/dufflebag](https://github.com/BishopFox/dufflebag) — search public EBS snapshots for secrets
- `kubectl` / `eksctl` / `cilium-cli` / `calico` — kubernetes tooling, may be deliberately omitted

### → Command-and-Control and Post-Exploitation Frameworks
- `adaptixc2` — [Adaptix-Framework/AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2) — C2 framework
- `koadic` — [offsecginger/koadic](https://github.com/offsecginger/koadic) — JScript RAT
- `nishang` — [samratashok/nishang](https://github.com/samratashok/nishang) — PowerShell offensive scripts
- `powercat` — [besimorhino/powercat](https://github.com/besimorhino/powercat) — PowerShell netcat
- `powersploit` — [PowerShellMafia/PowerSploit](https://github.com/PowerShellMafia/PowerSploit) — classic PS post-exploit
- `silenttrinity` — [byt3bl33d3r/SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) — .NET / IronPython C2

### → Cybersecurity Learning Resources and Catalogs
- `linux-exploit-suggester` — [mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) — local privesc auditor
- `linuxprivchecker` — [sleventyeleven/linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker) — script-based linux audit
- `windows-exploit-suggester` — [AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- `xss-payload-list` — [payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list)

### → Detection Engineering and Analytics
- `chainsaw` — [WithSecureLabs/chainsaw](https://github.com/WithSecureLabs/chainsaw) — fast Sigma-based event log triage (verify — high-priority)
- `loki` — [Neo23x0/Loki](https://github.com/Neo23x0/Loki) — Florian Roth's IOC scanner

### → Digital Forensics and Incident Response
- `bulk-extractor` — [simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)
- `kape` — Eric Zimmerman tooling already covered; verify KAPE specifically
- `regripper` — [keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0) — registry parser
- `samdump2` — old but still shipped
- `volatility-cmt` — [volatilityfoundation/community](https://github.com/volatilityfoundation/community) — Volatility plugin community

### → Email Security and Anti-Phishing
- `swaks` — [jetmore/swaks](https://github.com/jetmore/swaks) — SMTP swiss-army knife
- `phishery` — [ryhanson/phishery](https://github.com/ryhanson/phishery) — basic auth phishing for docs

### → Malware Analysis and Reverse Engineering
- `bytecode-viewer` — [Konloch/bytecode-viewer](https://github.com/Konloch/bytecode-viewer) — Java disassembler
- `manticore` — [trailofbits/manticore](https://github.com/trailofbits/manticore) — symbolic execution
- `pdfid` / `pdfparser` — [DidierStevens/DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite) — PDF triage
- `peepdf` — [jesparza/peepdf](https://github.com/jesparza/peepdf) — PDF analysis
- `radare2-cutter` — [rizinorg/cutter](https://github.com/rizinorg/cutter) — Qt disassembler GUI
- `stringsifter` — [mandiant/stringsifter](https://github.com/mandiant/stringsifter) — ML-ranked strings

### → OSINT and External Reconnaissance
- `cewl` — [digininja/CeWL](https://github.com/digininja/CeWL) — wordlist scraper
- `email2phonenumber` — [martinvigo/email2phonenumber](https://github.com/martinvigo/email2phonenumber)
- `metagoofil` — [laramies/metagoofil](https://github.com/laramies/metagoofil) — file metadata scraper
- `osrframework` — [i3visio/osrframework](https://github.com/i3visio/osrframework) — OSINT framework
- `pwndb` — [davidtavarez/pwndb](https://github.com/davidtavarez/pwndb) — leaked credential search

### → Wireless Security (slated for new List)
- `eaphammer` — [s0lst1c3/eaphammer](https://github.com/s0lst1c3/eaphammer) — WPA2-Enterprise targeted attacks
- `fluxion` — [FluxionNetwork/fluxion](https://github.com/FluxionNetwork/fluxion) — automated WPA evil twin
- `hcxdumptool` / `hcxtools` — [ZerBea/hcxdumptool](https://github.com/ZerBea/hcxdumptool) — modern WPA capture
- `hostapd-mana` — [sensepost/hostapd-mana](https://github.com/sensepost/hostapd-mana) — Mana rogue AP
- `pixiewps` — [wiire-a/pixiewps](https://github.com/wiire-a/pixiewps) — WPS pixie-dust attack
- `wifite2` — [derv82/wifite2](https://github.com/derv82/wifite2) — automated WPA cracking
- `airgeddon` — already covered

### → Application Security (SAST/DAST/AppSec)
- `graudit` — [wireghoul/graudit](https://github.com/wireghoul/graudit) — grep-based source auditor
- `ssh-audit` — [jtesta/ssh-audit](https://github.com/jtesta/ssh-audit) — SSH config auditor
- `sslyze` — [nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) — TLS scanner
- `testssl.sh` — [drwetter/testssl.sh](https://github.com/drwetter/testssl.sh) — TLS scanner (verify)
- `whatweb` — [urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb) — web fingerprinter
- `wfuzz` — [xmendez/wfuzz](https://github.com/xmendez/wfuzz) — web fuzzer
- `tplmap` — [epinna/tplmap](https://github.com/epinna/tplmap) — server-side template injection
- `weevely` — [epinna/weevely3](https://github.com/epinna/weevely3) — PHP webshell
- `joomscan` — [OWASP/joomscan](https://github.com/OWASP/joomscan)
- `skipfish` — abandoned; skip

## Out of scope: explicit non-additions

The following Kali-shipped tools are **deliberately excluded** from the worth-adding queue. Listing them here is the "show your work" half of the analysis.

- **Distro packages and OS components** — `apache2`, `bind9`, `bluez`, `bpf-linker`, `cabextract`, `capstone` (library), `chromium`, `cifs-utils`, `code-oss`, `cri-tools`, `cryptsetup`, `curl`, `dbeaver`, `ddrescue`, `dos2unix`, `expect`, `ethtool`, `fping`, `freeradius`, `freerdp3`, `fuse3`, `gdb`, `gdisk`, `git`, `glibc`, `gnuradio`, `gpart`, `gparted`, `gqrx-sdr`, `httrack`, `hwloc`, `i2c-tools`, `iputils`, `lftp`, `mingw-w64`, `minicom`, `mysql`, `nano`, `nasm`, `ncat`, `netcat-openbsd`, `netcat-traditional`, `network-manager-openvpn`, `notepadqq`, `nautilus-extension-gnome-terminal`, `parted`, `pkexec`, `pluma`, `poppler-utils`, `postgresql`, `proxychains4`, `python3`, `rdesktop`, `remmina`, `rng-tools`, `rsync`, `samba`, `scrcpy`, `socat`, `sshfs`, `strace`, `syslog-ng`, `tcl`, `texlive`, `thunderbird`, `tilix`, `tmux`, `tor-browser`, `torbrowser-launcher`, `ttf-bitstream-vera`, `unrar`, `upx`, `vagrant`, `vsftpd`, `wkhtmltopdf`, `wsl`, `xdotool`, `xfreerdp`, `zsh-autosuggestions`, `zsh-syntax-highlighting`. These belong in package management, not in a curated security-tools index.

- **Commercial / closed source** — `burpsuite`, `maltego`, `jeb-ce`, `nessus` (not in Kali default but referenced). The free trials live in the user's licence list, not the Stars Lists.

- **Deprecated / no commit activity in 5+ years** — `b374k`, `cisco7crack`, `cisco-ocs`, `cisco-torch`, `cisco-global-exploiter`, `copy-router-config`, `cutycapt`, `dbd`, `dhcpig`, `dirb`, `dirbuster`, `dnsmap`, `dns2tcp` (verify), `doona`, `dotdotpwn`, `enumiax`, `fierce`, `fiked`, `firmware-mod-kit`, `framework2`, `ftester`, `goldeneye`, `goofile`, `inetsim`, `intersect`, `intrace`, `ismtp`, `isr-evilgrade`, `joomscan` (slow), `kalibrate-rtl`, `magicrescue`, `medusa`, `mfcuk`, `mfoc`, `mfterm`, `miredo`, `missidentify`, `multimac`, `multimon-ng`, `ndiff`, `netdiscover` (verify), `nipper-ng`, `ohrwurm`, `ollydbg`, `ollydbg2`, `onesixtyone` (revived?), `parsero`, `pcaplookup`, `pdf-id`, `polenum`, `proxytunnel`, `psad`, `pst-utils`, `randomgenerator`, `rcracki-mt`, `rebind`, `redfang`, `regdump`, `rkhunter` (slow upstream), `rlogin-rcp-rsh`, `rsmangler`, `sakis3g`, `sbd`, `sca`, `scalpel`, `secure-delete`, `serpico`, `set` (Social Engineering Toolkit — verify), `shellnoob`, `shellter`, `siege`, `sipsak`, `slowhttptest`, `smbnetfs`, `smtp-user-enum`, `sniffjoke`, `snmpcheck`, `solfege`, `spike`, `sqlninja`, `sqlsus`, `ssss`, `stf`, `tachyon`, `tcpkill`, `thc-pptp-bruter`, `thc-ssl-dos`, `tnscmd10g`, `udptunnel`, `uniscan`, `vega`, `voipong`, `volume_key`, `webacoo`, `webscarab`, `websploit`, `wig`, `winexe`, `wnaf-tools`, `xerosploit`, `xprobe`, `xspy`, `xsser`, `yersinia`, `zerologon` (POC — research interest only). Triage by activity, not nostalgia.

## What this analysis is good for

- **Defending the curation against "you don't have X" challenges.** When someone asks "where's `feroxbuster`?" the answer is here, in the worth-adding queue, with a triage rationale.
- **Avoiding curation drift.** Mass-starring all 547 uncovered Kali tools would inflate the catalogue by 50% overnight with mostly distro-package noise. This document is the explicit decision *not* to do that.
- **Operating as a planning artifact.** The worth-adding queue is the next-actions list for the Stars Lists — additions go through the same classifier (`smart_categorize.py`) and bulk-add pipeline documented in [Field Notes](FIELD_NOTES.md).

## Adjacent reference distributions

Kali is one of three offensive-security baselines in regular use:

| Distro | Audience | Notes on coverage |
|---|---|---|
| [Kali Linux](https://www.kali.org/tools/all-tools/) | Offensive security generalist | Surveyed in this document |
| [Mandiant Commando VM](https://github.com/mandiant/commando-vm) | Windows-based offensive operations | The repo itself is starred; its package manifest overlaps heavily with `Active Directory Offensive Operations` and `Command-and-Control and Post-Exploitation Frameworks` Lists |
| [REMnux](https://github.com/REMnux) | Malware analysis Linux distro | The `Malware Analysis and Reverse Engineering` List covers REMnux's high-value upstream projects (CAPEv2, FLARE-FLOSS, capa, Volatility, YARA) |

---

*Last surveyed: 2026-04-17. Kali rolls forward; new tools are added every release. Re-survey quarterly or when a major Kali point release ships.*
