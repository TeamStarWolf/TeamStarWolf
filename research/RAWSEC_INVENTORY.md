# Rawsec Cybersecurity Inventory — Tools Reference

Curated tool index sourced from [Rawsec's CyberSecurity Inventory](https://inventory.raw.pm/) — a community-maintained catalog of 1,200+ security tools. Last synced April 2026.

> For the complete, up-to-date tool list visit [inventory.raw.pm](https://inventory.raw.pm/). The API is available at .

---

## Tool Categories

| Category | Tools in Index |
|---|---|
| [Red Teaming & Adversary Simulation](#red-teaming-adversary-simulation) | 15 shown of 88 total |
| [System & Network Exploitation](#system-network-exploitation) | 15 shown of 50 total |
| [Web Application Exploitation](#web-application-exploitation) | 20 shown of 241 total |
| [Reverse Engineering](#reverse-engineering) | 18 shown of 99 total |
| [Digital Forensics](#digital-forensics) | 15 shown of 20 total |
| [Incident Response](#incident-response) | 12 shown of 17 total |
| [OSINT & Reconnaissance](#osint-reconnaissance) | 20 shown of 120 total |
| [Cloud Security](#cloud-security) | 15 shown of 19 total |
| [Code Analysis & SAST/DAST](#code-analysis-sastdast) | 15 shown of 25 total |
| [Vulnerability Assessment](#vulnerability-assessment) | 10 shown of 11 total |
| [Threat Intelligence](#threat-intelligence) | 12 shown of 16 total |
| [Password Cracking & Hash Analysis](#password-cracking-hash-analysis) | 12 shown of 54 total |
| [Cryptography](#cryptography) | 10 shown of 19 total |
| [Networking & Traffic Analysis](#networking-traffic-analysis) | 15 shown of 173 total |
| [Defensive & Hardening](#defensive-hardening) | 12 shown of 20 total |
| [Honeypots & Deception](#honeypots-deception) | 7 shown of 7 total |
| [Binary Exploitation](#binary-exploitation) | 6 shown of 6 total |
| [Steganography](#steganography) | 10 shown of 17 total |
| [Wireless Security](#wireless-security) | 12 shown of 23 total |
| [Intentionally Vulnerable Applications](#intentionally-vulnerable-applications) | 14 shown of 16 total |

---

## Red Teaming & Adversary Simulation

| Tool | Language | Price | Description |
|---|---|---|---|
| [221b](https://github.com/CMEPW/221b) | Go | Free | Bake a windows payload from the C2 of your choice to bypass AV |
| [AVET](https://github.com/govolution/avet) |  | Free | AntiVirus Evasion Tool; targeting windows machines with executable files |
| [BadExclusions](https://github.com/iamagarre/BadExclusions) | CPlusPlus | Free | Identify folder custom or undocumented exclusions on AV/EDR |
| [BadExclusionsNWBO](https://github.com/iamagarre/BadExclusionsNWBO) | CPlusPlus | Free | Identify folder custom or undocumented exclusions on AV/EDR; evolution of BadExclusions but with better opsec |
| [BOF.NET](https://github.com/CCob/BOF.NET) | CSharp | Free | A .NET Runtime for Cobalt Strike's Beacon Object Files |
| [Brute Ratel](https://bruteratel.com/) |  | Paid | Command & Control server; DNS over HTTPS, external channels, indirect syscalls |
| [CarbonCopy](https://github.com/paranoidninja/CarbonCopy) | Python | Free | Create a spoofed certificate of any online website and signs an executable for AV Evasion; works for Windows a |
| [ConfuserEx](https://github.com/mkaring/ConfuserEx) | CSharp | Free | Protector for .NET applications |
| [Cortex XDR Config Extractor](https://github.com/Laokoon-SecurITy/Cortex-XDR-Config-Extractor) | Python | Free | Parse the Database Lock Files of the Cortex XDR Agent by Palo Alto Networks and extract Agent Settings, the Ha |
| [Covenant](https://github.com/cobbr/Covenant) | CSharp | Free | Command & Control framework with multi-user collaboration |
| [CredMaster](https://github.com/knavesec/CredMaster) | Python | Free | Password spraying, uses FireProx APIs to rotate IP addresses, stay anonymous, and beat throttling |
| [CSSG](https://github.com/RCStep/CSSG) | Python | Free | Cobalt Strike Shellcode Generator; script used to more easily generate and format beacon shellcode in Cobalt S |
| [dnscat2](https://github.com/iagox86/dnscat2) | Ruby | Free | DNS tunnel meant for encrypted Command & Control channel, data exfiltration |
| [Donut](https://github.com/TheWover/donut) | C | Free | Generates x86_32, x86_64, or AMD64 position-independent shellcode that loads .NET Assemblies, PE files (EXE),  |
| [EDRSilencer](https://github.com/netero1010/EDRSilencer) | C | Free | Uses Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting sec |

> Showing 15 of 88 tools. See [full list](https://inventory.raw.pm/) for more.

---

## System & Network Exploitation

| Tool | Language | Price | Description |
|---|---|---|---|
| [abuseACL](https://github.com/AetherBlack/abuseACL) | Python | Free | Automatically list vulnerable Windows ACEs/ACLs using DC's LDAP to list users/groups/computers/OU/certificate  |
| [aclpwn](https://github.com/fox-it/aclpwn.py) | Python | Free | Interacts with BloodHound to identify and exploit ACL based privilege escalation paths |
| [ADFSDump](https://github.com/mandiant/ADFSDump) | CSharp | Free | Read information from Active Directory and ADFS Configuration Database; fed information into ADFSpoof to gener |
| [ADFSpoof](https://github.com/mandiant/ADFSpoof) | Python | Free | Using ADFSDump information, produce a usable key/cert pair for token signing, produce a signed security token  |
| [Android_Emuroot](https://github.com/airbus-seclab/android_emuroot) | Python | Free | Grants root privileges on the fly to shells running on Android virtual machines that use google-provided emula |
| [bkhive](https://sourceforge.net/projects/ophcrack/files/) |  | Free | Dump the syskey bootkey from a Windows NT/2K/XP system hive, often used with samdump2, part of the ophcrack pr |
| [CoercedPotato](https://github.com/Prepouce/CoercedPotato) | C | Free | Elevation of privileges automated exploitation using SeImpersonatePrivilege or SeImpersonatePrimaryToken |
| [cookie_crimes](https://mango.pdf.zone/stealing-chrome-cookies-without-a-password) | Python | Free | Read local Chrome cookies without root or decrypting and display then in JSON |
| [CookieCrimesJS](https://github.com/clr2of8/CookieCrimesJS) | JavaScript | Free | Read local Chrome cookies without root or decrypting and display then in JSON; Javascript implementation of co |
| [creddump](https://github.com/moyix/creddump) | Python | Free | Dump windows credentials |
| [DCOMrade](https://github.com/sud0woodo/DCOMrade) | PowerShell | Free | Script that is able to enumerate the possible vulnerable DCOM applications that might allow for lateral moveme |
| [DLLInjector](https://github.com/OpenSecurityResearch/dllinjector) | CPlusPlus | Free | Dll injection tool |
| [DLLPasswordFilterImplant](https://github.com/GoSecure/DLLPasswordFilterImplant) | C | Free | Password filter DLL, triggered on password change to exfiltrate credentials |
| [DonPAPI](https://github.com/login-securite/DonPAPI) | Python | Free | Dumping DPAPI credentials remotely; dumps relevant information on compromised targets without AV detection |
| [Empire](https://github.com/EmpireProject/Empire) | Shell | Free | PowerShell and Python post-exploitation agent |

> Showing 15 of 50 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Web Application Exploitation

| Tool | Language | Price | Description |
|---|---|---|---|
| [0d1n](https://github.com/CoolerVoid/0d1n) | C | Free | Automate customized attacks against web applications |
| [1u.ms](http:/1u.ms) | Go | Free | zero-configuration DNS utilities for assisting in detection and exploitation of SSRF-related vulnerabilities |
| [230-OOB](http://xxe.sh/) | Python | Free | FTP server for OOB XXE attacks |
| [Acunetix](https://www.acunetix.com/) |  | Paid | Web application security scanner |
| [afrog](https://github.com/zan8in/afrog) | Go | Free | Web vulnerability scanner, based on templates |
| [Afuzz](https://github.com/RapidDNS/Afuzz) | Python | Free | Web directory and file scanner (wordlist bruteforce) |
| [altair](https://github.com/evilsocket/altair) | Python | Free | Modular web vulnerability scanner |
| [API-fuzzer](https://github.com/Fuzzapi/API-fuzzer) | Ruby | Free | Library to fuzz request attributes using common pentesting techniques and lists vulnerabilities |
| [Aquatone](https://michenriksen.com/blog/aquatone-now-in-go/) | Go | Free | Domain flyover tool; visual inspection of websites across a large amount of hosts and is convenient for quickl |
| [Arachni](http://www.arachni-scanner.com/) | Ruby | Free | Web application security scanner framework |
| [Arjun](https://github.com/s0md3v/Arjun) | Python | Free | HTTP parameter discovery suite |
| [AssassinGo](https://github.com/AmyangXYZ/AssassinGo) | Go | Free | Web pentest framework for information gathering and vulnerability scanning |
| [Astra](https://github.com/flipkart-incubator/astra) | Python | Free | REST API penetration testing tool |
| [Atlas](https://github.com/m4ll0k/Atlas) | Python | Free | Tool that suggests sqlmap tampers to bypass WAF/IDS/IPS based on status codes |
| [b374k](https://github.com/b374k/b374k) | PHP | Free | Webshell with many features: file manager, search, command execution, DB connection, SQL explorer, process lis |
| [badsecrets](https://github.com/blacklanternsecurity/badsecrets) | Python | Free | A library for detecting known or weak cryptographic secrets across many web frameworks |
| [BaRMIe](https://github.com/NickstaDB/BaRMIe) | Java | Free | Java RMI enumeration and attack tool |
| [Beeceptor](https://beeceptor.com/) |  | Paid | HTTP request collector and inspector |
| [BeEF](https://beefproject.com/) | Ruby | Free | Browser exploitation framework; JS payload and supporting software to be used as XSS payload or post exploitat |
| [BFAC](https://github.com/mazen160/bfac) | Python | Free | Backup File Artifacts Checker; automated backup artifacts checker |

> Showing 20 of 241 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Reverse Engineering

| Tool | Language | Price | Description |
|---|---|---|---|
| [androguard](https://github.com/androguard/androguard) | Python | Free | Tool for reverse engineering and malware analysis of Android applications |
| [angr](https://github.com/angr/angr) | Python | Free | Platform-agnostic binary analysis framework |
| [ANY RUN](https://any.run/) |  | Free | Online virtual machine for malware hunting, sandbox with interactive access, real-time data-flow |
| [Apk2Gold](https://github.com/lxdvs/apk2gold) | Shell | Free | Android decompiler (wrapper for apktool, dex2jar, and jd-gui) |
| [Apktool](https://ibotpeaches.github.io/Apktool/) | Java | Free | Android disassembler and rebuilder |
| [arm_now](https://github.com/nongiach/arm_now) | Python | Free | Tool that allows instant setup of virtual machines on various architectures for reverse, exploit, fuzzing and  |
| [Barf](https://github.com/programa-stic/barf-project) | Python | Free | Binary Analysis and Reverse engineering Framework |
| [BinDiff](https://github.com/google/bindiff) | CPlusPlus | Free | Binary diffing for many architectures compatible with IDA Pro, Binary Ninja and Ghidra |
| [BOF launcher](https://github.com/The-Z-Labs/bof-launcher) | Zig | Free | Beacon Object File (BOF) launcher; library for executing BOF files in C/C++/Zig applications |
| [bearparser](https://hshrzd.wordpress.com/pe-bear/) | CPlusPlus | Free | PE parsing library (from PE-bear) |
| [Binary Ninja](https://binary.ninja/) | Python | Paid | Crossplatform binary analysis framework |
| [binbloom](https://github.com/quarkslab/binbloom) | C | Free | Raw binary firmware analysis software; tries to determine the firmware loading address |
| [BinCAT](https://github.com/airbus-seclab/bincat) | OCaml | Free | Binary code static analyser, with IDA integration; performs value and taint analysis, type reconstruction, use |
| [binutils](https://www.gnu.org/software/binutils/binutils.html) | C | Free | GNU collection of binary tools |
| [binwalk](https://github.com/devttys0/binwalk) | Python | Free | Analyze, reverse engineer and extract firmware images (and other files, also usefull for Digital Forensics) |
| [Dexcalibur](https://www.reversense.com/dexcalibur) | JavaScript | Paid | Android reverse engineering platform focus on instrumentation automation (decompile/disass intercepted bytecod |
| [boomerang](https://github.com/nemerle/boomerang) | CPlusPlus | Free | x86 binaries to C decompiler |
| [CAPEv2](https://capesandbox.com/) | Python | Free | Malware sandbox derived from Cuckoo with the goal of adding automated malware unpacking, config and payload ex |

> Showing 18 of 99 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Digital Forensics

| Tool | Language | Price | Description |
|---|---|---|---|
| [Andriller](https://github.com/den4uk/andriller) | Python | Free | Software utility with a collection of forensic tools for smartphones; performs read-only, non-destructive acqu |
| [Cerbero Profiler](http://cerbero.io/profiler/) |  | Paid | File analyzer and inspector |
| [ds_store_exp](https://github.com/lijiejie/ds_store_exp) | Python | Free | Extract files from .DS_Store recursively |
| [EML analyzer](https://eml-analyzer.herokuapp.com/) | Python | Free | Analyze EML files: headers, bodies, attachments; extract IOCs; identify suspicious attachments |
| [ExifTool](http://www.sno.phy.queensu.ca/%7Ephil/exiftool/) | Perl | Free | Library and CLI tool for reading, writing and editing metadata for a lot of file types |
| [extundelete](http://extundelete.sourceforge.net/) |  | Free | Tool to recover deleted files from an ext3 or ext4 partition |
| [Fibratus](https://github.com/rabbitstack/fibratus) | Python | Free | Tool for exploration and tracing of the Windows kernel |
| [Foremost](http://foremost.sourceforge.net/) |  | Free | CLI tool to recover files based on their headers, footers, and internal data structures |
| [ForensicMiner](https://github.com/securityjoes/ForensicMiner) | PowerShell | Free | DFIR automation for collecting and analyzing evidence |
| [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager) |  | Paid | Investigate electronic devices; full disk imaging capabilities: preview and image hard drives from Windows and |
| [Live Forensicator](https://github.com/Johnng007/Live-Forensicator) | PowerShell | Free | Assist forensic investigators and incidence responders in carrying out a quick live forensic investigation |
| [MVT](https://mvt.re/) | Python | Free | Mobile Verification Toolkit; collection of utilities to simplify and automate the process of gathering forensi |
| [rekall](https://github.com/google/rekall) | Python | Free | Volatile memory extraction utility |
| [rekall (Fireeye fork)](https://github.com/fireeye/win10_rekall) | Python | Free | Fork of rekall with support for Windows 10 memory compression |
| [ResourcesExtract](http://www.nirsoft.net/utils/resources_extract.html) |  | Free | Scans dll/ocx/exe files and extract all resources found, Windows only |

> Showing 15 of 20 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Incident Response

| Tool | Language | Price | Description |
|---|---|---|---|
| [DFIR ORC](https://dfir-orc.github.io/) | CPlusPlus | Free | Forensics artefact collection tool for systems running Microsoft Windows |
| [DFIRTrack](https://github.com/stuhli/dfirtrack) | Python | Free | Incident response tracking web application, focused on handling one major incident with a lot of affected syst |
| [Fenrir](https://github.com/Neo23x0/Fenrir) | Shell | Free | IOC scanner |
| [IntelMQ](https://github.com/certtools/intelmq) | Python | Free | Solution for collecting and processing security feeds using a message queuing protocol |
| [IRIS](https://docs.dfir-iris.org/) | Python | Free | Collaborative platform aiming to help incident responders sharing technical details during investigations |
| [Loki](https://github.com/Neo23x0/Loki/) | Python | Free | IOC scanner |
| [Munin](https://github.com/Neo23x0/munin) | Python | Free | Online hash checker for Virustotal and other services |
| [Osquery](https://osquery.io/) | CPlusPlus | Free | Uses SQL queries to monitor and analyze operating systems, providing endpoint visibility for security |
| [SCOT](http://getscot.sandia.gov/) | Perl | Free | Sandia Cyber Omni Tracker; cyber security incident response management system and knowledge base |
| [Sigma](https://github.com/SigmaHQ/sigma) | Python | Free | Generic signature format for SIEM systems |
| [ThreatHound](https://github.com/MazX0p/ThreatHound) | Python | Free | Windows event log file viewer and analyser |
| [uncoder.io](https://uncoder.io/) |  | Free | Translate sigma rules into various SIEM, EDR, and XDR formats |

> Showing 12 of 17 tools. See [full list](https://inventory.raw.pm/) for more.

---

## OSINT & Reconnaissance

| Tool | Language | Price | Description |
|---|---|---|---|
| [alterx](https://github.com/projectdiscovery/alterx) | Go | Free | Customizable subdomain wordlist generator using DSL |
| [Amass](https://www.owasp.org/index.php/OWASP_Amass_Project) | Go | Free | DNS enumeration and network mapping tool suite: scraping, recursive brute forcing, crawling web archives, reve |
| [Argus](https://github.com/jasonxtn/Argus) | Python | Free | All-in-one toolkit for information gathering and reconnaissance |
| [Ars0n Framework](https://github.com/R-s0n/ars0n-framework) | JavaScript | Free | Bug bounty hunting framework to automate the reconnaissance in a WebUI |
| [Ars0n Framework v2](https://github.com/R-s0n/ars0n-framework-v2) | JavaScript | Free | Bug bounty hunting framework to automate the reconnaissance in a WebUI |
| [Asnlookup](https://github.com/yassineaboukir/Asnlookup) | Python | Free | Leverage ASN to look up IP addresses (IPv4 & IPv6) owned by a specific organization for reconnaissance purpose |
| [AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper) | Python | Free | Subdomain enumerator |
| [AutoRecon](https://github.com/Tib3rius/AutoRecon) | Python | Free | Multi-threaded network reconnaissance tool which performs automated enumeration of services |
| [badKarma](https://github.com/r3vn/badKarma) | Python | Free | Advanced network reconnaissance tool |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | Python | Free | OSINT framework; subdomain enumeration, port scanning, web screenshots, vulnerability scanning |
| [Belati](https://github.com/aancw/Belati) | Python | Free | OSINT tool, collect data and document actively or passively |
| [Bitcrook](https://github.com/ax-i-om/bitcrook) | Go | Free | Reconnaissance Apparatus; Information gathering, conglomerate of tools including custom algorithms, API wrappe |
| [cariddi](https://github.com/edoardottt/cariddi) | Go | Free | Takes a list of domains, crawls urls and scans for endpoints, secrets, api keys, file extensions, tokens |
| [Censys](https://search.censys.io/) |  | Paid | Search devices connected to the internet; helps find information about desktops, servers, IoT devices; includi |
| [Certstream](https://certstream.calidog.io/) | Elixir | Free | Intelligence feed that gives real-time updates from the Certificate Transparency Log network |
| [Darkshot](https://github.com/mxrch/darkshot) | Python | Free | Lightshot scraper with multi-threaded OCR and auto categorizing screenshots |
| [dataleaks](https://github.com/jeisonbeast/dataleaks) | PHP | Free | Self-hosted data breach search engine |
| [datasploit](https://github.com/DataSploit/datasploit) | Python | Free | OSINT framework, find, aggregate and export data |
| [DNSDumpster](https://dnsdumpster.com/) |  | Free | Domain research tool that can discover hosts related to a domain |
| [dnsenum](https://github.com/fwaeytens/dnsenum) | Perl | Free | DNS reconnaissance tool: AXFR, DNS records enumeration, subdomain bruteforce, range reverse lookup |

> Showing 20 of 120 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Cloud Security

| Tool | Language | Price | Description |
|---|---|---|---|
| [AWS Extender CLI](https://github.com/VirtueSecurity/aws-extender-cli) | Python | Free | Test S3 buckets as well as Google Storage buckets and Azure Storage containers for common misconfiguration iss |
| [aws_pwn](https://github.com/dagrz/aws_pwn/) | Python | Free | Collection of AWS penetration testing scripts |
| [AzSubEnum](https://github.com/yuyudhn/AzSubEnum) | Python | Free | Azure service subdomain enumeration |
| [AzureADRecon](https://github.com/adrecon/AzureADRecon) | PowerShell | Free | Gathers information about the Azure Active Directory and generates a report which can provide a holistic pictu |
| [AzureHound](https://github.com/SpecterOps/AzureHound) | Go | Free | BloodHound data collector for Microsoft Azure |
| [cloud-audit](https://github.com/gebalamariusz/cloud-audit) | Python | Free | AWS security scanner with 45 CIS benchmark checks across 15 services, copy-paste remediation (CLI + Terraform) |
| [CloudGPT](https://github.com/ustayready/cloudgpt) | Python | Free | Vulnerability scanner for AWS customer managed policies using ChatGPT |
| [CloudMapper](https://github.com/duo-labs/cloudmapper) | Python | Free | Analyze AWS environments auditing for security issues |
| [CloudTracker](https://github.com/duo-labs/cloudtracker) | Python | Free | Find over-privileged IAM users and roles by comparing CloudTrail logs with current IAM policies |
| [gato](https://github.com/praetorian-inc/gato) | Python | Free | Github Attack TOolkit; GitHub Actions pipeline enumeration and attacks |
| [gato-x](https://github.com/AdnaneKhan/gato-x) | Python | Free | Github Attack TOolkit - Extreme Edition; GitHub Actions pipeline enumeration and attacks |
| [gh-hijack-runner](https://github.com/synacktiv/gh-hijack-runner) | Python | Free | Create a fake GitHub runner and hijack pipeline jobs to leak CI/CD secrets |
| [IMDSpoof](https://github.com/grahamhelton/IMDSpoof) | Go | Free | Cyber deception; spoofs the AWS IMDS service to return HoneyTokens that can be alerted on |
| [octoscan](https://github.com/synacktiv/octoscan) | Go | Free | Static vulnerability scanner for GitHub action workflow |
| [Pacu](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/) | Python | Free | AWS exploitation framework |

> Showing 15 of 19 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Code Analysis & SAST/DAST

| Tool | Language | Price | Description |
|---|---|---|---|
| [Adhrit](https://github.com/abhi-r3v0/Adhrit) | Python | Free | Android APK reversing and analysis suite |
| [AndroBugs Framework](https://github.com/AndroBugs/AndroBugs_Framework) | Python | Free | Android APK vulnerability analyzer |
| [APKHunt](https://github.com/Cyber-Buddy/APKHunt) | Go | Free | Static code analysis for Android apps that is based on the OWASP MASVS framework |
| [APKLeaks](https://github.com/dwisiswant0/apkleaks) | Python | Free | Scanning APK file for URIs, endpoints and secrets |
| [Bearer](https://www.bearer.com) | Go | Free | Static application security testing tool that helps discover, filter, and prioritize security risks and vulner |
| [Brakeman](https://brakemanscanner.org/) | Ruby | Free | Static analysis security vulnerability scanner for Ruby on Rails applications |
| [cIFrex](https://cifrex.org) | PHP | Free | Regexp static code analysis |
| [CodeCat](https://github.com/timb-machine-mirrors/CoolerVoid-codecat/forks) | Python | Free | Automatic code static analysis tool to detect bugs and vulnerabilities |
| [CodeQL](https://codeql.github.com/) |  | Free | Semantic code analysis engine; discover vulnerabilities across a codebase, lets you query code as though it we |
| [Dawnscanner](https://github.com/thesp0nge/dawnscanner) | Ruby | Free | Static analysis security scanner for ruby written web applications; supports Sinatra, Padrino and Ruby on Rail |
| [grepmarx](https://github.com/Orange-Cyberdefense/grepmarx) | Python | Free | Source code static analysis platform with WebUI based on semgrep |
| [Joern](https://joern.io/) | Scala | Free | Code analysis platform for C/C++/Java/Binary/Javascript/Python/Kotlin based on code property graphs |
| [Kube-hunter](https://aquasecurity.github.io/kube-hunter/) | Python | Free | Scanner for security weaknesses in Kubernetes clusters |
| [LICMA](https://figshare.com/articles/software/LICMA_Language_Independent_Crypto-misuse_Analysis_with_a_Java_and_Python_analysis_component/16538568/1) | Java | Free | Language Independent Crypto-Misuse Analysis; multi-language analysis tool to identify incorrect initialization |
| [MobSF](https://mobsf.github.io/docs/) | Python | Free | Android APK vulnerability analyzer |

> Showing 15 of 25 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Vulnerability Assessment

| Tool | Language | Price | Description |
|---|---|---|---|
| [cve-search](https://github.com/cve-search/cve-search) | Python | Free | Tool to import CVE and CPE into a MongoDB to facilitate search and processing of CVEs |
| [CVEMap](https://github.com/projectdiscovery/cvemap) | Go | Free | CLI tool designed to provide a structured interface to various vulnerability databases |
| [cvss-suite](https://github.com/siemens/cvss-suite) | Ruby | Free | CVSS calculator library |
| [go-cve-dictionary](https://github.com/vulsio/go-cve-dictionary) | Go | Free | Self-hosted CVE feed server |
| [GVM](https://community.greenbone.net/t/about-gvm-architecture/1231) | C | Paid | The Greenbone Vulnerability Management (GVM) is a framework of several services: gvmd is the central service t |
| [nvd_feed_api](https://noraj.gitlab.io/nvd_api/) | Ruby | Free | A ruby API for NVD CVE feeds management, the library will help you to download and manage NVD Data Feeds, sear |
| [SECMON](https://github.com/alb-uss/SECMON) | Python | Free | Web-based platform for the automation of infosec watching and vulnerability management |
| [ThreatMapper](https://threatmapper.org/) | Go | Free | Identify vulnerabilities in running containers, images, hosts and repositories |
| [VRT Ruby Wrapper](https://bugcrowd.com/vrt) | Ruby | Free | Wrapper for the Vulnerability Rating Taxonomy |
| [Vulnogram](https://vulnogram.github.io/) | JavaScript | Free | Create and edit CVE information in CVE JSON format |

> Showing 10 of 11 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Threat Intelligence

| Tool | Language | Price | Description |
|---|---|---|---|
| [Intelligence X](https://intelx.io/) |  | Paid | Threat intelligence search engine: email addresses, domains, URLs, IPs, CIDRs, Bitcoin addresses, IPFS hashes, |
| [IsMalicious](https://ismalicious.com) |  | Paid | Malicious IP address and domain detection, classification and monitoring |
| [Hudson Rock Cybercrime Intelligence Tools](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) |  | Free | Cybercrime intelligence toolset to check if a specific digital asset was compromised in global infostealer mal |
| [Maltego](https://www.paterva.com/web7/buy/maltego-clients/maltego-ce.php) |  | Paid | Interactive data mining tool that renders directed graphs for link analysis. The tool is used in online invest |
| [MISP](https://www.misp-project.org/) | PHP | Free | Threat intelligence platform & open standards for threat information sharing (formerly known as Malware Inform |
| [Netglub](https://www.netglub.org/) |  | Free | Maltego alternative |
| [OpenCTI](https://filigran.io/solutions/products/opencti-threat-intelligence/) | TypeScript | Free | Platform designed for managing and analyzing cyber threat intelligence knowledge, centralizing data using the  |
| [PatrowlHears](https://patrowlhears.io/) | Python | Paid | Provides a unified source of vulnerability, exploit and threat Intelligence feeds; comprehensive and continuou |
| [Pulsedive](https://pulsedive.com/) |  | Free | CTI platform to search, scan, and enrich IPs, URLs, domains and other IOCs from OSINT feeds or submit your own |
| [Redirect Tracker](https://www.redirecttracker.com/) |  | Free | Track the HTTP redirect chains; 301 and 302, JavaScript and Meta fresh redirects |
| [sikkerapi.com](https://sikkerapi.com/) |  | Paid | IP reputation & threat intelligence, with behavioral data and published telemetry from honeypots |
| [threatfeeds.io](https://threatfeeds.io/) |  | Free | Open-source threat intelligence feeds; sharing malware URLs, IP reputation, bad IPs, etc. |

> Showing 12 of 16 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Password Cracking & Hash Analysis

| Tool | Language | Price | Description |
|---|---|---|---|
| [bkcrack](https://github.com/kimci86/bkcrack) | CPlusPlus | Free | Crack legacy zip encryption with Biham and Kocher's known plaintext attack |
| [BEWGor](https://github.com/berzerk0/BEWGor) | Python | Free | Bull's Eye Wordlist Generator, password wordlist generator based on target information |
| [Bopscrk](https://github.com/R3nt0n/bopscrk) | Python | Free | Before Outset PaSsword CRacKing, password wordlist generator with exclusive features like lyrics based mode |
| [CeWL](https://github.com/digininja/CeWL) | Ruby | Free | Custom wordlist generator based on website crawling |
| [ComPP](https://github.com/sec-it/ComPP) | Python | Free | Company Passwords Profiler helps making a bruteforce wordlist for a targeted company |
| [cook](https://github.com/giteshnxtlvl/cook) | Go | Free | Wordlist generator: create permutations and combinations of words with predefined sets of extensions, words an |
| [Cracken](https://github.com/shmuelamar/cracken) | Rust | Free | Password wordlist generator, Smartlist creation and password hybrid-mask |
| [CrackerJack](https://github.com/ctxis/crackerjack) | Python | Free | Hashcat WebUI; session management, mask generation, API, notifications, local and LDAP authentication |
| [Cracklord](http://jmmcatee.github.io/cracklord/) | Go | Free | Scalable, pluggable, and distributed system for hash cracking, supports Hashcat |
| [CrackQ](https://github.com/f0cker/crackq) | Python | Free | Hashcat cracking queue system, API and WebUI |
| [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) | C | Free | Multithreaded program to crack PKCS#12 files (p12 and pfx extensions) |
| [CrackStation](https://crackstation.net/) | PHP | Free | Pre-computed lookup tables to crack password hashes |

> Showing 12 of 54 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Cryptography

| Tool | Language | Price | Description |
|---|---|---|---|
| [c7decrypt](https://github.com/claudijd/c7decrypt) | Ruby | Free | Cisco password type-7 encryptor and decryptor |
| [Cipher Suite Info](https://ciphersuite.info/) | Python | Free | A searchable directory of TLS ciphersuites and related security details |
| [crypto-condor](https://quarkslab.github.io/crypto-condor/latest/index.html) | Python | Free | Compliance testing of implementations of cryptographic primitives |
| [CryptoGuard](https://github.com/CryptoGuardOSS/cryptoguard) | Java | Free | Program analysis tool to find cryptographic misuse in Java and Android |
| [crypto-identifier](https://github.com/Acceis/crypto_identifier) | Python | Free | Tool that try to identify what cipher is used and uncipher the data |
| [Crypton](https://github.com/ashutosh1206/Crypton) | Python | Free | Library consisting of explanation and implementation of all the existing attacks on various Encryption Systems |
| [CRYPTOREX](https://github.com/zhanglikernel/CRYPTOREX) | Python | Free |  Large-scale firmware analysis of cryptographic misuse in IoT devices; supports ARM, MIPS, MIPSel architetures |
| [Cryscanner](https://github.com/amit-choudhari/cryscanner) | Python | Free | Identify misuse of cryptographic libraries by collecting and analysing logs |
| [Dcode](http://www.dcode.fr/tools-list) |  | Free | Code and decode all kind of checksums, algorithms, codes or ciphers |
| [FeatherDuster](https://github.com/nccgroup/featherduster) | Python | Free | Cryptanalysis tool and library |

> Showing 10 of 19 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Networking & Traffic Analysis

| Tool | Language | Price | Description |
|---|---|---|---|
| [ActiveDirectoryEnumeration](https://github.com/CasperGN/ActiveDirectoryEnumeration) | Python | Free | Enumerate AD through LDAP with a collection of helpfull scripts being bundled: ASREPRoasting, Kerberoasting, d |
| [Adalanche](https://github.com/lkarlslund/Adalanche) | Go | Free | Active Directory ACL visualizer and explorer; similar to BloodHound |
| [AD Strider](https://github.com/PatchRequest/AD-Strider) | Go | Free | Automate the misconfigurations detectection in an Active Directory by analyzing data from Bloodhound |
| [ad-ldap-enum](https://github.com/CroweCybersecurity/ad-ldap-enum) | Python | Free | LDAP based Active Directory user and group enumeration tool |
| [ADCSKiller](https://github.com/grimlockx/ADCSKiller) | Python | Free | ADCS exploitation automation by weaponizing Certipy and Coercer |
| [ADenum](https://github.com/SecuProject/ADenum) | Python | Free | Find misconfiguration through the LDAP protocol and exploit some weaknesses with kerberos |
| [adfsbrute](https://github.com/ricardojoserf/adfsbrute) | Python | Free | Test credentials against Active Directory Federation Services (ADFS), allowing password spraying or bruteforce |
| [adidnsdump](https://github.com/dirkjanm/adidnsdump) | Python | Free | Enumeration and exporting of all DNS records in ADIDNS domain or forest DNS zones |
| [ADMiner](https://github.com/Mazars-Tech/AD_Miner) | Python | Free | Active Directory audit tool that extract data from Bloodhound to uncover security weaknesses and generate an H |
| [ADRecon](https://github.com/adrecon/ADRecon) | PowerShell | Free | Gathers information about the Active Directory and generates a report which can provide a holistic picture of  |
| [archtorify](https://github.com/brainfucksec/archtorify) | Shell | Free | Script for Arch Linux which use iptables settings to create a transparent proxy through Tor Network |
| [Arecibo](https://github.com/TarlogicSecurity/Arecibo) | Python | Free | Endpoint for Out-of-Band Exfiltration (DNS & HTTP) |
| [arp-scan](https://github.com/royhills/arp-scan) | C | Free | Discover hosts on your network using ARP requests |
| [ASNmap](https://github.com/projectdiscovery/asnmap) | Go | Free | CLI and Library for quickly mapping organization network ranges using ASN information |
| [beanshooter](https://github.com/qtc-de/beanshooter) | Java | Free | JMX enumeration and attacking; helps to identify common vulnerabilities on JMX endpoints |

> Showing 15 of 173 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Defensive & Hardening

| Tool | Language | Price | Description |
|---|---|---|---|
| [ADTimeline](https://github.com/ANSSI-FR/ADTimeline) | PowerShell | Free | Timeline of Active Directory changes with replication metadata |
| [AnoMark](https://github.com/ANSSI-FR/AnoMark) | Python | Free | Statistical learning algorithm to create a model on the command lines of the Process Creation events on Window |
| [BlueHound](https://github.com/zeronetworks/BlueHound) | TypeScript | Free | Helps blue teams pinpoint the security issues that actually matter by combining information about user permiss |
| [bom-view](https://github.com/hristiy4n/bom-view) | TypeScript | Free | Static web application for viewing SBOMs and performing on-demand vulnerability scanning with osv.dev |
| [DARKSURGEON](https://github.com/cryps1s/DARKSURGEON) | PowerShell | Free | Windows project to empower incident response, digital forensics, malware analysis, and network defense with Ha |
| [Deming](https://github.com/dbarzin/deming) | PHP | Free | Management tool for the information security management system (ISMS); manage, plan, track and report the effe |
| [DenyLocker](https://github.com/cert-cea/denylocker) | PowerShell | Free | Make the creation and maintenance of Applocker rules in blacklist mode easy and practical |
| [driftctl](https://github.com/snyk/driftctl) | Go | Free | Measures infrastructure as code coverage, and tracks infrastructure drift |
| [FalconHound](https://github.com/FalconForceTeam/FalconHound) | Go | Free | Plug BloodHound with a SIEM or other log aggregation |
| [GraphQL Armor](https://github.com/Escape-Technologies/graphql-armor) | TypeScript | Free | GraphQL security layer for Apollo and Yoga / Envelop servers |
| [Have I Been Squatted? - Twistr](https://www.haveibeensquatted.com/) | Rust | Free | Generate all permutations of a domain which are enriched for typosquatting detection |
| [Imagemagick Security Policy Evaluator](https://imagemagick-secevaluator.doyensec.com/) | JavaScript | Free | Allows developers and security experts to check if an Imagemagick XML Security Policy is hardened against a wi |

> Showing 12 of 20 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Honeypots & Deception

| Tool | Language | Price | Description |
|---|---|---|---|
| [broneypote](https://github.com/laluka/broneypote) | Python | Free | Honeypot |
| [Canarytokens](https://canarytokens.org/generate) | Python | Free | Quickly deployable honeypot with docker image, the online service allows to get alerted by email for URL token |
| [Coalmine](https://github.com/JohnEarle/coalmine) | Python | Free | Canary orchestration platform for deploying and managing canary objects in cloud infrastructure; manage the ca |
| [DejaVU](https://github.com/bhdresh/Dejavu) | PHP | Free | Deception framework which can be used to deploy decoys across the infrastructure |
| [Galah](https://github.com/0x4D31/galah) | Go | Free | LLM-powered web honeypot using the OpenAI API |
| [Honeyscanner](https://github.com/honeynet/honeyscanner) | Python | Free | Vulnerability analyzer for honeypots |
| [pypotomux](https://github.com/laluka/pypotomux) | Python | Free | Protocol demuxed honeypot and wordlists collected from it |

---

## Binary Exploitation

| Tool | Language | Price | Description |
|---|---|---|---|
| [ASLRay](https://github.com/cryptolok/ASLRay) | Shell | Free | Tool for ASLR bypass with stack-spraying |
| [heaphopper](https://github.com/angr/heaphopper) | Python | Free | Bounded model checking framework for Heap-implementations |
| [libformatstr](https://github.com/hellman/libformatstr) | Python | Free | Library to simplify format string exploitation |
| [pwntools](https://github.com/Gallopsled/pwntools) | Python | Free | Framework and exploit development library |
| [pwntools-ruby](https://github.com/peter50216/pwntools-ruby) | Ruby | Free | Framework and exploit development library, ported onto ruby |
| [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) | Python | Free | Framework for ROP exploitation |

---

## Steganography

| Tool | Language | Price | Description |
|---|---|---|---|
| [Aperi'Solve](https://aperisolve.fr/) | Python | Free | Steganalysis web platform with layer, zsteg, steghide and exiftool analysis |
| [Audacity](http://www.audacityteam.org/) |  | Free | Tool to edit and analyze audio tracks |
| [Depix](https://github.com/spipm/Depix) | Python | Free | Recover plaintext from pixelized screenshots |
| [exif](https://sourceforge.net/projects/libexif/files/exif/) | C | Free | Shows EXIF information for JPEG files only |
| [ExifTool](http://www.sno.phy.queensu.ca/~phil/exiftool/) | Perl | Free | Library and CLI tool to read and write meta information (EXIF, GPS, IPTC, XMP, JFIF, …) in files (JPEG, PNG, S |
| [Exiv2](http://www.exiv2.org/index.html) | CPlusPlus | Free | Library and CLI tool to read and write meta information (Exif, IPTC & XMP metadata and ICC Profile) in images  |
| [ImageMagick](http://www.imagemagick.org) | C | Free | Software suite and library to create, edit, compose, or convert images |
| Outguess |  | Free | Tool to hide messages in files (website down since 2004) |
| [SHIT](https://github.com/qll/shit) | Python | Free | Stego Helper Identification Tool, multi-purpose image steganography tool |
| [SmartDeblur](https://github.com/Y-Vladimir/SmartDeblur) | CPlusPlus | Free | To to restore defocused and blurred images (update binary only for Windows, Mac OS binary out of date) |

> Showing 10 of 17 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Wireless Security

| Tool | Language | Price | Description |
|---|---|---|---|
| [Aircrack-Ng](http://www.aircrack-ng.org/) | C | Free | Suite of tools to assess WiFi network security (cracking WEP and WPA PSK) |
| [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) | Shell | Free | Wireless network audit script |
| [BtleJack](https://github.com/virtualabs/btlejack) | Python | Free | Bluetooth Low Energy Swiss-army knife |
| [Crunch-Cracker](https://github.com/KURO-CODE/Crunch-Cracker) | Shell | Free | Wordlist generator and Wi-Fi cracker |
| [Fluxion](https://fluxionnetwork.github.io/fluxion/) | Shell | Free | MITM WPA attack tool |
| [FruityWiFi](https://github.com/xtr4nge/FruityWifi) | PHP | Free | Wireless network auditing tool controlled by a web interface |
| [Hijacker](https://github.com/chrisk44/Hijacker) | Java | Free | Android GUI for Aircrack, Airodump, Aireplay, MDK3 and Reaver |
| [Infernal-Wireless](https://github.com/entropy1337/infernal-twin) | Python | Free | Automated wireless hacking tool  |
| [intel-wifi-research-tools](https://github.com/Ledger-Donjon/intel-wifi-research-tools) | Python | Free | Research tools developed for Intel Wi-Fi chips : decode firmware files, communicate with the chip through Linu |
| [Kismet](https://www.kismetwireless.net/) | CPlusPlus | Free | Sniffer, WIDS, and wardriving tool for Wi-Fi, Bluetooth, Zigbee, RF |
| [MDK3-master](https://github.com/wi-fi-analyzer/mdk3-master) | C | Free | PoC tool to exploit common IEEE 802.11 protocol weaknesses |
| [MDK4](https://github.com/aircrack-ng/mdk4) | C | Free | PoC tool to exploit common IEEE 802.11 protocol weaknesses |

> Showing 12 of 23 tools. See [full list](https://inventory.raw.pm/) for more.

---

## Intentionally Vulnerable Applications

| Tool | Language | Price | Description |
|---|---|---|---|
| [Bodhi](https://github.com/amolnaik4/bodhi) | Python | Free | Client-side vulnerability playground, CTF style application, a bot program which simulates the real-world vict |
| [Bust-A-Kube](https://www.bustakube.com/) | PHP | Free | Intentionally-vulnerable Kubernetes cluster, intended to help people self-train on attacking and defending Kub |
| [bWAPP](http://www.itsecgames.com/) | PHP | Free | Buggy Web Application, insecure webapp for security trainings |
| [DVIA](http://damnvulnerableiosapp.com/) | Swift | Free | Damn Vulnerable iOS App, insecure webapp for mobile security trainings |
| [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | Python | Free | Damn Vulnerable GraphQL Application, insecure webapp for GraphQL security trainings |
| [DVWA](https://github.com/ethicalhack3r/DVWA) | PHP | Free | Damn Vulnerable Web Application, insecure webapp for security trainings |
| [Google Gruyere](http://google-gruyere.appspot.com) | Python | Free | Codelab for white-box and black-box hacking |
| [Hackazon](https://github.com/rapid7/hackazon) | PHP | Free | Intentionally vulnerable web shopping application using modern technologies and containing configurable areas |
| [Metasploitable](https://github.com/rapid7/metasploitable3) |  | Free | VM that is built from the ground up with a large amount of security vulnerabilities |
| [OopsSec Store](https://github.com/kOaDT/oss-oopssec-store) | JavaScript | Free | Intentionally vulnerable e-commerce application built with Next.js and React, REST API, solution documentation |
| [OWASP Juice Shop](http://owasp-juice.shop) | JavaScript | Free | Insecure web application with >85 challenges; supports CTFs, custom themes, tutorial mode etc. |
| [OWASP Mutillidae II](https://www.owasp.org/index.php/OWASP_Mutillidae_2_Project) | PHP | Free | Intentionally vulnerable web-application containing some OWASP Top Ten vulnerabilities, with hints and switch  |
| [OWASP WebGoat](https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project) | Java | Free | Deliberately insecure web application to teach web application security lessons |
| [simulator](https://github.com/controlplaneio/simulator) | Python | Free | Distributed systems and infrastructure simulator for attacking and debugging Kubernetes, creates a Kubernetes  |

> Showing 14 of 16 tools. See [full list](https://inventory.raw.pm/) for more.

---

## CTF Platforms

| Platform | Type | Price | Description |
|---|---|---|---|

---

## Training & Courses

| Resource | Price | Description |
|---|---|---|
| [API Security Academy](https://escape.tech/academy/) | Free | Platform dedicated to understand and secure GraphQL applications |
| [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/) | Free | Modules with slides, videos and sometimes labs to learn web security, by Bugcrowd |
| [CoursesOnline](https://www.coursesonline.co.uk/courses/cyber-security/) | Paid | Browse cyber security courses from a range of training providers, with options for beginners and tho |
| [Cybersecurity Guide](https://cybersecurityguide.org/) | Free | List of degree programs, scholarships, and certifications |
| [Cybrary](https://www.cybrary.it/) | Paid | Cyber Security learning, training and certification |
| [flAWS](http://flaws.cloud/) | Free | Learn about common mistakes and gotchas when using Amazon Web Services (AWS) from an offensive persp |
| [flAWS 2](http://flaws2.cloud/) | Free | Learn about common mistakes and gotchas when using Amazon Web Services (AWS) from an offensive and d |
| [Hacker101](https://www.hacker101.com/) | Free | Class for web security targeting bug bounty hunters and security professionals, with video lessons a |
| [Hextree](https://www.hextree.io/) | Paid | Hacking courses platform organized as micro learning |
| [ITonlinelearning](https://www.itonlinelearning.com/) | Paid | Training provider who offers certified online courses in IT, cyber security, and ethical hacking (Co |
| [OWASP Vulnerable Web Applications Directory](https://owasp.org/www-project-vulnerable-web-applications-directory/) | Free | Comprehensive and registry of all known vulnerable web applications currently available |
| [PentestAcademy](https://www.pentesteracademy.com/) | Paid | Cyber Security training with an online lab |
| [PentesterLab](https://pentesterlab.com/) | Paid | Pentest lab with exercises and videos: Unix, PCAP, HTTP, Code review, serialization, JWT, real vulne |
| [Portswigger Web Security Academy](https://portswigger.net/web-security) | Free | Web Security training with an online lab |
| [Pwned Labs](https://pwnedlabs.io/) | Paid | Cloud security labs |
| [SANS](https://www.sans.org/security-resources/) | Paid | Escal Institute of Advanced Technologies provides courses, certifications and learning materials |
| [The Learning People Cyber Security Courses](https://www.learningpeople.com/uk/courses/cyber-security-courses/) | Paid | Cyber security online learning courses |
| [Virtual Hacking Labs](https://www.virtualhackinglabs.com/labs/penetration-testing-lab/) | Paid | Pentest lab |

---

## Related Resources
- [Security Tools Reference](TOOLS.md) — TeamStarWolf curated tool matrix by category
- [Labs Reference](LABS.md) — hands-on practice platforms
- [HTB Learning Tracks](research/HTB_TRACKS.md) — structured HTB learning paths
- [Rawsec Live Inventory](https://inventory.raw.pm/) — full searchable tool database
- [Rawsec API](https://inventory.raw.pm/api/api.json) — JSON API for programmatic access