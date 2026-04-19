# Bug Bounty & Vulnerability Research

> Finding and responsibly disclosing security vulnerabilities in exchange for recognition or financial reward — the intersection of technical skill, legal frameworks, and researcher methodology.

## What Bug Bounty Hunters Do

- Conduct authorized security research against in-scope targets defined by program policies
- Identify and reproduce vulnerabilities: IDOR, SSRF, XSS, SQLi, auth bypass, RCE, logic flaws
- Write clear, reproducible proof-of-concept reports that triage teams can act on
- Navigate responsible disclosure and coordinated disclosure processes
- Work across web applications, APIs, mobile apps, cloud environments, and network services
- Build custom tooling and scripts to automate recon and vulnerability discovery
- Track disclosed CVEs and emerging vulnerability classes
- Participate in private programs, live hacking events (LHEs), and public programs

---

## Core Frameworks & Standards

| Framework | Purpose |
|---|---|
| [OWASP Testing Guide (OTG)](https://owasp.org/www-project-web-security-testing-guide/) | Web application security testing methodology |
| [Bug Bounty Hunter Methodology (Jason Haddix)](https://github.com/jhaddix/tbhm) | Community methodology guide |
| [PTES (Penetration Testing Execution Standard)](http://www.pentest-standard.org/) | General penetration testing methodology |
| [CVE / NVD](https://www.cve.org/) | Common Vulnerability naming standard |
| [CVSS](https://www.first.org/cvss/) | Common Vulnerability Scoring System |
| [ISO/IEC 29147](https://www.iso.org/standard/72311.html) | Vulnerability disclosure standard |
| [ISO/IEC 30111](https://www.iso.org/standard/69725.html) | Vulnerability handling processes |

---

## Bug Bounty Platforms

| Platform | Focus | Notes |
|---|---|---|
| [HackerOne](https://hackerone.com/) | Web, API, mobile, network | Largest platform; private + public programs |
| [Bugcrowd](https://bugcrowd.com/) | Web, API, mobile | Strong private program network |
| [Intigriti](https://www.intigriti.com/) | Web, API | EU-focused; growing rapidly |
| [Synack Red Team](https://www.synack.com/red-team/) | Invite-only, vetted | Higher payouts; curated researcher pool |
| [YesWeHack](https://www.yeswehack.com/) | Web, API, mobile | European platform |
| [Open Bug Bounty](https://www.openbugbounty.org/) | Web (XSS/CSRF focus) | Non-commercial; responsible disclosure |
| [Google Bug Hunters](https://bughunters.google.com/) | Google products | Android, GCP, Chrome, YouTube |
| [Microsoft Security Response Center](https://msrc.microsoft.com/bounty) | Microsoft products | Azure, M365, Windows, Edge |
| [Apple Security Research](https://security.apple.com/bounty/) | iOS, macOS, Safari | Up to $1M for critical iOS bugs |

---

## Free & Open-Source Tools

### Reconnaissance

| Tool | Purpose | Notes |
|---|---|---|
| [Amass](https://github.com/owasp-amass/amass) | Subdomain enumeration | OWASP; comprehensive recon |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery | Fast; uses many data sources |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probe | Probe subdomains for live hosts |
| [Shodan](https://www.shodan.io/) | Internet asset discovery | Find exposed services, ASN data |
| [Censys](https://search.censys.io/) | Internet scan data | Certificate transparency + port data |
| [crt.sh](https://crt.sh/) | Certificate transparency | Find subdomains from CT logs |
| [GitHub dorking](https://github.com/techgaun/github-dorks) | Source code recon | Find leaked secrets in public repos |
| [theHarvester](https://github.com/laramies/theHarvester) | OSINT gathering | Emails, names, subdomains, IPs |

### Web Application Testing

| Tool | Purpose | Notes |
|---|---|---|
| [Burp Suite Community](https://portswigger.net/burp/communitydownload) | Web proxy + scanner | Essential tool; free community edition |
| [Burp Suite Pro](https://portswigger.net/burp/pro) | Advanced scanner + extensions | Paid; worth it for serious hunters |
| [OWASP ZAP](https://www.zaproxy.org/) | Web app scanner | Free alternative to Burp Pro |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Template-based scanner | 5,000+ community vulnerability templates |
| [ffuf](https://github.com/ffuf/ffuf) | Web fuzzer | Directory/parameter/vhost fuzzing |
| [dirsearch](https://github.com/maurosoria/dirsearch) | Directory brute forcer | Find hidden endpoints and files |
| [sqlmap](https://sqlmap.org/) | SQL injection automation | Automated SQLi detection and exploitation |
| [dalfox](https://github.com/hahwul/dalfox) | XSS scanner | Fast, accurate XSS discovery |
| [gf](https://github.com/tomnomnom/gf) | Pattern grep for params | Find interesting URL parameters |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Historical URL discovery | Find old endpoints via Wayback Machine |
| [gau](https://github.com/lc/gau) | URL harvester | Fetches known URLs from passive sources |

### API Testing

| Tool | Purpose | Notes |
|---|---|---|
| [Postman](https://www.postman.com/) | API client + testing | Essential for API recon and testing |
| [Insomnia](https://insomnia.rest/) | REST/GraphQL client | Good GraphQL testing support |
| [GraphQL Voyager](https://github.com/graphql-kit/graphql-voyager) | GraphQL schema explorer | Visualize schema for attack surface |
| [Arjun](https://github.com/s0md3v/Arjun) | HTTP parameter discovery | Find hidden API parameters |

### Automation & Pipelines

| Tool | Purpose | Notes |
|---|---|---|
| [anew](https://github.com/tomnomnom/anew) | Append new lines to file | De-duplicate recon output |
| [notify](https://github.com/projectdiscovery/notify) | Notification gateway | Alert on new findings via Slack/Discord |
| [reNgine](https://github.com/yogeshojha/rengine) | Automated recon platform | Full recon pipeline with reporting |
| [axiom](https://github.com/pry0cc/axiom) | Cloud recon infrastructure | Distributed scanning across cloud VMs |

---

## High-Value Vulnerability Classes

| Vulnerability | Typical Payout Range | Key Resources |
|---|---|---|
| Remote Code Execution (RCE) | $5,000 – $1,000,000+ | OWASP A03; Deserialization, SSTI |
| Authentication Bypass | $2,000 – $50,000+ | OAuth flaws, JWT attacks, password reset |
| IDOR (Broken Object Level Auth) | $500 – $10,000+ | OWASP API2; parameter tampering |
| SSRF | $1,000 – $30,000+ | Internal metadata access, cloud SSRF |
| SQL Injection | $500 – $25,000+ | Union-based, blind, time-based |
| XXE | $500 – $10,000+ | XML external entity injection |
| Business Logic Flaws | $500 – $50,000+ | Price manipulation, privilege escalation |
| Subdomain Takeover | $100 – $5,000+ | Dangling DNS records |
| Account Takeover | $1,000 – $25,000+ | Password reset flaws, OAuth misconfig |
| Stored XSS | $200 – $10,000+ | Persistent XSS with high impact |

---

## ATT&CK Alignment

Bug bounty targets techniques that attackers use against the same applications:

- **T1190** — Exploit Public-Facing Application (web/API RCE)
- **T1078.001** — Default Accounts (credential stuffing, weak defaults)
- **T1059.007** — JavaScript (XSS leading to account takeover)
- **T1552.001** — Credentials in Files (exposed .env, config files in recon)
- **T1213** — Data from Information Repositories (IDOR, broken access control)

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| [BSCP (Burp Suite Certified Practitioner)](https://portswigger.net/web-security/certification) | PortSwigger | Web app security; exam via Web Security Academy |
| [OSCP](https://www.offensive-security.com/pwk-oscp/) | OffSec | Penetration testing fundamentals |
| [eWPT](https://elearnsecurity.com/product/ewpt-certification/) | eLearnSecurity | Web application pentesting |
| [GWAPT](https://www.giac.org/certifications/web-application-penetration-tester-gwapt/) | GIAC | Web application penetration testing |
| [GWEB](https://www.giac.org/certifications/web-application-defender-gweb/) | GIAC | Web application defender |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free labs | Best free web app security training; 250+ labs |
| [HackTheBox Bug Bounty Path](https://academy.hackthebox.com/path/preview/bug-bounty-hunter) | Course | Structured HTB bug bounty curriculum |
| [Nahamsec Bug Bounty Bootcamp](https://www.udemy.com/course/the-complete-bug-bounty-bootcamp/) | Course | Beginner-friendly; recon methodology |
| [Stök's YouTube Channel](https://www.youtube.com/@STOKfredrik) | Free videos | Hacking techniques, mindset, live hunts |
| [Insider PhD (LiveOverflow)](https://www.youtube.com/@LiveOverflow) | Free videos | Deep technical security research |
| [The Bug Bounty Playbook](https://payhip.com/b/wAoh) | Book | Frans Rosén and community methodology |
| [Hacktivity (HackerOne)](https://hackerone.com/hacktivity) | Disclosed reports | Read real disclosed bug reports |
| [Pentester Land](https://pentester.land/writeups/) | Write-ups | Curated bug bounty write-up database |

---

## Related Disciplines

- [Application Security](application-security.md) — Secure development that reduces bug bounty findings
- [Offensive Security](offensive-security.md) — Core hacking techniques
- [Vulnerability Management](vulnerability-management.md) — CVE scoring and triage
- [Detection Engineering](detection-engineering.md) — Detecting exploitation of disclosed vulnerabilities
