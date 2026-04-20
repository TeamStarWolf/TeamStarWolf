# Bug Bounty & Vulnerability Research

Bug bounty programs are structured arrangements where organizations invite external security researchers to identify and responsibly disclose vulnerabilities in exchange for recognition or financial rewards. Practitioners — called hunters or researchers — operate within a defined scope and rules of engagement, applying offensive security techniques to real production targets. The discipline sits at the intersection of web application security, network reconnaissance, reverse engineering, and technical writing. It matters because it surfaces vulnerabilities that internal teams miss, incentivizes responsible disclosure over black-market exploitation, and creates a continuous, community-driven security testing layer. Hunters range from students using free platforms to elite researchers earning millions annually through private programs. Defenders benefit equally: understanding hunter methodology reveals which controls to harden, which logs to monitor, and how exploitation chains actually assemble in the wild.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Learn HTTP basics, OWASP Top 10, and complete PortSwigger Web Security Academy labs. Set up Burp Suite Community and practice on legal targets (DVWA, HackTheBox Starting Point). | [PortSwigger Web Security Academy](https://portswigger.net/web-security) |
| Intermediate | Build a full recon pipeline (subfinder → httpx → nuclei), learn SSRF, IDOR, OAuth, and JWT attacks. Read disclosed HackerOne reports. Submit to public programs on HackerOne or Bugcrowd. | [Hacker101 CTF by HackerOne](https://ctf.hacker101.com/) |
| Advanced | Hunt on private programs, chain multi-step vulnerabilities (auth bypass → SSRF → RCE), write custom nuclei templates, automate recon pipelines on cloud VMs, and contribute CVEs. | [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| PortSwigger Web Security Academy | https://portswigger.net/web-security | XSS, SQLi, SSRF, XXE, IDOR, OAuth, JWT, deserialization — 250+ interactive labs |
| Hacker101 | https://www.hacker101.com/ | Web security fundamentals, CTF challenges, bug bounty methodology |
| Bugcrowd University | https://www.bugcrowd.com/hackers/bugcrowd-university/ | Scoping, recon, vulnerability classes, report writing |
| PentesterLab | https://pentesterlab.com/ | Web app exploitation exercises with solutions (free tier available) |
| OWASP WebGoat | https://github.com/WebGoat/WebGoat | Deliberately vulnerable app for hands-on practice locally |
| TryHackMe Bug Bounty Path | https://tryhackme.com/path/outline/bugbountyhunter | Guided learning path with labs and walkthroughs |
| HackXpert Labs | https://labs.hackxpert.com/ | Free vulnerable labs and recon practice |

---

## Tools & Repositories

### Reconnaissance

| Tool | Purpose | Repository |
|---|---|---|
| Amass | Subdomain enumeration via passive + active DNS | https://github.com/owasp-amass/amass |
| subfinder | Fast passive subdomain discovery using many data sources | https://github.com/projectdiscovery/subfinder |
| httpx | HTTP probing to identify live hosts from subdomain lists | https://github.com/projectdiscovery/httpx |
| katana | High-speed web crawler for endpoint and parameter discovery | https://github.com/projectdiscovery/katana |
| waybackurls | Fetch historical URLs from Wayback Machine | https://github.com/tomnomnom/waybackurls |
| gau | Fetch known URLs from AlienVault OTX, Wayback, URLScan | https://github.com/lc/gau |

### Parameter & Content Discovery

| Tool | Purpose | Repository |
|---|---|---|
| ffuf | Fast web fuzzer for directories, parameters, vhosts | https://github.com/ffuf/ffuf |
| Arjun | HTTP parameter discovery — finds hidden GET/POST/JSON params | https://github.com/s0md3v/Arjun |
| ParamSpider | Parameter mining from web archives | https://github.com/devanshbatham/ParamSpider |
| gf | Pattern-based grep to find interesting URL parameters | https://github.com/tomnomnom/gf |
| dirsearch | Directory and file brute-force enumeration | https://github.com/maurosoria/dirsearch |

### JavaScript Analysis

| Tool | Purpose | Repository |
|---|---|---|
| LinkFinder | Extract endpoints and parameters from JavaScript files | https://github.com/GerbenJavado/LinkFinder |
| SecretFinder | Find secrets and API keys in JavaScript files | https://github.com/m4ll0k/SecretFinder |

### Web Application Testing

| Tool | Purpose | Repository |
|---|---|---|
| Burp Suite Community | Core web proxy, interceptor, repeater, and intruder | https://portswigger.net/burp/communitydownload |
| nuclei | Template-based vulnerability scanner with 9,000+ community templates | https://github.com/projectdiscovery/nuclei |
| sqlmap | Automated SQL injection detection and exploitation | https://github.com/sqlmapproject/sqlmap |
| dalfox | Fast and accurate XSS scanner | https://github.com/hahwul/dalfox |
| OWASP ZAP | Free web application scanner and proxy | https://www.zaproxy.org/ |
| jwt_tool | Test and attack JWT tokens (algorithm confusion, key confusion) | https://github.com/ticarpi/jwt_tool |
| SSRFmap | SSRF exploitation and automation framework | https://github.com/swisskyrepo/SSRFmap |

---

## Commercial Platforms

| Platform | Description |
|---|---|
| HackerOne | World's largest bug bounty platform; private and public programs, triage services, and VDP hosting |
| Bugcrowd | Managed bug bounty and penetration testing marketplace with strong enterprise focus |
| Intigriti | European-headquartered platform with strong GDPR-aware programs and growing global researcher base |
| Synack Red Team | Invite-only, vetted researcher network with higher payouts and structured assessment services |
| YesWeHack | European platform popular in France and DACH regions with growing enterprise programs |
| Cobalt | Pentest-as-a-service integrating bug bounty methodology with compliance deliverables |
| Burp Suite Professional | Industry-standard web proxy with active scanner, extensions marketplace, and out-of-band Collaborator |

---

## Vulnerability Classes: Offensive & Defensive Perspectives

| Vulnerability | Offensive Technique | Defensive Detection |
|---|---|---|
| XSS (Reflected/Stored/DOM) | Inject script payloads via inputs or URL params to steal cookies or execute actions in victim browsers | CSP headers, output encoding, WAF rules alerting on script patterns in request and response bodies |
| SQL Injection | Union-based, blind time-based, error-based extraction via unsanitized database queries | Parameterized queries, WAF SQLi rules, anomalous query latency alerts in database logs |
| SSRF | Fetch internal metadata endpoints or pivot to internal services via user-supplied URLs | Egress filtering, IMDSv2 enforcement, deny-listing RFC-1918 ranges at the application layer |
| IDOR | Modify object IDs in requests to access other users' data without authorization checks | Object-level authorization on every data access, access control audit logs |
| OAuth Misconfiguration | Open redirect in redirect_uri, state parameter CSRF, implicit flow token leakage | Strict redirect_uri allowlisting, PKCE enforcement, short-lived tokens |
| JWT Weaknesses | Algorithm confusion (alg:none), RS256-to-HS256 key confusion, weak secret brute-force | Strict algorithm allowlisting on the server, long random secrets, short expiry and rotation |
| Business Logic Flaws | Price manipulation, race conditions on payments, privilege escalation via parameter tampering | Server-side validation of all state transitions, functional security testing in CI/CD |
| API Flaws (BOLA/BFLA) | Access other users' resources via predictable IDs; call admin functions via undocumented endpoints | Object-level authorization checks, API schema validation, per-endpoint rate limiting |

---

## Recon Methodology

A structured recon pipeline maximizes attack surface coverage before active testing:

1. **Subdomain Enumeration** — `subfinder -d target.com | httpx -silent` for passive discovery and live host probing
2. **JavaScript Analysis** — Run `katana` to crawl and extract JS files, then `LinkFinder` and `SecretFinder` on each file
3. **Parameter Discovery** — `gau target.com | gf xss` to pull historical URLs filtered for XSS-prone parameters; `Arjun` on API endpoints
4. **Google Dorks** — `site:target.com ext:php inurl:id=` to find parameter-rich pages and exposed configuration files
5. **Certificate Transparency** — Query `crt.sh` for subdomains from CT logs: `curl "https://crt.sh/?q=%.target.com&output=json"`
6. **GitHub Dorking** — Search `org:targetname` for exposed secrets, internal API keys, and development endpoints in source code
7. **Cloud Asset Discovery** — Use `nuclei -t exposures/` to scan for exposed S3 buckets, Firebase instances, and open cloud storage

---

## Writing a High-Quality Bug Report

| Report Component | What to Include |
|---|---|
| Title | Clear and specific: "Stored XSS in user profile bio field leads to account takeover" |
| Severity | CVSS v3.1 score with full vector string |
| Summary | Two to three sentences — what the bug is, where it exists, and what an attacker can do |
| Steps to Reproduce | Numbered, exact steps from unauthenticated state to demonstrated impact |
| Proof of Concept | Screenshots, HTTP request/response dumps from Burp Suite, video for complex chains |
| Impact | Business impact — what data, systems, or users are affected and how |
| Remediation | Specific fix recommendation, not generic advice |
| References | CWE number, OWASP classification, any related CVEs |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| SA-11 | System and Services Acquisition | Developer security testing; bug bounty supplements formal code review requirements |
| RA-5 | Risk Assessment | Vulnerability scanning; researcher findings feed the organizational risk register |
| SI-3 | Malicious Code Protection | Injection vulnerabilities (XSS, SQLi) map to malicious code execution risks |
| SI-10 | Information Input Validation | Input validation failures are the root cause of the majority of web bug bounty findings |
| SC-28 | Protection of Information at Rest | IDOR and broken access control expose data that SC-28 is designed to protect |
| CA-8 | Penetration Testing | Bug bounty programs function as continuous, community-driven penetration testing |
| AC-17 | Remote Access | OAuth and authentication bypass findings directly undermine remote access controls |
| SA-15 | Development Process Standards | Secure SDLC gaps that developers miss are routinely caught by external researchers |
| SI-7 | Software, Firmware, and Information Integrity | Dependency confusion and supply chain bugs compromise software integrity |
| RA-3 | Risk Assessment | High-severity bounty findings must feed into risk assessments and treatment plans |

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Initial Access | Core bug bounty target — web and API RCE, SSRF, SQLi exploitation |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Execution | XSS payloads executing JavaScript in victim browsers |
| T1055 | Process Injection | Privilege Escalation | Deserialization and memory corruption bugs enabling injection |
| T1078 | Valid Accounts | Defense Evasion / Persistence | Account takeover via auth bypass, OAuth flaws, JWT attacks |
| T1134 | Access Token Manipulation | Privilege Escalation | JWT algorithm confusion and OAuth token theft techniques |
| T1552 | Unsecured Credentials | Credential Access | Exposed API keys in JS files, .env files, and GitHub repositories |
| T1083 | File and Directory Discovery | Discovery | Path traversal and IDOR enabling enumeration of files and objects |
| T1203 | Exploitation for Client Execution | Execution | XSS and CSRF exploiting user browsers to execute attacker-controlled code |

---

## Certifications

| Certification | Issuer | Focus |
|---|---|---|
| BSCP (Burp Suite Certified Practitioner) | PortSwigger | Web application security; hands-on exam via Web Security Academy |
| OSCP (Offensive Security Certified Professional) | OffSec | Penetration testing fundamentals including web exploitation |
| eWPT (Web Application Penetration Tester) | eLearnSecurity / INE | Web application pentesting methodology |
| GWEB (GIAC Web Application Defender) | GIAC | Web application defense from an attacker-informed perspective |
| GWAPT (GIAC Web Application Penetration Tester) | GIAC | Web application penetration testing |
| PNPT (Practical Network Penetration Tester) | TCM Security | Practical offensive security with bug bounty-adjacent methodology |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free labs | Best free web app security training; 250+ labs covering every major vulnerability class |
| [Hacker101 CTF](https://ctf.hacker101.com/) | Free CTF | HackerOne-operated CTF that earns private program invitations |
| [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/) | Free course | Scoping, methodology, and report writing from practitioners |
| [PentesterLab](https://pentesterlab.com/) | Labs | Hands-on exercises from basic to advanced; free and Pro tiers |
| [Hacktivity (HackerOne)](https://hackerone.com/hacktivity) | Disclosed reports | Read real triaged and paid bug reports to study patterns and methodology |
| [Pentester Land Write-ups](https://pentester.land/writeups/) | Write-ups | Curated database of community write-ups organized by vulnerability type |
| [NahamSec Bug Bounty Bootcamp](https://www.udemy.com/course/the-complete-bug-bounty-bootcamp/) | Course | Beginner-friendly; recon methodology and live hunting demonstrations |
| [Real-World Bug Hunting — Peter Yaworski](https://nostarch.com/bughunting) | Book | Case studies of real disclosed reports organized by vulnerability type |
| [The Web Application Hacker's Handbook](https://www.wiley.com/en-us/The+Web+Application+Hacker%27s+Handbook%2C+2nd+Edition-p-9781118026472) | Book | Foundational reference for web vulnerability exploitation techniques |
| [Jason Haddix Bug Bounty Methodology](https://github.com/jhaddix/tbhm) | GitHub | Community methodology guide maintained by a top-ranked researcher |

---

## Related Disciplines

- [Application Security](application-security.md)
- [Offensive Security](offensive-security.md)
- [Vulnerability Management](vulnerability-management.md)
- [Detection Engineering](detection-engineering.md)
- [DevSecOps](devsecops.md)
- [Network Security](network-security.md)
