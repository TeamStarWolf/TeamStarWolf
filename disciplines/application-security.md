# Application Security

Application security encompasses the practices, tools, and disciplines used to design, build, and maintain software that resists attack. It spans the entire software development lifecycle — from threat modeling during design, to secure code review and static analysis during development, to dynamic testing and penetration testing before and after release. AppSec practitioners work at the intersection of software engineering and adversarial thinking: understanding both how applications are built and how they are broken. The field covers web applications, APIs, mobile apps, microservices, serverless functions, and the software supply chains that deliver them.

The attack surface of modern applications has expanded dramatically. APIs now represent the dominant attack vector in web application security — more data is exposed through poorly secured API endpoints than through classic XSS or SQLi vulnerabilities. Supply chain attacks (SolarWinds, XZ Utils, Log4Shell) have made software composition analysis and SBOM generation central to AppSec programs. And the shift-left movement has pushed security earlier into development, with practitioners spending as much time reviewing developer pull requests and configuring SAST pipelines as they do manually testing production applications.

---

## Where to Start

Application security rewards people who understand how software actually works before learning how it breaks. Get comfortable with HTTP, how web frameworks handle requests and sessions, and what developers actually think about when writing code. The lab environments available today make it possible to go from zero to job-ready without spending money. PortSwigger Web Security Academy is the single best free starting point in any security discipline — not just AppSec.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | HTTP fundamentals, OWASP Top 10, basic web app architecture, browser security model, session management | PortSwigger Web Security Academy (free), OWASP Top 10, TryHackMe Web Fundamentals path |
| Practitioner | Hands-on exploitation (SQLi, XSS, SSRF, XXE, deserialization), Burp Suite proficiency, API security, secure code review | OWASP WebGoat/Juice Shop, OWASP WSTG, HTB Academy Bug Bounty Hunter path, eWPT |
| Advanced | Threat modeling, SDLC integration, SAST/DAST/SCA pipeline tooling, bug bounty research, supply chain security, AppSec program design | OWASP ASVS, OWASP SAMM, GWEB/BSCP/OSWA certifications, HackerOne Hacktivity, CodeQL |

---

## Free Training

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — The single best free web security training available anywhere; structured paths covering every major vulnerability class with interactive browser-based labs; required material for every AppSec practitioner regardless of experience level
- [OWASP Foundation Resources](https://owasp.org/projects/) — Free guides, cheat sheets, testing methodologies, and standards covering every aspect of application security; the WSTG, ASVS, and Cheat Sheet Series alone represent months of study
- [TryHackMe Web Fundamentals Path](https://tryhackme.com/path/outline/web) — Guided beginner-to-intermediate path covering HTTP basics, OWASP Top 10, and common web vulnerabilities with browser-based labs
- [Hack The Box Academy Bug Bounty Hunter Path](https://academy.hackthebox.com) — Comprehensive web exploitation curriculum covering recon, fuzzing, XSS, SQLi, SSRF, and API attacks with hands-on modules; free Student tier
- [HackerOne Hacker101](https://www.hacker101.com) — Free video lessons and CTF challenges specifically designed for bug bounty hunters; run by HackerOne and kept current with real bug patterns
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/) — Free bug bounty training modules covering methodology, report writing, and specific vulnerability classes
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) — Deliberately insecure application with integrated lessons teaching exploitation and remediation of common vulnerabilities
- [TCM Security YouTube](https://www.youtube.com/@TCMSecurityAcademy) — Free practical web application security content and course previews
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts on web security, API attacks, and application-layer exploitation
- [PentesterLab](https://pentesterlab.com) — Structured web vulnerability exercises with a free tier; practical labs covering web fundamentals through advanced techniques

---

## Tools & Repositories

### OWASP Standards & Frameworks
- [OWASP/Top10](https://github.com/OWASP/Top10) — The canonical reference for the ten most critical web application security risks; the shared vocabulary for every AppSec conversation
- [OWASP/ASVS](https://github.com/OWASP/ASVS) — Application Security Verification Standard; the framework of security requirements for building and testing secure web applications
- [OWASP/wstg](https://github.com/OWASP/wstg) — Web Security Testing Guide; comprehensive manual for web application security testing covering every vulnerability class
- [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) — Concise guidance on implementing security controls; covers authentication, session management, input validation, cryptography, and dozens more topics
- [OWASP/API-Security](https://github.com/OWASP/API-Security) — OWASP API Security Top 10; the dedicated risk list for REST, GraphQL, and other API architectures
- [OWASP/samm](https://github.com/OWASP/samm) — Software Assurance Maturity Model; framework for building and measuring the maturity of an AppSec program
- [OWASP/mastg](https://github.com/OWASP/mastg) — Mobile Application Security Testing Guide; the definitive standard for iOS and Android application security testing
- [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) — Open-source threat modeling with visual diagram editor and STRIDE-based threat generation

### Proxy & Dynamic Analysis
- [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload) — The industry-standard web application proxy; the free Community edition is sufficient for learning and manual testing
- [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) — OWASP ZAP; the leading open-source web application scanner supporting active scanning, fuzzing, and CI/CD integration
- [wapiti-scanner/wapiti](https://github.com/wapiti-scanner/wapiti) — Command-line web vulnerability scanner covering XSS, SQLi, XXE, SSRF, and more
- [sullo/nikto](https://github.com/sullo/nikto) — Web server scanner checking for dangerous files, outdated software, and common misconfigurations

### Fuzzing & Discovery
- [ffuf/ffuf](https://github.com/ffuf/ffuf) — Fast web fuzzer for directory discovery, parameter fuzzing, vhost enumeration, and API endpoint brute-forcing
- [OJ/gobuster](https://github.com/OJ/gobuster) — Directory, file, DNS, and vhost brute-forcing; lightweight and fast for enumeration during web recon
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) — Template-based vulnerability scanner widely used in bug bounty automation pipelines

### Exploitation & Payloads
- [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) — Automated SQL injection detection and exploitation across all major database backends
- [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Massive curated collection of payloads and bypass techniques for every web vulnerability class

### Recon & Asset Discovery
- [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) — Fast HTTP toolkit for probing web servers, identifying live hosts, and fingerprinting technologies at scale
- [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) — Passive subdomain enumeration aggregating from dozens of OSINT sources
- [laramies/theHarvester](https://github.com/laramies/theHarvester) — OSINT tool for emails, hostnames, and employee names from public sources

### Static Analysis (SAST)
- [semgrep/semgrep](https://github.com/semgrep/semgrep) — Fast static analysis for security bugs across 30+ languages with human-readable rules; excellent for CI/CD integration
- [github/codeql](https://github.com/github/codeql) — GitHub's semantic code analysis engine; models code as data and queries it to find complex taint-flow vulnerability patterns
- [SonarSource/sonarqube](https://github.com/SonarSource/sonarqube) — Continuous code quality and security inspection with IDE and CI integration

### Secret Detection & Supply Chain
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — Searches git history and filesystems for secrets using entropy analysis and pattern matching
- [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) — Fast secret scanner for git repositories and pre-commit hooks
- [jeremylong/DependencyCheck](https://github.com/jeremylong/DependencyCheck) — OWASP Dependency-Check SCA identifying project dependencies with known CVEs
- [snyk/cli](https://github.com/snyk/cli) — Developer-first vulnerability scanning for code, open-source dependencies, containers, and IaC
- [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) — Static analysis for IaC detecting misconfigurations before deployment

### Threat Modeling
- [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) — Visual threat modeling with STRIDE methodology and mitigation tracking
- [Threagile/threagile](https://github.com/Threagile/threagile) — Agile threat modeling from YAML definitions; generates risk reports and DFDs for DevSecOps pipelines
- [izar/pytm](https://github.com/izar/pytm) — Pythonic threat modeling as code generating DFDs and STRIDE findings from source

### Vulnerable Apps for Practice
- [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) — OWASP Juice Shop; the most modern deliberately insecure web application with 100+ challenges covering OWASP Top 10 and beyond
- [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) — Deliberately insecure Node.js application for learning OWASP Top 10 in a modern JavaScript stack
- [digininja/DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application; the classic adjustable-difficulty PHP/MySQL practice target

---

## Commercial & Enterprise Platforms

Enterprise AppSec programs layer commercial tools on top of open-source for scale, developer workflow integration, and program management. These platforms dominate enterprise deployments.

| Platform | Strength |
|---|---|
| **Burp Suite Pro / Enterprise Edition** | The essential commercial web application security testing platform; Pro adds scanner automation, active scanning, and Collaborator for out-of-band testing; Enterprise Edition adds CI/CD pipeline scanning, scheduled scanning, and centralized reporting for large-scale web application programs |
| **Veracode** | One of the original enterprise SAST/DAST platforms; strong in regulated industries and compliance-heavy environments; policy-based security gates, developer IDE integration, and Software Composition Analysis; widely required in government contracting |
| **Checkmarx One** | Enterprise SAST, SCA, DAST, and IaC scanning unified platform; strong developer workflow integration, code-to-cloud coverage, and large enterprise customer base |
| **Synopsys Coverity / Black Duck** | Enterprise SAST (Coverity) and SCA (Black Duck) from Synopsys; particularly strong for C/C++ analysis and organizations with complex open-source license compliance requirements |
| **HackerOne** | Bug bounty program management, VDP hosting, and PTaaS; the largest bug bounty platform connecting organizations with a global vetted researcher community; the standard for enterprise vulnerability disclosure programs |
| **Bugcrowd** | Bug bounty and crowdsourced penetration testing platform; strong for managed programs where organizations want researcher vetting and triage support |
| **Snyk** | Developer-first security platform covering code, open-source dependencies, containers, and IaC; the defining tool of the shift-left movement; deep IDE and CI/CD integrations make it the most frictionless AppSec tool for developer adoption |
| **GitHub Advanced Security** | SAST (CodeQL), secret detection, and dependency review integrated into GitHub; lowest-friction option for organizations already using GitHub; Copilot Autofix adds AI-assisted remediation |
| **Invicti (formerly Netsparker)** | Enterprise DAST platform with proof-based scanning (exploits vulnerabilities to confirm them, reducing false positives); strong for large web application portfolios |
| **Qualys WAS** | Web Application Scanning integrated with Qualys VMDR; good for organizations already on the Qualys platform wanting unified web and infrastructure vulnerability management |

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Web Application Hacker's Handbook | Stuttard & Pinto | The foundational web penetration testing text; systematic methodology and comprehensive depth on HTTP, authentication, and injection attacks |
| Real-World Bug Hunting | Peter Yaworski | Real bug bounty case studies teaching pattern recognition and report writing; bridges theory and live program work |
| Hacking APIs | Corey Ball | The most thorough treatment of API security testing; covers REST, GraphQL, and gRPC with hands-on labs for modern microservice architectures |
| Alice and Bob Learn Application Security | Tanya Janca | Developer-friendly AppSec covering secure coding, threat modeling, and SDLC integration; the most empathetic and practical introduction for developers |
| Bug Bounty Bootcamp | Vickie Li | Structured roadmap from web fundamentals through advanced bug hunting; covers recon, exploitation, and report writing |

---

## Certifications

- **BSCP** (Burp Suite Certified Practitioner — PortSwigger) — Hands-on web application security certification built around Burp Suite; one of the most technically demanding AppSec credentials; directly validates real-world exploitation skill
- **GWEB** (GIAC Web Application Penetration Tester) — Web application security assessment methodology and exploitation; highly regarded by enterprise employers; pairs with SANS SEC542
- **OSWA** (Offensive Security Web Assessor — OffSec) — Web-focused certification from WEB-200; 24-hour hands-on exam against live applications; validates practical exploitation proficiency
- **eWPT** (eLearnSecurity Web Application Penetration Tester — INE Security, formerly eLearnSecurity) — Practical certification assessed via full penetration test report submission; well-regarded as an entry-to-mid level AppSec credential
- **CSSLP** (Certified Secure Software Lifecycle Professional — ISC2) — Governance-focused certification covering secure software design, implementation, testing, and supply chain practices

---

## Channels

- [LiveOverflow](https://www.youtube.com/@LiveOverflow) — In-depth web and binary exploitation, CTF walkthroughs, and browser security; exceptional technical depth
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTF walkthroughs, web vulnerability breakdowns, and accessible delivery
- [NahamSec](https://www.youtube.com/@NahamSec) — Bug bounty-focused content covering recon techniques and web vulnerability walkthroughs
- [PortSwigger Research](https://www.youtube.com/@PortSwiggerTV) — Conference talks covering cutting-edge web security research from the Burp Suite team
- [OWASP Global](https://www.youtube.com/@OWASPGLOBAL) — AppSec conference talks on threat modeling, secure development, and application security research
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Practical web application security training and methodology
- [HackerOne](https://www.youtube.com/@Hacker0x01) — Bug bounty guidance, vulnerability research spotlights, and disclosure best practices

---

## Who to Follow

- [@tanya_janca](https://x.com/tanya_janca) — Author of Alice and Bob Learn Application Security; champions developer-first AppSec education
- [@NahamSec](https://x.com/NahamSec) — Professional bug bounty hunter sharing recon techniques and web exploitation methodology
- [@albinowax](https://x.com/albinowax) — James Kettle, PortSwigger Research Director; original researcher behind HTTP request smuggling and web cache poisoning
- [@hakluke](https://x.com/hakluke) — Bug bounty hunter and tooling author; practical offensive tooling and methodology
- [@tomnomnom](https://x.com/tomnomnom) — Author of foundational bug bounty recon tools (waybackurls, gf, assetfinder); prolific open-source contributor
- [@stokfredrik](https://x.com/stokfredrik) — Bug bounty hunter focused on API and web targets
- [@PortSwigger](https://x.com/PortSwigger) — Web Security Academy updates and cutting-edge vulnerability research
- [@GossiTheDog](https://x.com/GossiTheDog) — Kevin Beaumont; CVE exploitation tracking and enterprise AppSec commentary
- [@jobertabma](https://x.com/jobertabma) — HackerOne co-founder; bug bounty disclosure policy and responsible research
- [@OWASP](https://x.com/owasp) — OWASP official; project updates, research releases, and AppSec community news
- [@danielmiessler](https://x.com/danielmiessler) — SecLists creator; security research and web security content

---

## Key Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — The definitive free web security training platform; interactive labs and structured paths for every major vulnerability class
- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Maps web exploitation techniques in Initial Access and Execution tactics; visualize how application-layer attacks connect to the full ATT&CK kill chain
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — The comprehensive testing methodology reference for web application security assessments
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — The framework for security requirements and application security maturity measurement
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org) — Concise developer and tester reference on implementing security controls correctly
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Public disclosure feed of real bug bounty findings; the best resource for learning what real-world vulnerabilities look like in production
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) — Dedicated risk list for API vulnerabilities; essential as APIs represent the dominant attack surface in modern applications
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/) — The most impactful software weaknesses with scoring, examples, and remediation guidance
- [Semgrep Registry](https://semgrep.dev/r) — Free community and official security rules for static analysis across every major language and framework
