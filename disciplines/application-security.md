# Application Security

Application security encompasses the practices, tools, and disciplines used to design, build, and maintain software that resists attack. It spans the entire software development lifecycle — from threat modeling during design, to secure code review and static analysis during development, to dynamic testing and penetration testing before and after release. AppSec practitioners work at the intersection of software engineering and adversarial thinking, understanding both how applications are built and how they are broken. The field covers web applications, APIs, mobile apps, microservices, and the supply chains that deliver them.

---

## Where to Start

Application security rewards those who understand how software actually works before learning how it breaks. Begin by getting comfortable with HTTP, how web frameworks handle requests, and what developers do — and do not — think about when writing code. The lab environments available today make it possible to go from zero to job-ready without spending a dollar. PortSwigger Web Security Academy is the single best free starting point in any security discipline.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | HTTP fundamentals, OWASP Top 10, basic web app architecture, browser security model | PortSwigger Web Security Academy (free), OWASP Top 10, TryHackMe Web Fundamentals path |
| Practitioner | Hands-on exploitation (SQLi, XSS, SSRF, XXE, deserialization), Burp Suite proficiency, API security, secure code review | OWASP WebGoat / Juice Shop, OWASP WSTG, HTB Academy Bug Bounty Hunter path, eWPT |
| Advanced | Threat modeling, SDLC integration, SAST/DAST/SCA pipeline tooling, bug bounty, supply chain security, AppSec program design | OWASP ASVS, OWASP SAMM, GWEB / BSCP / OSWA certifications, HackerOne Hacktivity, CodeQL |

---

## Free Training

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — The single best free web security training available anywhere; structured learning paths covering every major vulnerability class with interactive browser-based labs; required reading for every AppSec practitioner
- [OWASP Foundation Resources](https://owasp.org/projects/) — Free guides, cheat sheets, testing methodologies, and standards covering every aspect of application security; the WSTG, ASVS, and Cheat Sheet Series alone are worth months of study
- [TryHackMe Web Fundamentals](https://tryhackme.com/path/outline/web) — Guided beginner-to-intermediate path covering HTTP basics, OWASP Top 10, and common web vulnerabilities with browser-based labs requiring no local setup
- [Hack The Box Academy — Bug Bounty Hunter Path](https://academy.hackthebox.com) — Comprehensive web exploitation curriculum covering recon, fuzzing, XSS, SQLi, SSRF, and more with hands-on modules; free Student tier
- [TCM Security YouTube](https://www.youtube.com/@TCMSecurityAcademy) — Free practical web application security content and course previews
- [Antisyphon: Web App Attacks](https://www.antisyphontraining.com/course-catalog/) — Pay-what-you-can courses on web security topics including API attacks and modern application exploitation
- [HackerOne Hacker101](https://www.hacker101.com) — Free video lessons and CTF challenges specifically designed for bug bounty hunters; run by HackerOne
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/) — Free bug bounty training modules covering methodology, report writing, and specific vulnerability classes
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) — Deliberately insecure application with integrated lessons teaching you to exploit and understand common vulnerabilities in a safe environment
- [PentesterLab](https://pentesterlab.com) — Structured web vulnerability exercises with free tier; certificates of completion for paid tiers
- [BHIS Webcasts](https://www.blackhillsinfosec.com/blog/webcasts/) — Free webcasts on web security, API attacks, and application-layer exploitation
- [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) — No-cost training including secure software development and AppSec fundamentals

---

## Tools & Repositories

### OWASP Standards & Frameworks
- [OWASP/Top10](https://github.com/OWASP/Top10) — The canonical reference for the ten most critical web application security risks; essential context for every AppSec conversation
- [OWASP/ASVS](https://github.com/OWASP/ASVS) — Application Security Verification Standard; the framework of security requirements for designing, building, and testing secure web applications
- [OWASP/wstg](https://github.com/OWASP/wstg) — Web Security Testing Guide; the comprehensive manual for web application security testing covering every vulnerability class
- [OWASP/CheatSheetSeries](https://github.com/OWASP/CheatSheetSeries) — Concise, actionable guidance on implementing security controls; covers authentication, session management, input validation, cryptography, and dozens more topics
- [OWASP/API-Security](https://github.com/OWASP/API-Security) — OWASP API Security Top 10; the dedicated risk list for REST, GraphQL, and other API architectures
- [OWASP/samm](https://github.com/OWASP/samm) — Software Assurance Maturity Model; framework for building and measuring the maturity of an AppSec program
- [OWASP/DevGuide](https://github.com/OWASP/DevGuide) — Developer-focused guidance for integrating security into the software development lifecycle
- [OWASP/mastg](https://github.com/OWASP/mastg) — Mobile Application Security Testing Guide; the definitive standard for iOS and Android application security testing
- [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) — Open-source threat modeling tool with visual diagram editor and STRIDE-based threat generation

### Proxy & Dynamic Analysis
- [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload) — The industry-standard web application proxy; the free Community edition is sufficient for learning and manual testing
- [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy) — OWASP ZAP; the leading open-source web application scanner supporting active scanning, fuzzing, and CI/CD integration
- [wapiti-scanner/wapiti](https://github.com/wapiti-scanner/wapiti) — Command-line web application vulnerability scanner covering XSS, SQLi, XXE, SSRF, and more
- [sullo/nikto](https://github.com/sullo/nikto) — Classic web server scanner checking for dangerous files, outdated software, and common misconfigurations

### Fuzzing & Discovery
- [ffuf/ffuf](https://github.com/ffuf/ffuf) — Fast web fuzzer for directory discovery, parameter fuzzing, vhost enumeration, and API endpoint brute-forcing
- [OJ/gobuster](https://github.com/OJ/gobuster) — Directory, file, DNS, and vhost brute-forcing; lightweight and fast for enumeration during web recon
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) — Template-based vulnerability scanner widely used in bug bounty automation pipelines
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) — Community-maintained library of thousands of Nuclei scan templates covering CVEs, exposed panels, and misconfigurations

### Exploitation & Payloads
- [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) — Automated SQL injection detection and exploitation; the reference tool for SQLi testing across all major database backends
- [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Massive curated collection of payloads and bypass techniques for every web vulnerability class
- [swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap) — Automated SSRF fuzzing and exploitation tool supporting multiple protocols and cloud metadata endpoints
- [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) — GraphQL endpoint enumeration and exploitation for introspection exposure and injection vulnerabilities

### Recon & Asset Discovery
- [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) — Fast HTTP toolkit for probing web servers, discovering live hosts, and identifying technologies at scale
- [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) — Passive subdomain enumeration aggregating results from dozens of OSINT sources
- [laramies/theHarvester](https://github.com/laramies/theHarvester) — OSINT tool for gathering emails, hostnames, and employee names from public sources

### Static Analysis (SAST)
- [semgrep/semgrep](https://github.com/semgrep/semgrep) — Fast static analysis for finding security bugs across 30+ languages with human-readable rules; excellent for CI/CD integration
- [github/codeql](https://github.com/github/codeql) — GitHub's semantic code analysis engine; models code as data and queries it to find complex taint-flow vulnerability patterns
- [SonarSource/sonarqube](https://github.com/SonarSource/sonarqube) — Platform for continuous code quality and security inspection with IDE and CI integration across major languages

### Secret Detection & Supply Chain
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — Searches git history and filesystems for secrets using entropy analysis and pattern matching
- [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) — Fast secret scanner for git repositories and pre-commit hooks
- [GitGuardian/ggshield](https://github.com/GitGuardian/ggshield) — GitGuardian CLI for scanning repositories and CI pipelines for secrets
- [jeremylong/DependencyCheck](https://github.com/jeremylong/DependencyCheck) — OWASP Dependency-Check SCA tool identifying project dependencies with known CVEs
- [snyk/cli](https://github.com/snyk/cli) — Developer-first vulnerability scanning for code, open source dependencies, containers, and IaC
- [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) — Static analysis for IaC detecting misconfigurations before deployment

### Threat Modeling
- [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon) — Visual threat modeling with STRIDE methodology and mitigation tracking
- [Threagile/threagile](https://github.com/Threagile/threagile) — Agile threat modeling from YAML definitions; generates risk reports and DFDs for DevSecOps pipelines
- [izar/pytm](https://github.com/izar/pytm) — Pythonic threat modeling as code generating DFDs and STRIDE findings from source

### Vulnerable Apps for Practice
- [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) — OWASP Juice Shop; the most modern and comprehensive deliberately insecure web application; 100+ challenges covering OWASP Top 10 and beyond
- [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) — Deliberately insecure Node.js application for learning OWASP Top 10 in a modern JavaScript stack
- [OWASP/OWASPWebGoatPHP](https://github.com/OWASP/OWASPWebGoatPHP) — PHP-based vulnerable application for developers learning to identify and remediate PHP security flaws
- [digininja/DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application; the classic adjustable-difficulty PHP/MySQL practice target

---

## Books & Learning

| Book | Author | Why Read It |
|---|---|---|
| The Web Application Hacker's Handbook | Stuttard & Pinto | The foundational web penetration testing text; systematic methodology and comprehensive depth on HTTP, authentication, and injection attacks |
| Real-World Bug Hunting | Peter Yaworski | Real bug bounty case studies teaching pattern recognition and report writing; bridges theory and live program work |
| Hacking APIs | Corey Ball | The most thorough treatment of API security testing; covers REST, GraphQL, and gRPC with hands-on labs for modern microservice architectures |
| Alice and Bob Learn Application Security | Tanya Janca | Developer-friendly AppSec covering secure coding, threat modeling, and SDLC integration; the most empathetic and practical introduction to AppSec for engineers |
| Bug Bounty Bootcamp | Vickie Li | Structured roadmap from web fundamentals through advanced bug hunting; covers recon, exploitation, and report writing with a focus on live programs |

---

## Certifications

- **BSCP** (Burp Suite Certified Practitioner — PortSwigger) — Hands-on web application security certification built around Burp Suite; one of the most technically demanding and respected AppSec credentials; directly validates real-world exploitation skill
- **GWEB** (GIAC Web Application Penetration Tester) — GIAC's web application security certification covering assessment methodology and exploitation; highly regarded by enterprise employers
- **OSWA** (Offensive Security Web Assessor) — OffSec's web-focused certification from WEB-200; 24-hour hands-on exam exploiting live web applications; validates practical exploitation proficiency
- **eWPT** (eLearnSecurity Web Application Penetration Tester) — Practical certification assessed via full penetration test report submission; well-regarded as an entry-to-mid level AppSec credential
- **CSSLP** (Certified Secure Software Lifecycle Professional — ISC2) — Governance-focused certification covering secure software design, implementation, testing, and supply chain practices across the SDLC

---

## Channels

- [LiveOverflow](https://www.youtube.com/@LiveOverflow) — In-depth web and binary exploitation, CTF walkthroughs, and browser security; exceptional technical depth and production quality
- [John Hammond](https://www.youtube.com/@_JohnHammond) — CTF walkthroughs, web vulnerability breakdowns, and malware analysis with accessible delivery
- [NahamSec](https://www.youtube.com/@NahamSec) — Bug bounty-focused content covering recon techniques, web vulnerability walkthroughs, and live hacking streams
- [PortSwigger Research](https://www.youtube.com/@PortSwiggerTV) — Recorded conference talks covering cutting-edge web security research and novel attack techniques from the Burp Suite team
- [OWASP Global](https://www.youtube.com/@OWASPGLOBAL) — Recorded talks from OWASP AppSec conferences covering threat modeling, secure development, and application security research
- [TCM Security](https://www.youtube.com/@TCMSecurityAcademy) — Practical web application security training content and methodology
- [HackerOne](https://www.youtube.com/@Hacker0x01) — Bug bounty program guidance, vulnerability research spotlights, and disclosure best practices

---

## Who to Follow

- [@tanya_janca](https://x.com/tanya_janca) — Author of Alice and Bob Learn Application Security; leads We Hack Purple; champions developer-first AppSec education
- [@NahamSec](https://x.com/NahamSec) — Professional bug bounty hunter and educator sharing recon techniques and web exploitation methodology
- [@albinowax](https://x.com/albinowax) — James Kettle, PortSwigger Research Director; original researcher behind HTTP request smuggling and web cache poisoning
- [@hakluke](https://x.com/hakluke) — Bug bounty hunter and tooling author (hakrawler); practical offensive tooling and methodology
- [@tomnomnom](https://x.com/tomnomnom) — Author of foundational bug bounty recon tools (waybackurls, gf, assetfinder); prolific open-source contributor
- [@stokfredrik](https://x.com/stokfredrik) — Bug bounty hunter focused on API and web targets sharing methodology and field notes
- [@PortSwigger](https://x.com/PortSwigger) — Web Security Academy updates and cutting-edge vulnerability research publications
- [@GossiTheDog](https://x.com/GossiTheDog) — Kevin Beaumont; real-world CVE exploitation tracking and enterprise application security commentary
- [@jobertabma](https://x.com/jobertabma) — HackerOne co-founder; bug bounty disclosure policy and responsible research
- [@TomNomNom](https://x.com/tomnomnom) — Go-based web security tooling; recon pipeline fundamentals
- [@OWASP](https://x.com/owasp) — OWASP official; project updates, research releases, and AppSec community news
- [@danielmiessler](https://x.com/danielmiessler) — SecLists creator; security research and web security content

---

## Key Resources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — The definitive free web application security training platform; interactive labs and structured learning paths for every major vulnerability class
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — The comprehensive testing methodology reference for web application security assessments
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — The framework for defining security requirements and measuring application security maturity
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org) — Concise developer and tester reference on implementing security controls correctly
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Public disclosure feed of real bug bounty findings; the best resource for learning what real-world vulnerabilities look like in production
- [ATTACK-Navi](https://teamstarwolf.github.io/ATTACK-Navi/) — Maps web exploitation techniques in Initial Access and Execution tactics; visualize how application-layer attacks connect to the full ATT&CK kill chain
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/) — Dedicated risk list for API vulnerabilities; essential as APIs represent the dominant attack surface in modern applications
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/) — The most impactful software weaknesses with scoring, examples, and remediation guidance; the shared vocabulary for SAST findings and CVE descriptions
- [Semgrep Registry](https://semgrep.dev/r) — Free library of community and official security rules for static analysis across every major language and framework
