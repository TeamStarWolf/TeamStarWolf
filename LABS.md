# Hands-On Labs & Practice Environments

A curated index of free and accessible lab environments, CTF platforms, and practice ranges mapped to each security discipline. All platforms listed here offer a free tier or are fully open source.

---

## Platform Index

### General / Multi-Discipline

| Platform | Free Tier | Best For |
|---|---|---|
| [Hack The Box Academy](https://academy.hackthebox.com) | Student tier (free) | SOC, DFIR, pentesting, cloud security paths |
| [TryHackMe](https://tryhackme.com) | Free rooms available | Beginner-to-advanced browser-based labs |
| [Blue Team Labs Online](https://blueteamlabs.online) | Free challenges | Detection, forensics, IR investigations |
| [LetsDefend](https://letsdefend.io) | Free SOC simulator | Alert triage, threat analysis, IR playbooks |
| [PentesterLab](https://pentesterlab.com) | Free exercises | Web app security, code review, API security |
| [OverTheWire Wargames](https://overthewire.org/wargames/) | Free | Linux fundamentals, bandit, natas, web |
| [VulnHub](https://www.vulnhub.com/) | Free VMs | Offline practice VMs for penetration testing |
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Free | Web application security, API testing |
| [CISA Training Catalog](https://niccs.cisa.gov/training/catalog) | Free (federal) | ICS/OT, cloud, IR, workforce development |

---

## By Discipline

### Threat Intelligence
| Lab / Platform | Focus | Link |
|---|---|---|
| MISP Training Environment | Threat sharing, IOC ingestion | [misp-project.org/misp-training](https://www.misp-project.org/misp-training/) |
| OpenCTI Sandbox | Threat intel platform operations | [docs.opencti.io](https://docs.opencti.io/) |
| ISAC Threat Intel Feeds (free) | Sector-specific threat data | [cisa.gov/ais](https://www.cisa.gov/resources-tools/programs/automated-indicator-sharing-ais) |
| TraceLabs OSINT CTF | OSINT-based missing persons investigations | [tracelabs.org](https://www.tracelabs.org/) |

### Detection Engineering
| Lab / Platform | Focus | Link |
|---|---|---|
| Elastic SIEM (local) | Sigma rule testing, detection building | [elastic.co/security](https://www.elastic.co/security) |
| Splunk Attack Range | AWS/Azure attack simulation with Splunk | [GitHub: splunk/attack_range](https://github.com/splunk/attack_range) |
| DetectionLab | Windows domain lab with logging pre-configured | [GitHub: clong/DetectionLab](https://github.com/clong/DetectionLab) |
| Sigma HQ Rules | Detection rule library to study and test | [sigmahq.io](https://sigmahq.io/) |
| Atomic Red Team | ATT&CK-mapped test cases for detection validation | [GitHub: redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) |
| HELK (Hunting ELK) | Threat hunting ELK stack with Jupyter notebooks | [GitHub: Cyb3rWard0g/HELK](https://github.com/Cyb3rWard0g/HELK) |

### Incident Response & Digital Forensics
| Lab / Platform | Focus | Link |
|---|---|---|
| Blue Team Labs Online | IR investigation challenges | [blueteamlabs.online](https://blueteamlabs.online) |
| CyberDefenders | DFIR CTF challenges with evidence files | [cyberdefenders.org](https://cyberdefenders.org) |
| DFIR.training | Curated DFIR lab index | [dfir.training](https://www.dfir.training/) |
| NIST CFReDS | Forensic reference disk images | [cfreds.nist.gov](https://cfreds.nist.gov/) |
| Volatility Foundation Samples | Memory images for volatility practice | [GitHub: volatilityfoundation](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples) |
| Autopsy Training Cases | Disk forensics guided cases | [autopsy.com/training](https://www.autopsy.com/support/training/) |

### Offensive Security & Penetration Testing
| Lab / Platform | Focus | Link |
|---|---|---|
| Hack The Box (Machines) | Black-box machine hacking | [hackthebox.com](https://www.hackthebox.com) |
| TryHackMe (Offensive Paths) | Guided offensive learning paths | [tryhackme.com](https://tryhackme.com) |
| VulnHub | Offline VMs for offline pentesting | [vulnhub.com](https://www.vulnhub.com/) |
| DVWA | Damn Vulnerable Web Application (local) | [GitHub: digininja/DVWA](https://github.com/digininja/DVWA) |
| Metasploitable | Intentionally vulnerable VM | [rapid7.com/metasploitable](https://docs.rapid7.com/metasploit/metasploitable-2/) |
| HackTheBox ProLabs | Enterprise-style network labs (paid) | [hackthebox.com/hacker/pro-labs](https://www.hackthebox.com/hacker/pro-labs) |
| OWASP WebGoat | Deliberately insecure Java web app | [GitHub: WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) |

### Application Security & Bug Bounty
| Lab / Platform | Focus | Link |
|---|---|---|
| PortSwigger Web Security Academy | Web vulnerabilities, Burp Suite labs | [portswigger.net/web-security](https://portswigger.net/web-security) |
| HackTheBox Bug Bounty Path | Recon and web vuln methodology | [academy.hackthebox.com](https://academy.hackthebox.com) |
| OWASP Juice Shop | Vulnerable Node.js e-commerce app | [GitHub: juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) |
| Hacker101 CTF | Bug bounty fundamentals and CTF challenges | [ctf.hacker101.com](https://ctf.hacker101.com/) |
| crAPI (Completely Ridiculous API) | Vulnerable API for API security practice | [GitHub: OWASP/crAPI](https://github.com/OWASP/crAPI) |
| VAmPI | Vulnerable REST API | [GitHub: erev0s/VAmPI](https://github.com/erev0s/VAmPI) |

### Cloud Security
| Lab / Platform | Focus | Link |
|---|---|---|
| CloudGoat (Rhino Security Labs) | Intentionally vulnerable AWS environments | [GitHub: RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) |
| flaws.cloud | AWS security misconfiguration challenges | [flaws.cloud](http://flaws.cloud) |
| flaws2.cloud | AWS attacker/defender dual-track challenge | [flaws2.cloud](http://flaws2.cloud) |
| GCP Goat | Intentionally vulnerable GCP environment | [GitHub: JOSHUAJEBARAJ/GCP-Goat](https://github.com/JOSHUAJEBARAJ/GCP-Goat) |
| Sadcloud | Terraform-built vulnerable AWS scenarios | [GitHub: nccgroup/sadcloud](https://github.com/nccgroup/sadcloud) |
| HackTheBox Cloud Labs | AWS/Azure/GCP attack and defend | [academy.hackthebox.com](https://academy.hackthebox.com) |

### Malware Analysis
| Lab / Platform | Focus | Link |
|---|---|---|
| Any.run | Interactive malware sandbox (free tier) | [any.run](https://any.run) |
| MalwareBazaar | Malware sample repository | [bazaar.abuse.ch](https://bazaar.abuse.ch/) |
| Hatching Triage | Sandbox analysis (free tier) | [tria.ge](https://tria.ge/) |
| REMnux | Linux malware analysis distro | [remnux.org](https://remnux.org/) |
| Flare VM | Windows malware analysis environment | [GitHub: mandiant/flare-vm](https://github.com/mandiant/flare-vm) |
| VirusTotal | File/URL/domain multi-engine analysis | [virustotal.com](https://www.virustotal.com) |

### Network Security
| Lab / Platform | Focus | Link |
|---|---|---|
| GNS3 | Network lab simulation (free community edition) | [gns3.com](https://www.gns3.com/) |
| EVE-NG Community | Network emulation platform | [eve-ng.net](https://www.eve-ng.net/) |
| Malware Traffic Analysis | PCAP exercises with real malware traffic | [malware-traffic-analysis.net](https://malware-traffic-analysis.net/) |
| Wireshark Sample Captures | Official packet capture library | [wiki.wireshark.org/SampleCaptures](https://wiki.wireshark.org/SampleCaptures) |
| TryHackMe Network Rooms | Zeek, Snort, Wireshark labs | [tryhackme.com](https://tryhackme.com) |

### ICS / OT Security
| Lab / Platform | Focus | Link |
|---|---|---|
| CISA ICS-CERT Training | Free ICS security courses | [cisa.gov/ics-training](https://www.cisa.gov/resources-tools/training/ics-cybersecurity-training) |
| iTrust SWaT Dataset | Secure Water Treatment attack dataset | [itrust.sutd.edu.sg](https://itrust.sutd.edu.sg/research/dataset/) |
| OpenPLC Runtime | Soft PLC for lab simulation | [openplcproject.com](https://www.openplcproject.com/) |
| GrassMarlin | Passive ICS network mapping tool | [GitHub: nsacyber/GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) |

### AI & LLM Security
| Lab / Platform | Focus | Link |
|---|---|---|
| Gandalf (Lakera) | Prompt injection challenges | [gandalf.lakera.ai](https://gandalf.lakera.ai/) |
| OWASP LLM Top 10 Labs | LLM vulnerability exercises | [genai.owasp.org](https://genai.owasp.org/) |
| Anthropic Courses | Free AI and LLM security content | [github.com/anthropics/courses](https://github.com/anthropics/courses) |
| Garak | LLM vulnerability scanner (local) | [GitHub: leondz/garak](https://github.com/leondz/garak) |

### Vulnerability Management
| Lab / Platform | Focus | Link |
|---|---|---|
| Metasploitable 2/3 | Intentionally vulnerable VM with known CVEs | [rapid7.com/metasploitable](https://docs.rapid7.com/metasploit/metasploitable-2/) |
| OpenVAS / Greenbone Community | Free vulnerability scanner | [greenbone.net](https://www.greenbone.net/en/community-edition/) |
| NVD (NIST) | CVE database for research | [nvd.nist.gov](https://nvd.nist.gov/) |

---

## CTF & Competition Platforms

| Platform | Format | Level |
|---|---|---|
| [PicoCTF](https://picoctf.org/) | Jeopardy-style challenges | Beginner |
| [CTFtime.org](https://ctftime.org/) | CTF event calendar and archives | All levels |
| [Hack The Box](https://hackthebox.com) | Machine and challenge hacking | Intermediate–Advanced |
| [pwn.college](https://pwn.college/) | Binary exploitation and systems security | Intermediate |
| [pwnable.kr](https://pwnable.kr/) | Binary exploitation wargames | Intermediate |
| [Root-Me](https://www.root-me.org/) | 500+ challenges across all categories | All levels |
| [NahamCon CTF](https://www.nahamcon.com/) | Annual beginner-friendly CTF | Beginner–Intermediate |
| [RingZer0 CTF](https://ringzer0ctf.com/) | Broad category challenges | Intermediate |
| [DEF CON CTF](https://defcon.org/html/links/dc-ctf.html) | World's most prestigious hacking competition | Elite |

---

## Home Lab Builds

### Minimum Viable SOC Lab
A detection-focused lab that runs on a single host with 16 GB RAM:

| Component | Tool | Purpose |
|---|---|---|
| SIEM | Wazuh or Elastic SIEM | Log aggregation and detection |
| Endpoint | Windows VM with Sysmon | Telemetry generation |
| Threat Simulation | Atomic Red Team | ATT&CK test execution |
| SOAR | Shuffle (open source) | Alert automation |
| Threat Intel | MISP (local instance) | IOC management |

**Setup guides**: [DetectionLab](https://github.com/clong/DetectionLab) | [HELK](https://github.com/Cyb3rWard0g/HELK) | [Wazuh VM](https://documentation.wazuh.com/current/deployment-options/virtual-machine/virtual-machine.html)

### Offensive Lab
| Component | Tool | Purpose |
|---|---|---|
| Attacker OS | Kali Linux or Parrot OS | Full tool suite |
| Target VMs | Metasploitable 3, VulnHub VMs | Practice targets |
| C2 Framework | Metasploit Community | C2 operations |
| Traffic analysis | Wireshark | Network visibility |

### Cloud Security Lab (Free Tier)
Use AWS Free Tier + CloudGoat + Prowler:

1. Create free AWS account
2. Deploy [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) vulnerable scenarios
3. Run [Prowler](https://github.com/prowler-cloud/prowler) to identify misconfigurations
4. Practice with [flaws.cloud](http://flaws.cloud) — no AWS account needed

---

## Related Resources
- [Career Paths & Cert Roadmap](CAREER_PATHS.md) — skill progression by career track
- [Enterprise Security Pipeline](SECURITY_PIPELINE.md) — vendor and control mapping by stage
- [ATT&CK Navigator](navigator/) — technique coverage visualization
- [Starred Repositories](STARRED_REPOS.md) — curated tool and project repos
