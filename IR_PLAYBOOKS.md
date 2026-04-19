# Incident Response Playbooks

Structured response procedures for the most common incident types. Each playbook follows the NIST SP 800-61 lifecycle: Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident Activity.

These are generic templates. Adapt them to your environment, tools, and escalation paths.

---

## Playbook Index

| Incident Type | Severity Baseline | Estimated MTTR |
|---|---|---|
| [Ransomware](#ransomware) | Critical | 1–4 weeks |
| [Business Email Compromise (BEC)](#business-email-compromise-bec) | High | 24–72 hours |
| [Account Compromise / Credential Theft](#account-compromise--credential-theft) | High | 2–8 hours |
| [Data Exfiltration](#data-exfiltration) | High–Critical | 4–24 hours |
| [Phishing](#phishing) | Medium | 1–4 hours |
| [Malware / Trojan Infection](#malware--trojan-infection) | Medium–High | 4–12 hours |
| [Insider Threat](#insider-threat) | High | 1–5 days |
| [DDoS Attack](#ddos-attack) | High | 2–6 hours |
| [Cloud Security Incident](#cloud-security-incident) | High–Critical | 4–24 hours |
| [Supply Chain Compromise](#supply-chain-compromise) | Critical | 1–4 weeks |

---

## Ransomware

### Severity: Critical

### Detection Signals
- Mass file encryption alerts (EDR behavioral detection, FIM)
- Ransom note files created across filesystem
- Shadow copy deletion (vssadmin, wmic)
- Unusual outbound data transfer before encryption (double extortion)
- C2 beacon to known ransomware infrastructure

### Immediate Actions (0–1 hour)
1. **Isolate** affected systems immediately — disconnect from network (do not power off; preserve forensic state)
2. **Identify** blast radius — which systems/shares are encrypted? Use EDR telemetry
3. **Activate** IR team and escalate to CISO / legal / executive leadership
4. **Preserve** forensic artifacts — memory dump on key systems before any action
5. **Identify** patient zero — first infected system; check EDR for initial access vector
6. **Disable** compromised accounts used in lateral movement
7. **Check** backup integrity — verify backups are clean and offline/immutable before relying on them

### Containment
- Segment affected network zones
- Block known IOCs (C2 IPs, domains, file hashes) at firewall and DNS
- Disable Active Directory accounts involved in lateral movement
- Revoke compromised tokens/sessions (Entra ID, Okta)
- Enable break-glass accounts if primary admin accounts compromised

### Investigation
| Step | Activity | Tool |
|---|---|---|
| Timeline reconstruction | Identify initial access, lateral movement, pre-encryption dwell | EDR, SIEM |
| C2 identification | Extract C2 from memory or network logs | Volatility, Wireshark, Zeek |
| Exfiltration check | Was data exfiltrated before encryption? | DLP, proxy logs, CASB |
| Ransomware family ID | Identify variant and known decryptors | ID Ransomware (nomoreransom.org), VirusTotal |
| AD assessment | Check for persistence, new admin accounts, GPO changes | BloodHound, Event logs |

### Eradication
- Rebuild affected systems from known-good images
- Reset ALL credentials (not just affected accounts)
- Remove malware persistence (scheduled tasks, registry, services)
- Rotate service account passwords and API keys
- Patch the initial access vector (vulnerability, misconfiguration)

### Recovery
- Restore from clean, offline backups (verify integrity first)
- Bring systems online in isolated environment — monitor for re-infection
- Staged production restoration with enhanced monitoring

### Post-Incident
- Lessons learned review within 14 days
- Root cause analysis (initial access vector)
- Control gap analysis and remediation roadmap
- Cyber insurance notification (check policy timelines)
- Regulatory notification (GDPR 72h, SEC 4-day for public companies, sector-specific)

### Key References
- CISA Ransomware Guide: [cisa.gov/stopransomware](https://www.cisa.gov/stopransomware)
- No More Ransom Project: [nomoreransom.org](https://www.nomoreransom.org/)

---

## Business Email Compromise (BEC)

### Severity: High

### Detection Signals
- Email forwarding rules created to external addresses
- Unusual inbox access from new location/device
- Wire transfer or invoice fraud requests
- DMARC failures or lookalike domain emails
- Finance team reports suspicious payment request

### Immediate Actions (0–2 hours)
1. **Preserve** all email evidence before any mailbox changes
2. **Identify** scope — which mailboxes compromised? Review sign-in logs (Entra ID, Google Workspace)
3. **Revoke** active sessions for compromised accounts
4. **Block** attacker-created forwarding rules
5. **Notify** finance team — halt any pending wire transfers immediately
6. **Contact bank** if wire transfer was initiated — request recall (time-critical, <24h window)

### Investigation
| Step | Activity |
|---|---|
| Sign-in log review | Identify source IP, user agent, OAuth token grants |
| Email rule audit | Check for forwarding rules to external addresses |
| Email content review | Identify all emails read, sent, or forwarded by attacker |
| OAuth app review | Check for malicious app consent grants |
| Lookalike domain check | Search for attacker-registered domains impersonating your org |

### Containment
- Reset password and force MFA re-enrollment for compromised account
- Revoke all OAuth tokens
- Block lookalike sender domains at email gateway
- Report lookalike domains for takedown

### Eradication
- Remove attacker-created inbox rules
- Audit and remove unauthorized OAuth app grants
- Review and remove attacker-created delegate access

### Recovery
- Restore any deleted/moved emails from retention
- Brief finance and executive teams on BEC indicators
- Enable enhanced sign-in anomaly alerts

### Post-Incident
- Mandatory phishing-resistant MFA (FIDO2/hardware tokens) for all users
- DMARC/DKIM/SPF enforcement to p=reject
- Enable Microsoft Defender for Office 365 / Proofpoint advanced protection

---

## Account Compromise / Credential Theft

### Severity: High

### Detection Signals
- Sign-in from impossible travel or new geography
- UEBA anomaly alert (unusual time, application, or data access)
- Credential in breach database (HaveIBeenPwned, darkweb monitoring)
- Failed MFA push flood (MFA fatigue attack)
- Lateral movement from user workstation

### Immediate Actions (0–1 hour)
1. **Disable** account or force session revocation
2. **Identify** all active sessions — terminate all
3. **Check** for privilege escalation — did attacker elevate to admin?
4. **Review** recent activity — what did attacker access?
5. **Notify** user through out-of-band channel

### Investigation
| Step | Activity | Tool |
|---|---|---|
| Access timeline | What did attacker access/modify/exfiltrate? | SIEM, CASB, DLP |
| Lateral movement | Did attacker pivot to other systems? | EDR, event logs |
| Persistence check | New accounts, SSH keys, service installs? | EDR, AD logs |
| Source of compromise | Phishing? Password spray? Credential stuffing? | Email logs, auth logs |

### Containment
- Force password reset for compromised account
- Enroll in phishing-resistant MFA if not already enabled
- Block source IPs at firewall and Conditional Access
- Review and revoke suspicious OAuth grants

### Post-Incident
- Enforce phishing-resistant MFA organization-wide
- Enable Conditional Access policies (compliant device, location)
- Credential exposure monitoring (HaveIBeenPwned API, commercial dark web monitoring)

---

## Data Exfiltration

### Severity: High to Critical

### Detection Signals
- Large outbound data transfer to unusual destination
- DLP alert on sensitive data upload/email
- CASB alert on unusual cloud storage activity
- DNS tunneling detection
- USB/removable media data copy alert

### Immediate Actions (0–2 hours)
1. **Block** egress path (IP/domain at firewall, cloud app at CASB)
2. **Preserve** network flow data and proxy logs
3. **Identify** data involved — classify sensitivity, determine regulatory notification requirements
4. **Identify** actor — insider, external attacker, or compromised account?
5. **Engage** legal and privacy team if PII/PHI/PCI data involved

### Investigation
| Step | Questions to Answer |
|---|---|
| What was taken? | File types, volume, classification level |
| How was it taken? | Protocol, destination, tool used |
| Who did it? | User account, source IP, linked identity |
| How long was it happening? | First and last observed exfiltration event |
| Is it ongoing? | Real-time monitoring for continued egress |

### Eradication / Recovery
- Remediate initial access vector
- Block all exfiltration channels used
- For insider: coordinate with HR and legal before account action

### Post-Incident
- Notification obligations (GDPR 72h, HIPAA breach rule, SEC 4-day, state laws)
- Regulatory self-assessment using breach notification requirements matrix
- DLP policy tuning and CASB shadow IT blocking expansion

---

## Phishing

### Severity: Medium (Low if no credential capture; High if leads to compromise)

### Detection Signals
- User reports suspicious email
- Email security gateway alert (Proofpoint, Mimecast)
- DMARC/DKIM failure on inbound email
- Credential submission to unknown site (proxy log)
- Sandbox detonation of attachment

### Immediate Actions (0–30 minutes)
1. **Collect** phishing email headers, URLs, attachments
2. **Search and purge** — find all mailboxes that received the email, delete
3. **Block** sender domain/IP and malicious URLs at email gateway and proxy
4. **Identify** users who clicked or submitted credentials — prioritize response
5. **Sandbox** attachments and URLs for IOC extraction

### Investigation
- For credential harvest: treat as Account Compromise (see above)
- For malware delivery: treat as Malware/Trojan (see below)
- Submit IOCs to threat intelligence platform (MISP/OpenCTI)

### Post-Incident
- Report phishing site for takedown (Google Safe Browsing, APWG, PhishTank)
- Brief targeted users; add to enhanced monitoring if credentials submitted
- Update email security rules and blocklists

---

## Malware / Trojan Infection

### Severity: Medium to High

### Detection Signals
- EDR behavioral detection (process injection, unusual child processes)
- Network beacon to known C2 infrastructure
- YARA rule match on file
- Antivirus detection (treat as confirmed if EDR behavioral)
- Unusual process execution from document/email

### Immediate Actions (0–1 hour)
1. **Isolate** infected host (network isolation via EDR policy)
2. **Preserve** memory dump and disk image if threat severity warrants
3. **Identify** malware family — submit to sandbox (Any.run, Triage)
4. **Check** for lateral movement — has infection spread?
5. **Block** C2 infrastructure at firewall and DNS

### Investigation
| Step | Activity | Tool |
|---|---|---|
| Malware analysis | Static + dynamic analysis, family identification | Ghidra, Cuckoo, Any.run |
| IOC extraction | Hashes, C2 IPs/domains, mutex, registry keys | Volatility, YARA |
| Lateral movement | Check for credential theft, network scanning | EDR, SIEM |
| Persistence | Registry, scheduled tasks, services, startup | Autoruns, EDR |

### Eradication
- Remove malware and all persistence mechanisms
- Reset credentials for logged-on user accounts
- Block all extracted IOCs

### Recovery
- Reimage if root-cause removal is uncertain
- Restore from clean backup if files were modified

---

## Insider Threat

### Severity: High

> **Important**: Coordinate with HR and Legal before taking investigative actions against employees. Premature account disabling may trigger legal complications or destroy evidence.

### Detection Signals
- UEBA alert: unusual data access patterns for role
- DLP alert: mass download or external forwarding
- Badge access to restricted areas outside normal hours
- Resignation + unusual data activity within 30 days
- Access to systems outside role scope

### Response Principles
- **Legal hold** all evidence before any action
- **Need-to-know**: limit investigation team; avoid HR disclosure until legal review
- **Document everything**: chain of custody for all evidence
- **No confrontation** without HR/Legal alignment

### Investigation
| Step | Activity |
|---|---|
| Activity audit | Full access log review for 30–90 days prior |
| Data inventory | What was accessed, copied, or exfiltrated? |
| Communications review | Email, Slack, Teams (per legal authorization) |
| Timeline reconstruction | Correlate badge access, system access, network activity |

### Containment
- Coordinated with HR/Legal: restrict access, preserve logs, prepare termination if warranted
- Revoke all credentials simultaneously at termination

### Post-Incident
- Off-boarding procedure audit
- Data access review for departing employees (30-day pre-departure)
- DLP policy for sensitive data + privileged accounts

---

## DDoS Attack

### Severity: High

### Detection Signals
- Sudden spike in inbound traffic volume
- Service availability alerts (Pingdom, synthetic monitoring)
- Upstream ISP notification
- CDN/WAF DDoS mitigation alert

### Immediate Actions (0–30 minutes)
1. **Confirm** DDoS vs. legitimate traffic surge — check traffic patterns
2. **Engage** upstream ISP / CDN DDoS mitigation scrubbing
3. **Enable** rate limiting and geo-blocking if not already active
4. **Activate** DDoS mitigation provider (Cloudflare, Akamai, AWS Shield)
5. **Assess** whether attack is cover for simultaneous intrusion attempt

### Mitigation
- Cloudflare Magic Transit or similar ISP-level scrubbing
- CDN edge caching to absorb volumetric attacks
- Rate limiting at WAF/load balancer
- Null-routing specific source prefixes with ISP

### Post-Incident
- Traffic analysis to determine attack type (volumetric, protocol, application layer)
- Review and update DDoS response runbook
- Evaluate need for dedicated DDoS mitigation service contract

---

## Cloud Security Incident

### Severity: High to Critical

### Detection Signals
- AWS CloudTrail / Azure Activity Log anomaly
- CSPM alert (Wiz, Prisma Cloud, Defender for Cloud)
- Unusual IAM activity (new admin role, policy changes)
- Cryptomining detected (GPU/CPU spike, unusual egress)
- Cloud storage bucket publicly exposed

### Immediate Actions (0–1 hour)
1. **Identify** affected cloud account(s), region(s), resources
2. **Preserve** CloudTrail / Activity Logs (export before attacker deletes)
3. **Revoke** compromised IAM credentials / service account keys
4. **Isolate** affected resources (security group deny-all, resource isolation)
5. **Check** for persistence: new IAM users, roles, access keys, Lambda/EC2 backdoors

### Investigation
| Step | Activity | Tool |
|---|---|---|
| IAM timeline | Who created/modified what IAM entities? | CloudTrail, Athena |
| Resource inventory | What was created/modified/deleted? | AWS Config, resource audit |
| Data exposure | Public S3 buckets? Exposed databases? | Macie, CSPM |
| Lateral movement | Cross-account access, organization-level impact? | AWS Organizations |
| Exfiltration | Data copied to external accounts? | VPC Flow Logs, CloudTrail data events |

### Containment
- Rotate all IAM credentials and access keys for affected accounts
- Apply SCPs (Service Control Policies) to limit blast radius
- Enable GuardDuty / Defender for Cloud enhanced detection

### Post-Incident
- Implement least-privilege IAM with just-in-time access
- Enable CloudTrail in all regions with log integrity validation
- CSPM continuous monitoring for re-introduction of misconfigurations

---

## Supply Chain Compromise

### Severity: Critical

### Detection Signals
- Vendor notification of compromise
- EDR behavioral alert from legitimate software process
- Unusual outbound connection from trusted software (network monitoring)
- SBOM / SCA tool flags modified dependency
- Threat intelligence report on compromised package/vendor

### Immediate Actions (0–2 hours)
1. **Identify** all systems running the compromised component
2. **Assess** blast radius — what access did the compromised component have?
3. **Isolate** or disable affected software (balance risk of disabling vs. leaving active)
4. **Preserve** forensic evidence — memory, disk, logs
5. **Engage** vendor for guidance, IOCs, and clean version

### Investigation
| Step | Activity |
|---|---|
| Scope mapping | All systems/environments with compromised component installed |
| Activity analysis | What did the compromised component do? Network calls? File writes? |
| Credential review | Did attacker harvest credentials accessible to the component? |
| Lateral movement | Did attacker pivot from any compromised system? |

### Eradication
- Deploy patched/clean version across all affected systems
- Reset all credentials that may have been accessible
- Remove any attacker persistence installed via the compromised component

### Post-Incident
- Implement SBOM generation and monitoring in CI/CD
- Evaluate software signing and verification (Sigstore/Cosign)
- Vendor security assessment and supply chain risk program review

---

## Escalation Matrix Template

| Severity | Notify Within | Stakeholders |
|---|---|---|
| Critical | 15 minutes | CISO, CTO, CEO, Legal, IR retainer |
| High | 1 hour | CISO, IT leadership, Legal |
| Medium | 4 hours | Security manager, IT manager |
| Low | Next business day | Security team |

---

## Regulatory Notification Deadlines

| Regulation | Notification Deadline | Threshold |
|---|---|---|
| GDPR | 72 hours to supervisory authority | Personal data breach with risk to rights |
| HIPAA | 60 days (individual) / 60 days (HHS) | Unsecured PHI breach |
| PCI DSS | Immediately to card brands | Cardholder data compromise |
| NY SHIELD Act | "Most expedient time" | NY resident data |
| CCPA/CPRA | "Most expedient time possible" | CA resident data |
| SEC (public cos) | 4 business days (Form 8-K) | Material cybersecurity incident |
| NIS2 (EU) | 24h early warning / 72h notification | Significant incident |

---

## Related Resources
- [Incident Response](disciplines/incident-response.md) — full IR discipline page with tools and methodology
- [Digital Forensics](disciplines/digital-forensics.md) — forensic investigation techniques
- [Threat Intelligence](disciplines/threat-intelligence.md) — IOC collection and actor tracking
- [Security Operations](disciplines/security-operations.md) — SOC procedures and SOAR playbooks
- [Detection Engineering](disciplines/detection-engineering.md) — detection rules for each incident type
