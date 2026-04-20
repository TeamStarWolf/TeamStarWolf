# Social Engineering

> The art of manipulating people to divulge information or take actions that bypass technical controls — exploiting the human attack surface rather than software or hardware vulnerabilities.

Social engineering sits at the intersection of psychology, communication, and security. It covers both **offensive techniques** used in red team and penetration testing engagements, and **defensive programs** such as security awareness training, phishing simulations, and human risk management. Because people remain the most exploitable element in any security architecture, social engineering is relevant to nearly every other discipline.

---

## Key Techniques

| Technique | Description |
|---|---|
| Phishing | Mass or targeted deceptive emails designed to harvest credentials or deliver malware |
| Spear Phishing | Targeted phishing tailored to a specific individual using personal context |
| Whaling | Spear phishing aimed at executives or high-value targets |
| Smishing | Phishing delivered via SMS text messages |
| Vishing | Voice-based phishing — phone calls using pretexting or urgency |
| Pretexting | Fabricating a believable scenario to manipulate a target into action |
| Baiting | Leaving physical media (USB drives) or digital lures to entice victims |
| Tailgating / Piggybacking | Following authorized personnel through controlled access points |
| Impersonation | Posing as IT support, vendors, executives, or other trusted parties |
| Quid Pro Quo | Offering something (IT help, gift cards) in exchange for information or access |
| Watering Hole (social context) | Compromising sites or communities frequented by the target group |
| Business Email Compromise (BEC) | Impersonating executives or vendors via email to authorize fraudulent transfers or actions |
| Internal Spearphishing | Phishing sent from a compromised internal account to increase trust |

---

## Offensive Use Cases

Social engineering is a primary initial access vector in adversary simulation and red team engagements:

- **Red team initial access** — Phishing campaigns, vishing calls, and pretexting to gain footholds without touching technical defenses
- **Physical penetration testing** — Tailgating, impersonation, and badge cloning to gain unauthorized physical access (see Physical Security)
- **Vishing campaigns** — Calling help desks or employees to extract credentials, reset MFA, or reveal sensitive information
- **Phishing simulations** — Authorized campaigns to measure organizational susceptibility and train employees
- **Credential harvesting** — AiTM (Adversary-in-the-Middle) phishing via reverse proxies to capture session tokens and bypass MFA

---

## Defensive Programs

| Program | Purpose |
|---|---|
| Security Awareness Training (SAT) | Ongoing education covering phishing recognition, safe behavior, and policy compliance |
| Phishing Simulations | Controlled phishing campaigns to measure click/report rates and train employees |
| Anti-Phishing Controls | DMARC/DKIM/SPF enforcement, secure email gateways, URL filtering, sandboxing |
| Human Risk Management (HRM) | Data-driven platforms that track individual risk scores and target training accordingly |
| Tabletop Exercises | Scenario-based discussions that rehearse response to social engineering incidents |
| Reporting Culture | Encouraging employees to report suspicious contacts without fear of blame |

---

## NIST 800-53 Controls

| Control | Name | Relevance |
|---|---|---|
| AT-2 | Literacy Training and Awareness | Mandates security and privacy awareness training for all personnel |
| AT-3 | Role-Based Training | Requires tailored training for roles with elevated access or responsibility |
| AT-4 | Training Records | Requires documentation and retention of training completion records |
| PL-4 | Rules of Behavior | Defines acceptable use and behavior expectations for system users |
| PM-13 | Security and Privacy Workforce | Establishes an organization-wide security awareness and training program |
| IA-2 | Identification and Authentication (MFA) | MFA as a compensating control that limits the impact of credential harvesting |

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Notes |
|---|---|---|
| T1566 | Phishing | Parent technique — email-based phishing for initial access |
| T1566.001 | Spearphishing Attachment | Phishing with malicious attachments |
| T1566.002 | Spearphishing Link | Phishing with malicious or credential-harvesting links |
| T1566.003 | Spearphishing via Service | Phishing through social media, messaging, or third-party services |
| T1534 | Internal Spearphishing | Phishing from a compromised internal account |
| T1598 | Phishing for Information | Reconnaissance-focused phishing to gather credentials or data |
| T1204 | User Execution | Victim executes malicious file or link delivered via social engineering |
| T1078 | Valid Accounts | Credentials obtained via phishing used for legitimate-looking access |
| T1659 | Content Injection | Injecting malicious content into legitimate communications |

---

## Tooling

### Phishing Simulation Platforms

| Tool | Type | Notes |
|---|---|---|
| GoPhish | Open source | Self-hosted phishing simulation framework |
| KnowBe4 | Commercial | Leading SAT and phishing simulation platform with HRM features |
| Proofpoint Security Awareness Training | Commercial | Integrated with Proofpoint email security |
| Cofense PhishMe | Commercial | Phishing simulation with threat intelligence integration |
| Hoxhunt | Commercial | Gamified, adaptive phishing simulation and HRM |
| Ninjio | Commercial | Short-form video-based security awareness training |
| Curricula | Commercial | Story-driven awareness training platform |

### Red Team / Offensive Tooling

| Tool | Purpose |
|---|---|
| SET (Social-Engineer Toolkit) | Open-source framework for phishing, credential harvesting, and social engineering attacks |
| Evilginx2 | AiTM reverse proxy for capturing credentials and session cookies — bypasses MFA |
| Modlishka | AiTM phishing reverse proxy — alternative to Evilginx2 |

### Email Defense Controls

| Control | Purpose |
|---|---|
| DMARC / DKIM / SPF | Email authentication standards that reduce domain spoofing |
| Proofpoint Email Security | Commercial anti-phishing gateway with URL rewriting and sandboxing |
| Mimecast | Cloud email security platform with phishing and impersonation protection |

---

## Measuring Effectiveness

Phishing simulation and awareness programs should be tracked with meaningful metrics:

| Metric | Description |
|---|---|
| Click Rate | Percentage of employees who clicked a simulated phishing link |
| Report Rate | Percentage of employees who reported the phishing simulation |
| Dwell Time | Time between delivery and report or click |
| Repeat Offenders | Employees who click across multiple simulation cycles |
| Phishing Resilience Score | Composite score combining click rate, report rate, and speed of reporting |

---

## Certifications

| Certification | Issuer | Relevance |
|---|---|---|
| Security+ | CompTIA | Covers social engineering awareness and defensive controls |
| CEH (Certified Ethical Hacker) | EC-Council | Includes social engineering techniques and tools |
| OSCP | Offensive Security | Practical offensive cert — social engineering supports initial access |
| CPTE | Mile2 | Covers phishing and social engineering in pen testing context |
| SANS SEC467 | SANS / GIAC | Social Engineering for Penetration Testers — dedicated course |

---

## Learning Resources

- **Book**: Christopher Hadnagy — *Social Engineering: The Science of Human Hacking* (2nd ed.) — the foundational reference
- **Book**: Christopher Hadnagy — *Phishing Dark Waters* — focused on phishing psychology and defense
- **Podcast**: The Social-Engineer Podcast — practitioner discussions on SE techniques and defense
- **Conference**: DEF CON Social Engineering Village — live SE competitions (SECTF) and talks
- **Course**: SANS SEC467 — Social Engineering for Penetration Testers
- **Course**: KnowBe4 / Proofpoint SAT platforms — defender-side awareness content
- **Community**: Social-Engineer.org — resources, frameworks, and community from Christopher Hadnagy

---

## Related Disciplines

- [Offensive Security](offensive-security.md) — SE is a primary initial access vector in red team and pen test engagements
- [Incident Response](incident-response.md) — SE incidents trigger IR processes; phishing is a leading initial access method
- [Governance, Risk & Compliance](governance-risk-compliance.md) — SAT programs are compliance requirements (NIST, ISO 27001, PCI DSS, HIPAA)
- [Identity & Access Management](identity-access-management.md) — MFA and privileged access management limit the blast radius of credential harvesting
- [Network Security](network-security.md) — Email security gateways, DNS filtering, and proxy controls defend against phishing delivery
