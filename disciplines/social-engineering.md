# Social Engineering

Social engineering is the practice of exploiting human psychology rather than technical vulnerabilities to gain unauthorized access, extract sensitive information, or manipulate individuals into taking actions that serve an attacker's objectives. Where technical attacks target software flaws, social engineering targets cognitive biases, authority deference, urgency response, and trust — making it effective regardless of how well-patched an organization's infrastructure is. Social engineering underpins the majority of real-world breaches: phishing remains the leading initial access vector according to every major incident response data report. The discipline spans both offensive practice (used by red teamers and adversaries) and defensive programs (security awareness training, phishing simulation, human risk management). Security awareness trainers, penetration testers, red team operators, threat intelligence analysts, and GRC professionals all work within this domain.

---

## Where to Start

| Level | Description | Free Resource |
|---|---|---|
| Beginner | Learn the psychology of social engineering: authority, urgency, scarcity, social proof, and reciprocity. Study phishing email anatomy and practice identifying indicators of compromise. | [Phishing.org](https://www.phishing.org/) |
| Intermediate | Deploy GoPhish in a lab, run a simulated phishing campaign against test accounts, analyze click and report rates, and build a realistic lure template using OSINT. | [GoPhish Documentation](https://docs.getgophish.com/) |
| Advanced | Build adversary-in-the-middle (AiTM) phishing infrastructure with Evilginx2 to capture session tokens and bypass MFA; simulate vishing campaigns using pretexting scripts; combine physical social engineering with digital techniques. | [Evilginx2](https://github.com/kgretzky/evilginx2) |

---

## Free Training

| Platform | URL | What You Learn |
|---|---|---|
| GoPhish Documentation | https://docs.getgophish.com/ | Running phishing simulations, campaign setup, template creation |
| MITRE ATT&CK | https://attack.mitre.org/techniques/T1566/ | Phishing technique mapping, sub-techniques, detection guidance |
| Social-Engineer.org | https://www.social-engineer.org/ | SE frameworks, resources, and community knowledge |
| DEF CON SE Village | https://www.sevillage.org/ | Live SE competitions and talks |
| KnowBe4 Free Tools | https://www.knowbe4.com/free-phishing-security-test | Free phishing susceptibility test |
| Cofense Phishing Defense Center | https://cofense.com/knowledge-center/ | Phishing trend reports and analysis |
| SANS Cyber Aces | https://www.sans.org/cyberaces/ | Foundational security awareness content |

---

## Attack Types and Techniques

| Technique | Description | Offensive Use |
|---|---|---|
| Phishing | Mass or targeted deceptive emails designed to harvest credentials or deliver malware | Initial access via malicious links or attachments |
| Spear Phishing | Targeted phishing tailored to a specific individual using personal context and OSINT | Highly effective initial access; used by APTs |
| Whaling | Spear phishing aimed at executives or high-value targets (CFO, CEO, CISO) | BEC fraud, wire transfer authorization, credential theft |
| Smishing | Phishing delivered via SMS text messages | Credential harvesting, malware delivery to mobile devices |
| Vishing | Voice-based phishing — phone calls using pretexting or urgency | MFA reset fraud, credential extraction from helpdesks |
| Pretexting | Fabricating a believable scenario to manipulate a target into action | Foundation for most SE attacks; impersonation basis |
| Baiting | Leaving physical media (USB drives) or digital lures to entice victims | Malware delivery via autorun, credential harvesting pages |
| Quid Pro Quo | Offering something (IT help, gift cards) in exchange for information or access | IT support impersonation, credential theft |
| Tailgating / Piggybacking | Following authorized personnel through controlled access points | Physical breach enabling network access |
| Watering Hole | Compromising sites or communities frequented by the target group | Drive-by malware delivery targeting a specific industry |
| Business Email Compromise (BEC) | Impersonating executives or vendors via email to authorize fraudulent transfers | Wire fraud; average BEC loss exceeds USD 125,000 |
| Internal Spearphishing | Phishing sent from a compromised internal account to increase trust | Post-compromise lateral phishing to harvest more accounts |

---

## Phishing Infrastructure (Offensive)

Building realistic phishing infrastructure requires several components working together:

**GoPhish walkthrough**:
- Campaign setup: define SMTP relay, sending profile, target group, and schedule
- Template creation: clone legitimate login pages, add tracking pixels for open rates
- Landing pages: credential capture forms or redirect to legitimate site post-capture
- Tracking: per-user click, open, credential submission, and report metrics
- OPSEC: use aged domains, match legitimate email headers, configure DKIM/SPF on attack domain

**Adversary-in-the-Middle (AiTM) phishing**:
- Evilginx2 and Modlishka act as reverse proxies between the victim and the legitimate service
- The victim authenticates to the real service through the proxy — the session cookie is captured
- This technique bypasses TOTP and push-notification MFA because the session is live
- Defeated by: FIDO2/passkeys (phishing-resistant MFA), conditional access policies, CAE (Continuous Access Evaluation)

**Domain categorization tricks**:
- Register lookalike domains well in advance to age them past spam filters
- Use domain generation that mimics legitimate SaaS (e.g., microsoft-helpdesk[.]com)
- Apply for URL categorization with web filtering vendors before launching campaigns
- Use redirectors (Cloudflare Pages, legitimate cloud services) to mask C2 infrastructure

**TOAD (Telephone-Oriented Attack Delivery)** attacks:
- Callback phishing: email delivers no malicious payload; victim is instructed to call a number
- Attacker controls the phone number and impersonates IT support or a financial institution
- Once on the call, attacker guides victim through installing remote access tools (RAT)
- CrowdStrike Intelligence documented this as a rising enterprise threat vector

---

## Physical Social Engineering

Physical SE techniques are used in physical penetration testing and red team engagements:

| Technique | Description | Defensive Control |
|---|---|---|
| Tailgating / Piggybacking | Following an authorized person through badge-controlled doors | Mantraps, turnstiles, security guard challenge culture |
| Impersonation | Posing as IT support, delivery personnel, vendors, or inspectors | Visitor management systems, ID verification procedures |
| Badge Cloning | Using RFID readers to clone proximity cards worn by employees | HID cards with rolling codes, Seos credential technology |
| Dumpster Diving | Recovering sensitive documents, credentials, or hardware from trash | Cross-cut shredding, clean desk policy, secure media destruction |
| Shoulder Surfing | Observing screens or keyboards in public or open-plan offices | Privacy screens, clean desk policy, screen lock policy |

---

## Defensive Countermeasures

| Control | Description | Implementation |
|---|---|---|
| Security Awareness Training (SAT) | Ongoing education covering phishing recognition, safe behavior, and policy compliance | Annual + role-based training; KnowBe4, Proofpoint, Hoxhunt |
| Phishing Simulations | Controlled phishing campaigns to measure click/report rates and train employees | GoPhish (self-hosted), KnowBe4, Cofense, Hoxhunt |
| DMARC / DKIM / SPF | Email authentication standards that reduce domain spoofing | Enforce p=reject DMARC policy; monitor alignment reports |
| Phishing-Resistant MFA | FIDO2/passkeys cannot be intercepted by AiTM proxies | Replace TOTP with hardware keys (YubiKey) or passkeys |
| Anti-Impersonation Controls | Block lookalike domains, banner external emails, flag display name spoofing | SEG (Secure Email Gateway): Proofpoint, Mimecast, Microsoft Defender |
| Human Risk Management (HRM) | Data-driven platforms that track individual risk scores and target training | Repeat offenders receive more frequent and targeted exercises |
| Reporting Culture | Encourage employees to report suspicious contacts without fear of blame | One-click report button (Cofense Reporter, KnowBe4 PAB) |
| Vishing Controls | Callback verification procedures, helpdesk caller authentication | Shared secret challenge, require ticket number before password reset |

---

## Human Risk Metrics

Phishing simulation and awareness programs should be tracked with meaningful metrics:

| Metric | Description | Target |
|---|---|---|
| Phish Click Rate | Percentage of employees who clicked a simulated phishing link | Below 5% industry benchmark |
| Report Rate | Percentage of employees who reported the phishing simulation | Above 70%; high report rate limits dwell time |
| Repeat Offender Rate | Employees who click across multiple simulation cycles | Track for targeted remediation |
| Time to Report | Time between email delivery and employee report | Under 1 hour for high-risk roles |
| Credential Submission Rate | Employees who submitted credentials in a simulated landing page | Near 0%; highest risk action |
| Phishing Resilience Score | Composite: click rate minus report rate | Positive score = more reporters than clickers |

---

## Tools & Repositories

| Tool | Type | Purpose | Link |
|---|---|---|---|
| GoPhish | Open Source | Self-hosted phishing simulation framework | https://github.com/gophish/gophish |
| Evilginx2 | Open Source | AiTM reverse proxy for credential + session token capture | https://github.com/kgretzky/evilginx2 |
| Modlishka | Open Source | AiTM phishing reverse proxy — alternative to Evilginx2 | https://github.com/drk1wi/Modlishka |
| SET (Social-Engineer Toolkit) | Open Source | Framework for phishing, credential harvesting, and SE attacks | https://github.com/trustedsec/social-engineer-toolkit |
| King Phisher | Open Source | Phishing campaign toolkit with server and client components | https://github.com/rsmusllp/king-phisher |
| CredSniper | Open Source | Phishing framework with 2FA bypass support | https://github.com/ustayready/CredSniper |

---

## Commercial Platforms

| Platform | Capability | Notes |
|---|---|---|
| [KnowBe4](https://www.knowbe4.com/) | SAT + phishing simulation + HRM | Leading platform; largest phishing template library |
| [Proofpoint Security Awareness Training](https://www.proofpoint.com/us/products/security-awareness-training) | SAT + simulation | Integrated with Proofpoint email security |
| [Cofense PhishMe](https://cofense.com/) | Phishing simulation + threat intelligence | Reporter button for employee reporting; IR integration |
| [Hoxhunt](https://www.hoxhunt.com/) | Gamified adaptive phishing simulation | Behavioral science approach; individual risk scoring |
| [Phished](https://www.phished.io/) | AI-driven phishing simulation + SAT | Automated, personalized campaigns |
| [Ninjio](https://www.ninjio.com/) | Short-form video-based security awareness | Hollywood-style storytelling; high engagement rates |

---

## NIST 800-53 Control Alignment

| Control | Family | Relevance |
|---|---|---|
| AT-2 | Literacy Training and Awareness | Mandates security and privacy awareness training for all personnel |
| AT-3 | Role-Based Training | Requires tailored training for roles with elevated access or responsibility |
| SA-5 | System Documentation | Documenting social engineering attack surfaces and defensive controls |
| SI-3 | Malicious Code Protection | Anti-phishing controls, email sandbox, attachment scanning |
| IA-2 | Identification and Authentication (MFA) | MFA as compensating control limiting the impact of credential harvesting |
| IA-5 | Authenticator Management | Password policies and phishing-resistant authenticator requirements |
| AC-20 | Use of External Systems | Controls on using external systems that may be compromised for phishing delivery |
| SC-7 | Boundary Protection | Email security gateways, DNS filtering defending against phishing delivery |

---

## ATT&CK Coverage

| Technique ID | Name | Tactic | Relevance |
|---|---|---|---|
| T1566 | Phishing | Initial Access | Parent technique — email-based phishing for initial access |
| T1566.001 | Spearphishing Attachment | Initial Access | Phishing with malicious attachments (macros, LNK, ISO) |
| T1566.002 | Spearphishing Link | Initial Access | Phishing with malicious or credential-harvesting links |
| T1598 | Phishing for Information | Reconnaissance | Credential-focused phishing for intelligence gathering, not just access |
| T1598.001 | Spearphishing Service | Reconnaissance | Phishing through social media, messaging apps, or third-party platforms |
| T1656 | Impersonation | Defense Evasion | Impersonating trusted entities to bypass suspicion |
| T1534 | Internal Spearphishing | Lateral Movement | Phishing from a compromised internal account to spread further |
| T1204 | User Execution | Execution | Victim executes malicious file or link delivered via social engineering |

---

## Certifications

| Certification | Issuer | Relevance |
|---|---|---|
| [SEPP (Social Engineering Pentest Professional)](https://www.social-engineer.com/sepp/) | Social-Engineer LLC | Dedicated social engineering penetration testing certification |
| [OSCP](https://www.offsec.com/courses/pen-200/) | Offensive Security | Practical offensive cert — social engineering supports initial access |
| [GPEN](https://www.giac.org/certifications/penetration-tester-gpen/) | GIAC | Penetration testing including social engineering vectors |
| [CEH (Certified Ethical Hacker)](https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/) | EC-Council | Includes social engineering techniques and tools |
| [SANS SEC467](https://www.sans.org/cyber-security-courses/social-engineering-for-penetration-testers/) | SANS / GIAC | Social Engineering for Penetration Testers — dedicated course |
| [Security+](https://www.comptia.org/certifications/security) | CompTIA | Covers social engineering awareness and defensive controls |

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [Social Engineering: The Science of Human Hacking (Hadnagy)](https://www.wiley.com/en-us/Social+Engineering%3A+The+Science+of+Human+Hacking%2C+2nd+Edition-p-9781119433385) | Book | The foundational reference — psychology, techniques, and defense |
| [The Art of Deception (Mitnick)](https://www.wiley.com/en-us/The+Art+of+Deception-p-9780764542800) | Book | Classic case studies of SE attacks from the world's most famous social engineer |
| [Phishing Dark Waters (Hadnagy & Fincher)](https://www.wiley.com/en-us/Phishing+Dark+Waters-p-9781118958476) | Book | Deep dive on phishing psychology and enterprise defense |
| [DEF CON SE Village](https://www.sevillage.org/) | Conference | Live SE competitions (SECTF) and practitioner talks |
| [SANS SEC467](https://www.sans.org/cyber-security-courses/social-engineering-for-penetration-testers/) | Course | Hands-on social engineering for penetration testers |
| [Social-Engineer.org](https://www.social-engineer.org/) | Community | Frameworks, podcast, and community from Christopher Hadnagy |
| [The Social-Engineer Podcast](https://www.social-engineer.org/category/podcast/) | Podcast | Practitioner discussions on SE techniques and defense |

---

## Related Disciplines

- [Offensive Security](offensive-security.md) — SE is a primary initial access vector in red team and pen test engagements
- [Incident Response](incident-response.md) — SE incidents trigger IR processes; phishing is a leading initial access method
- [Governance, Risk & Compliance](governance-risk-compliance.md) — SAT programs are compliance requirements (NIST, ISO 27001, PCI DSS, HIPAA)
- [Identity & Access Management](identity-access-management.md) — MFA and privileged access management limit the blast radius of credential harvesting
- [Network Security](network-security.md) — Email security gateways, DNS filtering, and proxy controls defend against phishing delivery
- [Purple Teaming](purple-teaming.md) — Social engineering techniques are included in adversary emulation campaigns to test detection
