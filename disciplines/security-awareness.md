# Security Awareness

Security awareness is the discipline of designing, implementing, and measuring programs that reduce human-layer risk across an organization. It is distinct from social engineering, which covers offensive attack techniques — security awareness is the defensive program: training design, phishing simulation campaigns, security culture change, and measuring whether human behavior actually improves. The field is increasingly framed around Security Behavior and Culture Change (SBCC), reflecting a shift from checkbox compliance training toward evidence-based behavior modification.

The human layer remains the highest-leverage attack surface for adversaries. Phishing drives the majority of initial access events. Credential reuse enables credential stuffing at scale. Employees who fail to report anomalies extend dwell time. Security awareness programs exist to systematically reduce each of these risk vectors — not by making employees security experts, but by building habitual behaviors: recognizing phishing, using MFA, reporting suspicious activity, and escalating to the security team without fear of blame. The discipline requires expertise in adult learning principles, organizational psychology, and measurement design, not just security knowledge.

---

## Where to Start

Begin with the foundational understanding that completion rates are a proxy metric, not a success metric. Annual training that employees click through is not a security awareness program. Study adult learning principles (ADDIE model, spaced repetition, microlearning), then understand how to run a defensible phishing simulation baseline and measure behavior change over time. KnowBe4 and SANS MGT433 provide the most structured practitioner curricula.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Adult learning principles (ADDIE model), how phishing simulations work, NIST SP 800-50 awareness fundamentals, the difference between completion metrics and behavior metrics, building a basic phishing simulation with GoPhish | NIST SP 800-50 (free), GoPhish documentation, CISA awareness resources, Perry Carpenter's "Transformational Security Awareness" |
| Practitioner | Program design for role-based training, phishing simulation campaign methodology (baseline, campaign, remediation, retest), security champions programs, measuring behavior change, building a no-blame culture, KPI dashboards | SANS MGT433 course, KnowBe4 blog, Secureum awareness methodology resources, ENISA awareness guidelines |
| Advanced | Human risk scoring models, SBCC (Security Behavior and Culture Change) frameworks, enterprise-scale phishing simulation design, gamification and behavioral economics applications, board-level security culture reporting, program ROI measurement | Perry Carpenter research, SANS Security Awareness Summit talks, academic behavioral economics literature, Hoxhunt and KnowBe4 advanced methodology content |

---

## Free Training

- [NIST SP 800-50: Building an Information Technology Security Awareness and Training Program](https://csrc.nist.gov/publications/detail/sp/800-50/final) — The authoritative NIST guidance for designing federal and enterprise security awareness programs; covers program structure, role-based training, awareness vs. training distinctions, and evaluation; free and foundational
- [NIST SP 800-16: Information Technology Security Training Requirements](https://csrc.nist.gov/publications/detail/sp/800-16/final) — NIST role-based security training guidance; maps training requirements to job functions and responsibility levels; the companion document to SP 800-50 for structured training programs
- [CISA Security Awareness Resources](https://www.cisa.gov/secure-our-world) — Free awareness materials, posters, and campaign kits from CISA; includes phishing, password hygiene, and MFA awareness content ready for organizational deployment
- [GoPhish Documentation and Quickstart](https://getgophish.com/) — Open-source phishing simulation framework; free documentation covers campaign design, template creation, tracking configuration, and results analysis; the starting point for building in-house simulation capability
- [ENISA Awareness Raising Handbook](https://www.enisa.europa.eu/topics/cybersecurity-education/awareness-raising) — European Union Agency for Cybersecurity guidance on security awareness program design; covers campaign methodology, target audiences, and measurement; free and vendor-neutral
- [SANS Ouch! Newsletter](https://www.sans.org/newsletters/ouch/) — Free monthly security awareness newsletter from SANS designed for end users; covers current threats in accessible language; useful as supplementary awareness content for employees
- [MITRE ATT&CK M1017: User Training](https://attack.mitre.org/mitigations/M1017/) — MITRE's documentation of User Training as a mitigation mapping to specific ATT&CK techniques; provides the threat-informed framework for connecting awareness training content to real adversary tactics

---

## Tools & Repositories

### Phishing Simulation
- [gophish/gophish](https://github.com/gophish/gophish) — The most widely deployed open-source phishing simulation framework; campaign management, email template editor, landing page cloning, click and credential capture tracking, and results reporting; the standard for in-house phishing simulation programs
- [PhishingFrenzy](https://github.com/pentestgeek/phishing-frenzy) — Open-source phishing framework built on Metasploit; campaign management, template library, and reporting; alternative to GoPhish for teams already in the Metasploit ecosystem

### Awareness Content & Program Resources
- [CISA Phishing Guidance](https://www.cisa.gov/phishing) — Free phishing awareness materials, infographics, and campaign resources from CISA; ready-to-use content for organizational awareness programs
- [SANS Security Awareness](https://www.sans.org/security-awareness-training/) — SANS awareness program resources including the monthly OUCH! newsletter, awareness posters, and program design guidance; partially free with commercial tiers

### Metrics & Measurement
- [OWASP Human Factor Security Awareness](https://owasp.org/www-project-human-factor-security-awareness/) — OWASP project documenting awareness program metrics, KPI frameworks, and measurement methodologies; useful for building defensible program metrics beyond click rates

---

## Commercial & Enterprise Platforms

| Platform | Strength |
|---|---|
| **KnowBe4** | The market-leading security awareness training and phishing simulation platform; largest template library, Human Risk Score (HRS) metric, automated training assignments based on phishing performance, and strong analytics dashboard |
| **Proofpoint Security Awareness Training (PSAT)** | Tightly integrated with Proofpoint email security; awareness training correlated with real threat intelligence from the email gateway; strong for organizations already using Proofpoint for email |
| **Cofense PhishMe** | Phishing simulation specialist with a focus on training users to report phishing; PhishMe Reporter button integration and threat intelligence from the Cofense network of human-reported phish |
| **Hoxhunt** | Gamified phishing simulation and awareness platform with adaptive difficulty; Human Risk Score tracking, spaced reinforcement learning, and strong engagement metrics; popular in Europe |
| **Ninjio** | Short-form animated awareness training (3-4 minute episodes); high engagement rates compared to traditional e-learning; story-based content covering current threat scenarios |
| **Curricula** | Narrative-driven awareness training with story-based content and short module format; strong on engagement and completion rates; focused on making security training not feel like compliance training |
| **Terranova Security** | Multilingual awareness training platform with deep customization for global enterprise programs; strong analytics and program management capabilities |
| **Infosec IQ** | Awareness training platform with phishing simulation, policy acknowledgment, and role-based training; competitive pricing and broad content library for mid-market organizations |

---

## NIST 800-53 Control Alignment

| Control | ID | Security Awareness Relevance |
|---|---|---|
| Literacy Training and Awareness | AT-2 | The primary control for security awareness programs; requires organizations to provide literacy training and awareness activities focused on recognizing and responding to threats including social engineering and phishing |
| Role-Based Training | AT-3 | Requires training tailored to specific roles with security responsibilities — administrators, developers, incident responders, and executives each receive training appropriate to their access and responsibilities |
| Training Records | AT-4 | Documentation and retention of training completion records; awareness programs must maintain audit-ready records of who completed what training and when |
| Security and Privacy Workforce | PM-13 | Program management control for the organizational security workforce; ensures security awareness professionals have the skills and resources to run effective programs |
| Rules of Behavior | PL-4 | Acceptable use policies and rules of behavior that employees acknowledge; the policy foundation that awareness programs reinforce through training and simulation |
| Access Agreements | PS-6 | Signed access agreements and acceptable use acknowledgments that document employee understanding of security requirements; awareness programs support these agreements through ongoing reinforcement |

---

## ATT&CK Coverage

| Technique | ID | Awareness Program Control |
|---|---|---|
| Phishing | T1566 | The primary target of security awareness programs; phishing simulation (GoPhish, KnowBe4) combined with M1017 User Training is the recommended MITRE mitigation; training reduces click rates and increases report rates |
| Spearphishing via Service | T1566.003 | Awareness training specific to Business Email Compromise (BEC), LinkedIn spearphishing, and social media-based phishing; role-based training for executives and finance teams most at risk |
| Internal Spearphishing | T1534 | Training on recognizing suspicious internal requests; prompt reporting culture reduces dwell time when accounts are compromised and used for internal phishing campaigns |
| User Execution | T1204 | Awareness training on not executing unexpected attachments, macros, or downloaded files; contextual training triggered by simulation failures addresses this technique directly per M1017 |
| Phishing for Information | T1598 | Pre-texting and credential harvesting awareness; training employees to verify identity before sharing credentials or sensitive information via phone, email, or web forms |

---

## Certifications

- **CSAP** (Certified Security Awareness Professional — SANS/IISP) — The most recognized dedicated security awareness certification; covers program design, adult learning principles, phishing simulation methodology, and behavior change measurement; the credential for practitioners building awareness as a career specialty
- **Security+** (CompTIA) — Covers social engineering attack types and awareness fundamentals; useful foundation for practitioners entering the awareness discipline from a general security background
- **CISSP** (ISC2) — Domain 1 (Security and Risk Management) covers security awareness and training requirements; the credential for senior practitioners who need to align awareness programs with enterprise risk management
- **CISM** (ISACA) — Information security management credential with coverage of security awareness as a risk management control; appropriate for practitioners in governance and program management roles
- **SSAP** (Security Sensibilities Awareness Professional) — Specialist awareness certification focused on behavioral aspects of security culture; covers SBCC frameworks and organizational psychology applied to security behavior change

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [NIST SP 800-50](https://csrc.nist.gov/publications/detail/sp/800-50/final) | Free guide | Foundational NIST guidance for building security awareness and training programs |
| [NIST SP 800-16](https://csrc.nist.gov/publications/detail/sp/800-16/final) | Free guide | Role-based training requirements mapped to job functions and responsibilities |
| [Transformational Security Awareness (Perry Carpenter)](https://www.wiley.com/en-us/Transformational+Security+Awareness-p-9781119566342) | Book | The definitive practitioner book on security awareness as behavior change; covers SBCC, adult learning, and program design |
| [SANS MGT433: Managing Human Risk](https://www.sans.org/cyber-security-courses/managing-human-risk/) | Paid course | The most structured practitioner curriculum for security awareness professionals; covers program design, metrics, and culture change |
| [SANS Security Awareness Summit](https://www.sans.org/cyber-security-summit/awareness/) | Free/paid conference | Annual conference dedicated to security awareness; free recordings from past summits available |
| [KnowBe4 Blog](https://blog.knowbe4.com/) | Free blog | Practitioner-level content on phishing trends, simulation methodology, and awareness program design from the market leader |
| [ENISA Awareness Guidelines](https://www.enisa.europa.eu/topics/cybersecurity-education/awareness-raising) | Free guide | EU agency guidance on awareness campaign design and measurement; vendor-neutral and globally applicable |
| [GoPhish Documentation](https://docs.getgophish.com/) | Free reference | Complete documentation for deploying and running open-source phishing simulations |

---

## Related Disciplines

- [Social Engineering](social-engineering.md) — Security awareness is the primary defensive discipline against social engineering; understanding offensive social engineering techniques directly informs the design of effective awareness training content
- [Governance, Risk & Compliance](governance-risk-compliance.md) — Awareness training programs are required by most compliance frameworks (HIPAA, PCI DSS, SOC 2, ISO 27001); GRC practitioners are key stakeholders and consumers of awareness program reporting
- [Incident Response](incident-response.md) — Security awareness programs train employees to recognize and report incidents; reducing time-to-report is a direct awareness program outcome that improves incident response effectiveness
- [Identity & Access Management](identity-access-management.md) — Awareness programs address the human behaviors that undermine IAM controls: password reuse, credential sharing, phishing-based credential theft, and failure to report account compromise
