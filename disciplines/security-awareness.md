# Security Awareness

Security awareness is the discipline of designing, implementing, and measuring programs that reduce human-layer risk across an organization. It is distinct from social engineering, which covers offensive attack techniques — security awareness is the defensive program: training design, phishing simulation campaigns, security culture change, and measuring whether human behavior actually improves. The field is increasingly framed around Security Behavior and Culture Change (SBCC), reflecting a shift from checkbox compliance training toward evidence-based behavior modification.

The human layer remains the highest-leverage attack surface for adversaries. Phishing drives the majority of initial access events (T1566). Credential reuse enables credential stuffing at scale. Employees who fail to report anomalies extend dwell time. Security awareness programs exist to systematically reduce each of these risk vectors — not by making employees security experts, but by building habitual behaviors: recognizing phishing, using MFA, reporting suspicious activity, and escalating to the security team without fear of blame. The discipline requires expertise in adult learning principles, organizational psychology, and measurement design, not just security knowledge.

---

## Where to Start

Begin with the foundational understanding that completion rates are a proxy metric, not a success metric. Annual training that employees click through is not a security awareness program. Study adult learning principles (Fogg Behavior Model, nudge theory, spaced repetition, just-in-time training), then understand how to run a defensible phishing simulation baseline and measure behavior change over time.

| Stage | Focus | Where to Begin |
|---|---|---|
| Foundation | Adult learning principles (ADDIE model, spaced repetition, microlearning), how phishing simulations work, NIST SP 800-50 awareness fundamentals, the difference between completion metrics and behavior metrics, GoPhish setup | [NIST SP 800-50](https://csrc.nist.gov/publications/detail/sp/800-50/final) (free), GoPhish documentation, CISA awareness resources, Perry Carpenter's "Transformational Security Awareness" |
| Practitioner | Program design for role-based training, phishing simulation campaign methodology (baseline → template → analysis → retrain → trend tracking), security champions programs, human risk metrics, KPI dashboards | SANS MGT433, KnowBe4 blog, ENISA awareness guidelines, Hoxhunt methodology content |
| Advanced | Human risk scoring models, BJ Fogg Tiny Habits / nudge theory applied to security behavior, SBCC frameworks, enterprise-scale phishing simulation design, gamification, board-level security culture reporting | Perry Carpenter research, SANS Security Awareness Summit talks, academic behavioral economics literature |

---

## Behavior Change Science

Security awareness programs fail when they treat training as information delivery. Behavior change science provides evidence-based frameworks for actually changing what people do.

### BJ Fogg Tiny Habits
Fogg's Behavior Model: **B = MAP** (Behavior = Motivation × Ability × Prompt). A behavior occurs when motivation and ability are both sufficient *at the moment of a prompt*. Security implications:
- Don't ask employees to do things they find difficult (low ability) — simplify the secure action (one-click MFA approval, pre-configured password manager)
- Deliver the security prompt at the moment of risk (just-in-time training when an employee clicks a suspicious link — not during annual training)
- Celebrate tiny behaviors (reporting a phish) to build the habit through positive reinforcement
- **Tiny Habits**: Attach security behaviors to existing habits ("After I open my email, I will look at the sender domain before clicking any links")

### Nudge Theory
Thaler and Sunstein's nudge theory: design choice architectures that make the secure option the default or easiest choice.
- **Defaults**: Opt-out MFA rather than opt-in; pre-populated secure settings; secure defaults in software
- **Friction**: Add friction to risky actions (confirmation dialogs for large wire transfers, email banners on external messages)
- **Social proof**: "87% of your colleagues reported this phishing email" — normative messaging changes behavior

### Just-in-Time Training
Traditional annual training is ineffective because it is temporally disconnected from risk moments. Just-in-time (JIT) training delivers a micro-lesson immediately after a risky behavior (clicking a simulated phish, downloading an unsafe file). JIT training produces 2–5x better retention than equivalent annual module content because it occurs in the moment of relevance.

---

## Phishing Simulation Methodology

A defensible phishing simulation program follows a structured cycle:

```
1. Baseline Assessment
   → Run initial campaign with no prior warning
   → Establish baseline click rate, reporting rate, and credential submission rate
   → Use moderate-difficulty templates (not trivially obvious, not spear-phish quality)

2. Template Creation & Targeting
   → Develop templates matching real threat landscape (IT helpdesk, HR, financial institution)
   → Role-based targeting: finance team gets wire transfer pretexts; executives get board-meeting themes
   → Seasonal relevance: tax season, open enrollment, major company events

3. Campaign Execution
   → Send to randomized cohorts to prevent word-of-mouth warning
   → Track: delivery rate, click rate, credential submission rate, report rate, time-to-report

4. Analysis & Reporting
   → Identify repeat clickers, departments with high risk, role-based patterns
   → Segment by department, tenure, role, and previous simulation performance

5. Remediation Training
   → Automatic immediate micro-training for clickers (just-in-time)
   → Manager notification for repeat offenders (handle with care — blame culture is counterproductive)
   → Targeted role-based training for high-risk departments

6. Trend Tracking
   → Month-over-month and quarter-over-quarter click rate and report rate trends
   → Benchmark against industry (KnowBe4 Phishing Industry Benchmarks)
   → Report Human Risk Score to leadership
```

---

## Human Risk Metrics

Effective security awareness programs track behavioral metrics, not just training completion.

| Metric | Definition | Target Direction |
|---|---|---|
| **Click Rate** | % of simulation recipients who clicked the phishing link | Decrease over time; industry median ~10%, well-run programs target <5% |
| **Credential Submission Rate** | % who entered credentials after clicking | Decrease; more dangerous than click-only; target near zero |
| **Reporting Rate** | % of phishing simulations (and real phish) reported via security button | Increase; high reporting rate is a stronger positive signal than low click rate |
| **Time-to-Report** | Average time from receipt to security team notification | Decrease; faster reporting reduces dwell time when real attacks occur |
| **Training Completion Rate** | % of assigned training modules completed on time | Maintain above compliance threshold (typically 95%+); not a primary effectiveness metric |
| **Repeat Offender Rate** | % of employees who click across multiple simulation campaigns | Decrease; persistent repeat offenders require targeted intervention |
| **Human Risk Score (HRS)** | Composite score weighting all behavioral metrics (KnowBe4 model) | Decrease; enables prioritized risk-based intervention |

---

## Free Training

- [NIST SP 800-50: Building an IT Security Awareness and Training Program](https://csrc.nist.gov/publications/detail/sp/800-50/final) — Authoritative NIST guidance for designing federal and enterprise security awareness programs; covers program structure, role-based training, and evaluation; free and foundational
- [NIST SP 800-16: IT Security Training Requirements](https://csrc.nist.gov/publications/detail/sp/800-16/final) — NIST role-based training guidance; maps training requirements to job functions and responsibility levels
- [CISA Secure Our World](https://www.cisa.gov/secure-our-world) — Free awareness materials, posters, and campaign kits from CISA; phishing, password hygiene, and MFA awareness content
- [GoPhish Documentation and Quickstart](https://getgophish.com/) — Open-source phishing simulation framework; complete documentation for building in-house simulation capability
- [ENISA Awareness Raising Handbook](https://www.enisa.europa.eu/topics/cybersecurity-education/awareness-raising) — EU Agency guidance on security awareness campaign design, targeting, and measurement; vendor-neutral
- [SANS Ouch! Newsletter](https://www.sans.org/newsletters/ouch/) — Free monthly security awareness newsletter for end users; covers current threats in accessible language
- [MITRE ATT&CK M1017: User Training](https://attack.mitre.org/mitigations/M1017/) — MITRE's documentation of User Training as mitigation; connects awareness content to specific ATT&CK techniques

---

## Tools & Repositories

### Phishing Simulation
- [gophish/gophish](https://github.com/gophish/gophish) — Most widely deployed open-source phishing simulation framework; campaign management, email template editor, landing page cloning, click and credential capture tracking, and results reporting
- [PhishingFrenzy](https://github.com/pentestgeek/phishing-frenzy) — Open-source phishing framework built on Metasploit; campaign management, template library, and reporting

### Awareness Content & Program Resources
- [CISA Phishing Guidance](https://www.cisa.gov/phishing) — Free phishing awareness materials, infographics, and campaign resources
- [SANS Security Awareness](https://www.sans.org/security-awareness-training/) — SANS awareness resources including the monthly OUCH! newsletter, awareness posters, and program design guidance

### Metrics & Measurement
- [OWASP Human Factor Security Awareness](https://owasp.org/www-project-human-factor-security-awareness/) — Awareness program metrics, KPI frameworks, and measurement methodologies; useful for building defensible program metrics

---

## Commercial Platforms

| Platform | Strength |
|---|---|
| **KnowBe4** | Market-leading security awareness and phishing simulation platform; largest template library, Human Risk Score (HRS) metric, automated training assignments based on phishing performance |
| **Proofpoint Security Awareness Training (PSAT)** | Integrated with Proofpoint email security; awareness training correlated with real threat intelligence from the email gateway |
| **Cofense PhishMe** | Phishing simulation specialist with focus on training users to report phishing; Reporter button integration and threat intelligence from the Cofense network |
| **Hoxhunt** | Gamified phishing simulation with adaptive difficulty; Human Risk Score tracking and spaced reinforcement learning; strong engagement metrics and European market presence |
| **SANS Security Awareness** | SANS-developed awareness content; role-based training library used by government and enterprise; high credibility with security teams |
| **Ninjio** | Short-form animated awareness training (3-4 minute episodes); high engagement rates compared to traditional e-learning |
| **Curricula** | Narrative-driven awareness training with story-based content and short module format; focused on making security training engaging |
| **Infosec IQ** | Awareness training platform with phishing simulation, policy acknowledgment, and role-based training; competitive pricing for mid-market |

---

## NIST 800-53 Control Alignment

| Control | ID | Security Awareness Relevance |
|---|---|---|
| Literacy Training and Awareness | AT-2 | Primary control for security awareness programs; requires organizations to provide literacy training focused on recognizing and responding to threats including social engineering and phishing; mandates role-specific and general workforce awareness |
| Role-Based Training | AT-3 | Requires training tailored to specific roles with security responsibilities — administrators, developers, incident responders, and executives each receive training appropriate to their access and responsibilities |
| Training Records | AT-4 | Documentation and retention of training completion records; awareness programs must maintain audit-ready records of who completed what training and when; required by most compliance frameworks |
| Rules of Behavior | PL-4 | Acceptable use policies and rules of behavior that employees acknowledge; the policy foundation that awareness programs reinforce through training and simulation |
| Access Agreements | AC-20 | Signed access agreements for external systems and resources; awareness programs reinforce the security obligations employees assume when accessing organizational systems from personal or external devices |
| Developer Security Architecture and Design | SA-16 | Developers require specialized security awareness training covering secure coding practices, OWASP Top 10, and language-specific vulnerabilities; not addressed by general workforce awareness content |

---

## ATT&CK Coverage

Security awareness directly mitigates initial access and execution techniques by changing employee behavior before the attack succeeds.

| Technique | ID | Awareness Program Mitigation |
|---|---|---|
| Phishing | T1566 | Primary target of security awareness programs; phishing simulation (GoPhish, KnowBe4) combined with MITRE M1017 User Training is the recommended mitigation; training reduces click rates and increases report rates; addresses all T1566 sub-techniques |
| Phishing for Information | T1598 | Pre-texting, vishing, and credential harvesting awareness; train employees to verify identity before sharing credentials or sensitive information via phone, email, or web forms |
| User Execution | T1204 | Awareness training on not executing unexpected attachments, macros, or downloaded files; just-in-time training triggered by simulation failures directly addresses this technique per M1017 |
| Impersonation | T1656 | Business Email Compromise (BEC) and executive impersonation awareness; train finance and administrative staff on verbal confirmation procedures for financial requests regardless of email authority |

---

## Certifications

- **SSAP** (Security Sensibilities Awareness Professional — SANS/ISACA) — The most recognized dedicated security awareness certification; covers program design, adult learning principles, phishing simulation methodology, and behavior change measurement; the credential for practitioners building awareness as a career specialty
- **Security+** (CompTIA) — Covers social engineering attack types and awareness fundamentals; useful foundation for practitioners entering the awareness discipline from a general security background; widely recognized as a baseline credential
- **CISSP** (ISC2) — Domain 1 (Security and Risk Management) covers security awareness and training program requirements; the credential for senior practitioners who need to align awareness programs with enterprise risk management and compliance
- **CISM** (ISACA) — Information security management credential covering security awareness as a risk management control; appropriate for practitioners in governance and program management roles
- **GSLC** (GIAC Security Leadership Certificate) — Security leadership and management credential with coverage of awareness program governance, metrics reporting, and organizational security culture

---

## Learning Resources

| Resource | Type | Notes |
|---|---|---|
| [NIST SP 800-50](https://csrc.nist.gov/publications/detail/sp/800-50/final) | Free guide | Foundational NIST guidance for building security awareness and training programs |
| [NIST SP 800-16](https://csrc.nist.gov/publications/detail/sp/800-16/final) | Free guide | Role-based training requirements mapped to job functions |
| Transformational Security Awareness (Perry Carpenter) | Book | Definitive practitioner book on security awareness as behavior change; covers SBCC, BJ Fogg Tiny Habits, nudge theory, and program design |
| [SANS MGT433: Managing Human Risk](https://www.sans.org/cyber-security-courses/managing-human-risk/) | Paid course | Most structured practitioner curriculum for security awareness professionals |
| [SANS Security Awareness Summit](https://www.sans.org/cyber-security-summit/awareness/) | Free/paid conference | Annual conference dedicated to security awareness; free recordings from past summits |
| [KnowBe4 Blog](https://blog.knowbe4.com/) | Free blog | Practitioner content on phishing trends, simulation methodology, and program design from the market leader |
| [ENISA Awareness Guidelines](https://www.enisa.europa.eu/topics/cybersecurity-education/awareness-raising) | Free guide | EU agency guidance on awareness campaign design and measurement |
| [GoPhish Documentation](https://docs.getgophish.com/) | Free reference | Complete documentation for deploying and running open-source phishing simulations |

---

## Related Disciplines

- [Social Engineering](social-engineering.md)
- [Governance, Risk & Compliance](governance-risk-compliance.md)
- [Incident Response](incident-response.md)
- [Identity & Access Management](identity-access-management.md)
- [Phishing & Email Security](phishing-email-security.md)
