# Mimecast

Mimecast is a cloud-delivered email security and resilience service. It sits in front of the mail platform and inspects inbound and outbound messages before delivery. This page describes the generally available product in 2026. Licence tier decides which capabilities are in force.

## What it is and where it fits

Email remains a primary delivery path for phishing, malware, and business email compromise. Mimecast is the control on that delivery path. Messages route through the service before they reach mailboxes, so threats are inspected and filtered ahead of the user.

The service operates as a secure email gateway. Mail Exchange (`MX`) records point at Mimecast, and policy decides what is blocked, held, or allowed. Outbound mail can route through the same service for inspection and data loss prevention.

In a security program, treat Mimecast as the first layer that reduces what reaches endpoints and identities. It complements endpoint and identity controls rather than replacing them.

## Architecture and how it works

Mimecast is multi-tenant and cloud-hosted. Each tenant has its own configuration, policies, and logs. The service accepts mail over `SMTP`, applies inspection, then relays accepted mail to the destination mail platform.

Inbound flow starts with connection-level checks such as reputation and `SMTP` validation. Messages then pass through anti-spam, anti-malware, and anti-phishing engines. Links and attachments receive added inspection before the message is released.

Outbound flow routes sending mailboxes through the service. Policies apply data loss prevention, content examination, and encryption where configured. The service also stores mail for archiving and continuity when those features are licensed.

Administration happens in a web console. Policies are ordered and scoped, so a precise rule can override a broad default. Logs and message tracking support investigation and tuning.

## Key capabilities

- Secure email gateway with anti-spam, anti-malware, and anti-phishing inspection on inbound mail.
- `URL` protection that rewrites and checks links at click time, so a link weaponized after delivery is still inspected.
- Attachment protection that sandboxes or transcribes files before release.
- Impersonation detection for display-name and lookalike-domain fraud used in business email compromise.
- Data loss prevention on outbound mail, with content rules and encryption options.
- Archiving with retention and search, supporting legal hold and compliance needs.
- Continuity that keeps mail flowing when the primary mail platform is unavailable.
- Awareness training that delivers phishing simulations and short lessons to users.

## Deployment and operations

Deployment starts by pointing `MX` records at the service and configuring the destination relay back to the mail platform. Sender Policy Framework (`SPF`), DomainKeys Identified Mail (`DKIM`), and Domain-based Message Authentication (`DMARC`) records are aligned so authentication checks hold.

Policies begin from vendor defaults and are tuned to the organization. Day-to-day work centers on the held-message queue, release requests, and reported-phish handling. Analysts review quarantined mail and adjust rules where legitimate mail is caught.

Operations also cover directory synchronization so policies map to current users and groups. Reporting shows blocked volume, click activity, and training completion. Tuning is continuous because sender patterns and attack themes shift over time.

## Integrations and data flow

Mimecast exposes an `API` for tenant administration, message tracking, and event retrieval. Security teams pull message and threat events into a `SIEM` such as Splunk for correlation with endpoint and identity signals.

Click and threat events can feed a security orchestration tool to drive takedown and user-notification workflows. Directory integration keeps user and group data current. Threat telemetry can inform block decisions in other controls.

Data flows outward as logs and events for monitoring. Data flows inward as directory updates and policy changes. Keep the connected accounts scoped to only the data each integration needs.

## Hardening and secure use

- Enforce role-based administration. Give console operators only the scope their job requires, and separate policy authors from release approvers.
- Protect `API` credentials. Do not embed keys in scripts or configuration files, which is a hardcoded-credential weakness (CWE-798). Store them in a secret manager and rotate on a schedule.
- Require strong authentication and single sign-on for the admin console, with multi-factor enrollment for every administrator.
- Tune policy to balance blocking against false positives. Over-blocking pushes users to work around the gateway. Under-blocking lets threats through.
- Review the held-message queue and release logs for abuse, and alert on unusual bulk-release activity.
- Keep authentication records (`SPF`, `DKIM`, `DMARC`) aligned so spoofed mail is rejected rather than delivered.

## Where it fits in the program

Mimecast is the email delivery-path control in a defense-in-depth design. It reduces the volume of phishing and malware that reaches users, so endpoint and identity controls handle a smaller and higher-signal set of events.

For incident response, Mimecast message tracking and search help scope a phishing campaign and find every recipient. For vulnerability management, the awareness-training data shows which user populations need added attention.

## Resources

- Mimecast Administration Console Guide
- Mimecast Email Security documentation
- Mimecast API documentation
- Mimecast Data Loss Prevention policy documentation
- Mimecast Awareness Training documentation

## Related pages

- [Security platforms](/platforms/README.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Proofpoint](/platforms/proofpoint.md)
- [Abnormal AI](/platforms/abnormal.md)
- [Microsoft Defender for Endpoint](/platforms/microsoft-defender.md)
