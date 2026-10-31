# Abnormal AI

Abnormal AI is a behavioral-artificial-intelligence email security service. It models normal communication for an organization, then flags messages that deviate from that baseline. This page describes the generally available product in 2026. Licence tier decides which capabilities are in force.

## What it is and where it fits

Signature and reputation controls catch known-bad mail. They struggle with socially engineered attacks that carry no malware and come from a legitimate or newly compromised account. Abnormal AI targets that gap.

The service learns who normally talks to whom, about what, and in what style. When a message breaks that pattern, such as a sudden wire-transfer request from a vendor, the service scores it as abnormal and acts on policy.

Abnormal AI fits alongside a secure email gateway, not in place of one. The gateway removes bulk spam and known malware. Abnormal AI addresses business email compromise, account takeover, and targeted fraud that evade signatures.

## Architecture and how it works

Abnormal AI integrates through the mail platform `API` rather than sitting inline in the `SMTP` path. It reads mail, identity, and sign-in signals through a scoped grant to the mail tenant. No `MX` change is required.

The service builds behavioral baselines per user and per organization. Models cover communication patterns, sending infrastructure, and normal content. Incoming mail is scored against those baselines in near real time.

Because integration is `API`-based, Abnormal AI can read signals beyond the single message, such as mailbox rules and recent sign-in activity. This supports account-takeover detection, where a legitimate account begins acting out of pattern.

Detected threats can be auto-remediated out of the mailbox. The service also surfaces detections and context in its own console for analyst review.

## Key capabilities

- Behavioral baselines that model normal communication per user and across the organization.
- Business email compromise detection for payment fraud, vendor fraud, and executive impersonation.
- Account-takeover detection from anomalous sign-in and mailbox-rule activity.
- Automatic remediation that pulls malicious mail from mailboxes after delivery.
- Detection of socially engineered messages that carry no payload and pass signature checks.
- Abuse-mailbox handling that triages user-reported messages automatically.
- Visibility into risky mailbox configuration changes such as new auto-forwarding rules.

## Deployment and operations

Deployment grants the service a scoped connection to the mail tenant. There is no `MX` cutover, so rollout carries low delivery risk. The service observes first, then enforces as confidence in the baselines grows.

Operations center on reviewing detections, confirming auto-remediation, and triaging the abuse mailbox. Because the service learns continuously, analyst correction of a misjudged message feeds back into the models.

Monitor the connected grant for scope changes and for any revocation. If the grant is removed, detection stops, so alert on its health. Keep an eye on account-takeover detections, which often need identity-side action such as a forced password reset.

## Integrations and data flow

Abnormal AI connects to the mail platform through an `API` grant and reads mail and identity signals from it. Detections and events can forward to a `SIEM` such as Splunk for correlation with endpoint and network data.

Account-takeover signals can drive identity response, such as session revocation in the identity provider. Case data can feed a security orchestration tool for notification and ticketing.

Data flows inward from the mail tenant as the signals the models need. Data flows outward as detections and events. Keep the grant limited to the scopes the service actually uses.

## Hardening and secure use

- Grant the service only the `API` or `OAuth` scopes it needs on the mail tenant. An over-broad grant is a missing-authorization weakness (CWE-862) that widens the blast radius if the integration is abused.
- Enforce role-based access to the Abnormal AI console, and separate analysts who review from administrators who change policy.
- Protect integration credentials and tokens. Do not store them in scripts or shared files, which is a hardcoded-credential weakness (CWE-798). Keep them in a secret manager and rotate them.
- Require single sign-on and multi-factor authentication for console access.
- Monitor the health and scope of the mail-tenant grant, and alert on unexpected scope expansion or revocation.
- Pair account-takeover detections with identity-side response so a compromised session is actually closed.

## Where it fits in the program

Abnormal AI is the behavioral layer that catches what signatures miss. In a layered email design, the gateway handles bulk and known-bad mail, and Abnormal AI handles targeted fraud and account takeover.

For incident response, its detections scope a compromise and show which mailboxes changed behavior. For vulnerability management, its view of risky mailbox rules and repeat targets highlights where user and identity hardening pays off.

## Resources

- Abnormal AI product documentation
- Abnormal AI integration and API documentation
- Abnormal AI deployment guide

## Related pages

- /platforms/README.md
- /INCIDENT_RESPONSE_REFERENCE.md
- /VULNERABILITY_MANAGEMENT_REFERENCE.md
- /platforms/mimecast.md
- /platforms/proofpoint.md
- /platforms/microsoft-defender.md
