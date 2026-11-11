# Abnormal AI

Abnormal AI is a behavioral-artificial-intelligence email security service. It models normal communication for an organization, then flags messages that deviate from that baseline. This page describes the generally available product in 2026. Licence tier decides which capabilities are in force.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Email security engineers, messaging administrators and SOC analysts who run, tune or assess Abnormal AI

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,053 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Abnormal AI for email protection, you are hardening its deployment, or you need to see where it fits in the program and what it shares data with

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Vulnerability Management](/VULNERABILITY_MANAGEMENT_REFERENCE.md), [Mimecast](/platforms/mimecast.md), [Proofpoint](/platforms/proofpoint.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

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

## Adversary perspective

Abnormal AI is a control attackers study and try to slip past, so they shape messages to read as normal and abuse trusted relationships, and the mail-tenant grant it runs on is itself a target. The defensive steps are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Staying inside the baseline: because detection is behavioral, an attacker who compromises a real account and sends from it, in the expected style and to the usual contacts, can act within the learned pattern before the model reacts.
- Trusted-sender and allow-list abuse: mail from a partner domain or an address on an allow-list can skip scrutiny, so attackers favor compromised third-party accounts and vendor-thread hijacking for payment fraud.
- Look-alike and display-name fraud: registered look-alike domains and spoofed display names carry no payload and no known-bad signal, which is the gap behavioral scoring aims at but does not always close.

### Residual risk and own exposure

No model catches every socially engineered message, and one that stays within pattern or arrives from a trusted account can still get through. Because integration is through a scoped grant to the mail tenant, that grant is a high-value target: an over-broad or stolen token ([CWE-862](https://cwe.mitre.org/data/definitions/862.html)) could read mail and identity signals, so the connection belongs in the monitoring and review scope.

### Why it matters

Pair the control with identity response and user reporting, and treat sudden payment or vendor-change requests as worth out-of-band verification regardless of a clean verdict. See [the incident response reference](/INCIDENT_RESPONSE_REFERENCE.md) for scoping a mail compromise and [the red team reference](/RED_TEAM_REFERENCE.md) for social-engineering technique.

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

- [Security platforms](/platforms/README.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Mimecast](/platforms/mimecast.md)
- [Proofpoint](/platforms/proofpoint.md)
- [Microsoft Defender for Endpoint](/platforms/microsoft-defender.md)
