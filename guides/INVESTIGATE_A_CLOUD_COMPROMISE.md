# Investigate a Cloud Account Compromise

> **By the end of this guide you will have contained a suspected cloud identity compromise, preserved and integrity-validated the logs before they age out, reconstructed what the attacker did as a UTC timeline, scoped the blast radius (what data was read and what was created), and eradicated persistence — leaving a written incident record with an initial-access finding.** Written for the SOC analyst, cloud engineer, or incident responder who just got an alert like "impossible-travel sign-in," "new IAM access key," or "unfamiliar OAuth consent" on an AWS, Microsoft Entra/M365, or Google Cloud/Workspace identity — no prior cloud-forensics background assumed.

| **Time** | **Difficulty** | **You need** | **You'll produce** |
|---|---|---|---|
| First hour is containment; full investigation 1–5 days by scope | High — cross-provider, and the evidence ages by the hour | Break-glass admin to the affected tenant/account from a known-clean device, read access to the log stores (CloudTrail / Log Analytics / Purview / Cloud Logging), out-of-band comms, and your legal/IR contacts | A contained identity, integrity-validated log exports, a UTC activity timeline, an initial-access + persistence findings list, a scoped blast-radius statement, and an eradication + hardening record |

Cloud incidents have no host to seize — the evidence is API logs held by the provider, and much of it is short-lived or off by default. This guide is the response procedure; its evidence-acquisition backbone is the library's [Cloud, SaaS & Mobile Forensics Reference](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md), the attacker techniques you are chasing are catalogued in [Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md), and the controls you rebuild toward live in [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md). It plugs into the account-compromise, BEC, and data-exfiltration playbooks in [IR Playbooks](/IR_PLAYBOOKS.md). Because it changes containment state — rotating keys, revoking sessions, disabling identities — run it from a break-glass identity on a clean device, with legal engaged, and log every action with a UTC timestamp.

## Before you start

- [ ] **Read the AWS / Azure–M365 / Google sections and the incident quick-start checklist** of the [Cloud, SaaS & Mobile Forensics Reference](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md#incident-quick-start-checklist) — this guide operationalizes them and assumes their vocabulary (control plane vs data plane, retention clock, OAuth consent grant).
- [ ] **Know your break-glass path.** You must be able to act even if the attacker holds an admin identity: an AWS account with `IAMFullAccess`/root recovery, an Entra account with Privileged Authentication Administrator, or a GCP Organization Admin — signed in from a device you trust, on an out-of-band channel (the attacker may be reading the tenant's mail and chat).
- [ ] **Confirm logging was actually on before the incident.** Check the [cloud forensic readiness](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md#cloud-forensic-readiness) table: AWS CloudTrail **S3/Lambda data events** and GCP **Data Access** logs are *off by default* — if they were off, "what did they read?" may be unanswerable, and you note that gap now.
- [ ] **Install the collectors** you may need, from a clean workstation: the [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation) and [Exchange Online PowerShell](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2) for Entra/M365, the [AWS CLI](https://docs.aws.amazon.com/cli/) v2, and the [Google Cloud CLI](https://cloud.google.com/sdk/gcloud). For turnkey log pull, [CISA's Untitled Goose Tool](https://github.com/cisagov/untitledgoosetool) (Entra/M365/Azure) and [Microsoft-Extractor-Suite](https://github.com/invictus-ir/Microsoft-Extractor-Suite) (Invictus IR).
- [ ] **Open the incident record now** — a ticket or notes page where every finding, query, and containment action gets a UTC timestamp. In a cloud case the timeline *is* the investigation.
- [ ] **Know your escalation and notification path.** Confirmed data access starts breach-notification clocks ([Regulatory Landscape Reference](/REGULATORY_LANDSCAPE_REFERENCE.md)); decide now who owns that call.

## Step 1 — Confirm the compromise and identify the plane

Before you touch anything, answer three questions in your notes — they set everything that follows:

1. **Which cloud, and which identity?** AWS, Entra/M365, GCP/Workspace — and the exact principal: a UPN/email, an AWS IAM user ARN, a role, or a **service account / service principal**. The identity *type* decides containment, because non-human identities revoke differently (Step 2).
2. **Is this a human or a workload identity?** A human account compromise is usually phishing/token theft; a service-account/service-principal compromise is usually a leaked key or an over-permissioned app. A leaked long-lived key in a public repo, an unfamiliar OAuth consent grant, and an impossible-travel interactive sign-in are three different investigations.
3. **How privileged is it, and is it federated?** A Global Administrator, AWS root or admin role, or GCP Organization Admin means assume tenant-wide reach. Note any federation/SSO trust (the identity may be a pivot into other clouds or SaaS).

Do a fast reality check against the provider's own detection surface before declaring an incident: AWS **GuardDuty** findings (its Extended Threat Detection emits correlated *attack-sequence* findings you can use as the spine of the timeline), Entra **ID Protection** risky-user/risky-sign-in and the unified **Microsoft Defender** incident, or GCP **Security Command Center** / Google **Alert Center**. A single alert may be a false positive; a cluster around one identity is an incident.

**Checkpoint:** Your notes name the cloud, the exact principal and its type (human vs workload), its privilege level, and the one or two signals that triggered this — plus a first hypothesis (credential leak / token theft / illicit OAuth consent).

**Watch out:** Do not tip off the actor. Investigate quietly from the break-glass identity and out-of-band comms until you are ready to contain in Step 2 — a premature password reset on a low-privilege account can push an actor who still holds a token to burn their access (mass export, resource destruction) before you have logs.

## Step 2 — Contain in the first hour

This is the containment checklist. Work it in order — **preserve before you destroy**: deactivate and disable, don't delete, so credentials and their audit trail survive as evidence. Do the plane your compromised identity lives in; do all of them if the identity is federated across clouds.

**First-hour containment checklist**

- [ ] **Snapshot the state before you change it** — export or screenshot the identity's current keys, sessions, roles, app grants, and MFA methods, so you can prove what you removed.
- [ ] **Cut the credential** (deactivate keys / block sign-in), then **kill live sessions** (revoke tokens), then **freeze persistence** (disable, don't yet delete, rogue identities and grants).
- [ ] **Preserve the fast-aging logs** in parallel (Step 3) — the containment clock and the retention clock run at the same time.
- [ ] **Protect the evidence store**: turn on S3 Object Lock / immutable blob on the log bucket so the actor (or a well-meaning admin) can't erase it.

**AWS**

- **Deactivate the exposed access key** — do not delete it yet: `aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name <suspect>`. Deactivation stops the key immediately while keeping it (and clean CloudTrail attribution) for the investigation.
- **Revoke temporary role sessions.** In the IAM console, open the role → **Revoke sessions** → **Revoke active sessions**; IAM attaches the managed inline policy **`AWSRevokeOlderSessions`**, which denies all actions for credentials issued before "now" (plus ~30 seconds for propagation). This is the only way to kill already-issued STS session tokens — you cannot individually expire them. Requires `PutRolePolicy` on the role. ([AWS: Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html))
- **IAM Identity Center (SSO) users:** revoke the user's active sessions and disable the user in the identity source ([Revoke user access](https://docs.aws.amazon.com/singlesignon/latest/userguide/revoke-user-permissions.html)).
- **Root account compromise:** rotate the root password, delete any root access keys, re-establish root MFA, and open a case with AWS Support — treat as the highest severity.

**Microsoft Entra ID / M365** (Microsoft's [emergency access-revocation](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access) order; the deprecated AzureAD/MSOnline modules retired in 2025 — use Microsoft Graph PowerShell):

- **Block sign-in:** `Update-MgUser -UserId $id -AccountEnabled:$false` (or the **Revoke sessions** control on the user's Overview page in the Entra admin center).
- **Revoke refresh tokens / sessions:** `Revoke-MgUserSignInSession -UserId $id` — resets `signInSessionsValidFromDateTime`, invalidating issued refresh tokens.
- **Reset the password** (and any leaked app secret). For a hybrid/synced account, reset in on-prem AD.
- **Understand the timing:** issued *access* tokens live up to ~1 hour unless the app supports **Continuous Access Evaluation (CAE)** — Exchange Online, SharePoint, and Teams are CAE-capable and reject the token in near real time. For non-CAE apps, revocation takes effect when the token expires.

**Google Cloud / Workspace** (Google's [compromised-credentials](https://docs.cloud.google.com/docs/security/compromised-credentials) guidance — the revocation model differs sharply by identity type):

- **Human user:** in the Workspace Admin console, suspend the user, force a password reset, and **remove the Google Cloud CLI (and any suspect app) from the user's Connected Apps** — then note the caveat: *resetting the password or sign-in cookies does not invalidate access tokens the attacker already holds*. Revoke a specific stolen token at the [OAuth revoke endpoint](https://oauth2.googleapis.com/revoke) or have the user clear it from [Account permissions](https://myaccount.google.com/permissions).
- **Service account:** short-lived SA tokens **cannot be revoked** and stay valid to expiry (default up to 60 min). To actually stop a compromised SA you must **disable or delete the service account itself** — disabling a *key* alone does not kill tokens already minted from it. After disabling, **wait at least 60 minutes** before considering re-enable so the last token expires. Also strip `roles/iam.serviceAccountTokenCreator` from any principal that shouldn't have it, to stop new token minting.

**Checkpoint:** The compromised credential is deactivated, live sessions are revoked, rogue identities/grants are disabled (not deleted), the evidence store is locked, and every action is in the incident record with a UTC time. You can state, per plane, exactly what still-valid tokens might survive and until when.

**Watch out:** Containment is partial until tokens expire. On GCP especially, a disabled service account can keep acting for up to an hour on an already-issued token — plan the 60-minute window, don't assume "disabled = stopped." And never delete the compromised principal in the first hour: deletion destroys the attribution you need to read the logs in Step 3.

## Step 3 — Preserve and pull the right logs

Cloud logs are the crime scene, and the tightest retention window sets your pace. Freeze first, analyze second.

**AWS — CloudTrail is the control-plane record.**

- Validate integrity before you trust it: `aws cloudtrail validate-logs --trail-arn <arn> --start-time <UTC>`.
- Console **Event history** covers ~90 days; for anything older or for real queries, use **CloudTrail Lake** (SQL) or **Athena** over the log bucket. Pull management events plus **S3/Lambda data events** if they were enabled.
- Add **GuardDuty** findings, **VPC Flow Logs**, and **Config** history as corroboration. Automation: the **AWS Security Incident Response** service and open-source **AWS IR** / **Cado** / **Velociraptor**.

**Entra ID / M365 — the identity and workload record.**

- Export Entra **sign-in logs** (interactive, **non-interactive**, and **service-principal/managed-identity**), **audit logs**, and **Graph Activity Logs** (raw Graph API calls — essential for token/OAuth cases). Retention is short (7 days Free / 30 days P1–P2), so pull *now* or rely on your Log Analytics export.
- Query the **Purview Unified Audit Log (UAL)** for the cross-workload record (Exchange, SharePoint/OneDrive, Teams, Entra):

  ```powershell
  Connect-ExchangeOnline
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) `
    -UserIds suspect@contoso.com -ResultSize 5000 `
    -Operations MailItemsAccessed,Send,New-InboxRule,Set-InboxRule,`
    Add-MailboxPermission,"Consent to application","Add service principal credentials",`
    "Update user","Add member to role" | Export-Csv .\ual.csv -NoTypeInformation
  ```

  `Search-UnifiedAuditLog` is still the workhorse cmdlet; the newer **Microsoft Purview Audit Search (AuditLog Query) Graph API** is an emerging alternative that has moved between preview and GA — check current docs before scripting against it. Standard-tier UAL retention is 180 days for logs on/after 17 Oct 2023.
- Turnkey collectors when logs aren't already in a SIEM: **Untitled Goose Tool** (CISA), **Microsoft-Extractor-Suite** (Invictus IR), **Hawk**, **DFIR-O365RC**.

**GCP / Workspace.**

- **Cloud Audit Logs**: *Admin Activity* is always on (~400 days); *Data Access* is off by default outside BigQuery (~30 days when on). Query in **Cloud Logging** by `protoPayload.authenticationInfo.principalEmail`, `protoPayload.methodName`, and `protoPayload.requestMetadata.callerIp`, or analyze BigQuery-exported logs.
- **Workspace**: Admin console **Reports → Audit & investigation** (Login, Admin, Drive, OAuth Token log); preserve with **Google Vault**; **Email Log Search** for delivery path + IPs.

Hash every export at collection and record chain of custody (who, which credential, which query, UTC start/end).

**Checkpoint:** You hold integrity-validated, hashed exports of the control-plane and identity logs covering a window that starts *before* your earliest suspicious signal, with custody recorded. Fast-aging sources (Entra sign-ins, SaaS logs) are captured, not just "still available."

**Watch out:** The gaps are the story. If S3 data events or GCP Data Access logs were off, say so explicitly rather than concluding "no data was read" — absence of a log is not absence of access. And check for anti-forensics in the log stream itself: CloudTrail `StopLogging`/`DeleteTrail`/`UpdateTrail`, deleted GCP log sinks, or a disabled Purview audit are attacker actions, not gaps.

## Step 4 — Find the initial access vector

You cannot close what you cannot name. Work backward from the first confirmed malicious action to the first attacker authentication.

1. **Anchor on the earliest bad event** and pivot on its metadata: source IP + ASN, user-agent, and (for token cases) the OAuth **app/client ID** and `session_id`/token ID. Carry these pivot keys across every source.
2. **Classify the entry.** The common cloud initial-access classes ([Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md)):
   - **Leaked long-lived credential** — an access key or SA key in a public repo, CI log, or image. AWS: correlate the first use of the `AKIA...` key and its source IP. GCP: first use of the SA key ID.
   - **Phishing / token theft / AiTM** — an interactive or *non-interactive* sign-in from anomalous IP/geo/device, often replaying a stolen session token (so it satisfies MFA). This is where Entra non-interactive and Graph Activity logs earn their keep. If a phishing email is in scope, run the [phishing investigation guide](INVESTIGATE_A_PHISHING_EMAIL.md) in parallel.
   - **Illicit OAuth consent** — the user (or an admin) consented to a malicious app; the app now holds a refresh token independent of the password. Look for the consent event and the app's granted scopes.
   - **Password spray / legacy-auth** — many failures then one success on a legacy protocol that bypasses MFA.
   - **Misconfiguration / SSRF to metadata** — a public resource or an app SSRF that reached the instance metadata service (IMDSv1) to steal role credentials.
3. **Fix the earliest-foothold time (UTC).** Everything before it is normal; everything after is suspect. Record it — Step 6's timeline and Step 5's persistence hunt both key off it.

**Checkpoint:** Your notes state a supported initial-access hypothesis, the earliest-foothold UTC timestamp, and the pivot keys (IPs, user-agents, app/client IDs, key IDs) you'll sweep with.

**Watch out:** MFA "passing" does not clear a token-theft or consent case — an AiTM proxy and an OAuth app both authenticate legitimately because the attacker holds a real token, not a password. Don't stop at "MFA was on"; check *how* the session was established.

## Step 5 — Hunt persistence across the identity fabric

Cutting one credential means nothing if the actor left three more ways in. Sweep every persistence surface, keyed off your earliest-foothold time.

**AWS**
- New IAM **users**, **access keys added to existing users** (a second key on an admin is a classic backdoor), new **roles** or edited **trust policies** (especially trust to an external account), new **login profiles** (console access on a service identity).
- Backdoored **Lambda** functions / layers, new **identity providers** or SAML federation, and `PutUserPolicy`/`AttachUserPolicy` privilege grants.

**Entra ID / M365**
- New **app registrations / service principals**, and **credentials/secrets added to existing apps** (`Add service principal credentials`) — the dominant SaaS-era persistence path.
- **OAuth consent grants** to unfamiliar apps and their scopes; **new federated domains** or changed federation trust (a "golden SAML"-class move).
- **MFA/auth-method changes** — a new authenticator, phone, or **Temporary Access Pass** registered on the account.
- **Inbox rules** that forward or delete (`New-InboxRule`/`Set-InboxRule` in your Step 3 UAL pull; confirm with `Get-InboxRule`), added **mailbox delegation/permissions**, and new eDiscovery/transport rules.

**GCP / Workspace**
- New **service account keys**, grants of `roles/iam.serviceAccountTokenCreator` (token minting), broad new **IAM bindings** at project/folder/org, altered **org policies**, and deleted/redirected **log sinks**.
- Workspace: new **OAuth token** grants, forwarding filters, and admin-role additions.

**Checkpoint:** You have an enumerated persistence list — every rogue identity, key, app credential, consent grant, federation change, MFA method, and mail rule created after the foothold time — captured for Step 8's eradication.

**Watch out:** Persistence often outlives the session you revoked. An OAuth grant, an added app secret, or a new access key keeps working after the password reset — which is exactly why Step 2 blocked sign-in and revoked tokens but Step 8, not Step 2, removes these (you enumerate before you destroy).

## Step 6 — Build the UTC activity timeline

The deliverable of the investigation is one normalized, UTC **super-timeline** stitched from identity, control-plane, data-plane, and endpoint sources ([timeline building](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md#timeline-building-and-cross-source-correlation)).

1. **Normalize every source to UTC** and record each source's native zone in custody notes — skew silently destroys correlation.
2. **Correlate on the known pattern:** anomalous **sign-in** (Entra/Okta/Workspace) → **consent/token** grant → **control-plane** action (CloudTrail/Azure Activity/Cloud Audit) → **data-plane** access (S3 GetObject / `MailItemsAccessed` / Drive export) → optional **endpoint** corroboration.
3. **Pivot keys** to thread events: user/UPN, IP + ASN, user-agent, OAuth app/client ID, session/token ID, key ID, resource ARN/URI.
4. **Tooling:** **Timesketch** (fed by cloud logs and, where relevant, **plaso**) for a collaborative timeline; native **CloudTrail Lake / Athena / KQL / BigQuery** for the cloud tables; **Sigma** for repeatable detection over the exports.

**Checkpoint:** A single UTC-ordered timeline from earliest foothold to last observed attacker action, each entry sourced to a log line, that a colleague can read without you in the room.

**Watch out:** One provider's clock or a forwarder's rewrite can shift events by hours — verify zones, and don't infer causation from two events that merely look adjacent until the pivot keys tie them together.

## Step 7 — Scope the blast radius

Now answer the questions leadership, legal, and regulators will ask: what did they reach, and what did they make?

- **Data accessed (the notification-driving question).** AWS: S3 **data events** (`GetObject`) — if they were off, state that gap. M365: `MailItemsAccessed` (was the mailbox actually read?), SharePoint/OneDrive `FileDownloaded`/`FileSyncDownloaded`. GCP/Workspace: **Data Access** logs, BigQuery export jobs, Drive export/download events. Quantify volume and sensitivity where you can.
- **Resources created / changed.** New compute (crypto-mining is the classic payoff — check for new instances, new/enabled regions, GPU types), new data stores, **SES/email-sending** abuse, new subscriptions or projects, and any deletion/tampering (`T1485`/`T1490`-class).
- **Lateral movement.** Assumed roles / cross-account `sts:AssumeRole`, pivots into connected SaaS via SSO, and reach into other tenants through the federation trust you found in Step 5.
- **Cost and quota anomalies** are a fast proxy signal — a billing spike or a hit service quota often marks the data-plane or mining activity before you've read every log.

**Checkpoint:** A written blast-radius statement — data confirmed or plausibly accessed (with the log-coverage caveat), resources created/modified, accounts/tenants reached — sufficient for legal to start the notification analysis ([Regulatory Landscape Reference](/REGULATORY_LANDSCAPE_REFERENCE.md)).

**Watch out:** "No evidence of access" and "evidence of no access" are different sentences. If the logs that would show data reads were disabled, your statement says *coverage gap*, not *no impact* — regulators and counsel need that distinction, and stating it wrong is its own liability.

## Step 8 — Eradicate and harden

Only now do you remove what you enumerated in Step 5 — and close the door you found in Step 4.

1. **Remove every persistence item** from the Step 5 list: delete rogue IAM users/keys/roles and login profiles; revoke illicit OAuth consent grants and disable/delete malicious app registrations and their added secrets; remove attacker-registered MFA methods and TAPs; delete malicious inbox rules, delegations, log-sink changes, and federation trusts.
2. **Rotate everything the identity could touch.** Assume any secret it could read is burned: rotate access keys, app secrets, SA keys, and any credentials stored in Secrets Manager / Key Vault / Secret Manager that were in reach.
3. **Close the initial access vector** from Step 4 — remove the leaked key from the repo/history and rotate it, block legacy authentication, fix the SSRF and enforce **IMDSv2**, or tighten the consent policy that allowed the illicit grant.
4. **Harden against a repeat**, guided by the reference programs: enforce phishing-resistant MFA and CAE, restrict user consent to an admin-approval workflow, apply least privilege and permission boundaries, turn on the data-plane logging that was off, and set immutability on the log store ([Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md), [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md)). For M365 specifically, re-baseline the tenant with the [ScubaGear assessment guide](ASSESS_M365_WITH_SCUBAGEAR.md).
5. **Close out.** Confirm containment held (no re-auth on the revoked identity, no persistence reappearing), work the notification decision with counsel against the clocks, and schedule the after-action review with tracked remediation owners.

**Checkpoint:** Persistence inventory closed, credentials rotated, initial vector remediated, hardening items tracked with owners, and a written eradication statement the incident lead will sign — plus a notification decision recorded with legal.

**Watch out:** Declaring eradication while a token still lives is the classic cloud failure — re-check the Step 2 token-expiry windows (especially the GCP 60-minute SA case) before you call it. And a rebuilt identity handed back its old over-broad permissions just resets the same trap; least privilege is part of eradication, not a later project.

## What good looks like

- Containment happened in the first hour and in the right order — credential cut, sessions revoked, persistence frozen, evidence locked — with every action timestamped in UTC.
- The fast-aging logs (Entra sign-ins, SaaS audit) were exported and hashed *before* they aged out, and any logging that was off is named as a coverage gap rather than glossed as "no impact."
- Initial access is a specific, evidenced finding with an earliest-foothold time — not "phishing, probably."
- The persistence sweep covered the whole identity fabric (keys, roles, app secrets, consent grants, MFA methods, mail rules, federation), and eradication removed all of it, not just the one alert.
- The blast-radius statement distinguishes confirmed access from coverage gaps, and it reached legal in time for the notification clocks.
- The initial vector is closed and the tenant is measurably harder than before — the incident produced hardening, not just cleanup.

## Go deeper

**In this library:**

- [Cloud, SaaS & Mobile Forensics Reference](/CLOUD_SAAS_MOBILE_FORENSICS_REFERENCE.md) — the acquisition backbone: per-provider log sources, retention clocks, collectors, and the incident quick-start checklist this guide sequences
- [Cloud Security Reference](/CLOUD_SECURITY_REFERENCE.md) — the controls (CloudTrail, GuardDuty, Entra CA, Defender for Cloud, org policy) you rebuild toward in Step 8
- [Cloud Attack Reference](/CLOUD_ATTACK_REFERENCE.md) — the attacker techniques (IAM privesc, IMDS SSRF, consent abuse, CloudTrail evasion) you're identifying in Steps 4–5
- [IR Playbooks](/IR_PLAYBOOKS.md) — the Account Compromise / Credential Theft, BEC, and Data Exfiltration playbooks this procedure operationalizes
- [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md) — the NIST SP 800-61 lifecycle and cloud/BEC response detail behind these steps
- [Identity & Access Management Reference](/IDENTITY_ACCESS_MANAGEMENT_REFERENCE.md) · [Identity Security Reference](/IDENTITY_SECURITY_REFERENCE.md) — conditional access, CAE, token handling, and the OAuth/consent governance behind containment
- [SaaS Security Reference](/SAAS_SECURITY_REFERENCE.md) — the case studies (Storm-0558, Midnight Blizzard, Okta support, Salesloft Drift) that motivate the persistence hunt
- [Digital Forensics Reference](/DIGITAL_FORENSICS_REFERENCE.md) — §9 cloud & email artifact-path tables and forensic reporting structure
- [SIEM Reference](/SIEM_REFERENCE.md) — exporting these logs and building the sign-in, consent-grant, and data-access detections that catch the next one
- [Regulatory Landscape Reference](/REGULATORY_LANDSCAPE_REFERENCE.md) — the breach-notification clocks that run alongside the investigation

**External:**

- [AWS — Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html) — the `AWSRevokeOlderSessions` mechanism used in Step 2
- [AWS Security Incident Response Guide](https://docs.aws.amazon.com/security-ir/latest/userguide/welcome.html) — AWS's own IR methodology and the cloud IR domains
- [Microsoft — Revoke user access in an emergency in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access) — the containment order and cmdlets in Step 2
- [Microsoft — Compromised and malicious applications investigation](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app) — the OAuth-app / consent-grant IR playbook
- [Google Cloud — Respond to compromised Google Cloud credentials](https://docs.cloud.google.com/docs/security/compromised-credentials) — the user vs service-account revocation model and the 60-minute token caveat
- [CISA — Untitled Goose Tool](https://github.com/cisagov/untitledgoosetool) — post-incident Entra/M365/Azure log collection

*Guides are procedures, not doctrine: cloud consoles, cmdlets, and API surfaces change continuously — verify every command and menu path against current official documentation before relying on it in production, and never test techniques against tenants you are not authorized to touch.*

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
