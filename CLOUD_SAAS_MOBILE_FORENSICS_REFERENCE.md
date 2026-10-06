# Cloud, SaaS & Mobile Forensics

> Acquisition, preservation, and investigation when the evidence lives in an API, a tenant, or a phone, not on a disk you can image. The cloud/SaaS/mobile-first companion to the host-, disk-, and memory-centric [DIGITAL_FORENSICS_REFERENCE.md](DIGITAL_FORENSICS_REFERENCE.md).

| | |
|---|---|
| Read this when | you are responding to a cloud/SaaS/identity incident and there is no server to image, you need to acquire logs before a retention window closes, you are collecting an iOS/Android device for exam, or you must preserve cloud evidence defensibly for legal hold |
| Start at | [Cloud forensic readiness](#cloud-forensic-readiness), [Mobile acquisition workflows](#mobile-acquisition-workflows), [Incident quick-start checklist](#incident-quick-start-checklist) |
| Pairs with | [DIGITAL_FORENSICS_REFERENCE.md](DIGITAL_FORENSICS_REFERENCE.md), [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md), [SAAS_SECURITY_REFERENCE.md](SAAS_SECURITY_REFERENCE.md), [MOBILE_SECURITY_REFERENCE.md](MOBILE_SECURITY_REFERENCE.md), [NETWORK_FORENSICS_REFERENCE.md](NETWORK_FORENSICS_REFERENCE.md) |

> Not legal advice. Preservation obligations, lawful-access limits (e.g. the US CLOUD Act, GDPR cross-border rules), and consent requirements for personal-device exam turn on facts and jurisdiction. Confirm scope and authority with counsel before collecting. Every version, retention window, and product name below was verified 2026-09-29; anything that drifts is marked *to confirm*.

The center of gravity in incident response has moved. The majority of 2024-2025 intrusions the community documented were identity-, cloud-, and SaaS-first: stolen OAuth tokens (Salesloft Drift / UNC6395), credential reuse against a SaaS data platform with no MFA (Snowflake / UNC5537), forged tokens and legacy-app abuse against M365 (Storm-0558, Midnight Blizzard). In none of these was there a host to seize. The artifact is an audit event in a tenant you may not fully own, held only as long as your license tier retains it. This reference covers what to enable *before* that day, how to acquire and preserve it *on* that day, and how to do the same for the mobile endpoints that increasingly hold the highest-value data.

This doc consolidates and extends the scattered cloud/mobile material in the library. For the underlying artifact-path tables (iOS `sms.db`, Android `mmssms.db`, M365 audit-operation meanings, CloudTrail JSON fields) see [DIGITAL_FORENSICS §8-9](DIGITAL_FORENSICS_REFERENCE.md#_8-mobile-device-forensics); this doc adds the acquisition workflows, preservation/chain-of-custody layer, readiness posture, open tooling, and cross-source timelining that a host-forensics doc does not.

---

## Why this discipline is different

| Host forensics assumption | Cloud / SaaS / mobile reality |
|---|---|
| You can physically seize and write-block the media | Evidence is provider-held; you acquire via API, admin console, or legal request, and you rarely touch the storage layer |
| Order of volatility runs memory -> disk | Inverted and *retention-bounded*: the most volatile evidence is a log that ages out on a timer (7-90-180 days), so preservation is a race, not a sequence |
| A full disk image is ground truth | There is no image; ground truth is reconstructed from logs across identity, control-plane, data-plane, and endpoint |
| Single tenant, single owner | Multi-tenancy and shared responsibility: you get customer-side logs; the provider holds the rest (subpoena/CLOUD Act territory) |
| Time is one clock | Sources span time zones and formats; normalize everything to UTC before correlating |

Two consequences drive everything below: (1) forensic readiness is the control that matters most; evidence you did not configure to retain simply does not exist later; and (2) acquisition and preservation are the hard part, not analysis. NIST codifies this: NIST IR 8006 (*Cloud Computing Forensic Science Challenges*, 2020) enumerates the 65 challenges, and NIST SP 800-201 (*Cloud Computing Forensic Reference Architecture*, final July 2024) gives the readiness model.

---

## Standards, chain of custody, and legal preservation

Work to recognized standards so the result is admissible and reproducible:

| Standard | Scope |
|---|---|
| ISO/IEC 27037:2012 | Identification, collection, acquisition, preservation of digital evidence (all media, incl. cloud reachable via a controlled endpoint) |
| ISO/IEC 27041 / 27042 / 27043 | Assurance of methods, analysis & interpretation, overarching investigation principles and process |
| ISO/IEC 27050 | Electronic discovery (eDiscovery) |
| NIST SP 800-86 | Integrating forensic techniques into incident response |
| NIST SP 800-101 Rev. 1 | Guidelines on mobile device forensics (acquisition modes, validation) |
| NIST SP 800-201 / NIST IR 8006 | Cloud forensic reference architecture (2024) and forensic-science challenges (2020) |
| SWGDE | Scientific Working Group on Digital Evidence: practitioner best-practice documents |

Chain of custody in the cloud. You cannot hash a running tenant, so custody attaches to the exported artifact: record who ran the export, the API/console used, the exact query and time range, source and collection timestamps (UTC), the account/credential and its authorization, and a hash of the resulting file computed at collection. Preserve the export read-only.

Preservation and immutability. Make the evidence tamper-evident and un-deletable:

- AWS: enable CloudTrail log file integrity validation (hourly signed digest files, SHA-256 hashing + SHA-256-with-RSA signing; verify with `aws cloudtrail validate-logs`). Store evidence in an S3 bucket with Object Lock (WORM) in compliance mode.
- Azure / M365: apply immutable blob storage (WORM/legal hold); use Microsoft Purview eDiscovery legal holds to freeze mailboxes/sites before collection.
- GCP: bucket retention policy + retention lock; export audit logs to a locked bucket or BigQuery sink.

Legal preservation. Issue a legal hold and log-export/preservation request to the vendor before retention expires: third-party SaaS logs are often gone in 90-180 days. Jurisdiction (data residency, CLOUD Act reach, GDPR transfer rules) governs what you may lawfully pull directly vs. what needs legal process. See [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md) for notification clocks that run in parallel.

---

## Cloud forensic readiness

What must be on before the incident, per provider. If it is not enabled at time-of-event, the evidence does not exist.

| Provider | Enable / configure | Default retention (raw) | Extend via |
|---|---|---|---|
| AWS | CloudTrail (management + S3/Lambda data events), log-file integrity validation, GuardDuty, VPC Flow Logs, Config | CloudTrail console history 90 days; delivered logs = as long as you keep the bucket | CloudTrail Lake / Athena over S3; Object Lock |
| Azure / Entra | Diagnostic settings streaming Entra sign-in/audit + Graph Activity Logs to Log Analytics/Storage; Defender for Cloud | Entra logs 7 days (Free) / 30 days (P1/P2); Graph Activity Logs P1/P2, not retained unless routed | Diagnostic settings -> Log Analytics / Event Hub / Storage |
| Microsoft 365 | Purview Audit (verify `UnifiedAuditLogIngestionEnabled`) | 180 days (Standard, logs on/after 17 Oct 2023) | Purview Audit (Premium) up to 10 years (E5 / add-on) |
| Google Workspace | Admin audit/investigation logging; BigQuery log export; Vault | Admin log events retention varies by event type | BigQuery export (indefinite); Vault retention rules |
| GCP | Cloud Audit Logs: Admin Activity on by default; enable Data Access logs (off except BigQuery) | Admin Activity 400 days; Data Access 30 days | Log sinks -> locked bucket / BigQuery |

> The one that bites people: GCP Data Access logs and AWS S3/Lambda data events are off by default, so "who read the bucket" is often unrecoverable after the fact. M365 `MailItemsAccessed` ("was the mailbox actually read?"), once E5-only, was de-gated to Audit Standard in 2024 (along with `Send` and search-query events), a direct outcome of the Storm-0558 logging-gap criticism.

---

## AWS acquisition and investigation

- Control-plane timeline: CloudTrail. The authoritative record of API activity. Pull with Athena or CloudTrail Lake (SQL); for the field-level query set (IAM changes, S3 data events, evasion detection such as `StopLogging`/`DeleteTrail`) see [DIGITAL_FORENSICS §9](DIGITAL_FORENSICS_REFERENCE.md#_9-cloud-amp-email-forensics) and [CLOUD_ATTACK_REFERENCE.md](CLOUD_ATTACK_REFERENCE.md). Validate integrity first:
  ```bash
  aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:us-east-1:ACCT:trail/NAME \
      --start-time 2026-09-01T00:00:00Z
  ```
- Detections as leads: GuardDuty Extended Threat Detection. GuardDuty now emits AI/ML attack sequences correlating CloudTrail, VPC Flow, DNS, and runtime signals (GA Dec 2024; EKS added Jun 2025; EC2/ECS `AttackSequence:*` critical findings Dec 2025). Use the sequence as the spine of the timeline, then corroborate from raw logs.
- Disk-level acquisition: EBS snapshot workflow (the cloud analog of imaging):
  1. Snapshot the volume(s) of the affected instance: immutable, point-in-time.
  2. Isolate the instance (restrictive SG, revoke instance-profile creds) rather than terminating it; capture instance metadata and, where possible, memory.
  3. Share the snapshot to a dedicated, isolated forensic account, create a volume from it there, and attach to a hardened analysis instance: the original snapshot stays untouched.
  4. Hash the resulting volume/image and record custody.
- Automate it. AWS Security Incident Response service (GA Dec 2024) provides monitoring, case management, and 24/7 access to the AWS CIRT; the Automated Forensics Orchestrator for Amazon EC2 & EKS (AWS Solutions) scripts snapshot/memory capture and isolation. Open-source: AWS IR, Cado, Velociraptor.

---

## Azure and Microsoft 365

- Identity plane: Entra ID. Pull sign-in logs (interactive + non-interactive + service-principal/managed-identity), audit logs, and Graph Activity Logs (records raw Graph API calls; critical for token-/OAuth-abuse cases like Midnight Blizzard). Retention is short (7d Free / 30d P1/P2), so collect immediately or rely on your Log Analytics export.
- M365: Purview Unified Audit Log (UAL). The cross-workload record (Exchange, SharePoint/OneDrive, Teams, Entra). Query via `Search-UnifiedAuditLog` or the Purview portal; operation meanings are tabulated in [DIGITAL_FORENSICS §9](DIGITAL_FORENSICS_REFERENCE.md#_9-cloud-amp-email-forensics).
  ```powershell
  Connect-ExchangeOnline
  Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-90) -EndDate (Get-Date) `
    -Operations MailItemsAccessed,Send,New-InboxRule,Add-MailboxPermission,Consent to application `
    -UserIds suspect@contoso.com -ResultSize 5000 | Export-Csv ual.csv -NoTypeInformation
  ```
- Purpose-built collectors (use when logs are not already in a SIEM):

  | Tool | Source | Collects |
  |---|---|---|
  | Untitled Goose Tool | CISA (`cisagov`) | Entra sign-in/audit, M365 UAL, Azure activity, MDE/Defender data |
  | Microsoft-Extractor-Suite | Invictus IR | Broad UAL/Entra/Graph/message-trace export, PowerShell |
  | Hawk | Community | M365 tenant/user BEC investigation (rules, forwarding, OAuth grants) |
  | DFIR-O365RC | Community | Office 365 / Entra log collection to JSON |

- OAuth/app abuse. Enumerate enterprise applications, service principals, consent grants, and app credentials/secrets added: the dominant SaaS-era persistence path. Cross-link the hardening/governance side in [SAAS_SECURITY_REFERENCE.md](SAAS_SECURITY_REFERENCE.md) and [IDENTITY_SECURITY_REFERENCE.md](IDENTITY_SECURITY_REFERENCE.md).

---

## Google Workspace and GCP

- Workspace: Admin console Reports -> Audit & investigation (Login, Admin, Drive, Gmail, OAuth Token). Preserve with Google Vault (matter -> hold -> export MBOX/JSON/PST). Email Log Search gives delivery path + IPs. Route audit events to BigQuery for durable, queryable retention and to survive console retention limits.
- GCP: Cloud Audit Logs: *Admin Activity* (always on, ~400 days) and *Data Access* (off by default outside BigQuery; enable it, ~30 days). Query in Cloud Logging, or analyze BigQuery-exported logs by `principalEmail`, `methodName`, `callerIp`. Alert Center aggregates Google-surfaced threats.

---

## SaaS application forensics

SaaS is "someone else's software, your security problem," and its logs are license-gated and short-lived. Identify every app (via Entra/Workspace enterprise apps and SSO config), determine each app's retention, and issue export/hold requests early.

| Platform | Log access | Default retention |
|---|---|---|
| Salesforce | Setup -> Event Monitoring / Event Log Files (API/UI); Shield adds real-time | Log files ~24h-30d; Event Monitoring/Shield extends |
| Okta | System Log (UI + API) | ~90 days (API) |
| GitHub | Org/enterprise Audit Log (UI + API + streaming) | ~90-180 days; audit-log streaming for durable |
| Slack | Audit Logs API + Discovery API (Enterprise Grid) | Plan-dependent |
| Box / Dropbox / Zoom | Admin console events / reports / API | Plan-dependent |

Investigation focus mirrors the abused-trust pattern: third-party OAuth token grants and replay, API-key/PAT creation, session-token theft, mass export/download events, and new integration connections. The public case studies that motivate each control (Storm-0558, Okta support-system, Midnight Blizzard, Salesloft Drift/UNC6395) are documented in [SAAS_SECURITY_REFERENCE.md](SAAS_SECURITY_REFERENCE.md); this doc is the acquisition side of the same coin.

---

## Mobile acquisition workflows

Choose the least-invasive method that yields the needed data, and document why. Acquisition ladder (least -> most invasive), consistent with NIST SP 800-101r1:

iOS

| Method | Yields | Requires |
|---|---|---|
| Encrypted iTunes/Finder backup | App data incl. keychain, messages, health | Backup encryption password (set one: it *increases* data captured) |
| `sysdiagnose` / logical | Diagnostic logs, `shutdown.log`, process/network state | Device unlocked; on-device trigger |
| Advanced / commercial (agent or exploit) | Full File System (FFS) | Cellebrite/Magnet/Elcomsoft; often passcode |
| checkm8 / checkra1n | FFS via BootROM exploit | A5-A11 (iPhone 4S-iPhone X) only; tethered/single-boot; BFU or AFU |
| Chip-off | Raw NAND | Destructive, lab-level |

`checkm8` is a hardware BootROM flaw Apple cannot patch on affected chips: a durable acquisition path for older devices; A12+ needs commercial exploit tooling. Note BFU (Before First Unlock) yields far less than AFU (After First Unlock) because file-based encryption keys are still sealed.

Android

- `adb backup` is dead for forensics: deprecated in Android 12 (API 31) and removed from platform-tools r34 (May 2023); modern apps opt out of it entirely. Do not build a workflow on it.
- Logical/triage: `adb bugreport`, content-provider pulls, and AndroidQF (MVT project): packages `bugreport`, logcat, package list, and accessible files with hashes.
- Full File System / physical: root/exploit, EDL (Qualcomm), or commercial tooling; parse the resulting image with the tools below.

MDM as an evidence source (Intune, Jamf Pro, Workspace ONE): device inventory, compliance history (was encryption/passcode on?), app install/removal, location (if policy-enabled), and, forensically important, remote-wipe commands (who issued, when, whether executed): potential spoliation evidence. See [DIGITAL_FORENSICS §8](DIGITAL_FORENSICS_REFERENCE.md#_8-mobile-device-forensics) for the full iOS/Android artifact-path tables and [MOBILE_SECURITY_REFERENCE.md](MOBILE_SECURITY_REFERENCE.md) for platform architecture.

---

## Spyware and targeted-implant triage

For suspected mercenary spyware (Pegasus/Predator-class) on a consenting user's device:

- MVT (Mobile Verification Toolkit): Amnesty International Security Lab; iOS + Android; scans a backup/FFS against STIX2 IOCs for traces of known campaigns. Pair with AndroidQF for the acquisition step.
  ```bash
  pip install mvt
  mvt-ios check-backup --iocs indicators.stix2 --output out/ /path/to/backup
  mvt-android check-androidqf --iocs indicators.stix2 --output out/ androidqf_acquisition/
  ```
- iOS lightweight signals: `sysdiagnose`/`shutdown.log` anomalies and diagnostic logs can flag reboots that coincide with implant activity (the technique Kaspersky published as *iShutdown*). Treat as a *lead*, not proof.
- Caveats: public IOCs are necessary but not sufficient: a clean MVT run does not certify a clean device, and absence of a known IOC ≠ absence of compromise. iOS Lockdown Mode reduces attack surface but is not a forensic control. MVT is an investigator tool, not end-user self-assessment.

---

## Timeline building and cross-source correlation

The deliverable is one normalized, UTC super-timeline stitched from identity, cloud control-plane, SaaS, and endpoint sources.

- Normalize to UTC first. Every source has its own zone/format; skew destroys correlation. Record each source's native zone in custody notes.
- Pivot keys across sources: user/UPN, IP + ASN, user-agent, OAuth app/client ID, `session_id`/token ID, device ID, and resource ARNs/URLs.
- Correlation pattern: anomalous sign-in (Entra/Okta/Workspace) -> consent/token grant -> control-plane action (CloudTrail/Azure activity) -> data-plane access (S3 data events / `MailItemsAccessed` / Drive export) -> endpoint corroboration.
- Tooling: Timesketch (collaborative timeline) fed by plaso/log2timeline (host artifacts) plus cloud logs; Sigma rules for repeatable detection over exported logs; native Athena / CloudTrail Lake / KQL / BigQuery for the cloud tables. Network-side reconstruction (flow <-> CloudTrail correlation) is in [NETWORK_FORENSICS §9](NETWORK_FORENSICS_REFERENCE.md#_9-cloud-amp-container-network-forensics).

---

## Open-source tooling matrix

| Tool | Domain | Role |
|---|---|---|
| iLEAPP / ALEAPP (+ RLEAPP, VLEAPP): `leapps.org` | Mobile / returns | Free Python artifact parsers; GUI + module filtering (v3.3.0, Feb 2025); LAVA artifact viewer/report |
| APOLLO | iOS | Pattern-of-life correlation across iOS databases |
| MVT + AndroidQF | iOS / Android | Consensual spyware forensics + Android acquisition |
| Untitled Goose Tool | Azure / M365 | CISA post-incident cloud log collector |
| Microsoft-Extractor-Suite / Hawk / DFIR-O365RC | M365 / Entra | Log export & BEC investigation |
| AWS IR / Automated Forensics Orchestrator / Velociraptor | AWS / endpoint | Snapshot & memory capture, isolation, live response |
| Cado / Velociraptor | Multi-cloud + host | Cross-source acquisition and analysis |
| Timesketch + plaso | Timeline | Super-timeline and collaborative analysis |
| libimobiledevice | iOS | Open backup/pairing (`idevicebackup2`) |

Commercial platforms remain standard for court work and locked devices: Cellebrite Inseyets/UFED, Magnet AXIOM and Magnet GrayKey, Oxygen Forensic Detective, Elcomsoft (iOS/cloud). Product names verified current 2026-09-29.

---

## Incident quick-start checklist

When a cloud/SaaS/identity incident lands and there is no host to seize:

1. Preserve first, analyze second. Enumerate every relevant source and its retention clock; the tightest window sets the pace.
2. Freeze the fast-aging evidence: export Entra/Okta/Workspace sign-in + audit logs and the M365 UAL now; enable/verify S3 Object Lock or immutable blob for the evidence store.
3. Issue legal holds / vendor export requests for third-party SaaS before 90-180-day windows expire.
4. Validate integrity on acquisition (`cloudtrail validate-logs`; hash every export at collection) and record chain of custody (who, credential, query, UTC times).
5. Snapshot, don't terminate affected instances; share to an isolated forensic account; capture memory where possible.
6. Investigate identity and tokens: anomalous sign-ins, OAuth consent grants, new app credentials/PATs, inbox/forwarding rules, mass exports.
7. Acquire mobile with the least-invasive sufficient method; if targeted-spyware is suspected and the user consents, run MVT against fresh IOCs.
8. Build one UTC super-timeline and correlate across identity -> cloud -> SaaS -> endpoint.
9. Report to the [DIGITAL_FORENSICS §10](DIGITAL_FORENSICS_REFERENCE.md#_10-forensic-reporting-amp-tools-reference) structure; map notification clocks via [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md).

---

## Related Resources

- [DIGITAL_FORENSICS_REFERENCE.md](DIGITAL_FORENSICS_REFERENCE.md): host/disk/memory forensics; §8 mobile and §9 cloud & email artifact-path tables this doc builds on
- [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md): the IR lifecycle and cloud/BEC response procedures these acquisitions feed
- [SAAS_SECURITY_REFERENCE.md](SAAS_SECURITY_REFERENCE.md): SaaS threat surface, case studies, and the hardening side of SaaS logging
- [MOBILE_SECURITY_REFERENCE.md](MOBILE_SECURITY_REFERENCE.md), [MOBILE_ATTACK_ATLAS.md](MOBILE_ATTACK_ATLAS.md): mobile platform architecture and ATT&CK Mobile
- [NETWORK_FORENSICS_REFERENCE.md](NETWORK_FORENSICS_REFERENCE.md): cloud/container network reconstruction (flow <-> CloudTrail)
- [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md), [CLOUD_ATTACK_REFERENCE.md](CLOUD_ATTACK_REFERENCE.md): the controls and attacker techniques behind the detections
- [IDENTITY_SECURITY_REFERENCE.md](IDENTITY_SECURITY_REFERENCE.md): identity-plane context for token/OAuth investigation
- [REGULATORY_LANDSCAPE_REFERENCE.md](REGULATORY_LANDSCAPE_REFERENCE.md): breach-notification clocks that run alongside the investigation
- [IR_PLAYBOOKS.md](IR_PLAYBOOKS.md), [THREAT_HUNTING_REFERENCE.md](THREAT_HUNTING_REFERENCE.md): operational playbooks and hunting hypotheses

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
