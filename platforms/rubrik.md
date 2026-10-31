# Rubrik

Rubrik Security Cloud provides backup and cyber recovery with a focus on data security posture. It stores backups in immutable, append-only form and adds analytics that detect ransomware and anomalies inside protected data. The platform also discovers sensitive data and supports investigation after an incident. Licence tier decides which modules and workload coverage are in force.

## What it is and where it fits

Rubrik Security Cloud is a data protection and cyber-recovery platform. It protects virtual machines, physical servers, databases, cloud workloads, and SaaS data, and manages them from a cloud-delivered control plane.

Rubrik frames itself around data security rather than backup alone. Beyond keeping recoverable copies, it tries to answer where sensitive data lives, whether backups show signs of attack, and how to recover to a clean point.

In a security program, Rubrik sits in the recover function and contributes to detection. It is the corrective control that restores systems after destructive attacks, and it adds analytics that flag compromise in the backup data.

## Architecture and how it works

Rubrik combines on-site or cloud data capture with a cloud-delivered control plane.

- The control plane runs the management, policy, and analytics services. Administrators define protection through policies rather than per-job scripting.
- Data is captured from sources through integrations with hypervisors, databases, operating systems, and cloud APIs.
- Backup data is stored in an immutable, append-only format. Once written, a backup cannot be changed in place.
- Copies can be tiered to cloud object storage and archive targets for long retention.

Protection is policy-driven. An administrator assigns a workload to a policy that defines frequency, retention, and where copies live. The system then captures, stores, and ages data to match the policy without hand-built jobs.

The append-only design means each backup is a new, independent point. There is no in-place rewrite that an attacker or faulty process could use to corrupt existing restore points.

## Key capabilities

- Backup and recovery for virtual, physical, database, cloud, and SaaS workloads.
- Immutable, append-only storage so restore points cannot be altered after they are written.
- Data Threat Analytics, which analyses backups for anomalies and signs of ransomware.
- Ransomware Investigation, which helps locate the point of compromise and identify a clean recovery point.
- Sensitive Data Discovery, which classifies and locates sensitive data across protected workloads.
- Air-gapped or logically isolated copies for recovery that survives a live intrusion.
- Granular and full recovery, including recovery to original or alternate locations.

## Deployment and operations

Rubrik is delivered as a cloud-managed platform, with data capture on-premises or in cloud environments depending on where workloads run. Management, policy, and analytics are consumed through the control plane.

Operations focus on policy design and posture, not individual jobs. Administrators map workloads to protection policies and monitor compliance against them. The platform reports which workloads are protected, which fall outside policy, and where retention or recovery goals are at risk.

Security operations use the analytics features as part of incident work. Anomaly findings and investigation views feed into the broader response process when an attack is suspected.

Recovery testing and runbooks remain an operational responsibility. The platform supports recovery, but the program must rehearse and record restores.

## Immutability, air-gap, and ransomware recovery

This is the security heart of the platform. Rubrik is built so that backups resist tampering and help find a clean recovery point.

The storage layer is immutable and append-only. Backups are written once and cannot be modified afterward, which blocks an attacker or faulty process from editing existing restore points. This property is enforced by the platform rather than left to repository configuration.

Air-gapped or logically isolated copies extend protection. A copy kept logically separate, or archived to a target an attacker cannot reach from the production network, survives an intrusion that compromises primary systems. These isolated copies are what make recovery credible after a wide breach.

Rubrik supports the intent of the 3-2-1-1-0 rule: multiple copies, on different media or locations, with at least one offline or immutable copy, and recovery verified so restores are known to work. The immutable copy and the verified restore are what defeat ransomware that targets both production and backups.

Data Threat Analytics provides backup-anomaly detection. It studies change rates, encryption-like patterns, and deletion behaviour across restore points. When it flags anomalies, responders get an earlier signal and a narrower window to investigate.

Ransomware Investigation builds on that analysis. It helps responders trace when compromise began and which restore point predates the damage. Choosing a clean point matters, because recovering from an infected backup reintroduces the attack.

Sensitive Data Discovery adds impact context. Knowing which sensitive data a compromised system held informs notification, prioritization, and the order of recovery.

## Hardening and secure use

The backup platform is a prime target because it holds the recovery capability and copies of sensitive data.

- Use separate credentials and identities for Rubrik administration. Do not reuse production domain administrator accounts.
- Require multi-factor authentication for all administrative and console access.
- Apply least privilege through role-based access, so no single account can both manage policy and erase retained copies without controls.
- Isolate management access to the platform from general user networks.
- Protect the control plane and management console as a critical asset. Unauthorized access can expose stored credentials and sensitive data, which maps to missing authorization (CWE-862) and the risk of hard-coded or reused credentials (CWE-798).
- Keep at least one air-gapped or logically isolated copy that a live intrusion cannot reach.
- Test restores on a schedule and record the results, so recovery is proven before an incident.

Because the platform stores credentials and indexes sensitive data, treat its compromise as a serious breach in its own right, not only a loss of backups.

## Where it fits in the program

Backup and cyber recovery is the corrective control after destructive exploitation. Prevention and detection reduce the frequency and dwell time of incidents, but cannot promise that production survives every attack.

When systems are encrypted or wiped, recovery from immutable, verified copies restores the business. Rubrik provides that corrective capability and adds analytics that help responders find a clean point and understand data impact.

This page pairs with the program-level references. See `/RANSOMWARE_DEFENSE_REFERENCE.md` for how immutable and isolated copies fit ransomware response, and `/CYBER_RESILIENCE_BCDR_REFERENCE.md` for recovery objectives, runbooks, and continuity planning.

## Resources

- Rubrik Security Cloud product documentation.
- Rubrik user and administration guides.
- Rubrik Data Threat Analytics documentation.
- Rubrik Ransomware Investigation documentation.
- Rubrik Sensitive Data Discovery documentation.

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/veeam.md`
- `/platforms/cohesity.md`
- `/platforms/commvault.md`
