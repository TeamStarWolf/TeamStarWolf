# Cohesity

Cohesity is a data management and security platform that consolidates backup with threat and anomaly analytics. DataProtect handles backup and recovery with immutable snapshots, while DataHawk adds threat detection and data classification. The Helios control plane manages estates from one place. Licence tier decides which products and capabilities are in force.

## What it is and where it fits

Cohesity is a platform for backup, recovery, and data security. It protects virtual machines, physical servers, databases, cloud workloads, and SaaS data, and manages them across sites from a cloud-delivered control plane.

A defining idea is consolidation. Cohesity brings backup data and security analytics together, so the same protected copies are also analysed for threats, anomalies, and sensitive content.

In a security program, Cohesity sits in the recover function and contributes to detection and data governance. It is the corrective control that restores systems after destructive attacks, and it analyses the backup data for signs of compromise.

## Architecture and how it works

Cohesity is built on a distributed file system that stores backup data, with management delivered through a cloud control plane.

- Helios is the control plane. It manages clusters, policies, and reporting across sites and provides the management interface.
- Clusters store backup data on a distributed, scale-out file system. Capacity and performance grow by adding nodes.
- DataProtect is the backup and recovery application that captures and restores workloads.
- Sources are protected through integrations with hypervisors, databases, operating systems, and cloud APIs. Agents cover workloads that need them.
- Data can tier to cloud object storage and archive targets for long retention.

Protection is policy-driven. Administrators assign workloads to policies that set frequency, retention, and copy locations. The platform captures snapshots, stores them, and ages them to match the policy.

Snapshots are stored so that they cannot be modified in place. This gives each backup point a fixed, independent state on the file system.

## Key capabilities

- DataProtect backup and recovery for virtual, physical, database, cloud, and SaaS workloads.
- Immutable snapshots so backup points cannot be altered after capture.
- Instant recovery of workloads directly from backup storage.
- DataHawk for threat detection, anomaly detection, and data classification.
- Sensitive data classification to locate regulated or confidential data across protected workloads.
- Helios control plane for multi-site management, policy, and reporting.
- Tiering to cloud and archive storage for long retention.
- Consolidation of backup and security analytics on one platform.

## Deployment and operations

Cohesity runs on-premises on clusters, in cloud environments, or in a mixed model, with Helios providing management across all of them. Workload capture happens where the data lives.

Operations focus on policies and estate health. Administrators map workloads to protection policies and monitor compliance from Helios. The control plane reports protection coverage, job health, capacity, and workloads that fall outside policy.

Because analytics are built in, security operations consume anomaly and classification findings as part of their workflow. Findings about suspected compromise or sensitive data feed the wider response and governance processes.

Recovery testing and runbooks stay an operational responsibility. The platform supports instant and granular recovery, but restores must be rehearsed and recorded.

## Immutability, air-gap, and ransomware recovery

This is the security heart of the platform. Cohesity protects the backup data and analyses it for attack signals.

Snapshots are immutable. Once a backup snapshot is written, it cannot be modified in place, which prevents an attacker or faulty process from editing existing recovery points. Immutability is a property of the platform rather than a single repository setting.

Air-gapped and isolated copies extend protection. Copies tiered to cloud or archive targets, or kept logically isolated from the production network, survive an intrusion that reaches primary systems. An isolated copy is what makes recovery credible after a wide compromise.

Cohesity supports the intent of the 3-2-1-1-0 rule: several copies, across different media or locations, with at least one offline or immutable copy, and recovery verified so restores are known to work. The immutable copy and the tested restore are what defeat ransomware that targets production and backups together.

DataHawk provides backup-anomaly and threat detection. It studies change rates, encryption-like patterns, and other anomalies across snapshots, and applies threat intelligence to flag indicators of compromise. These signals give responders earlier warning and help locate a clean recovery point.

Data classification adds impact context. Knowing which sensitive data a compromised system held informs notification, prioritization, and recovery order.

Recovery testing turns the verification step into evidence. Scheduled restores and documented results confirm that the surviving copies recover cleanly.

## Hardening and secure use

The platform is a top target because it holds the recovery capability and copies of sensitive data.

- Use separate credentials and identities for Cohesity administration. Do not reuse production domain administrator accounts.
- Require multi-factor authentication for all administrative and console access.
- Apply least privilege through role-based access, so no single account can both change policy and erase retained copies without controls.
- Isolate management access to the clusters and Helios from general user networks.
- Protect the control plane and management console as a critical asset. Unauthorized access can expose stored credentials and sensitive data, which maps to missing authorization (CWE-862) and the risk of hard-coded or reused credentials (CWE-798).
- Keep at least one immutable or isolated copy that a live intrusion cannot reach.
- Test restores on a schedule and record the results, so recovery is proven before an incident.

Because the platform stores credentials and classifies sensitive data, treat its compromise as a serious breach in its own right, not only a loss of backups.

## Where it fits in the program

Backup and recovery is the corrective control after destructive exploitation. Prevention and detection lower the frequency and dwell time of incidents, but do not guarantee that production survives every attack.

When systems are encrypted or wiped, recovery from immutable, verified snapshots restores the business. Cohesity provides that corrective capability and consolidates analytics that help responders detect compromise and understand data impact.

This page pairs with the program-level references. See `/RANSOMWARE_DEFENSE_REFERENCE.md` for how immutable and isolated copies fit ransomware response, and `/CYBER_RESILIENCE_BCDR_REFERENCE.md` for recovery objectives, runbooks, and continuity planning.

## Resources

- Cohesity DataProtect product documentation.
- Cohesity DataHawk documentation.
- Cohesity Helios documentation.
- Cohesity administration and user guides.

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/rubrik.md`
- `/platforms/commvault.md`
- `/platforms/veeam.md`
