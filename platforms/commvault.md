# Commvault

Commvault Cloud is a data protection and cyber-recovery platform that covers backup, recovery, and resilience across workloads. It includes the Metallic software-as-a-service offerings for cloud-delivered protection. The platform adds immutable and air-gapped copies, Threatwise cyber deception, and recovery orchestration and testing. Licence tier decides which products and capabilities are in force.

## What it is and where it fits

Commvault Cloud is a platform for backup, recovery, and cyber resilience. It protects virtual machines, physical servers, databases, applications, cloud workloads, and SaaS data across on-premises and cloud environments.

The Metallic offerings deliver Commvault protection as software-as-a-service, so teams can consume backup and recovery without running all of the infrastructure themselves. On-premises, hybrid, and SaaS models can coexist in one estate.

In a security program, Commvault sits in the recover function and adds detection and deception. It is the corrective control that restores systems after destructive attacks, and it includes features that help detect and investigate compromise.

## Architecture and how it works

A Commvault deployment is built from a control layer, data movers, and storage targets, available as managed infrastructure or as a service.

- The control plane coordinates policies, schedules, and the catalog of protected data. It is the management and reporting layer.
- Data movers read source workloads, process the data, and transport it to storage. They handle deduplication, compression, and transfer.
- Storage targets include disk, deduplicated storage, cloud object storage, and tape for long retention and offline copies.
- Agents and integrations protect workloads through hypervisor, database, application, operating system, and cloud APIs.

Protection is plan-driven. Administrators define plans that set backup frequency, retention, and storage targets, then assign workloads to them. The platform captures data, stores it, and ages copies across tiers to match each plan.

In the Metallic model, much of the control and storage infrastructure is delivered as a service, while data capture still happens where the workloads run.

## Key capabilities

- Backup and recovery across virtual, physical, database, application, cloud, and SaaS workloads.
- Metallic software-as-a-service delivery for cloud-managed protection.
- Immutable copies so backup data cannot be altered after it is written.
- Air-gapped copies through offline and isolated storage targets.
- Threatwise cyber deception, which places decoys to detect attacker activity early.
- Anomaly detection across backup data to flag signs of ransomware.
- Recovery orchestration that automates and sequences large-scale restores.
- Recovery testing to validate that restores work as planned.

## Deployment and operations

Commvault runs as managed infrastructure on-premises, as the Metallic service, or in a hybrid model. Teams choose how much of the stack they operate versus consume as a service.

Operations centre on plans and estate health. Administrators assign workloads to protection plans and monitor compliance, job success, and capacity from the management layer. Reporting shows coverage, failures, and workloads outside policy.

Recovery orchestration is a core operational feature. It defines the order and dependencies for restoring groups of systems, so a large recovery follows a planned sequence rather than ad hoc effort.

Recovery testing and runbooks remain an operational discipline. The platform automates orchestration, but the program must rehearse restores and record the outcomes.

## Immutability, air-gap, and ransomware recovery

This is the security heart of the platform. Commvault protects backup data from tampering and adds detection to find attacks early.

Immutable copies prevent modification after write. Backup data placed on immutable storage, including object-lock cloud targets, cannot be changed or deleted for the retention period, which blocks an attacker from editing or erasing recovery points.

Air-gapped copies add isolation. Offline targets such as tape, and logically isolated copies that the production network cannot reach, survive an intrusion that compromises primary systems. An isolated copy is what makes recovery credible after a wide breach.

Commvault supports the intent of the 3-2-1-1-0 rule: multiple copies, across different media or locations, with at least one offline or immutable copy, and recovery verified so restores are known to work. The immutable or offline copy and the tested restore are what defeat ransomware that targets production and backups together.

Anomaly detection provides backup-side warning. It studies change rates, encryption-like patterns, and deletion behaviour across backups, and flags anomalies that may indicate an attack. These signals help responders find a clean recovery point before reinfection.

Threatwise adds cyber deception. It places decoy assets that have no legitimate use, so interaction with them is a strong signal of attacker activity. Early detection through deception can shorten dwell time before an attack reaches production and backups.

Recovery orchestration and testing turn verification into a repeatable process. Orchestrated test restores confirm that the surviving copies recover in the right order and within recovery targets.

## Hardening and secure use

The platform is a top target because it holds the recovery capability and the catalog of protected data.

- Use separate credentials and identities for Commvault administration. Do not reuse production domain administrator accounts.
- Require multi-factor authentication for all administrative and console access.
- Apply least privilege through role-based access, so no single account can both change plans and erase retained copies without controls.
- Isolate management access to the control plane from general user networks.
- Protect the management console as a critical asset. Unauthorized access can expose stored credentials and allow backup deletion, which maps to missing authorization (CWE-862) and the risk of hard-coded or reused credentials (CWE-798).
- Keep at least one immutable or air-gapped copy that a live intrusion cannot reach.
- Test restores on a schedule and record the results, so recovery is proven before an incident.

Because the platform stores credentials for many systems and catalogs protected data, treat its compromise as a broad breach, not only a loss of backups.

## Where it fits in the program

Backup and recovery is the corrective control after destructive exploitation. Prevention and detection reduce the frequency and dwell time of incidents, but do not guarantee that production survives every attack.

When systems are encrypted or wiped, recovery from immutable, verified copies restores the business. Commvault provides that corrective capability, adds deception and anomaly detection, and orchestrates large-scale restores so recovery follows a plan.

This page pairs with the program-level references. See `/RANSOMWARE_DEFENSE_REFERENCE.md` for how immutable and offline copies fit ransomware response, and `/CYBER_RESILIENCE_BCDR_REFERENCE.md` for recovery objectives, runbooks, and continuity planning.

## Resources

- Commvault Cloud product documentation.
- Commvault and Metallic administration and user guides.
- Commvault Threatwise documentation.
- Commvault recovery orchestration documentation.

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/veeam.md`
- `/platforms/cohesity.md`
- `/platforms/dell-powerprotect.md`
