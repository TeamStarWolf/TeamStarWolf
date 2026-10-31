# Dell PowerProtect

Dell PowerProtect is a family for data protection and cyber recovery. It combines PowerProtect Data Manager software, PowerProtect Data Domain protection storage, and the PowerProtect Cyber Recovery vault. Together they back up workloads, store them with deduplication and retention lock, and keep an isolated copy for recovery after a destructive attack. The isolated vault pattern is the product's defining security feature.

## What it is and where it fits

PowerProtect Data Manager discovers workloads, runs protection policies, and tracks copies. PowerProtect Data Domain is the storage tier that holds those copies with deduplication and immutability.

PowerProtect Cyber Recovery is a separate, isolated vault. It holds a locked copy of critical data behind a controlled network link that stays closed most of the time.

In a security program the family is a corrective control. It supplies the clean data and the analytics needed to trust that data after ransomware or a wiper reaches production. Licence tier and edition decide which capabilities, such as CyberSense analytics, are in force.

## Architecture and how it works

Data Manager is the control layer. It finds virtual machines, databases, file systems, Kubernetes, and application data, then drives backups according to policy.

Data Domain is the protection storage. It applies variable-length deduplication so repeated data is stored once, which keeps long retention practical.

Backups land on Data Domain in the production environment for fast local restore. A policy then replicates selected copies into the Cyber Recovery vault.

The vault sits on its own Data Domain system in an isolated environment. The network link between production and the vault, the air gap, opens only to synchronize data and then closes again.

Inside the vault, CyberSense reads the data and its metadata. It builds an index of content and change behavior so it can score whether a copy shows signs of corruption or ransomware.

## Key capabilities

Deduplicated protection storage reduces the stored footprint. This makes it affordable to keep many restore points over a long window.

Retention Lock provides immutability. A locked copy cannot be modified or deleted before its retention expires, which blocks tampering by an operator or an attacker.

The Cyber Recovery vault provides an air-gapped, isolated copy. Because the link is normally closed, online attackers cannot see or reach the vaulted data.

CyberSense analytics detect data corruption and ransomware. They analyze content, not just metadata, and flag mass encryption, suspicious file changes, and deletions.

Recovery workflows help bring data back from the vault in a controlled way. Analytics identify the last known good copy so recovery starts from trusted data.

Broad workload support covers common hypervisors, major databases, file systems, and containers. One policy model spans these workloads.

## Deployment and operations

Start from recovery objectives for each critical workload. Recovery time objective and recovery point objective drive backup frequency, retention, and what enters the vault.

Decide which data is critical enough for the Cyber Recovery vault. The vault protects the crown jewels needed to restart the business, not every copy.

Configure synchronization windows for the air gap. The link should open only long enough to replicate, then close, so the vault stays isolated.

Schedule CyberSense analysis after each synchronization. Review its scores and alerts, and investigate any copy flagged as corrupted.

Monitor Data Domain capacity, deduplication ratios, and replication health. Patch Data Manager, Data Domain, and the vault software on a defined cadence.

## Immutability, air-gap, and ransomware recovery

Retention Lock is the immutability control. Locked copies on Data Domain cannot be erased or altered early, which preserves the restore points you depend on.

The Cyber Recovery vault is the air-gapped, isolated copy. Its normally closed link is the strongest barrier in the design, because it removes the attacker's network path to the backups.

Follow the 3-2-1-1-0 rule. Keep three copies on two media types, one offsite, one offline or immutable, and zero recovery errors confirmed by testing.

CyberSense is the anomaly detection layer. Content-level analysis finds the corruption that metadata alone can miss, and it points to the last clean copy for recovery.

Test vault recovery on a schedule. Rehearse recovering critical systems from the vault so the air gap does not hide a broken restore path.

## Hardening and secure use

Give the backup and vault systems their own identities and credentials. Do not share production administrator accounts with Data Manager, Data Domain, or the vault.

Use separate operators for the vault. The Cyber Recovery environment should have its own small set of accounts, distinct from day-to-day backup administration.

Require multi-factor authentication and multi-person approval for destructive actions. Early deletion or unlocking of retained data should need more than one person.

Treat the backup and vault control planes as top targets. Missing authorization maps to CWE-862, and hard-coded or default credentials map to CWE-798. Audit roles and service accounts against both.

Test restores as a security control. Confirm recovered data is clean and complete within the recovery time objective, and record who ran each recovery.

## Where it fits in the program

PowerProtect is the corrective control after destructive exploitation. The vault and CyberSense exist because prevention can fail and the organization still needs a trusted copy to return to.

Pair it with the preventive and detective controls in `/RANSOMWARE_DEFENSE_REFERENCE.md`. Those reduce the chance of encryption, while PowerProtect provides isolated recovery when they do not.

Place its objectives inside the continuity plan in `/CYBER_RESILIENCE_BCDR_REFERENCE.md`. The vault should hold what the business impact analysis identifies as essential to restart operations.

## Resources

- Dell PowerProtect Data Manager Administration and User Guide
- Dell PowerProtect Data Domain documentation
- Dell PowerProtect Cyber Recovery Product Guide
- Dell PowerProtect Cyber Recovery with CyberSense documentation
- Dell PowerProtect Data Domain Retention Lock documentation

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/veritas-netbackup.md`
- `/platforms/rubrik.md`
- `/platforms/cohesity.md`
