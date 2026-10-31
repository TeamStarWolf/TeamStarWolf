# Veritas NetBackup

Veritas NetBackup is an enterprise backup and recovery product for large, heterogeneous environments. The product line continues under Cohesity, which acquired Veritas as an organization. It protects physical servers, virtual machines, databases, applications, and cloud workloads from one control layer. Its security value is the ability to recover clean data after a destructive attack.

## What it is and where it fits

NetBackup centralizes data protection across a mixed estate of operating systems, hypervisors, databases, and storage targets. It fits organizations that need one policy model to cover thousands of workloads at scale.

In a security program it is a corrective control. When ransomware or a wiper destroys production data, NetBackup supplies the clean, retained copies used to restore service. It sits beside, not inside, the preventive controls that try to stop the attack.

The product is sold as software you deploy and as the NetBackup Flex family of appliances. Licence tier and edition decide which capabilities, such as malware scanning and recovery orchestration, are in force for a given deployment.

## Architecture and how it works

A NetBackup domain centers on a primary server that holds the catalog and schedules work. The catalog records what was backed up, when, and where each copy lives.

Media servers move data between clients and storage. They write to disk pools, deduplication storage, tape, and cloud object targets. Clients run agents that read application and file data in a consistent state.

Storage Lifecycle Policies describe how a backup is created, duplicated to a second tier, and expired. This lets one policy keep a local copy for fast restore and a second copy on immutable or offsite storage.

NetBackup supports deduplication through its own media server deduplication pool and through integration with purpose-built storage. Deduplication reduces the stored footprint so longer retention stays affordable.

The Flex appliances package the primary, media, and storage roles with a hardened operating system. Appliance form factors reduce the configuration drift that comes with self-built servers.

## Key capabilities

NetBackup covers a broad set of workloads. Supported targets include common hypervisors, database engines, container platforms, SaaS data, and the major public clouds.

Immutable and indelible WORM storage prevents a backup image from being changed or deleted before its retention expires. This holds even against an operator or an attacker with storage credentials.

Malware scanning inspects backup images for known threats. Scans can run before a restore so that recovery does not reintroduce a dormant payload into production.

Anomaly detection watches backup metadata for signs of compromise. Sudden changes in data-change rate, deduplication ratio, or file entropy can indicate encryption by ransomware.

Recovery orchestration automates multi-step restores. Runbooks bring back systems in the right order with network and validation steps, which shortens recovery of a full application stack.

Role-based access control and audit logging record who changed policy and who ran a restore. These records support investigation and separation of duties.

## Deployment and operations

Plan the domain around recovery objectives first. Recovery time objective and recovery point objective for each workload decide backup frequency, retention, and how many copies are kept.

Size the primary server and catalog for the number of jobs and the catalog growth rate. The catalog is the system of record, so protect and replicate it.

Use Storage Lifecycle Policies to enforce a tiered copy pattern. A typical pattern keeps a fast local copy plus a duplicated copy on immutable storage or an offsite target.

Monitor job success, media capacity, and anomaly alerts daily. A backup that never completes offers no protection, so treat chronic job failures as incidents.

Patch the primary, media, and appliance software on a defined cadence. The backup control plane is itself a target, so keep it current and reduce its exposed services.

## Immutability, air-gap, and ransomware recovery

Immutable storage is the core defense. NetBackup WORM storage and immutable, indelible storage options stop backups from being altered or erased before retention ends.

An air-gapped or isolated copy adds depth. Duplicating backups to tape, to an offline vault, or to a logically isolated storage target gives a copy that online attackers cannot reach.

Follow the 3-2-1-1-0 rule. Keep three copies of data on two media types with one copy offsite, one copy offline or immutable, and zero recovery errors confirmed by testing.

Anomaly detection and malware scanning address the quiet attack that encrypts or poisons data over time. Scanning before restore reduces the chance that recovery reinstates the infection.

Test recovery on a schedule. A restore that has never been exercised is an assumption, not a capability, so validate full application recoveries, not just single files.

## Hardening and secure use

Give the backup system its own identity store and credentials. Do not reuse production domain administrator accounts for backup operations, because a single stolen credential should not expose both tiers.

Require multi-factor authentication for consoles and multi-person or multi-user authorization for destructive actions. Expiring or deleting retained images early should need more than one approval.

Treat the backup control plane as a top target. Weak or missing authorization is CWE-862 Missing Authorization, and embedded or default credentials are CWE-798 Use of Hard-coded Credentials. Audit both in NetBackup roles and appliance accounts.

Isolate the backup management network. Limit which hosts can reach the primary server and storage, and restrict outbound paths from the backup domain.

Test restores as a security control, not only an operations task. Confirm that the recovered data is clean, complete, and usable within the recovery time objective.

## Where it fits in the program

NetBackup is the corrective control that restores service after destructive exploitation. It does not prevent intrusion. It assumes prevention can fail and keeps a clean path back to operations.

Pair it with the preventive and detective controls described in `/RANSOMWARE_DEFENSE_REFERENCE.md`. Those controls aim to stop or detect encryption early, while NetBackup provides the recovery of last resort.

Place its recovery objectives inside the broader continuity plan in `/CYBER_RESILIENCE_BCDR_REFERENCE.md`. Backup frequency and copy strategy should follow the business impact analysis, not the other way around.

## Resources

- Veritas NetBackup Administrator's Guide
- Veritas NetBackup Deduplication Guide
- Veritas NetBackup Security and Encryption Guide
- Veritas NetBackup Flex Appliance Administrator's Guide
- Veritas NetBackup Malware Detection and Anomaly Detection documentation

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/cohesity.md`
- `/platforms/commvault.md`
- `/platforms/dell-powerprotect.md`
