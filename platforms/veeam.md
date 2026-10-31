# Veeam

Veeam Data Platform provides backup and replication across virtual, physical, cloud, and SaaS workloads. It positions backup as a recovery control against ransomware and other destructive events. The platform pairs immutable storage with recovery verification so that restores are proven, not assumed. Licence tier decides which capabilities, editions, and workload coverage are in force.

## What it is and where it fits

Veeam Data Platform is a backup, replication, and recovery product for mixed estates. It protects VMware and Hyper-V virtual machines, physical servers, workstations, cloud instances, and SaaS data such as Microsoft 365.

In a security program, Veeam sits in the recover function. It is the control that restores systems and data after prevention and detection have been bypassed. When attackers encrypt, wipe, or corrupt production, verified backups are the path back to a known-good state.

Backup is not a substitute for prevention. It is the corrective layer that assumes some incidents will succeed and plans for clean restoration.

## Architecture and how it works

A Veeam deployment is built from a small set of roles that can run on one server or scale across many.

- The backup server runs the configuration database and coordinates jobs. It is the control plane and a high-value target.
- Proxies move data between source workloads and repositories. They handle the read, compression, deduplication, and transport work.
- Backup repositories are the storage targets. They can be Windows or Linux servers, deduplication appliances, SMB or NFS shares, or object storage.
- Agents protect physical and cloud workloads where no hypervisor API is available.

The data flow starts when the backup server triggers a job. A proxy reads source data, processes it, and writes backup files to a repository. Replication jobs instead create and maintain a standby copy of a VM at a secondary site or host.

Scale-out backup repositories group several storage extents under one logical target. They let short-term backups land on fast storage and age out to capacity or archive tiers, including object storage.

## Key capabilities

- Image-level backup of virtual machines, with changed-block tracking for faster incremental runs.
- Agent-based backup for physical servers, workstations, and cloud instances.
- Replication that keeps a ready-to-start VM replica at a recovery site.
- Instant VM recovery, which runs a machine directly from the backup file while the full restore happens in the background.
- Granular restore of files, application items, and whole machines.
- Immutable backups through hardened repositories and object-lock storage.
- SureBackup, which boots restored machines in an isolated environment and verifies they recover.
- Veeam ONE monitoring and reporting for capacity, job health, and anomaly signals.

## Deployment and operations

Veeam runs on-premises, in cloud instances, or in a mixed model. The backup server, proxies, and repositories can be sized and placed to match the estate and recovery targets.

Operational practice centres on job design and retention. Administrators define backup jobs, schedules, and retention policies, then map them to repositories and storage tiers. Scale-out repositories automate movement between performance, capacity, and archive tiers.

Day-to-day work includes watching job success, validating restore points, and tracking repository capacity. Veeam ONE surfaces failures, trends, and workloads that fall outside policy.

Recovery operations should be rehearsed, not improvised. Documented runbooks and scheduled test restores keep recovery time predictable during an incident.

## Immutability, air-gap, and ransomware recovery

This is the security heart of the platform. Backups only help if an attacker cannot delete or alter them.

Veeam supports immutable backups in two main ways. A hardened Linux repository uses immutability flags so backup files cannot be modified or deleted for a set period, even by an account with elevated rights. Object storage immutability uses object lock, so copies written to supported S3-compatible or cloud object stores are retained in a write-once-read-many state for the lock period.

Air-gapped and offline copies add another layer. A copy that is physically offline, on removable media, or logically isolated cannot be reached by a live intrusion. Tape remains a valid offline tier for long retention.

Veeam frames resilience around the 3-2-1-1-0 rule:

- Keep at least 3 copies of data.
- Store them on 2 different media types.
- Keep 1 copy off-site.
- Keep 1 copy offline, air-gapped, or immutable.
- Verify 0 errors through recovery testing.

The trailing 1 and 0 are what harden backups against ransomware. An immutable or offline copy survives an attacker who reaches the production and primary backup tiers. The 0 means every restore point is tested, so the surviving copy is known to recover.

Backup-anomaly detection watches for signals that often mean an attack, such as unusual change rates, deletion patterns, or encryption-like behaviour in protected data. These signals give responders earlier warning and help identify a clean restore point before reinfection.

SureBackup supports recovery testing by booting machines from backups in an isolated lab, running checks, and confirming they come up cleanly. Scheduled verification turns the final 0 of the rule into evidence.

## Hardening and secure use

The backup system is a top target because it is the last line of recovery. Attackers try to destroy backups before or during an attack so victims cannot restore.

- Use separate credentials and identities for the backup console, repositories, and service accounts. Do not reuse production domain administrator accounts.
- Require multi-factor authentication for console and management access.
- Isolate the backup network and management interfaces from general user and server networks.
- Protect the backup server and console as a critical asset. Unauthorized access to it can expose stored credentials and allow backup deletion, which maps to missing authorization (CWE-862) and the risk of hard-coded or reused credentials (CWE-798).
- Keep at least one immutable or offline copy that no single administrator account can erase.
- Patch the backup software, operating systems, and appliances on a defined cadence.
- Test restores on a schedule and record the results, so recovery capability is proven before it is needed.

Storing credentials for many systems makes the backup console a credential store in its own right. Treat its compromise as equivalent to a broad domain compromise and defend it accordingly.

## Where it fits in the program

Backup and recovery is the corrective control that follows destructive exploitation. Prevention and detection reduce how often incidents succeed and how long they run. They do not guarantee that production survives.

When an attack encrypts or wipes systems, recovery from verified, immutable backups is what restores the business. Veeam provides that corrective capability and the verification that makes it trustworthy.

This page pairs with the program-level references. See `/RANSOMWARE_DEFENSE_REFERENCE.md` for how immutable and offline copies fit ransomware response, and `/CYBER_RESILIENCE_BCDR_REFERENCE.md` for recovery objectives, runbooks, and continuity planning.

## Resources

- Veeam Data Platform product documentation.
- Veeam Backup & Replication User Guide.
- Veeam Hardened Repository documentation.
- Veeam ONE documentation.
- Veeam Backup for Microsoft 365 documentation.

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/rubrik.md`
- `/platforms/commvault.md`
- `/platforms/veritas-netbackup.md`
