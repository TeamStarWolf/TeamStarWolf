# Azure Backup

Azure Backup is the native backup service for Microsoft Azure. It protects Azure virtual machines, databases, file shares, and other workloads using Recovery Services vaults and Backup vaults. Immutability, soft delete, and multi-user authorization defend the backups themselves against tampering. For a security team it is the corrective control that restores cloud data after a destructive attack or a rogue administrator.

## What it is and where it fits

Azure Backup centralizes backup for Azure workloads through two vault types. Recovery Services vaults cover virtual machines, SQL and SAP in Azure VMs, and Azure Files. Backup vaults cover newer workloads such as Azure Blobs, disks, and PostgreSQL.

It fits teams running production on Azure that need consistent retention and recovery without per-resource scripting. Policy defines schedule and retention for each protected resource.

In a security program it is a corrective control. When ransomware, a stolen credential, or a malicious administrator destroys data, Azure Backup holds the retained copies used to recover. Licence and pricing follow usage, and the features in force depend on the vault type and configuration.

## Architecture and how it works

A vault is the management and storage boundary for backups. It holds recovery points, backup policies, and the access controls over them.

A backup policy sets the schedule and retention for protected items. Items are enrolled against a policy per workload type.

Azure Backup integrates with Azure Resource Manager and Azure role-based access control. Permissions on vaults and backup operations are granted through Azure RBAC roles.

Soft delete retains deleted backup data for a period after a delete request. This gives a window to recover from accidental or malicious deletion before the data is gone.

Cross-region restore lets you recover to a paired Azure region. This supports recovery when the primary region is unavailable.

## Key capabilities

Immutable vaults prevent backup data from being modified or deleted before retention expires. A locked immutable vault keeps this protection even against a privileged account.

Soft delete holds deleted backups for a retention window. It defends against a delete-then-encrypt pattern by keeping the data recoverable for a time after deletion.

Multi-user authorization, MUA, adds a second approver for sensitive operations. Built on Azure Resource Manager, it requires a separate security principal to approve actions such as disabling soft delete or reducing retention.

Cross-region restore provides recovery in a paired region. This separates recovery from a single region's availability.

Alerting and monitoring report job status, policy compliance, and security operations against vaults. Alerts surface failed jobs and suspicious changes.

## Deployment and operations

Start from recovery objectives for each workload. Recovery time objective and recovery point objective drive the backup schedule and retention in each policy.

Choose the vault type that matches the workload. Use Recovery Services vaults and Backup vaults according to the resource being protected.

Enable immutability, soft delete, and multi-user authorization at vault setup, not after an incident. These controls protect you only when they are in place before the attack.

Separate the roles that manage backup from those that manage production. Grant Azure RBAC on vaults using least privilege.

Monitor job success and backup security alerts regularly. Investigate failed jobs and any attempt to weaken vault protections.

## Immutability, air-gap, and ransomware recovery

Immutable vaults are the core immutability control. When locked, the setting cannot be reversed, so backups cannot be deleted or shortened before retention expires.

Soft delete and multi-user authorization together blunt the rogue-admin path. Soft delete keeps deleted data for a window, and MUA requires a second principal before protections can be removed.

Cross-region restore provides a geographically separate copy for recovery. Combined with immutability, it gives a protected copy away from the primary region.

Follow the 3-2-1-1-0 rule in cloud terms. Keep multiple copies across regions, with at least one immutable copy, and confirm zero recovery errors through testing.

Anomaly detection comes from the surrounding services. Use Microsoft Defender for Cloud and Azure Monitor alerts to flag mass deletions, suspicious restores, or attempts to disable soft delete.

Test restores on a schedule. Recover virtual machines, databases, and file shares into an isolated environment to confirm the recovery points are usable.

## Hardening and secure use

Give backups their own identity boundary. Separate the principals that run and manage backup from production administrators.

Apply least privilege through Azure RBAC. Grant only the backup and restore permissions required, and limit who can change or delete vaults.

Require multi-user authorization against a rogue administrator. MUA means a single compromised admin account cannot disable soft delete or destroy retained data without a second approval.

Treat the backup control plane as a top target. Missing or excessive authorization maps to CWE-862 Missing Authorization, and embedded credentials map to CWE-798 Use of Hard-coded Credentials. Prefer managed identities over stored secrets.

Test restores as a security control. Confirm recovered data is clean and complete within the recovery time objective, and keep an audit trail of every restore.

## Where it fits in the program

Azure Backup is the corrective control after destructive exploitation in the cloud. It does not prevent a compromise. It assumes compromise is possible and keeps an immutable, recoverable copy.

Pair it with the preventive and detective controls in `/RANSOMWARE_DEFENSE_REFERENCE.md`. Those aim to stop or detect an attack, while Azure Backup provides recovery when they do not.

Place its objectives inside the continuity plan in `/CYBER_RESILIENCE_BCDR_REFERENCE.md`. Backup schedule, region strategy, and retention should follow the business impact analysis.

## Resources

- Azure Backup documentation
- Azure Backup immutable vault documentation
- Azure Backup soft delete documentation
- Azure Backup multi-user authorization documentation
- Azure Backup cross-region restore documentation

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/aws-backup.md`
- `/platforms/entra-id.md`
- `/platforms/veeam.md`
