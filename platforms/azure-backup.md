# Azure Backup

Azure Backup is the native backup service for Microsoft Azure. It protects Azure virtual machines, databases, file shares, and other workloads using Recovery Services vaults and Backup vaults. Immutability, soft delete, and multi-user authorization defend the backups themselves against tampering. For a security team it is the corrective control that restores cloud data after a destructive attack or a rogue administrator.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Backup administrators, infrastructure engineers and incident responders who run, tune or assess Azure Backup

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,258 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Azure Backup for backup and cyber recovery, you are hardening its deployment, or you need to see where it fits in the program

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [AWS Backup](/platforms/aws-backup.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

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

## Adversary perspective

Because Azure Backup is the recovery of last resort, ransomware actors and rogue administrators treat it as something to neutralize before they detonate, and the vaults, their policies, and the identities over them are themselves an attack surface. The steps to lock the service down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Destroying recovery before impact (ATT&CK T1490, Inhibit System Recovery): with a stolen or malicious admin identity an attacker tries to delete recovery points or shorten retention before encrypting production. Soft delete keeps deleted data for a window, and a locked immutable vault cannot be weakened early, which blunts this path.
- Disabling the protections first (ATT&CK T1685, Disable or Modify Tools): the attacker's precursor step is to turn off soft delete or lower retention. Multi-user authorization requires a second principal to approve those sensitive changes, so one compromised account is not enough.
- Abusing the backup identity (ATT&CK T1078, Valid Accounts): over-broad Azure RBAC on vaults, or a compromised privileged account, lets an attacker alter policy or destroy copies ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).

### Residual risk and own exposure

Azure Backup cannot prevent a compromise and cannot recover workloads that were never enrolled, so unprotected resources are a silent gap. The service runs with high privilege over backup data, and backup software across the industry has been a notable exploitation target, so its control plane and the identities over it belong in the patch and monitoring scope.

### Why it matters

A tester probes whether soft delete can be disabled or retention weakened with the access at hand, and whether multi-user authorization is actually enforced. A defender alarms on attempts to disable soft delete, retention changes, and mass deletion as incidents in their own right. See [the ransomware defense reference](/RANSOMWARE_DEFENSE_REFERENCE.md) for how immutable and isolated copies fit, and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for keeping the control itself in scope.

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

- [Security platforms](/platforms/README.md)
- [Ransomware Defense & Resilience Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [AWS Backup](/platforms/aws-backup.md)
- [Microsoft Entra ID](/platforms/entra-id.md)
- [Veeam](/platforms/veeam.md)
