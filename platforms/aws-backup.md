# AWS Backup

AWS Backup is the native, centralized backup service for Amazon Web Services. It applies backup plans and policies across many AWS services from one place instead of per-service scripts. Backups land in Backup Vaults, which can be locked for write-once-read-many immutability. For a security team it is the corrective control that restores cloud data after a destructive attack or accidental deletion.

## What it is and where it fits

AWS Backup coordinates backup across AWS services such as EBS, RDS, DynamoDB, EFS, S3, and others. It replaces scattered, per-service snapshot jobs with one policy-driven service.

It fits teams that run production on AWS and need consistent retention and recovery across accounts. Policies can be applied organization-wide through AWS Organizations.

In a security program it is a corrective control. When ransomware, a compromised credential, or a mistaken deletion destroys cloud data, AWS Backup holds the retained copies used to recover. Licence and pricing follow usage, and the service features in force depend on the chosen configuration.

## Architecture and how it works

A backup plan defines rules: what to protect, how often, how long to retain, and where to copy. Resources are assigned to a plan by tag or by resource type.

Backups are stored in a Backup Vault. A vault is a container that holds recovery points and controls access to them.

AWS Backup uses an IAM service role to act on resources. The role grants the specific permissions needed to create and restore backups.

Cross-region copy duplicates recovery points into a second AWS Region. Cross-account copy duplicates them into a separate AWS account, which creates distance from a compromised source account.

AWS Backup Vault Lock applies a write-once-read-many policy to a vault. In compliance mode the lock cannot be removed or weakened by anyone, including the account root user, until retention expires.

## Key capabilities

Centralized backup plans cover many services with one policy model. This reduces the gaps that appear when each team writes its own snapshot scripts.

Backup Vault Lock provides immutability. Compliance mode makes recovery points undeletable before their retention ends, which blocks early deletion by an attacker or an operator.

Cross-region copy protects against a regional event or a Region-scoped compromise. Cross-account copy keeps a copy outside the blast radius of the source account.

Organization-wide policies let a central team enforce backup across many accounts. This closes the gap where a single team forgets to back up a workload.

Monitoring and reporting show backup job status, compliance against policy, and restore activity. Alerts surface failed jobs so they can be treated as incidents.

## Deployment and operations

Begin from recovery objectives for each workload. Recovery time objective and recovery point objective drive backup frequency and retention in each plan.

Assign resources to plans by tag so new resources inherit protection automatically. A missed tag is a missed backup, so audit coverage regularly.

Use a separate, dedicated backup account as the copy destination. Cross-account copy into it keeps backups reachable even if the production account is compromised.

Apply backup policies through AWS Organizations for consistency. Central policy prevents individual accounts from drifting away from the standard.

Monitor job success and policy compliance daily. Investigate failed jobs and any resource that is in scope but has no recent recovery point.

## Immutability, air-gap, and ransomware recovery

Backup Vault Lock in compliance mode is the core immutability control. Once locked, recovery points cannot be deleted or shortened before retention expires, even by the root user.

Cross-account and cross-region copies provide the isolated copy. Storing backups in a separate account functions as a logical air gap against a source-account compromise.

Follow the 3-2-1-1-0 rule in cloud terms. Keep multiple copies across Regions and accounts, with at least one immutable locked copy, and confirm zero recovery errors by testing.

Anomaly detection in AWS comes from the surrounding services. Use CloudTrail, GuardDuty, and CloudWatch alarms to flag mass deletions, policy changes, or suspicious restore activity against vaults.

Test restores on a schedule. Recover EBS volumes, RDS databases, and other resources into an isolated environment to confirm the recovery points are usable.

## Hardening and secure use

Give backups their own identity boundary. Use a dedicated backup account and a scoped IAM service role, not broad administrator permissions.

Apply least privilege to the service role and to human access. Grant only the backup and restore permissions required, and separate who can run backups from who can delete vaults.

Require multi-factor authentication for consoles and for sensitive vault operations. Use Vault Lock so that even privileged users cannot remove retention early.

Treat the backup control plane as a top target. Missing or overly broad authorization maps to CWE-862 Missing Authorization, and embedded long-lived keys map to CWE-798 Use of Hard-coded Credentials. Prefer roles over static keys.

Test restores as a security control. Confirm recovered data is clean and complete within the recovery time objective, and log every restore through CloudTrail.

## Where it fits in the program

AWS Backup is the corrective control after destructive exploitation in the cloud. It does not prevent a compromise. It assumes a compromise can happen and keeps a locked, recoverable copy.

Pair it with the preventive and detective controls in `/RANSOMWARE_DEFENSE_REFERENCE.md`. Those aim to stop or spot an attack, while AWS Backup provides recovery when they do not.

Place its objectives inside the continuity plan in `/CYBER_RESILIENCE_BCDR_REFERENCE.md`. Backup frequency, Region strategy, and retention should follow the business impact analysis.

## Resources

- AWS Backup Developer Guide
- AWS Backup Vault Lock documentation
- AWS Backup cross-Region and cross-account copy documentation
- AWS Organizations backup policy documentation
- AWS Well-Architected Framework, Reliability Pillar

## Related pages

- `/platforms/README.md`
- `/RANSOMWARE_DEFENSE_REFERENCE.md`
- `/CYBER_RESILIENCE_BCDR_REFERENCE.md`
- `/INCIDENT_RESPONSE_REFERENCE.md`
- `/platforms/azure-backup.md`
- `/platforms/wiz.md`
- `/platforms/veritas-netbackup.md`
