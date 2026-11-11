# Dell PowerProtect

Dell PowerProtect is a family for data protection and cyber recovery. It combines PowerProtect Data Manager software, PowerProtect Data Domain protection storage, and the PowerProtect Cyber Recovery vault. Together they back up workloads, store them with deduplication and retention lock, and keep an isolated copy for recovery after a destructive attack. The isolated vault pattern is the product's defining security feature.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Backup administrators, infrastructure engineers and incident responders who run, tune or assess Dell PowerProtect

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,292 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are evaluating or running Dell PowerProtect for backup and cyber recovery, you are hardening its deployment, or you need to see where it fits in the program

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture and how it works](#architecture-and-how-it-works), [Hardening and secure use](#hardening-and-secure-use), [Where it fits in the program](#where-it-fits-in-the-program)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Ransomware Defense & Resilience](/RANSOMWARE_DEFENSE_REFERENCE.md), [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md), [Incident Response Reference](/INCIDENT_RESPONSE_REFERENCE.md), [Veritas NetBackup](/platforms/veritas-netbackup.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

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

## Adversary perspective

Because PowerProtect is the recovery of last resort, ransomware actors treat it as something to neutralize before they detonate, and Data Manager, Data Domain, and the Cyber Recovery vault are themselves an attack surface. The steps to lock the family down are in the "Hardening and secure use" section that follows.

### Evasion and bypass

- Destroying recovery before impact (ATT&CK T1490, Inhibit System Recovery): with backup admin access an attacker tries to delete backups, expire policy, or unlock retention before encrypting production. Retention Lock and the normally closed vault link are the counters, because a locked copy cannot be erased early and the air gap removes the network path to the vaulted data.
- Abusing the backup identity (ATT&CK T1078, Valid Accounts): a compromised Data Manager or Data Domain administrator, or a shared production admin account, can change policy or attempt early deletion, which is why separate vault operators and multi-person approval matter ([CWE-269](https://cwe.mitre.org/data/definitions/269.html)).
- Poisoning the copy: an attacker who corrupts data slowly tries to have the damage replicated into the vault before it is noticed, which is what CyberSense content analysis is meant to catch by pointing to the last clean copy.

### Residual risk and own exposure

PowerProtect cannot prevent a compromise, cannot protect data left out of the vault scope, and cannot help if recovery starts from an infected point. The backup and vault control planes run with high privilege, and backup software across the industry has been a notable exploitation target, so Data Manager, Data Domain, and the vault software belong in the patch and monitoring scope.

### Why it matters

A tester probes whether backups can be deleted or retention unlocked with the access at hand, and whether the air-gap link is ever left open. A defender alarms on early deletion attempts, retention changes, and synchronization-window edits as incidents, and treats CyberSense scores as a trigger. See [the ransomware defense reference](/RANSOMWARE_DEFENSE_REFERENCE.md) for how immutable and isolated copies fit, and [the vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md) for keeping the control itself in scope.

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

- [Security platforms](/platforms/README.md)
- [Ransomware Defense & Resilience Reference](/RANSOMWARE_DEFENSE_REFERENCE.md)
- [Cyber Resilience & BCDR Reference](/CYBER_RESILIENCE_BCDR_REFERENCE.md)
- [Incident Response Reference Library](/INCIDENT_RESPONSE_REFERENCE.md)
- [Veritas NetBackup](/platforms/veritas-netbackup.md)
- [Rubrik](/platforms/rubrik.md)
- [Cohesity](/platforms/cohesity.md)
