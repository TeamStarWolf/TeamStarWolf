# ServiceNow Vulnerability Response

ServiceNow Vulnerability Response is the Security Operations application that turns scanner findings into tracked, owned, and measured remediation work on the Now Platform.

## What it is and where it fits

Vulnerability Response (often shortened to VR) sits inside the ServiceNow Security Operations suite. It is not a scanner. It consumes findings that scanners produce and gives them a workflow: ownership, priority, service-level agreements, and closure evidence.

The product solves a specific problem. Scanners find many issues across many assets, but a raw finding list is not actionable work. VR normalizes those findings, groups them, matches them to known configuration items, and assigns remediation to the teams that own the affected systems.

Because VR runs on the Now Platform, it inherits the same data model, workflow engine, reporting, and access control used by IT Service Management. This lets a vulnerability program use the same change and task constructs that IT operations already follow.

## Architecture and how it works

VR is built from platform tables, business rules, and scheduled jobs. The core tables matter to anyone working the queue.

- `sn_vul_vulnerable_item`: a Vulnerable Item (VI) is one finding on one asset. It is auto-created when scanner data is imported. Each VI links a vulnerability entry to a configuration item.
- `sn_vul_vulnerability_group`: a Vulnerability Group rolls many related Vulnerable Items into a single unit of work, for example all assets affected by the same vulnerability, or all findings on one host.
- `sn_vul_entry`: a vulnerability definition record, drawn from third-party vulnerability content and feeds such as the National Vulnerability Database.

The flow runs in stages. Scanner integrations import results on a schedule. Each result row becomes or updates a Vulnerable Item. Grouping rules then assemble Vulnerability Groups by matching criteria an administrator defines. Assignment rules route each group or item to an assignment group based on the affected configuration item, its support group, or other field conditions.

Configuration item matching connects findings to the Configuration Management Database (CMDB). A finding against a hostname or IP is reconciled to a CI record when a match is found. Good CMDB data quality is the single biggest factor in whether VR assigns work to the right owner.

## Key capabilities

- Ingestion of findings from multiple scanners, including Tenable, Qualys, Rapid7, and others, through vendor integration packs.
- Automatic creation and deduplication of Vulnerable Items so one finding on one asset is one record.
- Vulnerability Groups that let a team work many related items as one effort and report progress at the group level.
- CMDB reconciliation that maps findings to configuration items and their owning groups.
- Assignment rules that route work without manual triage.
- Remediation Tasks (`sn_vul_remediation_task`) that carry the fix work, link to change requests, and hold closure notes.
- Service-level agreements that set time-to-remediate targets by severity and track breaches.
- Risk scoring and calculators that combine vulnerability severity, asset importance, and exposure signals into a prioritized order.
- Dashboards and reporting built on platform reporting, with drill-down from program metrics to individual items.

## Deployment and operations

VR is delivered as a scoped application on a ServiceNow instance. A customer activates the plugin and configures integrations, rules, and roles. There is no separate server to run; it lives in the same instance as the rest of the platform.

Day-to-day operation centers on the import schedules, the grouping and assignment rules, and the state of the CMDB. An administrator tunes grouping so that work units are meaningful, and tunes assignment so that items land with the right teams.

The role `sn_vul.read_all` grants read access across all vulnerability data and is a common grant for program analysts and reporting users. Writer and admin roles are separate and scoped more tightly. Roles should be assigned by job need, not by convenience.

State models track each Vulnerable Item from open through assigned, in progress, and closed, with closure reasons such as fixed, risk accepted, or false positive. Risk acceptance should route through an approval so that exceptions are recorded, not silent.

## Integrations and data flow

The inbound side pulls from scanners. Integration packs for Tenable, Qualys, Rapid7, and similar products fetch findings on a schedule and map them into Vulnerable Items. Third-party vulnerability content feeds populate and update vulnerability entries.

The outbound and lateral side uses the platform. Remediation Tasks can open or link to Change Requests in Change Management. Notifications and approvals use platform workflow. Findings and groups feed platform reporting and Performance Analytics for trend tracking.

Data flows one direction for findings (scanner into VR) and one direction for state back to reporting. VR does not push fixes to assets; it directs the people and changes that apply them.

## Hardening and secure use

Access control is the first concern. Use role-based access so that a user receives only the vulnerability roles their job requires. Grant `sn_vul.read_all` deliberately; broad read of vulnerability data is sensitive because it maps weaknesses to named assets.

Apply Access Control List (ACL) rules on the VR tables so that record-level and field-level reads and writes are enforced, not assumed. Missing authorization on a table or field is a real exposure; this maps to CWE-862 (Missing Authorization). Review ACLs after any customization that adds fields or tables.

Scope the integration accounts. Each scanner integration authenticates to the scanner with a service account. Give that account the least privilege needed to read findings, and isolate it per integration so one compromised credential does not expose all of them. An over-broad shared integration account is an authorization weakness in the same family as CWE-862.

Handle integration credentials with care. Store scanner credentials in the platform credential store, not in script fields, system properties, or integration definitions in plaintext. Hardcoded or plaintext credentials map to CWE-798 (Use of Hard-coded Credentials). Rotate them on a schedule and when staff change.

Audit changes to grouping and assignment rules. A rule change can silently redirect or suppress work, so track who changed what and review the effect.

## Where it fits in the program

VR is the system of record for remediation work. It is where a scanner finding becomes an owned task with a deadline and a closure trail. In a vulnerability management program it occupies the orchestration and accountability layer: it does not detect and it does not patch, but it governs the loop between the two.

For a team that runs several scanners, VR is the place that reconciles them into one view keyed to assets and owners. For leadership, it is where mean-time-to-remediate and SLA compliance come from. For auditors, it is where exception approvals and closure evidence live.

## Resources

- ServiceNow Product Documentation, Vulnerability Response
- ServiceNow Security Operations documentation
- ServiceNow CMDB and Configuration Management documentation
- ServiceNow Now Platform administration documentation, access control and ACLs

## Related pages

- [Platforms index](/platforms/README.md)
- [Vulnerability Management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Scanner platforms reference](/SCANNER_PLATFORMS_REFERENCE.md)
- [Incident response reference](/INCIDENT_RESPONSE_REFERENCE.md)
- [Tenable](/platforms/tenable.md)
- [Qualys](/platforms/qualys.md)
- [Rapid7 InsightVM](/platforms/rapid7-insightvm.md)
