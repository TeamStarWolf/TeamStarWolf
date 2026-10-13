# AWS Native Security (Inspector / GuardDuty / Security Hub / Config)

*Amazon Web Services (AWS) · Cloud-native security services suite (CSPM/CWPP + vulnerability assessment + threat detection + patch orchestration)*

AWS's first-party security services collectively provide continuous vulnerability assessment (Inspector), threat detection (GuardDuty), unified findings aggregation and cloud risk/exposure management (Security Hub), and OS/application patch orchestration (Systems Manager Patch Manager) for AWS accounts and workloads. Rather than a single product, they are composable, account-native services that together cover the discover-assess-prioritize-mitigate-remediate lifecycle for AWS estates. They solve the problem of getting vulnerability, misconfiguration, and threat visibility plus remediation for cloud workloads without deploying third-party agents everywhere.

## Capabilities & architecture

**Core capabilities**
- Amazon Inspector: continuous, automated vulnerability scanning of EC2 instances, container images in Amazon ECR, Lambda functions and Lambda layers, and (expanded) code repositories; CVE matching against OS packages and programming-language dependencies; Inspector risk score (contextualized CVSS factoring network reachability and exploitability); agentless EC2 scanning option via EBS snapshots in addition to SSM-agent-based scanning
- Amazon GuardDuty: agentless threat detection from VPC Flow Logs, DNS logs, CloudTrail management/data events; Malware Protection; S3 Protection; EKS/Kubernetes Protection; RDS Protection; Lambda Protection; Runtime Monitoring (agent-based) for EC2/ECS/EKS; GuardDuty Extended Threat Detection correlating multi-stage attack sequences (EKS extension GA June 2025)
- AWS Security Hub: aggregation and normalization of findings (ASFF format) from Inspector, GuardDuty, Macie, IAM Access Analyzer, and partners; security standards/compliance checks (CIS AWS Foundations, AWS Foundational Security Best Practices, PCI DSS, NIST 800-53); the re-launched exposure-based Security Hub (GA announced re:Invent 2025) adding AI-assisted correlation of threats+vulnerabilities+misconfigurations, attack path visualization, and asset inventory (verify exact GA scope against AWS What's New)
- AWS Systems Manager Patch Manager: patch baselines (approval rules by classification/severity/age plus explicit approve/reject lists), patch groups (PatchGroup tag), maintenance windows for scheduling, AWS-RunPatchBaseline document in scan-only or scan-and-install modes, override lists in S3, patch compliance reporting, cross-platform (Windows/Linux/macOS) and hybrid/on-prem/multicloud via SSM Agent
- AWS Macie (data security), IAM Access Analyzer, and AWS Config (configuration drift/compliance) feed Security Hub as adjacent posture signals

**Architecture & deployment.** Cloud-native, account-resident AWS services enabled per-region and aggregated via AWS Organizations (delegated administrator model) for multi-account estates. GuardDuty is primarily agentless (log-based) with an optional runtime agent; Inspector uses the SSM Agent for EC2 or agentless EBS-snapshot scanning and scans ECR/Lambda from the control plane; Patch Manager requires the SSM Agent plus an instance profile with AmazonSSMManagedInstanceCore. Data stays within AWS; findings flow into Security Hub as the single pane. Security Hub has expanded to multicloud (native Azure resource monitoring reported mid-2026 - verify) and GovCloud (US) regions (March 2026).

**Editions & licensing.** Consumption/usage-based pricing per service, no seats. Inspector bills per instance-scan, per ECR image-scan, and per Lambda-function assessment per month. GuardDuty bills per GB of logs analyzed (CloudTrail events, VPC Flow/DNS log volume) plus per-resource runtime monitoring. Security Hub bills per security check and per finding ingested (the newer exposure-based tier has its own pricing; a consolidated 'Extended' billing option across AWS security services plus partners was described in 2026 - verify). Systems Manager Patch Manager itself has no additional charge for core patching on managed nodes (standard SSM); advanced-tier/hybrid activations and some automation incur cost. Free trials (typically 30 days for GuardDuty/Inspector).

**Key integrations.** Security Hub as native aggregation hub (ASFF); Amazon EventBridge for automation and SOAR/ticketing hand-off; AWS Organizations for multi-account governance; Third-party SIEM/SOAR (Splunk, Sumo Logic, Datadog); ITSM (ServiceNow, Jira) via EventBridge/partners; Inspector findings consumable by Wiz and other CNAPPs; Chainguard/hardened images reduce Inspector/ECR findings; CloudWatch, S3 (compliance exports), Lambda (automated remediation).

**Differentiators**
- Deepest native integration with AWS control plane - no third-party agent sprawl, uses existing SSM Agent and log sources
- Largely agentless posture (GuardDuty log-based, Inspector EBS-snapshot and ECR/Lambda control-plane scanning) lowering operational friction
- Inspector risk score contextualizes CVSS with network reachability and exploit data, reducing noise
- Patch Manager closes the loop to actual remediation natively - rare among cloud-native security tools which usually stop at detection
- Pay-as-you-go consumption model with no upfront licensing; tight IAM and Organizations governance

**Limitations & considerations**
- AWS-centric: native depth is for AWS workloads; multicloud/on-prem coverage is comparatively shallow despite recent Azure additions (verify maturity)
- Multiple services must be composed and governed individually; no single turnkey CNAPP experience out of the box compared to Wiz/Defender for Cloud
- Consumption pricing can be unpredictable at scale (GuardDuty log-volume costs, Security Hub per-finding/per-check fees)
- Inspector agentless EBS scanning and runtime coverage have gaps vs dedicated CWPP; container runtime depth weaker than specialist CNAPPs
- No true virtual-patching/WAF-rule generation inside these services (AWS WAF/Shield are separate); mitigation is via network controls and patch orchestration, not inline shielding
- Cross-account/region aggregation requires disciplined Organizations and delegated-admin setup

## Vulnerability-mitigation role

Acts across the full detect-and-remediate axis within AWS. Inspector continuously discovers and assesses CVEs and scores exploitability/reachability so teams can prioritize; Security Hub correlates those vulnerabilities with misconfigurations and active GuardDuty threats to surface genuinely exploitable exposure (attack paths) during the patch window; Systems Manager Patch Manager is the actual remediation/virtual-patch-adjacent control, pushing approved patches through maintenance windows or applying tightened patch baselines fast. In the pre-patch window, compensating mitigation is achieved via security-group/NACL changes, AWS WAF/Shield rules (separate services), SSM automation to isolate or reconfigure, and GuardDuty-triggered EventBridge response - reducing reachability and detecting exploitation until the patch lands.

**VM lifecycle:** Discover · Assess/Scan · Prioritize · Mitigate · Remediate/Patch · Validate · Monitor/Detect

**Framework mapping:** NIST CSF 2.0: Identify (asset/vuln inventory - Inspector, Config), Protect (Patch Manager, baselines), Detect (GuardDuty, Security Hub), Respond (EventBridge automation); CIS Controls v8: 1-2 (inventory), 4 (secure config), 7 (continuous vulnerability management - Inspector), 8 (audit logs - GuardDuty), 12 (network), 13 (monitoring); MITRE ATT&CK mitigations: M1051 Update Software (Patch Manager), M1030 Network Segmentation (SGs/NACLs), M1047 Audit, M1049 Antivirus/Antimalware (GuardDuty Malware Protection), M1026 Privileged Account Management (IAM Access Analyzer)

**In a critical-CVE scenario.** First 24-72h of a critical internet-facing-app CVE: Inspector re-scans EC2/ECR/Lambda to identify every affected package and image across accounts; Security Hub exposure view (and attack-path visualization) ranks which affected assets are internet-reachable and already targeted by GuardDuty, producing a prioritized remediation list. As compensating mitigation, tighten security groups/NACLs and add AWS WAF rules to cut reachability, and enable/verify GuardDuty Runtime Monitoring to detect exploitation. Then build or update a Patch Manager baseline approving the fix, target the affected patch group, and push it via an emergency maintenance window in scan-and-install mode; Inspector re-scan and Security Hub compliance checks validate closure.

## Validation & telemetry

**Log sources**
- Amazon Inspector v2: continuously scans ECR images, EC2 (via SSM agent), Lambda for CVEs; findings via console/ListFindings API, EventBridge (source aws.inspector2, detail-type 'Inspector2 Finding'), and into Security Hub.
- Security Hub CSPM: aggregation layer that normalizes Inspector/GuardDuty/Macie/control-checks into ASFF (AWS Security Finding Format); re-emits to EventBridge detail-type 'Security Hub Findings - Imported' (one finding per event in detail.findings[]).
- GuardDuty: analyzes CloudTrail mgmt+data events, VPC Flow Logs, DNS logs, EKS audit logs, and (Runtime Monitoring) an eBPF agent; findings via API and EventBridge (source aws.guardduty, detail-type 'GuardDuty Finding').
- AWS Config: records configuration items, evaluates managed/custom rules and conformance packs (ComplianceType COMPLIANT|NON_COMPLIANT|INSUFFICIENT_DATA); delivers snapshots/history to S3, notifications to SNS, events to EventBridge.
- CloudTrail: control-plane audit log (management events always on, data events opt-in) to S3/CloudWatch Logs; also GuardDuty's primary input.
- SIEM collection: EventBridge->Firehose/Lambda, S3 pull, CloudWatch Logs subscription, Splunk Add-on for AWS; Security Hub findings also map to OCSF via the Security Lake integration.
- VERIFIED: aws.inspector2 'Inspector2 Finding' and aws.guardduty 'GuardDuty Finding' detail-types; Security Hub->ASFF normalization; Config ComplianceType enum; CloudTrail eventSource config.amazonaws.com for Config writes.

**Telemetry format / transport.** JSON throughout: ASFF JSON (Security Hub), service-native JSON (Inspector2/GuardDuty EventBridge detail), CloudTrail JSON records (gzip in S3), Config configuration-item/compliance-change JSON. Transport: EventBridge, S3, CloudWatch Logs, SNS. Security Hub findings also map to OCSF 1.x Parquet via Security Lake.

**Control-presence check (present & configured?).** Inspector: `aws inspector2 batch-get-account-status` -> state.status ENABLED and resourceState.ec2/ecr/lambda ENABLED; per-host coverage `aws inspector2 list-coverage` (SCANNED vs SSM unreachable). Security Hub: `aws securityhub describe-hub` + get-enabled-standards. GuardDuty: `aws guardduty list-detectors` then `get-detector --detector-id <id>` -> Status ENABLED and each Feature (CloudTrail/DNS/FlowLogs/RuntimeMonitoring) ENABLED. Config: `aws configservice describe-configuration-recorder-status` -> recording=true,lastStatus=SUCCESS, plus describe-config-rules/describe-conformance-pack-compliance. CloudTrail: `aws cloudtrail get-trail-status` -> IsLogging=true and get-event-selectors for data events. Agent health: `aws ssm describe-instance-information` PingStatus=Online for Inspector EC2 + GuardDuty runtime coverage status.

**Validation signals (actually working?)**
- CONFIGURED: recorder/detector ENABLED, Config rule present, trail IsLogging=true.
- EFFECTIVE (Inspector): finding status NEW->CLOSED with fixAvailable and resource installedVersion >= fixedInVersion after patch — CVE actually remediated, not just reported.
- EFFECTIVE (Config): rule ComplianceType flips NON_COMPLIANT->COMPLIANT and, if auto-remediation attached, a CloudTrail StartAutomationExecution of the SSM document (e.g. AWS-ConfigureS3BucketPublicAccessBlock) — enforcement fired.
- EFFECTIVE (Security Hub): finding Workflow.Status RESOLVED and Compliance.Status PASSED.
- EFFECTIVE (GuardDuty): an exploitation/recon finding against the host (detective only) plus, if paired with EventBridge->Lambda, a quarantine-SG action logged in CloudTrail — that is the actual block.
- Distinguish: Inspector/Config prove the mitigation is PRESENT; a closed finding + patched version + executed-remediation CloudTrail event prove it WORKED.

**Key events / fields / tables / APIs**
- ASFF (Security Hub): Findings[].Vulnerabilities[].Id (CVE), .VulnerablePackages[].Name/Version, .FixAvailable; Compliance.Status (PASSED|FAILED|WARNING|NOT_AVAILABLE); Workflow.Status (NEW|NOTIFIED|RESOLVED|SUPPRESSED); RecordState; ProductName.
- Inspector2 EventBridge: detail.findingArn, detail.status, detail.packageVulnerabilityDetails.vulnerabilityId (CVE), .vulnerablePackages[].version/fixedInVersion, detail.inspectorScore.
- GuardDuty: detail.type (e.g. Recon:EC2/PortProbeUnprotectedPort, CryptoCurrency:EC2/BitcoinTool.B, Execution:Runtime/*), detail.severity (numeric; >=7 high/critical), detail.service.action.*, detail.resource.resourceType.
- Config: configRuleName, newEvaluationResult.complianceType, resourceId, configRuleInvokedTime.
- CloudTrail: eventSource, eventName, userIdentity.arn, requestParameters, responseElements, errorCode (AccessDenied = effective-block signal).
- Splunk CIM mapping: Vulnerabilities (Inspector), Intrusion_Detection (GuardDuty), Change/Compliance (Config), Authentication/Change (CloudTrail) via the Splunk Add-on for AWS.

**Example queries**

*Presence: confirm GuardDuty detector + all data sources/runtime monitoring enabled* (CLI)

```
aws guardduty list-detectors --query DetectorIds[0] --output text | xargs -I{} aws guardduty get-detector --detector-id {} --query '{Status:Status,Features:Features[].{Name:Name,Status:Status}}'
```

*Validation: Inspector CVE findings now CLOSED with fix applied (mitigation worked) vs still open* (SPL)

```spl
index=aws sourcetype="aws:securityhub:finding" ProductName="Inspector" | spath Vulnerabilities{}.Id output=cve | eval status=coalesce('Workflow.Status',RecordState) | stats latest(status) as status latest(FixAvailable) as fix by cve, Resources{}.Id | search status IN ("ARCHIVED","RESOLVED")
```

*Validation: prove Config rule enforcement — resources flipped to COMPLIANT + remediation ran in CloudTrail* (CLI)

```
aws configservice get-compliance-details-by-config-rule --config-rule-name <rule> --compliance-types COMPLIANT && aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StartAutomationExecution
```

**How it mitigates (mechanism).** Config enforcement (non-compliant resource auto-remediated by an attached SSM Automation document, removing the exposure) and Inspector patch verification (installedVersion advancing past fixedInVersion removes CVE reachability) are the observable mitigations; GuardDuty is detective and only becomes a block when its finding triggers an EventBridge->Lambda isolation action, itself logged in CloudTrail.

**Logging gotchas**
- Inspector EC2 scanning needs a healthy SSM agent — hosts without it show UNSCANNED coverage, so an empty finding list can be a blind spot, not a clean host.
- GuardDuty is detection-only by default (no inline prevention).
- CloudTrail data events (S3 object-level, Lambda invoke) are OFF unless explicitly selected — data-plane exploitation can be invisible.
- Config records only enabled resource types; INSUFFICIENT_DATA rolls a conformance pack up as effectively compliant.
- Security Hub finding updates are throttled/deduplicated (UpdatedAt may lag); CloudTrail->S3 delivery can lag ~15 min, so real-time validation should use the EventBridge stream.
- Could not verify the exact 2025 GuardDuty Runtime Monitoring finding-type list against official docs — confirm against the finding-type reference before alerting on specific type strings.

## Documentation & repositories

_Official documentation & manuals_
- [Amazon Inspector User Guide](https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html)
- [Amazon GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)
- [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)
- [AWS Config Developer Guide](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html)
- [AWS Prescriptive Guidance: Configure AWS security services (vulnerability management)](https://docs.aws.amazon.com/prescriptive-guidance/latest/vulnerability-management/configure-aws-security-services.html)

_API & developer docs_
- [Amazon Inspector2 API Reference](https://docs.aws.amazon.com/inspector/v2/APIReference/Welcome.html)
- [Amazon GuardDuty API Reference](https://docs.aws.amazon.com/guardduty/latest/APIReference/Welcome.html)
- [AWS Security Hub API Reference](https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html)
- [AWS Config API Reference](https://docs.aws.amazon.com/config/latest/APIReference/Welcome.html)
- [AWS provider (hashicorp/aws) Terraform docs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [AWS SDK for Python (Boto3) documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

_GitHub (official)_
- [aws-samples org](https://github.com/aws-samples)
- [amazon-guardduty-multiaccount-scripts](https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts)
- [Automated Security Response on AWS (Security Hub remediation solution)](https://github.com/aws-solutions/automated-security-response-on-aws)
- [AWS Config Rules (awslabs)](https://github.com/awslabs/aws-config-rules)
- [aws org (official)](https://github.com/aws)

_Community / integration / detection repos_
- [Prowler (AWS/multi-cloud security assessment, maps to Security Hub)](https://github.com/prowler-cloud/prowler)
- [ScoutSuite (NCC Group multi-cloud auditing)](https://github.com/nccgroup/ScoutSuite)
- [Steampipe AWS Compliance mod](https://github.com/turbot/steampipe-mod-aws-compliance)
- [Cloud Custodian (policy-as-code / Config-style rules)](https://github.com/cloud-custodian/cloud-custodian)

_Learning & reference_
- [AWS Workshop Studio catalog (Security Hub/GuardDuty workshops)](https://catalog.workshops.aws/)
- [AWS Skill Builder](https://skillbuilder.aws/)
- [AWS Security Blog](https://aws.amazon.com/blogs/security/)
- [AWS Security Maturity Model](https://maturitymodel.security.aws.dev/)

> Note: Doc landing URLs are the long-stable AWS entry points (Inspector = Inspector2/v2; Config lives under the Developer Guide). IMPORTANT: Security Hub now has two variants — classic Security Hub CSPM (ASFF format, APIReference 1.0) and the newer Security Hub (OCSF); confirm which your account uses before wiring automation. The aws-samples GuardDuty multi-account repo and aws-solutions ASR repo are the canonical official examples. Search-session budget was exhausted before every GitHub path could be re-confirmed live this run; AWS doc hostnames (docs.aws.amazon.com) are authoritative and stable.

## Current state (2025-26)

Security Hub was re-launched as an exposure-based risk management service with AI-assisted correlation, attack path visualization and asset inventory, announced GA around re:Invent 2025 (verify exact GA date/feature scope on AWS What's New). GuardDuty Extended Threat Detection EKS extension GA June 2025; new GuardDuty AI-workload protections reported 2026 (verify). Security Hub reached AWS GovCloud (US-East/US-West) on March 30 2026 and reportedly added native Azure resource monitoring for multicloud misconfiguration/vulnerability discovery in 2026 (verify on AWS primary sources). Inspector reported to add AI-generated remediation guidance (verify). No ownership change - all first-party AWS.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
