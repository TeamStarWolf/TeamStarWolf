# AWS WAF

*Amazon Web Services · Cloud-native, fully managed web application firewall for AWS-fronted apps and APIs*

AWS WAF is Amazon's fully managed, cloud-native WAF that lets you create web ACLs of rules to allow, block, count, CAPTCHA, or challenge HTTP(S) requests to AWS-fronted resources. It solves edge/application-layer protection for workloads behind CloudFront, ALB, API Gateway, AppSync, Cognito, App Runner, Amplify, and Verified Access, with no appliance to run. It is tightly coupled to AWS Shield (DDoS) and AWS Firewall Manager (multi-account policy), and in 2025 added a dedicated application-layer (L7) anti-DDoS managed rule group.

## Capabilities & architecture

**Core capabilities**
- Web ACLs with custom rules (IP sets, geo-match, rate-based rules, string/regex match, size constraints, SQLi and XSS match statements, label-based logic)
- AWS Managed Rules rule groups (Core/common rule set CRS, Known Bad Inputs, SQL database, Linux/POSIX/Windows, PHP, WordPress, IP reputation/Amazon threat intel, Anonymous IP list)
- AWS WAF Bot Control (common + targeted bot management; December 2025 expanded category detection for Advertising, AI, Content Fetcher, Social Media bots)
- Fraud Control: Account Takeover Prevention (ATP) and Account Creation Fraud Prevention (ACFP)
- AWS WAF Anti-DDoS managed rule group (launched June 2025) for rapid L7 HTTP-flood detection/mitigation with Count/Block/Challenge actions
- CAPTCHA and silent Challenge (JS/token) actions
- Marketplace managed rules from third-party vendors (F5, Fortinet, Imperva, etc.)
- Logging to CloudWatch Logs, S3, or Kinesis Data Firehose; request sampling; labels and metrics
- Web ACL Capacity Units (WCU) budgeting; configurable request-body inspection size (default 16KB on CloudFront/API Gateway/Cognito/App Runner/Verified Access, fixed 8KB on ALB/AppSync)

**Architecture & deployment.** Cloud-native managed service, enforced inline at the attachment point of the fronting AWS resource. Two scopes: CLOUDFRONT (web ACL and WAF resources must live in us-east-1, enforced globally at CloudFront edge) and REGIONAL (ALB, API Gateway REST APIs, AppSync GraphQL, Cognito user pools, App Runner, Amplify, Verified Access), created per-region. No agents or appliances; configured via console, CloudFormation/CDK/Terraform, or the WAFv2 API. Firewall Manager centrally deploys and enforces web ACL policies across an AWS Organization's accounts. A web ACL can be retrofitted into a Firewall Manager policy, after which only Firewall Manager manages its FM rule groups.

**Editions & licensing.** No editions/tiers — pure pay-as-you-go consumption. Charged per web ACL per month, per rule per month, and per million requests inspected, with add-on charges for Bot Control, Fraud Control (ATP/ACFP), intelligent threat mitigation, CAPTCHA attempts, and body inspection beyond the default size. The Anti-DDoS managed rule group is +$20/month plus request charges for standalone WAF customers (included for Shield Advanced customers up to a 50-billion-request monthly limit). As of November 2025, CloudFront distributions associated with AWS WAF can subscribe to CloudFront flat-rate pricing plans with preset quotas instead of pure pay-as-you-go.

**Key integrations.** AWS Shield Standard (free, always-on) and Shield Advanced (enhanced DDoS, now adopting the Anti-DDoS managed rule group as default L7 mitigation); AWS Firewall Manager for org-wide policy; AWS Organizations; CloudWatch (metrics/alarms/dashboards), S3, Kinesis Data Firehose for logs; Security Hub and GuardDuty for findings aggregation; Fronting services: CloudFront, ALB, API Gateway, AppSync, Cognito, App Runner, Amplify, Verified Access; IaC: CloudFormation, CDK, Terraform; SDKs/CLI; third-party managed rules via AWS Marketplace.

**Differentiators**
- Deepest native integration with the AWS stack and single-pane multi-account control via Firewall Manager
- Fully consumption-priced with no appliances, minimum, or edition gating; scales with CloudFront's global edge
- AWS-maintained managed rules plus Amazon threat intelligence (IP reputation) and a Marketplace of third-party rule groups
- Tight Shield Advanced coupling for combined L3/L4 + L7 DDoS; 2025 L7 anti-DDoS rule group reacts in seconds after ~15-min baselining
- WCU model makes rule capacity explicit and predictable

**Limitations & considerations**
- Protects only AWS-fronted resources — not a universal WAF for on-prem or other clouds
- CloudFront-scope resources must be managed in us-east-1, a common operational gotcha
- Request-body inspection capped (default 16KB; fixed 8KB on ALB/AppSync) can miss large-payload attacks unless raised (extra cost, and not raisable on ALB/AppSync)
- Cost can escalate unpredictably with Bot Control, Fraud Control, CAPTCHA, and high request volumes
- Managed rules are comparatively coarse; tuning advanced custom logic and avoiding false positives requires real expertise and WCU budgeting
- Weaker standalone API-schema/positive-security and advanced bot capabilities than dedicated WAAP vendors; no built-in API discovery comparable to edge WAAP products

## Vulnerability-mitigation role

Serves as a fast, code-free virtual-patching and compensating control for AWS-fronted apps: when a critical CVE lands, you add a custom string/regex/SQLi rule or enable the relevant AWS Managed Rule group (e.g., Known Bad Inputs, CRS) to block exploit-shaped requests at the edge before they reach the vulnerable workload, buying time until the code/AMI/container is patched. Rate-based rules and the Anti-DDoS rule group contain exploitation-driven floods. It mitigates exposure but does not remediate the underlying flaw and should be tracked as a temporary control.

**VM lifecycle:** Mitigate · Monitor/Detect · Validate

**Framework mapping:** NIST CSF 2.0: PROTECT (PR.PS, PR.IR), DETECT (DE.CM), RESPOND (RS.MI); CIS Controls v8: 13.10 (application-layer filtering/WAF), 13 (network monitoring and defense), 7 (continuous vulnerability management - compensating control), 8 (audit log management); MITRE ATT&CK mitigations: M1050 Exploit Protection, M1037 Filter Network Traffic, M1031 Network Intrusion Prevention, M1036 Account Use Policies (ATP/ACFP, bot control)

**In a critical-CVE scenario.** First 24-72h on a critical CVE in an internet-facing app and a cloud workload: (1) identify which CloudFront/ALB/API Gateway resources front the vulnerable service; (2) deploy a custom WAF rule matching the exploit (URI/header/body regex or SQLi/XSS statement) and/or enable AWS Managed Rules Known Bad Inputs/CRS, starting in Count mode; (3) inspect sampled requests and CloudWatch metrics to confirm attack traffic matches and legitimate traffic does not, then flip to Block; (4) use Firewall Manager to push the rule to every account/web ACL across the org in one action; (5) add a rate-based rule and the Anti-DDoS managed rule group if exploitation drives floods; (6) keep the rule as a tracked temporary control pending the real patch/redeploy.

## Validation & telemetry

**Log sources**
- WAFv2 web ACL logging to one of: CloudWatch Logs log group (name MUST start with aws-waf-logs-), S3 bucket (prefix aws-waf-logs-), or Kinesis Data Firehose delivery stream (aws-waf-logs-*).
- CloudWatch metrics (AWS/WAFV2 namespace): BlockedRequests, AllowedRequests, CountedRequests, CaptchaRequests per Rule/WebACL — fast 'is it blocking' signal without parsing logs.
- GetSampledRequests API — random sample (<=500) from the first 5,000 requests in the last <=3h, per rule metric name.
- Splunk Add-on for AWS (sourcetype aws:waf via S3/SQS or aws:firehose:waf) mapped to CIM Web / Intrusion_Detection; Microsoft Sentinel AWS WAF connector -> AWSWAFLogs/AWSWAF table (Azure Monitor); Amazon Security Lake -> OCSF (I could NOT verify the exact OCSF class/event_class_uid for WAF from primary docs — confirm in the Security Lake source-mapping reference before relying on a class name).

**Telemetry format / transport.** JSON log records (formatVersion 1), one per inspected request (subject to the web ACL's LoggingFilter). Delivered to CloudWatch Logs, S3, or Kinesis Data Firehose. Amazon Security Lake re-normalizes to OCSF Parquet.

**Control-presence check (present & configured?).** Logging + enforcement are two separate checks. (1) Logging enabled: `aws wafv2 get-logging-configuration --resource-arn <webACL-ARN> [--log-scope CUSTOMER]` returns LoggingConfiguration{LogDestinationConfigs:[...], LoggingFilter{...}, RedactedFields}. Empty/absent = NO logs (off by default). LogScope SECURITY_LAKE / CLOUDWATCH_TELEMETRY_RULE_MANAGED indicate service-owned configs, not yours. (2) Rule is set to block (not count): `aws wafv2 get-web-acl --name <n> --scope REGIONAL|CLOUDFRONT --id <id>` and inspect each Rule's Action (Block/Allow/Count/Captcha/Challenge) and, for managed groups, OverrideAction (None=enforce vs Count=detect-only) and RuleActionOverrides. (3) Association: `aws wafv2 list-resources-for-web-acl` / `get-web-acl-for-resource` (ALB/API GW/AppSync); for CloudFront check the distribution's WebACLId. (4) `aws wafv2 get-sampled-requests` validates recent live matches.

**Validation signals (actually working?)**
- Log record with action = "BLOCK" (terminating actions are only ALLOW or BLOCK; COUNT/CAPTCHA/CHALLENGE on a terminating line mean non-blocking) AND terminatingRuleId = your rule/managed-group (e.g. AWS-AWSManagedRulesKnownBadInputsRuleSet, or Log4JRCE for CVE-2021-44228).
- terminatingRuleType in {REGULAR, RATE_BASED, GROUP, MANAGED_RULE_GROUP}; Default_Action in terminatingRuleId means nothing matched (request allowed by default).
- labels[] containing the managed-rule label (e.g. awswaf:managed:aws:known-bad-inputs:Log4JRCE) — proves the rule evaluated/matched; first 100 labels only.
- terminatingRuleMatchDetails / nonTerminatingMatchingRules[].ruleMatchDetails populated (ONLY for SQLi and XSS statements) — gives the matched location/data.
- Distinguish configured vs effective: get-web-acl showing Rule Action=Block (OverrideAction None) = CONFIGURED; a log line action=BLOCK + CloudWatch BlockedRequests>0 for that rule = ACTUALLY blocked. action=COUNT or a managed group in Count override = evaluated but NOT enforced.

**Key events / fields / tables / APIs**
- Top-level: timestamp, formatVersion(1), webaclId(ARN/GUID), terminatingRuleId, terminatingRuleType, action, terminatingRuleMatchDetails, httpSourceName, httpSourceId, ruleGroupList[], rateBasedRuleList[], nonTerminatingMatchingRules[], labels[], ja3Fingerprint, ja4Fingerprint, captchaResponse, challengeResponse, requestHeadersInserted, responseCodeSent
- httpRequest.{clientIp, country, uri, args, httpVersion, httpMethod, requestId, headers[]}
- ruleGroupList[].{ruleGroupId, terminatingRule{ruleId,action,ruleMatchDetails}, nonTerminatingMatchingRules[], excludedRules[]}
- APIs: wafv2 get-logging-configuration / get-web-acl / get-web-acl-for-resource / list-resources-for-web-acl / get-sampled-requests; CloudWatch AWS/WAFV2 BlockedRequests; Splunk CIM Web(action,src,url)/Intrusion_Detection; Sentinel AWSWAFLogs table

**Example queries**

*Presence: confirm logging is on and the rule is in Block (not Count) mode* (AWS CLI)

```
aws wafv2 get-logging-configuration --resource-arn arn:aws:wafv2:us-east-1:123456789012:global/webacl/prod/abcd ; aws wafv2 get-web-acl --name prod --scope CLOUDFRONT --id abcd --query "WebACL.Rules[].{name:Name,action:Action,override:OverrideAction}"
```

*Validate active blocking attributed to a CVE managed rule (e.g. Log4j)* (CloudWatch Logs Insights)

```
fields @timestamp, httpRequest.clientIp, httpRequest.uri | filter action = "BLOCK" and terminatingRuleId like /KnownBadInputs|Log4JRCE/ | stats count() as blocks by terminatingRuleId, terminatingRuleType | sort blocks desc
```

*Blocks vs counts per terminating rule, to catch detect-only rules masquerading as coverage* (KQL (Sentinel AWSWAFLogs))

```
AWSWAFLogs | where TimeGenerated > ago(24h) | extend rule=tostring(terminatingRuleId_s) | summarize blocked=countif(action_s=='BLOCK'), counted=countif(action_s=='COUNT') by rule | where counted>0 and blocked==0
```

**How it mitigates (mechanism).** Inline evaluation at CloudFront/ALB/API Gateway: the first terminating rule to match applies BLOCK and AWS WAF stops inspecting, returning 403 before origin — a virtual patch when the rule targets a CVE pattern. The observable proof is action=BLOCK with terminatingRuleId = that rule (and its label present).

**Logging gotchas**
- Logging is OFF by default — no web ACL logs exist until a LoggingConfiguration is attached; also the destination name must begin with aws-waf-logs-.
- LoggingFilter can suppress records (e.g. DefaultBehavior DROP, only keep BLOCK) — 'no ALLOW logs' may be a filter, not absence of traffic; RedactedFields blanks chosen fields.
- Count mode is the big trap: a managed group with OverrideAction=Count, or a rule Action=Count, still produces match logs/labels but action resolves to COUNT/ALLOW — coverage looks present but nothing is blocked.
- action is applied on the FIRST terminating match and inspection stops; a blocked request may carry other unlogged threats. labels capped at 100.
- terminatingRuleMatchDetails / ruleMatchDetails are populated ONLY for SQLi and XSS statements — other rule types give you the id/label but not matched content.
- get-sampled-requests samples only the first 5,000 requests over the last 3h — absence of a sample is not absence of the attack.
- WAF Classic (aws waf / waf-regional) is a different, retiring API; use wafv2. For CloudFront the scope is CLOUDFRONT and region must be us-east-1.

## Documentation & repositories

_Official documentation & manuals_
- [AWS WAF Developer Guide](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)
- [AWS WAF Developer Guide (what is AWS WAF)](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
- [AWS WAF product page](https://aws.amazon.com/waf/)
- [AWS WAF endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/waf.html)

_API & developer docs_
- [AWS WAFV2 API Reference](https://docs.aws.amazon.com/waf/latest/APIReferenceV2/Welcome.html)
- [AWS CLI wafv2 command reference](https://docs.aws.amazon.com/cli/latest/reference/wafv2/index.html)
- [Boto3 WAFV2 client (Python SDK)](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/wafv2.html)
- [Terraform aws_wafv2_web_acl resource (HashiCorp AWS provider)](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl)
- [CloudFormation AWS::WAFv2::WebACL reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html)

_GitHub (official)_
- [AWS GitHub org](https://github.com/aws)
- [aws-samples org (example repos & blog code)](https://github.com/aws-samples)
- [awslabs org](https://github.com/awslabs)
- [hashicorp/terraform-provider-aws (contains all aws_wafv2_* resources)](https://github.com/hashicorp/terraform-provider-aws)

_Community / integration / detection repos_
- [aws-solutions/aws-waf-security-automations (managed WAF rule set + IP reputation/flood/scanner protection)](https://github.com/aws-solutions/aws-waf-security-automations)
- [aws-samples/aws-waf-sample (sample WAF conditions/rules)](https://github.com/aws-samples/aws-waf-sample)
- [awslabs/aws-waf-security-automations-partner-dashboard / AWS WAF dashboards](https://github.com/aws-samples/aws-cloudwatch-dashboard-for-aws-waf)

_Learning & reference_
- [AWS Security blog — WAF category](https://aws.amazon.com/blogs/security/category/security-identity-compliance/aws-waf/)
- [AWS WAF Workshop (Workshop Studio)](https://catalog.workshops.aws/aws-waf/en-US)
- [AWS Skill Builder (free training)](https://skillbuilder.aws/)
- [AWS WAF Managed Rules & AWS Marketplace rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups.html)

> Note: Use WAFV2 (the current API, single set of endpoints for regional + CloudFront/global). AWS WAF Classic (waf/wafregional, waf.amazonaws.com endpoint) is legacy — do not use for new work. The aws-solutions/aws-waf-security-automations solution is scheduled to retire December 2026; AWS now recommends native AWS Managed Rules + rate-based rules instead. Verify the Terraform aws_wafv2_web_acl page in-browser (Terraform Registry is JS-rendered and did not return text to WebFetch, but the resource is a long-standing part of the hashicorp/aws provider).

## Current state (2025-26)

AWS WAF (WAFv2) remains the current product. June 2025: AWS launched the AWS WAF Anti-DDoS managed rule group for application-layer (L7) DDoS, detecting/mitigating HTTP floods in seconds after ~15 min baselining; it uses 50 WCUs vs 150 for Shield's prior automatic mitigation and supports Count/Block/Challenge. Shield Advanced is transitioning to this rule group as its default (then sole) L7 mitigation, starting to add it to eligible web ACLs in Count mode (verify exact 2025 rollout dates on the AWS Security Blog). December 2025: Bot Control expanded category detection (Advertising, AI, Content Fetcher, Social Media). October 2025: CRS/common rule set updated. November 2025: CloudFront flat-rate pricing plans can apply to WAF-associated distributions; default ALB-associations-per-web-ACL quota is 100. Confirm current per-request/WCU rates on the AWS WAF pricing page.

---
*Generic reference. Confirm product facts, event IDs, fields and URLs against current vendor sources. Descriptive, not an endorsement.*
