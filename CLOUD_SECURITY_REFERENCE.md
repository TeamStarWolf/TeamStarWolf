# Cloud Security Reference

A comprehensive reference for cloud security across AWS, Azure, and GCP — covering shared responsibility, native security services, IAM deep dives, attack techniques, CSPM, Kubernetes security, serverless, detection & response, and compliance frameworks.

---

## Table of Contents

- [Cloud Shared Responsibility Model](#1-cloud-shared-responsibility-model)
- [AWS Security — Native Services & Controls](#2-aws-security--native-services--controls)
  - [IAM Deep Dive](#iam-deep-dive)
  - [AWS Security Services](#aws-security-services)
  - [AWS Attacks & Misconfigurations](#aws-attacks--misconfigurations)
  - [AWS Logging & Detection](#aws-logging--detection)
- [Azure Security — Native Services & Controls](#3-azure-security--native-services--controls)
  - [Microsoft Entra ID & RBAC](#microsoft-entra-id--rbac)
  - [Azure Security Services](#azure-security-services)
  - [Azure Attacks & Misconfigurations](#azure-attacks--misconfigurations)
  - [Azure Logging & Detection](#azure-logging--detection)
- [GCP Security — Native Services & Controls](#4-gcp-security--native-services--controls)
  - [IAM & Resource Hierarchy](#iam--resource-hierarchy)
  - [GCP Security Services](#gcp-security-services)
  - [GCP Attacks](#gcp-attacks)
- [Cloud Attack Frameworks & Tools](#5-cloud-attack-frameworks--tools)
- [Cloud Security Posture Management (CSPM)](#6-cloud-security-posture-management-cspm)
- [Kubernetes Security](#7-kubernetes-security)
- [Serverless Security](#8-serverless-security)
- [Cloud Detection & Response](#9-cloud-detection--response)
- [Cloud Compliance & Frameworks](#10-cloud-compliance--frameworks)

---

## 1. Cloud Shared Responsibility Model

Understanding the division of security duties between cloud provider and customer is the foundation of every cloud security program. Misunderstanding this boundary is one of the most common sources of cloud breaches.

### Shared Responsibility Comparison Table

| Layer | IaaS (e.g. EC2, Azure VMs, GCE) | PaaS (e.g. RDS, Azure App Service, Cloud Run) | SaaS (e.g. M365, Google Workspace) |
|---|---|---|---|
| Physical / Data Center | **Provider** | **Provider** | **Provider** |
| Network Infrastructure | **Provider** | **Provider** | **Provider** |
| Hypervisor / Host OS | **Provider** | **Provider** | **Provider** |
| Guest OS / VM OS | **Customer** | **Provider** | **Provider** |
| Middleware / Runtime | **Customer** | **Provider** | **Provider** |
| Application Code | **Customer** | **Customer** | **Provider** |
| Application Data | **Customer** | **Customer** | **Customer** |
| Identity & Access | **Customer** | **Customer** | **Customer** |
| Network Controls (SG/NSG) | **Customer** | **Shared** | **Provider** |
| Client Endpoints | **Customer** | **Customer** | **Customer** |

### Provider Responsibilities (All Models)
- Physical security of data centers (SOC 2, ISO 27001, FedRAMP-authorized facilities)
- Hardware maintenance, replacement, and disposal (secure media sanitization)
- Global network backbone, DDoS scrubbing at infrastructure layer
- Hypervisor isolation between tenants
- Core managed service availability and patching (e.g., AWS RDS engine patching)

### Customer Responsibilities (All Models)
- Identity and access management: user accounts, MFA enforcement, role assignments
- Data classification and encryption (at rest and in transit)
- Network access controls: security groups, NACLs, NSGs, firewall rules
- Monitoring and logging: enabling CloudTrail, Azure Monitor, GCP Cloud Audit Logs
- Vulnerability management for customer-managed OS and application layers
- Incident response procedures and business continuity planning

### Common Customer Misconfigurations

| Misconfiguration | Risk | Detection |
|---|---|---|
| Public S3 bucket / Azure Blob container | Unauthenticated data access | AWS Config, Macie, Defender for Cloud |
| Security group / NSG open to 0.0.0.0/0 | Unrestricted inbound access to sensitive ports | AWS Config rule `restricted-ssh`, Azure Policy |
| No MFA enforced for console/portal access | Account takeover via credential stuffing | IAM credential report, Entra Sign-in Logs |
| Weak or overpermissive IAM policies | Privilege escalation to full admin | IAM Access Analyzer, PMapper, Prowler |
| Secrets and API keys in source code / env vars | Credential theft from repo scan or logs | Macie, truffleHog, GitGuardian, Gitleaks |
| Unencrypted EBS volumes / storage accounts | Data exposure on snapshot share | AWS Config `encrypted-volumes`, Defender for Cloud |
| No CloudTrail / audit logging | Blind to all API activity | AWS Security Hub CIS check 2.1 |
| Default VPC with default security groups | Unintended broad connectivity | AWS Config, Prowler check `vpc_default_restrict` |
| IMDSv1 enabled on EC2 (no token requirement) | SSRF → credential theft | AWS Config `ec2-imdsv2-check` |
| Service account keys stored long-term (GCP) | Key exfiltration → persistent access | SCC, IAM recommender |

---

## 2. AWS Security — Native Services & Controls

### IAM Deep Dive

AWS Identity and Access Management (IAM) is the central authorization layer for all AWS API calls. Every API call to AWS is authenticated (via access key or session token) and authorized (via policy evaluation).

#### IAM Policy Structure

Every IAM policy is a JSON document with one or more statements:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadSpecificBucket",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::company-app-bucket",
        "arn:aws:s3:::company-app-bucket/*"
      ],
      "Condition": {
        "Bool": {"aws:SecureTransport": "true"},
        "StringEquals": {"aws:RequestedRegion": "us-east-1"}
      }
    }
  ]
}
```

| Field | Description |
|---|---|
| `Version` | Always `"2012-10-17"` for modern policies |
| `Sid` | Optional statement identifier for readability |
| `Effect` | `Allow` or `Deny` |
| `Action` | AWS service:action pairs (e.g., `s3:GetObject`, `ec2:DescribeInstances`) |
| `Resource` | ARN of the resource(s) the statement applies to; `*` = all |
| `Principal` | Used in resource-based policies; identifies who the policy applies to |
| `Condition` | Optional conditions: IP range, MFA required, time of day, secure transport |

#### IAM Policy Types

| Policy Type | Where Attached | Purpose |
|---|---|---|
| Identity-based | IAM users, groups, roles | Grant permissions to AWS principals |
| Resource-based | AWS resources (S3 bucket, KMS key, etc.) | Grant cross-account access, define trust |
| Service Control Policies (SCPs) | AWS Organizations OU/account | Hard guardrails; cap maximum permissions |
| Permission Boundaries | IAM users/roles | Constrain effective permissions without granting |
| Session Policies | STS sessions | Further restrict permissions in an assumed session |

#### IAM Policy Evaluation Logic

AWS evaluates policies in this order (first explicit deny wins):

1. **Explicit Deny** — Any deny in any policy stops evaluation immediately
2. **SCP** — Organization policy must allow the action for the account
3. **Permission Boundary** — Must allow the action if set
4. **Identity Policy** — The user/role's own policy must allow
5. **Resource Policy** — Cross-account: both identity and resource policy must allow; same-account: either suffices

#### Service Control Policy — Protect Logging and Org Membership

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDisableCloudTrailAndLeaveOrg",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "organizations:LeaveOrganization",
        "config:DeleteConfigurationRecorder",
        "config:StopConfigurationRecorder",
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromMasterAccount",
        "securityhub:DisableSecurityHub"
      ],
      "Resource": "*"
    }
  ]
}
```

#### AWS STS (Security Token Service)

| Operation | Use Case |
|---|---|
| `AssumeRole` | Cross-account access, delegation, EC2 instance profile |
| `AssumeRoleWithWebIdentity` | OIDC federation (GitHub Actions, EKS workload identity) |
| `AssumeRoleWithSAML` | SAML federation (corporate IdP → AWS console) |
| `GetFederationToken` | Custom broker for temporary federated credentials |

IAM Access Analyzer:
- Identifies resources shared outside the account/organization (S3, KMS, IAM roles, Lambda, SQS, SNS)
- Generates least-privilege policies from CloudTrail activity (policy generation feature)
- Unused access findings: identify users/roles with permissions never exercised in 90 days

#### Least Privilege Implementation Strategy

1. Start with `Deny *` — never start with broad `Allow *`
2. Identify exact API actions required (use IAM Access Analyzer policy generation from CloudTrail)
3. Scope resources to specific ARNs; avoid `*` on sensitive services
4. Add conditions: `aws:SecureTransport`, `aws:MultiFactorAuthPresent`, `aws:SourceVpc`, `aws:RequestedRegion`
5. Attach to roles, not users; use groups for human access
6. Rotate access keys; prefer instance profiles and OIDC over long-term keys
7. Enable credential report and regularly review unused access

---

### AWS Security Services

| Service | Purpose | Key Features |
|---|---|---|
| **AWS GuardDuty** | Threat detection | ML-based anomaly detection; analyzes CloudTrail, VPC Flow Logs, DNS logs; 50+ finding types; Malware Protection for EBS/S3 |
| **AWS SecurityHub** | Aggregated security findings | CIS/PCI/NIST benchmarks; cross-account and cross-region aggregation; ASFF finding format; automated remediation via EventBridge |
| **AWS Config** | Configuration compliance | Managed and custom rules; conformance packs (CIS, NIST, PCI); auto-remediation with SSM Automation; resource relationship graph |
| **AWS CloudTrail** | API audit logging | Management events (control plane) + data events (S3 object, Lambda invoke); log file integrity validation; organization trail |
| **AWS Inspector v2** | Vulnerability scanning | EC2 via SSM Agent (no agent install); ECR container image scanning; Lambda function scanning; EPSS and CVSS scoring |
| **AWS Macie** | S3 data classification | PII/sensitive data discovery; custom data identifiers; findings per S3 bucket; cross-account scanning |
| **AWS WAF v2** | Web application firewall | Managed rule groups (OWASP, known bad inputs, IP reputation); rate limiting per IP/session; Bot Control; Fraud Control |
| **AWS Shield Standard** | DDoS protection (free) | Layer 3/4 protection on all AWS resources; automatic SYN flood mitigation |
| **AWS Shield Advanced** | DDoS protection (paid) | $3,000/month base; Layer 7 protection; SRT team access; DDoS cost protection; 24/7 proactive engagement |
| **AWS KMS** | Key management | Customer Managed Keys (CMKs); automatic annual rotation; CloudHSM integration; key policies and grants; cross-region replica keys |
| **AWS Secrets Manager** | Secrets storage | Automatic rotation via Lambda; cross-account access; VPC endpoint support; native RDS/Redshift/DocumentDB integration |
| **AWS SSM** | Systems management | Session Manager (no SSH/bastion, VPC endpoint); Parameter Store (SecureString); Patch Manager; Run Command; Fleet Manager |
| **AWS IAM Access Analyzer** | Access analysis | External access findings; unused access; policy validation; policy generation from CloudTrail |
| **AWS Detective** | Security investigation | Automatically builds behavior baseline; VPC flow, CloudTrail, GuardDuty findings graph; visual investigation of findings |
| **Amazon Security Lake** | Security data lake | OCSF-normalized data; multi-source (CloudTrail, VPC Flow, Route53, Security Hub, custom); subscriber model for SIEM/analytics |
| **AWS Verified Access** | Zero trust network access | ZTNA for internal apps; integrates with AWS IAM Identity Center and SAML IdPs; no VPN required |

---

### AWS Attacks & Misconfigurations

#### S3 Bucket Exposure

```bash
# Check for public access on unauthenticated basis
aws s3 ls s3://target-bucket-name --no-sign-request

# List all buckets (requires credentials)
aws s3 ls

# Check bucket ACL
aws s3api get-bucket-acl --bucket target-bucket-name

# Check bucket policy
aws s3api get-bucket-policy --bucket target-bucket-name

# Check public access block settings (should all be true)
aws s3api get-public-access-block --bucket target-bucket-name
```

#### SSRF to EC2 Instance Metadata Service (IMDS)

The EC2 metadata service at `169.254.169.254` exposes temporary IAM credentials. An SSRF vulnerability that can reach this IP can result in full credential theft.

```bash
# IMDSv1 (no token required — vulnerable)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration

# IMDSv2 (token required — mitigated)
TOKEN=$(curl -s -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
  http://169.254.169.254/latest/api/token)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Use stolen creds
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts get-caller-identity
```

**Mitigation:** Enforce IMDSv2 (`aws ec2 modify-instance-metadata-options --http-tokens required`) or use AWS Config rule `ec2-imdsv2-check`.

#### IAM Privilege Escalation Paths

Common escalation paths exploited by attackers with partial IAM permissions:

| Permission | Escalation Technique |
|---|---|
| `iam:CreatePolicyVersion` | Create a new policy version with `AdministratorAccess` and set it as default |
| `iam:SetDefaultPolicyVersion` | Switch an existing policy to a previously created permissive version |
| `iam:AttachUserPolicy` | Attach `arn:aws:iam::aws:policy/AdministratorAccess` to own user |
| `iam:AttachRolePolicy` | Attach admin policy to a role you can assume |
| `iam:CreateAccessKey` (on other user) | Create new access keys for an admin user |
| `iam:UpdateLoginProfile` | Reset console password for an admin user |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with admin instance profile, use IMDS to get creds |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create Lambda with admin execution role, invoke to run arbitrary code |
| `iam:PassRole` + `ecs:RegisterTaskDefinition` + `ecs:RunTask` | Deploy ECS task with admin role |
| `iam:PassRole` + `glue:CreateJob` + `glue:StartJobRun` | Execute Glue job with admin role |
| `sts:AssumeRole` | Assume a role with broader permissions than current |

**Tools:**
- **PMapper** — `python3 -m principalmapper graph --create` then `python3 -m principalmapper query "who can become admin?"`
- **Pacu** — `run iam__privesc_scan`
- **aws_escalate** — `python aws_escalate.py`

#### Pacu — AWS Exploitation Framework

```bash
# Install
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip3 install -r requirements.txt

# Start
python3 pacu.py

# Key modules
pacu> run iam__bruteforce_permissions       # Determine effective permissions
pacu> run iam__enum_users_roles_policies    # Enumerate IAM objects
pacu> run iam__privesc_scan                 # Identify privilege escalation paths
pacu> run ec2__enum                         # Enumerate EC2 instances, SGs, VPCs
pacu> run s3__enum                          # Enumerate S3 buckets
pacu> run guardduty__enum                   # Check GuardDuty status
pacu> run cloudtrail__download_event_history # Download CloudTrail events
pacu> run lambda__enum                      # Enumerate Lambda functions
```

#### ScoutSuite — Multi-Cloud Auditing

```bash
# Install
pip3 install scoutsuite

# Run against AWS profile
python scout.py aws --profile default --report-dir ./reports

# Run against Azure
python scout.py azure --cli

# Run against GCP
python scout.py gcp --service-account /path/to/key.json --project project-id
```

#### Prowler — Compliance Scanning

```bash
# Install
pip3 install prowler

# CIS AWS Foundations Benchmark Level 2
prowler aws --compliance cis_aws_benchmark_level2_aws

# Specific check
prowler aws -c s3_bucket_public_access_block_enabled
prowler aws -c iam_root_mfa_enabled
prowler aws -c cloudtrail_multi_region_enabled

# NIST CSF
prowler aws --compliance nist_csf_aws

# Output to HTML
prowler aws -o html -F /tmp/prowler-report
```

#### CloudTrail Evasion Techniques

```bash
# Stop logging (requires cloudtrail:StopLogging)
aws cloudtrail stop-logging --name my-trail

# Delete trail (requires cloudtrail:DeleteTrail)
aws cloudtrail delete-trail --name my-trail

# Disable log validation (reduces integrity assurance)
aws cloudtrail update-trail --name my-trail --no-enable-log-file-validation

# Event selector manipulation (removes data event logging)
aws cloudtrail put-event-selectors --trail-name my-trail \
  --event-selectors '[{"ReadWriteType":"None","IncludeManagementEvents":false}]'
```

**Defense:** SCPs denying these actions; GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` finding.

---

### AWS Logging & Detection

#### Key CloudTrail Events to Alert On

| Event | Indicator | Suggested Alert |
|---|---|---|
| `ConsoleLogin` | Without MFA | `additionalEventData.MFAUsed = No AND userIdentity.type = IAMUser` |
| `CreateUser` | New IAM user | Any `CreateUser` not from IaC pipeline |
| `CreateAccessKey` | New access key | Any creation, especially for admin users |
| `AttachUserPolicy` / `AttachRolePolicy` | Policy attachment | Especially attaching `AdministratorAccess` |
| `AuthorizeSecurityGroupIngress` | Port opened to 0.0.0.0/0 | Any `0.0.0.0/0` or `::/0` ingress rule |
| `PutBucketPolicy` / `PutBucketAcl` | S3 policy change | Any change; alert on public ACLs |
| `DisableKey` / `ScheduleKeyDeletion` | KMS key compromise | Any key deletion/disable event |
| `AssumeRole` | Cross-account | From unusual source account or IP |
| `StopLogging` | CloudTrail disabled | Immediate critical alert |
| `DeleteTrail` | CloudTrail deleted | Immediate critical alert |
| `DeleteDetector` | GuardDuty disabled | Immediate critical alert |
| `LeaveOrganization` | Account leaving org | Immediate critical alert |
| `PutBucketPublicAccessBlock` | Block removed | Alert on setting any value to `false` |
| `RunInstances` | Large instance launch | Alert on `m5.24xlarge` etc. (crypto mining) |

#### CloudWatch Alarms for Security Events

```bash
# Create metric filter for root account usage
aws logs put-metric-filter \
  --log-group-name CloudTrail/DefaultLogGroup \
  --filter-name RootAccountUsage \
  --filter-pattern '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}' \
  --metric-transformations metricName=RootAccountUsageCount,metricNamespace=CloudTrailMetrics,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountUsage \
  --metric-name RootAccountUsageCount \
  --namespace CloudTrailMetrics \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:SecurityAlerts
```

#### GuardDuty Finding Categories

| Category | Example Findings |
|---|---|
| **Backdoor** | `Backdoor:EC2/DenialOfService.Tcp` — EC2 sending DoS traffic |
| **CryptoCurrency** | `CryptoCurrency:EC2/BitcoinTool.B!DNS` — Bitcoin mining traffic |
| **Impact** | `Impact:S3/AnomalousBehavior.Write` — Unusual S3 write activity |
| **InitialAccess** | `InitialAccess:IAMUser/AnomalousBehavior` — Unusual sign-in |
| **Persistence** | `Persistence:IAMUser/NetworkPermissions` — New security group rule |
| **PrivilegeEscalation** | `PrivilegeEscalation:IAMUser/AnomalousBehavior` |
| **Recon** | `Recon:EC2/PortProbeUnprotectedPort` — Port scanning |
| **Stealth** | `Stealth:IAMUser/CloudTrailLoggingDisabled` |
| **Trojan** | `Trojan:EC2/DropPoint` — EC2 communicating with known dropper |
| **UnauthorizedAccess** | `UnauthorizedAccess:EC2/SSHBruteForce` |

---

## 3. Azure Security — Native Services & Controls

### Microsoft Entra ID & RBAC

Microsoft Entra ID (formerly Azure Active Directory) is the identity provider for all Azure resources and Microsoft 365.

#### Azure RBAC Built-In Roles

| Role | Scope | Use Case |
|---|---|---|
| Owner | Sub / RG / Resource | Full control including access management |
| Contributor | Sub / RG / Resource | Full resource control, no access management |
| Reader | Sub / RG / Resource | Read-only access to resources |
| Security Admin | Subscription | Manage security policies, alerts, recommendations |
| Security Reader | Subscription | Read security posture (Defender for Cloud) |
| User Access Administrator | Sub / RG / Resource | Manage user access to Azure resources |
| Network Contributor | Sub / RG | Manage networks, not access |
| Key Vault Administrator | Key Vault | Full Key Vault data plane access |
| Key Vault Secrets User | Key Vault | Read secrets only |
| Monitoring Reader | Sub / RG | Read monitoring data, metrics, logs |

#### Custom RBAC Roles

```json
{
  "Name": "Custom Security Analyst",
  "IsCustom": true,
  "Description": "Can read security posture and view alerts",
  "Actions": [
    "Microsoft.Security/*/read",
    "Microsoft.OperationalInsights/workspaces/*/read",
    "Microsoft.Insights/alertRules/read"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": ["/subscriptions/SUBSCRIPTION_ID"]
}
```

#### Azure Resource Hierarchy & Policy

```
Azure AD Tenant
└── Management Group (Org root)
    ├── Management Group (Corp)
    │   ├── Subscription (Prod)
    │   │   ├── Resource Group (app-rg)
    │   │   │   └── Resources (VMs, Storage, KV, etc.)
    │   │   └── Resource Group (network-rg)
    │   └── Subscription (Dev)
    └── Management Group (Sandbox)
```

Azure Policy effects (in order of strictness):
- `Deny` — Block the resource operation
- `Audit` — Allow but log non-compliant resources
- `AuditIfNotExists` — Audit if a related resource doesn't exist
- `DeployIfNotExists` — Auto-deploy a related resource if missing
- `Modify` — Alter tags or properties on resources

Built-in policy initiatives: **CIS Azure Foundations**, **NIST SP 800-53**, **PCI DSS**, **ISO 27001**, **HIPAA HITRUST**

#### Azure AD Privileged Identity Management (PIM)

- Just-in-time (JIT) role activation — no standing privileged access
- Activation requires MFA, approval workflow, and/or justification
- Time-bounded assignments (max 8 hours for Global Admin by default)
- Access reviews: periodic re-certification of role assignments
- Alert on permanent Global Admin assignments, role activation without MFA

---

### Azure Security Services

| Service | Purpose |
|---|---|
| **Microsoft Defender for Cloud** | CSPM + CWPP; Secure Score; recommendations and regulatory compliance assessments |
| **Microsoft Sentinel** | Cloud-native SIEM/SOAR; KQL queries; analytics rules; playbooks (Logic Apps) |
| **Azure Monitor / Log Analytics** | Centralized log ingestion; KQL query language; metrics and alerts |
| **Microsoft Defender for Endpoint** | EDR for Windows/macOS/Linux/Android/iOS (formerly ATP) |
| **Microsoft Defender for Identity** | On-prem Active Directory attack detection (formerly ATA) |
| **Defender for Office 365 (MDO)** | Email phishing/malware, Safe Links, Safe Attachments, Attack Simulator |
| **Defender for Cloud Apps (MCAS)** | CASB; shadow IT discovery; session control; conditional access app control |
| **Azure Firewall Premium** | IDPS, TLS inspection, URL filtering, threat intelligence feeds |
| **Azure DDoS Protection Standard** | Volumetric, protocol, and resource-layer protection with SLA guarantee |
| **Azure Key Vault** | Secrets, keys, and certificate management; HSM-backed option; RBAC data plane |
| **Azure AD PIM** | JIT privileged access, access reviews, activation approvals |
| **Microsoft Purview** | Data governance, data classification, DLP policies, eDiscovery |
| **Azure Private Link** | Private connectivity to PaaS services; no public IP required |
| **Microsoft Entra Conditional Access** | Policy-based access: MFA, device compliance, location, risk level |
| **Microsoft Entra ID Protection** | Risk-based sign-in and user risk detection; leaked credentials |

---

### Azure Attacks & Misconfigurations

#### Azure AD / Entra ID Attack Techniques

**Password Spray:**
```powershell
# MSOLSpray
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\users.txt -Password "Winter2024!"

# AADInternals
Import-Module AADInternals
# Enumerate users
Get-AADIntLoginInformation -UserName victim@corp.com
Invoke-AADIntUserEnumerationAsInsider -UserName victim@corp.com

# Spray365 (supports smart lockout evasion)
python spray365.py spray --credfile creds.csv --execution_plan ./ep.json
```

**Device Code Phishing (T1528):**
```
1. Attacker: GET https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode
             Body: client_id=...&scope=openid+profile+email+offline_access
   Response: {"device_code":"...","user_code":"XXXXX-XXXXX","verification_uri":"https://microsoft.com/devicelogin"}

2. Attacker sends victim: "Please visit https://microsoft.com/devicelogin and enter: XXXXX-XXXXX"

3. Victim authenticates with their credentials + MFA

4. Attacker polls: POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
                   Body: grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=...
   Receives: access_token, refresh_token (persistent access)
```

**Token Theft:**
- Steal `ESTSAUTH` / `ESTSAUTHPERSISTENT` cookies → replay session without MFA
- Pass-the-PRT: steal Primary Refresh Token from joined device (`RequestAADRefreshToken`)
- Evilginx2 / Modlishka: adversary-in-the-middle proxy to capture tokens post-MFA

**Managed Identity Abuse:**
```bash
# From an Azure VM with managed identity
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns: access_token for Azure Resource Manager
```

#### Azure Enumeration Tools

```bash
# Azure CLI enumeration
az account list
az resource list --output table
az role assignment list --all --output table
az keyvault list
az storage account list
az ad user list --output table
az ad sp list --output table

# ROADtools — Azure AD enumeration
pip3 install roadtools
roadrecon auth -u user@corp.com -p "Password123"
roadrecon gather
roadrecon gui    # Web UI at http://localhost:5000

# AzureHound — BloodHound for Azure
./azurehound -u user@corp.com -p "Password123" list --tenant "corp.com" -o azurehound.json
# Import into BloodHound for attack path analysis
```

#### Storage Account Exposure

```bash
# Check for public blob container access
az storage container list --account-name targetaccount --output table

# Download from public container (no auth)
az storage blob download --account-name targetaccount \
  --container-name public --name file.txt --file ./file.txt --no-auth-required

# Enumerate SAS tokens (look in URLs, logs, source code)
# SAS token indicators: sv=, ss=, srt=, sp=, se=, st=, spr=, sig=
```

---

### Azure Logging & Detection

#### Key Log Sources

| Log Type | Data | Location |
|---|---|---|
| Azure Activity Log | Resource operations (control plane) | Monitor → Activity Log; export to Log Analytics |
| Microsoft Entra Sign-in Logs | All authentication events | Entra ID → Monitoring → Sign-ins |
| Microsoft Entra Audit Logs | User/group/role changes | Entra ID → Monitoring → Audit logs |
| Azure Diagnostic Logs | Resource-specific (KV access, NSG flow) | Per resource → Diagnostic settings |
| Microsoft Defender for Cloud Alerts | Security findings | Defender for Cloud → Security alerts |
| Microsoft Sentinel Incidents | Correlated alerts → incidents | Sentinel → Incidents |

#### KQL Detection Examples

```kql
// Failed sign-ins — potential password spray
SigninLogs
| where ResultType != "0"
| summarize FailCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailCount > 10
| order by FailCount desc

// New Owner role assignment
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| extend RoleDefId = tostring(parse_json(Properties).roleDefinitionId)
| where RoleDefId endswith "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  // Owner role GUID
| project TimeGenerated, Caller, ResourceGroup, SubscriptionId

// Key Vault secret access from unusual IP
AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName == "SecretGet"
| where ResultType == "Success"
| summarize count() by CallerIPAddress, identity_claim_appid_g
| where count_ > 50

// Conditional Access bypass — sign-in without CA policies applied
SigninLogs
| where ConditionalAccessStatus == "notApplied"
| where UserType == "Member"
| where AppDisplayName in ("Azure Portal", "Microsoft Azure Management")

// MFA not satisfied
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where MfaDetail.authMethod == ""
| where ResultType == "0"  // Successful without MFA actually completing
```

---

## 4. GCP Security — Native Services & Controls

### IAM & Resource Hierarchy

GCP organizes resources in a hierarchy with policy inheritance flowing downward:

```
Organization (domain.com)
└── Folders (Business Units)
    └── Projects (workloads)
        └── Resources (GCE VMs, GCS buckets, BigQuery, etc.)
```

**IAM Role Types:**

| Type | Example | Notes |
|---|---|---|
| Primitive | Owner, Editor, Viewer | Legacy; overly broad; avoid in prod |
| Predefined | `roles/compute.instanceAdmin.v1` | Service-specific, curated |
| Custom | `custom/securityAnalystRole` | Defined per org; union of permissions |

**Service Accounts:**
- Identities for workloads (VMs, containers, functions)
- Best practice: dedicated SA per service; no keys if possible (use Workload Identity Federation)
- Service account impersonation: `iam.serviceAccounts.actAs` permission allows assuming another SA

**Organization Policy Constraints:**

| Constraint | Effect |
|---|---|
| `constraints/compute.requireOsLogin` | Requires OS Login (SSH keys managed by IAM) |
| `constraints/iam.allowedPolicyMemberDomains` | Restrict IAM bindings to specific domains |
| `constraints/compute.restrictPublicIPAddresses` | Block public IPs on GCE instances |
| `constraints/storage.uniformBucketLevelAccess` | Disable ACLs on GCS buckets |
| `constraints/compute.requireShieldedVm` | Require Shielded VM features |
| `constraints/gcp.resourceLocations` | Restrict resource creation to specific regions |

**VPC Service Controls:**
- Create a security perimeter around GCP services (GCS, BigQuery, etc.)
- Prevent data exfiltration: API calls from outside the perimeter are denied
- Context-aware access: allow access based on identity + device + network

---

### GCP Security Services

| Service | Purpose |
|---|---|
| **Security Command Center (SCC)** | CSPM; vulnerability findings (misconfigurations, CVEs); threat detection; asset inventory |
| **Chronicle** | Cloud-native SIEM at petabyte scale; UDM normalized events; YARA-L detection rules |
| **Cloud Armor** | WAF + DDoS protection; managed rule sets; custom rules; adaptive protection (ML-based) |
| **Cloud KMS / Cloud HSM** | Key management; FIPS 140-2 Level 3 (HSM); customer-managed keys for GCP services |
| **Secret Manager** | Secrets storage; versioning; automatic rotation; audit logging |
| **Binary Authorization** | Enforce signed container images in GKE; attestation-based deploy policy |
| **Artifact Analysis** | Container image vulnerability scanning (CVE); OS packages; language packages |
| **Access Transparency** | Logs of Google admin access to customer data in GCP |
| **VPC Service Controls** | Service perimeter to prevent data exfiltration |
| **Cloud Audit Logs** | Admin Activity, Data Access, System Event logs for all GCP services |
| **Chronicle SOAR** | Playbook automation for security operations |

---

### GCP Attacks

#### SSRF to GCP Metadata Service

```bash
# GCP requires Metadata-Flavor: Google header (mitigates naive SSRF)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
# Returns: access_token (OAuth 2.0 bearer token for the instance SA)

# Get instance info
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true"

# Get project info
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
```

#### Service Account Key Exfiltration

```bash
# List service account keys
gcloud iam service-accounts keys list \
  --iam-account=sa-name@project.iam.gserviceaccount.com

# Create new SA key (requires iam.serviceAccountKeys.create)
gcloud iam service-accounts keys create sa-key.json \
  --iam-account=sa-name@project.iam.gserviceaccount.com

# Authenticate with stolen key
gcloud auth activate-service-account --key-file=sa-key.json
```

#### GCP Enumeration & Attack Tools

```bash
# GCPBucketBrute — find public GCS buckets
python3 GCPBucketBrute.py --keyword targetcompany

# gcp_scanner — multi-resource enumeration
python3 scanner.py -g -p project-id

# GCP privilege escalation: iam.serviceAccounts.actAs
gcloud iam service-accounts add-iam-policy-binding \
  admin-sa@project.iam.gserviceaccount.com \
  --member="serviceAccount:low-priv-sa@project.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator"
# Then impersonate:
gcloud auth print-access-token --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com
```

#### GCP Privilege Escalation Paths

| Permission | Escalation |
|---|---|
| `iam.serviceAccounts.actAs` + `run.services.create` | Deploy Cloud Run service as higher-priv SA |
| `iam.serviceAccounts.actAs` + `cloudfunctions.functions.create` | Deploy Cloud Function as higher-priv SA |
| `iam.roles.update` | Add permissions to existing custom role |
| `iam.roles.create` | Create new custom role with desired permissions |
| `resourcemanager.projects.setIamPolicy` | Grant any permission at project level |
| `compute.instances.create` + `iam.serviceAccounts.actAs` | Launch VM with higher-priv SA attached |

---

## 5. Cloud Attack Frameworks & Tools

| Tool | Platform | Purpose |
|---|---|---|
| **CloudFox** | AWS, Azure | Attack path analysis; `github.com/BishopFox/cloudfox`; finds exploitable paths (SSRF, misconfigs, secrets) |
| **Pacu** | AWS | Exploitation framework; 50+ modules; simulate attacker techniques; `github.com/RhinoSecurityLabs/pacu` |
| **ScoutSuite** | AWS, Azure, GCP, Alibaba, Oracle | Multi-cloud security auditing; generates HTML report; maps to CIS/NIST |
| **Prowler** | AWS, Azure, GCP | Compliance scanning; CIS, NIST, PCI, HIPAA, GDPR; CI/CD integration |
| **Steampipe** | All clouds | SQL queries across cloud APIs; `select * from aws_s3_bucket where bucket_policy_is_public` |
| **Cartography** | AWS | Graph-based cloud asset inventory; Neo4j; shows blast radius of access |
| **PMapper** | AWS | IAM privilege escalation graph; `who can become admin?` queries |
| **ROADtools** | Azure | Azure AD enumeration; GUI for exploring relationships; `roadrecon gather` |
| **AzureHound** | Azure | BloodHound collector for Azure; maps RBAC attack paths |
| **BloodHound CE** | Azure, on-prem AD | Attack path visualization; shortest path to admin |
| **Nuclei cloud templates** | All | Cloud misconfiguration detection templates; `nuclei -t cloud/aws/` |
| **TruffleHog** | All | Secrets scanning in git repos, S3, GCS, Jira |
| **gitleaks** | All | Pre-commit hook and CI/CD secrets detection |
| **CloudSplaining** | AWS | IAM policy analysis; identifies resource exposure and privilege escalation |
| **Parliament** | AWS | IAM policy linter; identifies mistakes before deployment |

---

## 6. Cloud Security Posture Management (CSPM)

### What CSPM Does

Cloud Security Posture Management continuously assesses cloud resource configurations against security benchmarks, compliance frameworks, and best practices.

**Core CSPM Functions:**
1. Asset inventory across accounts/subscriptions/projects
2. Configuration assessment against CIS, NIST, PCI, SOC 2 benchmarks
3. Drift detection — alert when configuration deviates from baseline
4. Risk prioritization — vulnerability context + identity access + data sensitivity
5. Compliance reporting — automated evidence collection for auditors
6. Remediation guidance — step-by-step fix instructions (or auto-remediation)

### Commercial CSPM Tools

| Tool | Differentiator |
|---|---|
| **Wiz** | Security graph connecting identities → workloads → data → vulnerabilities; CNAPP platform |
| **Prisma Cloud (Palo Alto)** | Broad CNAPP; strong DevSecOps integration; code-to-cloud |
| **Lacework** | Behavioral anomaly detection; ML-based threat detection |
| **Orca Security** | Agentless side-scanning of workloads; no agent needed |
| **Tenable Cloud Security** | Vulnerability-centric; JIT access; IaC scanning (formerly Accurics) |
| **CrowdStrike Falcon Cloud Security** | Agent-based CWPP + agentless CSPM; unified XDR platform |
| **Sysdig Secure** | Container/K8s focused; runtime security; Falco-based |

### Wiz Security Graph Concept

Wiz correlates multiple risk factors into attack paths:
- **Identity risk**: overpermissive roles, unused permissions
- **Workload vulnerability**: CVEs on running instances/containers
- **Network exposure**: internet-exposed resources
- **Data sensitivity**: PII/secrets in S3/storage
- **Combined toxic combination**: "EC2 with critical CVE + internet-exposed + has admin role + accesses S3 with PII"

### Key Security Benchmarks

| Benchmark | Source | Coverage |
|---|---|---|
| CIS AWS Foundations 2.0 | CIS | 58 recommendations; IAM, logging, networking, monitoring |
| CIS Azure 2.0 | CIS | Identity, defender, storage, database, networking, logging |
| CIS GCP 2.0 | CIS | IAM, logging, VMs, storage, cloud SQL, networking |
| AWS Well-Architected Security Pillar | AWS | IAM, detection, infra protection, data protection, IR |
| NIST SP 800-53 Cloud | NIST | 1000+ controls mapped to cloud services |
| SOC 2 Trust Service Criteria | AICPA | CC (security), A (availability), C (confidentiality), PI (processing integrity), P (privacy) |

---

## 7. Kubernetes Security

### K8s Attack Surface

| Component | Risk |
|---|---|
| API server (`kube-apiserver`) | Unauthenticated access, SSRF, JWT bypass |
| etcd | Stores all cluster secrets in base64 (not encrypted by default); direct access = cluster compromise |
| kubelet | Unauthenticated kubelet port 10250 → exec into any pod |
| Container runtime | Privilege escalation from container to host |
| Service accounts | Default SA auto-mounted with token; abused for lateral movement |
| Helm charts | Default values with insecure settings |

### RBAC Misconfigurations

```yaml
# DANGEROUS: cluster-admin for service account
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dangerous-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: default
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io

# DANGEROUS: wildcard permissions
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
```

### Secure Pod Security Context

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    image: app:1.0
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
    resources:
      limits:
        cpu: "500m"
        memory: "128Mi"
```

### Container Escape Techniques

| Technique | Requirement | Description |
|---|---|---|
| Privileged container | `securityContext.privileged: true` | Access host devices; mount host filesystems |
| `docker.sock` mount | `/var/run/docker.sock` mounted | Create new privileged containers on host |
| `hostPath` write | Writable path to `/etc`, `/root`, etc. | Write SSH keys, cron jobs, or binaries |
| `hostPID` | `hostPID: true` | Access host processes; ptrace attack |
| `hostNetwork` | `hostNetwork: true` | Access host network stack; SSRF from host IP |
| CVE-based | Varies (CVE-2019-5736, CVE-2022-0847) | Container runtime / kernel exploits |

### K8s Security Tooling

| Tool | Purpose |
|---|---|
| **Trivy** | Image vulnerability scanning; also misconfig and secret scanning |
| **Falco** | Runtime security; detects unexpected process execution, file access, network connections |
| **kube-bench** | CIS Kubernetes Benchmark compliance check |
| **kube-hunter** | Active penetration testing of K8s clusters |
| **kyverno** | Policy-as-code; admission controller; mutation and validation webhooks |
| **OPA Gatekeeper** | Rego-based policy enforcement at admission time |
| **Checkov** | IaC static analysis; K8s manifests, Terraform, Helm charts |
| **Kubescape** | NSA/CISA K8s hardening framework compliance check |

---

## 8. Serverless Security

### Attack Surface: Lambda / Azure Functions / Cloud Functions

| Vector | Risk |
|---|---|
| Environment variable secrets | Secrets in `process.env`; visible in function configuration; exposed via XXE/SSRF/LFI |
| Overprivileged execution role | Lambda with `*:*` on `*` — full account compromise via function invoke |
| Event injection | Malicious payload via SNS/SQS/S3 event trigger; if function evaluates input unsafely |
| Dependency vulnerabilities | npm/pip packages in deployment package; no runtime patching |
| Cold start timing | Information leakage about function warm/cold state |
| Shared /tmp | Persistent /tmp between invocations in same container (625MB); potential data leakage |
| SSRF from function | Lambda in VPC can reach internal resources + IMDS at 169.254.169.254 |

### Lambda Security Best Practices

```python
# INSECURE: secrets in environment variables
import os
db_password = os.environ['DB_PASSWORD']  # Visible in Lambda console

# SECURE: use Secrets Manager
import boto3
import json

def get_secret(secret_name):
    client = boto3.client('secretsmanager')
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response['SecretString'])

# INSECURE: overly broad execution role (AdministratorAccess)
# Resource: "*"
# Action: "*:*"

# SECURE: least-privilege execution role
# Allow only: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents
# Plus specific actions needed: e.g., s3:GetObject on specific bucket
```

**Least-Privilege Lambda Execution Role:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:us-east-1:ACCOUNT:log-group:/aws/lambda/my-function:*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": "arn:aws:s3:::specific-bucket/specific-prefix/*"
    },
    {
      "Effect": "Allow",
      "Action": ["secretsmanager:GetSecretValue"],
      "Resource": "arn:aws:secretsmanager:us-east-1:ACCOUNT:secret:my-secret-*"
    }
  ]
}
```

**Function URL Security:**
```python
# INSECURE: public function URL with no auth
FunctionUrl:
  AuthType: NONE  # Anyone on the internet can invoke

# SECURE: IAM auth required
FunctionUrl:
  AuthType: AWS_IAM
  Cors:
    AllowOrigins:
      - "https://app.example.com"
```

### Serverless Attack Tools
- **ServerlessGoat** — deliberately vulnerable Lambda app for learning: `github.com/OWASP/ServerlessGoat`
- **PurpleCloud** — serverless attack simulation environment
- **SLSDetect** — serverless-specific detection rules
- **WeirdAAL** — AWS attack library including Lambda-specific techniques

---

## 9. Cloud Detection & Response

### Cloud IR Priorities

**Phase 1 — Contain (minutes)**
```bash
# AWS: Revoke IAM access key
aws iam update-access-key \
  --access-key-id AKIAIOSFODNN7EXAMPLE \
  --status Inactive \
  --user-name compromised-user

# AWS: Deny all STS sessions for a role (attach inline deny policy)
aws iam put-role-policy --role-name CompromisedRole \
  --policy-name EmergencyDeny \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# AWS: Isolate EC2 (move to deny-all security group)
aws ec2 modify-instance-attribute \
  --instance-id i-0123456789abcdef0 \
  --groups sg-00000000000000000  # Pre-created deny-all SG

# Azure: Disable user account
az ad user update --id user@corp.com --account-enabled false

# Azure: Revoke all user sessions
az ad user revoke-sign-in-sessions --id user@corp.com

# GCP: Disable service account
gcloud iam service-accounts disable sa-name@project.iam.gserviceaccount.com

# GCP: Remove SA from project IAM
gcloud projects remove-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:sa@project.iam.gserviceaccount.com" \
  --role="roles/owner"
```

**Phase 2 — Preserve Evidence**
```bash
# AWS: Create EBS snapshot before terminating
aws ec2 create-snapshot --volume-id vol-0123456789abcdef0 \
  --description "IR-$(date +%Y%m%d-%H%M%S)-forensic"

# AWS: Export CloudTrail to S3 for investigation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time 2024-01-01T00:00:00 \
  --end-time 2024-01-02T00:00:00 \
  > cloudtrail-events.json

# AWS: Enable VPC Flow Logs if not already enabled
aws ec2 create-flow-logs --resource-type VPC \
  --resource-ids vpc-0123456789abcdef0 \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::forensics-bucket/flow-logs/
```

**Phase 3 — Investigate**
```bash
# AWS: Enumerate what the compromised identity did
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE

# List all IAM changes in last 24h
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)

# List all S3 data events for bucket
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=arn:aws:s3:::sensitive-bucket

# Check for new IAM users/roles created
aws iam list-users --query 'Users[?CreateDate>=`2024-01-01`]'
aws iam list-roles --query 'Roles[?CreateDate>=`2024-01-01`]'
```

### SIEM Integration Architecture

```
AWS:
CloudTrail → S3 → EventBridge / SQS → Lambda → SIEM (Splunk/Sentinel/Chronicle)
GuardDuty findings → SecurityHub → EventBridge → Lambda → SIEM + ticketing
VPC Flow Logs → S3 / CWL → SIEM

Azure:
Activity Log → Event Hub → SIEM
Entra Sign-in Logs → Log Analytics → Sentinel (built-in)
Defender for Cloud alerts → Sentinel (native connector)

GCP:
Cloud Audit Logs → Pub/Sub → SIEM
SCC findings → Pub/Sub → SIEM / Chronicle
VPC Flow Logs → Cloud Storage → SIEM
```

### Cloud SOAR Playbook — Auto-Quarantine on GuardDuty

```python
# Lambda function triggered by GuardDuty HIGH severity finding via EventBridge

import boto3
import json

def lambda_handler(event, context):
    finding = event['detail']
    severity = finding['severity']

    if severity < 7.0:  # Only act on HIGH (7+) and CRITICAL (9+)
        return {"action": "no_action", "severity": severity}

    finding_type = finding['type']

    # EC2 instance compromise
    if 'instanceDetails' in finding.get('resource', {}):
        instance_id = finding['resource']['instanceDetails']['instanceId']
        ec2 = boto3.client('ec2')

        # Move to quarantine security group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=['sg-QUARANTINE_SG_ID']
        )

        # Create forensic snapshot
        instance = ec2.describe_instances(InstanceIds=[instance_id])
        for device in instance['Reservations'][0]['Instances'][0].get('BlockDeviceMappings', []):
            vol_id = device['Ebs']['VolumeId']
            ec2.create_snapshot(
                VolumeId=vol_id,
                Description=f"Auto-IR-{finding['id'][:8]}"
            )

    # IAM credential compromise
    if 'accessKeyDetails' in finding.get('resource', {}):
        access_key_id = finding['resource']['accessKeyDetails']['accessKeyId']
        user_name = finding['resource']['accessKeyDetails'].get('userName', '')

        iam = boto3.client('iam')
        if user_name:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status='Inactive'
            )

    return {"action": "quarantine_applied", "finding_id": finding['id']}
```

---

## 10. Cloud Compliance & Frameworks

### AWS Well-Architected Security Pillar

Six best practice areas:

| Area | Key Controls |
|---|---|
| **Identity and Access Management** | Root MFA, least privilege, no long-term keys, SCP, Permission Boundaries |
| **Detection** | CloudTrail, Config, GuardDuty, SecurityHub, CloudWatch alarms |
| **Infrastructure Protection** | VPC design, SGs, NACLs, WAF, Shield, Systems Manager (no SSH) |
| **Data Protection** | Encryption at rest (KMS), in transit (TLS), S3 versioning, Macie |
| **Incident Response** | Playbooks, IR role, GameDays, forensic account, AWS CIRT partnership |
| **Application Security** | Static/dynamic analysis, Inspector, CodeGuru, secure pipeline |

### CIS Benchmarks

Free PDF download from **cisecurity.org**:

| Benchmark | Version | Key Focus Areas |
|---|---|---|
| CIS AWS Foundations | 2.0 (2023) | IAM (14 recs), Storage, Logging, Monitoring, Networking |
| CIS Azure Foundations | 2.0 (2023) | Identity, Defender, Storage, Database, Networking, Logging |
| CIS GCP Foundations | 2.0 (2023) | IAM, Logging, VMs, Storage, Cloud SQL, BigQuery, Networking |
| CIS EKS | 1.4 | Control plane, worker nodes, RBAC, networking |
| CIS Docker | 1.6 | Host config, daemon config, container images, runtime |

### CSA Cloud Controls Matrix (CCM) v4.0

197 control objectives across 17 domains:
- AIS (Application & Interface Security)
- BCR (Business Continuity Management)
- CCC (Change Control & Configuration Management)
- CEK (Cryptography, Encryption & Key Management)
- DSP (Data Security & Privacy Lifecycle Management)
- GRC (Governance, Risk & Compliance)
- HRS (Human Resources Security)
- IAM (Identity & Access Management)
- IPY (Interoperability & Portability)
- IVS (Infrastructure & Virtualization Security)
- LOG (Logging & Monitoring)
- SEF (Security Incident Management, E-Discovery & Cloud Forensics)
- STA (Supply Chain Management, Transparency & Accountability)
- TVM (Threat & Vulnerability Management)
- UEM (Universal Endpoint Management)

### Compliance Framework Mapping

| Framework | Applicability | Key Cloud Requirements |
|---|---|---|
| **FedRAMP** | US federal contractors | NIST 800-53 Rev 5; Low/Moderate/High; ATO process; monthly ConMon |
| **ISO 27017** | Cloud-specific controls | Extension of 27001; provider and customer controls; virtual machine hardening |
| **SOC 2 Type II** | Service providers | Trust Service Criteria; 6-12 month audit period; covers security, availability, confidentiality |
| **PCI DSS v4.0** | Cardholder data | Network segmentation; encryption; access control; logging; IR; 12 requirements |
| **HIPAA** | US healthcare | ePHI protection; BAA with cloud provider; encryption addressable; audit controls |
| **GDPR** | EU personal data | Data residency; DPA with cloud provider; breach notification 72h; right to erasure |
| **NIST CSF 2.0** | Voluntary framework | Govern, Identify, Protect, Detect, Respond, Recover functions; tiers and profiles |

### CISA SCuBA (Secure Cloud Business Applications)

Hardening baselines for Microsoft 365 cloud services:

```bash
# ScubaGear — automated M365 configuration assessment
git clone https://github.com/cisagov/ScubaGear
cd ScubaGear
Install-Module -Name ScubaGear -Force
Import-Module ScubaGear
Invoke-SCuBA -ProductNames teams,exo,aad,powerplatform,sharepoint,onedrive
# Generates HTML report with pass/fail against CISA baseline policies
```

Products covered: Azure AD, Exchange Online, Teams, SharePoint, OneDrive, Power Platform, Defender for O365.

---

## Quick Reference: Detection & Response Checklists

### AWS Credential Compromise Checklist

- [ ] Identify affected access key(s): `aws sts get-caller-identity`
- [ ] Disable affected key: `aws iam update-access-key --status Inactive`
- [ ] Review key activity: CloudTrail `lookup-events` for access key ID
- [ ] Check for new IAM entities created: `list-users`, `list-roles`, `list-policies`
- [ ] Check for new S3 buckets or changes: `aws s3 ls` and S3 events in CloudTrail
- [ ] Check for Lambda functions or EC2 launched by attacker
- [ ] Check for new VPC/SG resources (persistence or exfil infrastructure)
- [ ] Check all regions (attacker may pivot to less-monitored regions)
- [ ] Rotate affected credentials and revoke all active sessions
- [ ] Review and tighten IAM policies; enable permission boundaries
- [ ] Review GuardDuty findings for the timeframe

### Azure Account Compromise Checklist

- [ ] Disable compromised user: `az ad user update --account-enabled false`
- [ ] Revoke all sessions: Entra ID → User → Revoke sessions
- [ ] Review sign-in logs: unusual IPs, locations, user agents
- [ ] Review audit logs: role assignments, MFA changes, app registrations
- [ ] Check Azure Activity Log: resource creation, policy changes, RBAC changes
- [ ] Review Defender for Cloud alerts and recommendations
- [ ] Check for new service principals or app registrations
- [ ] Check for new RBAC assignments at subscription level
- [ ] Review conditional access policy changes
- [ ] Enable or review MFA enforcement; check for authentication method changes
- [ ] Check Microsoft Sentinel incidents for correlated activity

---

*Reference: AWS Security Documentation, Microsoft Learn Security, GCP Security Best Practices, CIS Benchmarks, NIST SP 800-207, CSA CCM v4.0, CISA SCuBA*
