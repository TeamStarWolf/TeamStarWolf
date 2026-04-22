# Cloud Security Benchmark Reference

CIS Benchmarks and hardening controls for AWS, Azure, and GCP — with specific checks, automated remediation, and detection queries. Complements the [Cloud Attack Reference](CLOUD_ATTACK_REFERENCE.md) with a defensive posture focus.

---

## AWS CIS Benchmark (v3.0)

### Identity and Access Management

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 1.1 | Root account MFA enabled | Critical | `aws iam get-account-summary` → `AccountMFAEnabled` must be 1 |
| 1.2 | No root account access keys | Critical | `aws iam get-account-summary` → `AccountAccessKeysPresent` must be 0 |
| 1.3 | MFA enabled for all IAM users with console access | High | `aws iam list-users` + `aws iam list-mfa-devices --user-name USERNAME` |
| 1.4 | No access keys for root | Critical | Console: Security Credentials → delete access keys |
| 1.5 | IAM password policy: min length 14 | Medium | `aws iam update-account-password-policy --minimum-password-length 14` |
| 1.6 | IAM password policy: prevent reuse (24) | Medium | `aws iam update-account-password-policy --password-reuse-prevention 24` |
| 1.7 | MFA enabled for all IAM users | High | Enforce via IAM policy requiring MFA for all API calls |
| 1.8 | No unused credentials older than 45 days | Medium | `aws iam generate-credential-report` → review LastUsed |
| 1.9 | Credential unused in 45 days: disable | Medium | `aws iam update-access-key --access-key-id KEY --status Inactive` |
| 1.10 | MFA on root account | Critical | Console only — enable hardware or virtual MFA |
| 1.11 | No inline policies attached to users | Low | `aws iam list-user-policies` — move to managed policies |
| 1.12 | IAM Access Analyzer enabled | Medium | `aws accessanalyzer create-analyzer --analyzer-name AccessAnalyzer --type ACCOUNT` |

**Automated IAM Check Script**:
```bash
# Check for users without MFA (console access)
aws iam generate-credential-report --output text > /dev/null
sleep 5
aws iam get-credential-report --output text --query 'Content' | base64 -d | \
  awk -F',' 'NR>1 && $4=="true" && $8=="false" {print $1, "NO MFA"}' 

# List access keys older than 90 days
aws iam list-users --query 'Users[*].UserName' --output text | tr '\t' '\n' | while read user; do
  aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?Status=='Active'].[UserName,AccessKeyId,CreateDate]" --output text
done
```

### Logging and Monitoring

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 2.1.1 | S3 server access logging enabled | Medium | `aws s3api put-bucket-logging` |
| 2.1.2 | S3 Block Public Access (account level) | High | `aws s3control put-public-access-block --account-id ACCOUNT_ID --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true` |
| 2.2 | CloudTrail enabled in all regions | Critical | `aws cloudtrail create-trail --name multi-region-trail --s3-bucket-name BUCKET --is-multi-region-trail` |
| 2.3 | CloudTrail log file validation | High | `aws cloudtrail update-trail --name TRAIL --enable-log-file-validation` |
| 2.4 | CloudTrail logs encrypted with KMS | Medium | `aws cloudtrail update-trail --name TRAIL --kms-key-id KMS_KEY_ARN` |
| 2.5 | AWS Config enabled in all regions | High | `aws configservice put-configuration-recorder` |
| 2.6 | CloudTrail S3 bucket not publicly accessible | Critical | Check bucket ACL and policy |
| 2.7 | CloudWatch alarms for root account usage | High | Create metric filter + alarm on CloudTrail log group |

**CloudWatch Alarm for Root Usage**:
```bash
# Create metric filter
aws logs put-metric-filter \
  --log-group-name CloudTrail-Log-Group \
  --filter-name RootAccountUsage \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations metricName=RootAccountEventCount,metricNamespace=CISBenchmark,metricValue=1

# Create alarm
aws cloudwatch put-metric-alarm \
  --alarm-name RootAccountUsage \
  --metric-name RootAccountEventCount \
  --namespace CISBenchmark \
  --statistic Sum --period 300 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions SNS_TOPIC_ARN
```

### Networking

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 3.1 | No security group allows 0.0.0.0/0 to port 22 | Critical | Remove inbound rule or restrict to management IP |
| 3.2 | No security group allows 0.0.0.0/0 to port 3389 | Critical | Remove RDP from internet-facing SGs |
| 3.3 | Default security group restricts all traffic | Medium | Remove all inbound/outbound from default SG |
| 3.4 | VPC flow logs enabled | High | `aws ec2 create-flow-logs --resource-type VPC --resource-ids VPC_ID --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name VPCFlowLogs --deliver-logs-permission-arn ROLE_ARN` |
| 3.5 | No routing from VPC to internet without NAT | Medium | Review route tables; 0.0.0.0/0 to IGW = direct internet access |
| 3.6 | Restrict access to SSH/RDP to bastion only | High | Network ACL + Security Group layering |

```bash
# Find all SGs with port 22 open to the internet
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=22 Name=ip-permission.to-port,Values=22 Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output table

# Find all SGs with port 3389 (RDP) open to internet
aws ec2 describe-security-groups \
  --filters Name=ip-permission.from-port,Values=3389 Name=ip-permission.to-port,Values=3389 Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[*].[GroupId,GroupName]' \
  --output table
```

---

## Azure CIS Benchmark (v2.0)

### Identity and Access (Entra ID / Azure AD)

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 1.1.1 | MFA required for all users | Critical | Conditional Access Policy requiring MFA for all users |
| 1.1.2 | MFA required for privileged users | Critical | Enforce via PIM + Conditional Access |
| 1.1.3 | No guest users with privileged roles | High | `az ad user list --filter "userType eq 'Guest'"` → check role assignments |
| 1.1.4 | Legacy authentication blocked | High | Conditional Access: block legacy auth protocols |
| 1.2.1 | Global Admin limited to < 5 users | High | `az role assignment list --role "Global Administrator" --all` |
| 1.2.2 | PIM used for privileged roles | High | Azure PIM — just-in-time activation for GA, Owner, Contributor |
| 1.2.3 | Security defaults or Conditional Access enabled | Critical | Security defaults provide baseline; CA provides more control |
| 1.3.1 | Password hash sync or PTA (not ADFS only) | Medium | Enables leaked credential detection |
| 1.3.2 | SSPR registration required | Medium | Self-Service Password Reset reduces help desk load |

**Azure Privileged Role Check**:
```powershell
# Find all Global Administrators
Connect-AzureAD
Get-AzureADDirectoryRole | Where-Object {$_.DisplayName -eq "Global Administrator"} | ForEach-Object {
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId
} | Select DisplayName, UserPrincipalName, UserType

# Check for guest users with privileged roles
Get-AzureADDirectoryRole | ForEach-Object {
    $role = $_
    Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId | 
    Where-Object {$_.UserType -eq "Guest"} | 
    Select @{N="Role";E={$role.DisplayName}}, DisplayName, UserPrincipalName
}
```

### Security Center / Defender for Cloud

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 2.1 | Microsoft Defender for Cloud Standard tier | High | Enable per-subscription in Defender for Cloud |
| 2.1.1 | Defender for Servers Plan 2 | High | `az security pricing create --name VirtualMachines --tier Standard` |
| 2.1.2 | Defender for Storage | High | Enable to detect malicious blob access and malware upload |
| 2.1.3 | Defender for SQL | High | Enable for Azure SQL and SQL on VMs |
| 2.1.4 | Defender for Containers | High | Enable for AKS and ACR scanning |
| 2.1.5 | Auto-provisioning of agents | Medium | Enable MMA/AMA auto-provisioning in Defender for Cloud |
| 2.1.6 | Email notifications for high severity alerts | Medium | Security Center Settings → Email notifications |
| 2.1.7 | Microsoft Defender for Cloud Apps connected | Medium | MCAS integration for anomaly detection |

### Storage Accounts

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 3.1 | Secure transfer required (HTTPS only) | High | `az storage account update --https-only true` |
| 3.2 | Public blob access disabled | Critical | `az storage account update --allow-blob-public-access false` |
| 3.3 | Storage account keys rotated annually | Medium | `az storage account keys renew --account-name NAME --key primary` |
| 3.4 | Storage logging enabled | Medium | Enable diagnostic logs for blob/table/queue |
| 3.5 | Shared Access Signature expiry < 1 hour | Medium | Policy in SAS token generation |
| 3.6 | Blob soft delete enabled | Medium | `az storage blob service-properties delete-policy update --enable true --days-retained 30` |
| 3.7 | Private endpoints for storage | High | Remove public network access; use Private Endpoints |

```bash
# Find storage accounts with public blob access
az storage account list --query "[?allowBlobPublicAccess==true].[name,resourceGroup,location]" -o table

# Find storage accounts without HTTPS-only
az storage account list --query "[?enableHttpsTrafficOnly==false].[name,resourceGroup]" -o table
```

### Key Vault

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 8.1 | Key Vault recoverable (soft delete + purge protection) | High | `az keyvault update --name VAULT --enable-soft-delete true --enable-purge-protection true` |
| 8.2 | Key expiry date set | Medium | Set expiry on all keys |
| 8.3 | Secret expiry date set | Medium | Set expiry on all secrets |
| 8.4 | Certificate auto-rotation | High | Configure certificate contacts and auto-renewal |
| 8.5 | Key Vault firewall and virtual network | High | Restrict access to specific VNets/IPs |
| 8.6 | Key Vault logging enabled | High | Enable Diagnostic Settings → send to Log Analytics |

---

## GCP CIS Benchmark (v3.0)

### IAM and Organization

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 1.1 | No legacy basic roles (Owner/Editor/Viewer) | High | Replace with fine-grained IAM roles |
| 1.2 | No service accounts with admin privileges | Critical | `gcloud iam service-accounts list` → review roles |
| 1.3 | No user-managed service account keys | High | Use Workload Identity Federation instead |
| 1.4 | Organization policy: restrict domain login | High | `constraints/iam.allowedPolicyMemberDomains` |
| 1.5 | Separation of duties: no user owns and manages SAs | Medium | Review SA key creators vs users |
| 1.6 | Cloud KMS keys rotated within 90 days | High | `gcloud kms keys describe KEY --rotation-period=90d` |
| 1.7 | Pub/Sub subscriptions use push endpoints with HTTPS | Low | Use authenticated push endpoints |
| 1.8 | Secret Manager used for secrets (not env vars) | High | Audit Cloud Run/Functions for hardcoded secrets in env |

**GCP IAM Policy Review**:
```bash
# List all primitive roles assigned to any user
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format="table(bindings.role,bindings.members)" \
  --filter="bindings.role:(roles/owner OR roles/editor OR roles/viewer)"

# Find service accounts with service account token creator role
gcloud projects get-iam-policy PROJECT_ID \
  --flatten="bindings[].members" \
  --format="table(bindings.role,bindings.members)" \
  --filter="bindings.role:roles/iam.serviceAccountTokenCreator"
```

### Logging and Monitoring

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 2.1 | Cloud Audit Logs: admin activity enabled | Critical | Cannot be disabled — verify data access logs enabled |
| 2.2 | Cloud Audit Logs: data access for all services | High | `gcloud logging sinks list` + enable data access logs |
| 2.3 | Log sinks configured for all log entries | Medium | Create org-level sink to Cloud Storage/BigQuery |
| 2.4 | Log metric + alert for project ownership changes | High | Create log-based metric + alerting policy |
| 2.5 | Log metric + alert for audit config changes | High | Monitor `SetIamPolicy` changes to audit log config |
| 2.6 | Log metric + alert for custom role changes | Medium | Alert on `CreateRole`, `UpdateRole`, `DeleteRole` |

**GCP Log Metric + Alert for Admin Changes**:
```bash
# Create log metric for IAM changes
gcloud logging metrics create iam-policy-changes \
  --description="IAM Policy Changes" \
  --log-filter='protoPayload.methodName="SetIamPolicy" OR protoPayload.methodName="google.iam.v1.IAMPolicy.SetIamPolicy"'

# Create alerting policy (requires Monitoring API)
gcloud alpha monitoring policies create --policy-from-file=alerting_policy.json
```

### Compute Engine

| CIS Control | Check | Severity | Remediation |
|---|---|---|---|
| 4.1 | Project-wide SSH keys not used | High | Use instance-level keys or OS Login instead |
| 4.2 | Instances not open to internet on port 22/3389 | Critical | Firewall rule audit; use IAP for SSH/RDP instead |
| 4.3 | OS Login enabled | Medium | `gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE` |
| 4.4 | Block project-wide SSH keys on instances | Medium | `--metadata block-project-ssh-keys=TRUE` |
| 4.5 | Shielded VM enabled (Secure Boot, vTPM, Integrity Monitoring) | Medium | `--shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring` |
| 4.6 | Compute default service account not used | High | Create custom SA with minimum permissions per workload |
| 4.7 | VM serial port access disabled | Low | `gcloud compute instances add-metadata INSTANCE --metadata serial-port-enable=false` |
| 4.8 | Disk encryption with CMEK | Medium | Use customer-managed encryption keys |

```bash
# Find instances with default SA
gcloud compute instances list --format="table(name,serviceAccounts[].email)" \
  --filter="serviceAccounts.email:compute@developer.gserviceaccount.com"

# Find firewall rules allowing SSH from internet
gcloud compute firewall-rules list \
  --filter="allowed.ports:22 AND sourceRanges:0.0.0.0/0" \
  --format="table(name,network,allowed,sourceRanges)"
```

---

## CSPM Tool Reference

Cloud Security Posture Management tools continuously check cloud environments against benchmarks.

| Tool | Cloud Support | Type | Key Features |
|---|---|---|---|
| Wiz | AWS, Azure, GCP, OCI, K8s | Commercial (agentless) | Full attack path visualization, CIEM, secret detection, IaC scanning |
| Orca Security | AWS, Azure, GCP | Commercial (agentless) | SideScanning, risk prioritization, shift-left |
| Prisma Cloud | AWS, Azure, GCP, OCI | Commercial | Comprehensive: CSPM + CWPP + CIEM + CNAPP |
| Lacework | AWS, Azure, GCP | Commercial | Behavioral anomaly detection, polygraph visualization |
| Aqua Security | AWS, Azure, GCP | Commercial | CNAPP focused on containers and Kubernetes |
| Prowler | AWS | Open-source | CIS Benchmark checks; 900+ controls; CLI and web |
| ScoutSuite | AWS, Azure, GCP | Open-source | Multi-cloud security audit; Python-based |
| CloudSploit | AWS, Azure, GCP | Open-source (Aqua OSS) | Automated vulnerability scanning |
| Steampipe | AWS, Azure, GCP | Open-source | SQL queries over cloud APIs; CIS Benchmark mods |

**Prowler Example**:
```bash
# Install
pip install prowler

# Run CIS Benchmark for AWS
prowler aws --compliance cis_2.0_aws

# Run specific check
prowler aws --check iam_root_mfa_enabled

# Output to HTML
prowler aws --output-formats html --output-directory /tmp/prowler-output/
```

**ScoutSuite Example**:
```bash
# Install
pip install scoutsuite

# Scan AWS
scout aws --report-dir /tmp/scoutsuite-report/

# Scan Azure
scout azure --cli --report-dir /tmp/scoutsuite-report/

# Scan GCP
scout gcp --user-account --report-dir /tmp/scoutsuite-report/
# Report opens in browser at index.html
```

---

## Cloud Security Quickstart Checklist

### AWS
- [ ] Root account MFA enabled; no root access keys
- [ ] CloudTrail enabled multi-region with log validation
- [ ] GuardDuty enabled in all regions
- [ ] Security Hub enabled with CIS Benchmark standard
- [ ] Config enabled with required rules
- [ ] No SGs with 0.0.0.0/0 to port 22 or 3389
- [ ] S3 Block Public Access at account level
- [ ] VPC Flow Logs enabled
- [ ] IMDSv2 required on all EC2 instances
- [ ] No unused IAM access keys > 90 days

### Azure
- [ ] MFA required via Conditional Access (not Security Defaults alone)
- [ ] Legacy authentication blocked
- [ ] < 5 Global Administrators
- [ ] PIM enabled for privileged roles
- [ ] Defender for Cloud Standard enabled
- [ ] No public blob access on storage accounts
- [ ] Key Vault soft delete and purge protection enabled
- [ ] Diagnostic settings logging to Log Analytics
- [ ] No public network access on PaaS services (use Private Endpoints)
- [ ] Azure Policy assigned for governance

### GCP
- [ ] No primitive roles (Owner/Editor) assigned to users
- [ ] Cloud Audit logging enabled (data access)
- [ ] OS Login enabled project-wide
- [ ] No SSH/RDP firewall rules open to 0.0.0.0/0
- [ ] Shielded VMs enabled
- [ ] Org-level log sink configured
- [ ] VPC Service Controls for sensitive APIs
- [ ] Binary Authorization for GKE
- [ ] No user-managed service account keys

## Related Resources
- [Cloud Attack Reference](CLOUD_ATTACK_REFERENCE.md) — Offensive techniques and escalation paths
- [Cloud Security Discipline](disciplines/cloud-security.md) — Learning path and tooling
- [FRAMEWORKS.md](FRAMEWORKS.md) — CSA CCM and ISO 27017 for cloud
- [Controls Mapping](CONTROLS_MAPPING.md) — Wiz, Orca, Lacework → NIST 800-53 controls

---
