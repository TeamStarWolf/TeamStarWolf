# Deception Technology Reference

> Comprehensive reference for honeypots, honeytokens, canary tokens, deception platforms,
> breadcrumb strategies, detection rules, and metrics. Maintained as part of the
> [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) cybersecurity reference library.

---

## Table of Contents

- [Deception Technology Fundamentals](#deception-technology-fundamentals)
- [Honeypots](#honeypots)
- [Honeytokens](#honeytokens)
- [Deception Platforms](#deception-platforms)
- [Deception Deployment Strategy](#deception-deployment-strategy)
- [Detection Rules for Deception](#detection-rules-for-deception)
- [Metrics](#metrics)
- [ATT&CK and Compliance Mapping](#attck-and-compliance-mapping)

---

## Deception Technology Fundamentals

### Why Deception Works

Deception technology exploits a fundamental asymmetry: defenders must protect every asset,
but attackers must avoid every trap. A single honeytoken access or decoy system interaction
generates a near-zero false-positive alert with full attacker context (IP, credential used,
time, lateral path).

**Attacker psychology factors:**
- Attackers perform reconnaissance and assume any accessible resource is legitimate
- Discovery tools (nmap, BloodHound, Mimikatz) touch decoys the same way they touch real assets
- Credential reuse is automatic — attackers try found passwords everywhere, including honeytokens
- Time pressure during intrusions discourages careful validation of every resource

**Alert fidelity:** Deception alerts are true positives by design. No tuning required.
Any interaction with a decoy or honeytoken is definitionally malicious because no legitimate
user should ever access it.

### Deception vs Traditional Detection

| Attribute | Traditional Detection (SIEM/EDR) | Deception Technology |
|---|---|---|
| Alert volume | High | Very low |
| False positive rate | 30–95% depending on tuning | Near 0% |
| Coverage | Known TTPs and signatures | Catches novel/unknown activity |
| Attacker requirement | Must trigger a known rule | Must perfectly avoid every decoy |
| Deployment complexity | High (tuning, log sources) | Low (place and forget) |
| Cost (enterprise) | High | Low–Medium |
| Lateral movement detection | Difficult, noisy | Early, high-fidelity |
| Insider threat detection | Limited | Effective (token access) |
| Cloud coverage | Requires agent/log config | Native (cloud honeytokens) |

### Deception Grid Design Principles

1. **Breadcrumbs lead to decoys** — plant fake credentials, DNS entries, SSH configs, and
   AWS profiles that point to decoy systems. Attackers following stolen breadcrumbs land on
   honeypots instead of real assets.
2. **Decoys blend with real assets** — match OS versions, service banners, and naming
   conventions to the production environment. Decoys named `CORP-DC03` in an environment
   with `CORP-DC01` and `CORP-DC02` are convincing.
3. **Comprehensive coverage** — every subnet, VLAN, and credential store should contain
   at least one decoy or honeytoken.
4. **Active decoys** — generate realistic background traffic (scheduled tasks, fake logins)
   so decoys appear live on the network.
5. **No legitimate access** — decoys and honeytokens must be excluded from monitoring
   whitelists, password managers, and automation. Any access is an alert.

### ATT&CK Techniques Deception Detects

| ATT&CK Tactic | Technique | Deception Method |
|---|---|---|
| Discovery | T1046 Network Service Scanning | Decoy services on unused ports |
| Discovery | T1083 File and Directory Discovery | Honeytoken files with audit triggers |
| Discovery | T1069 Permission Groups Discovery | Honey groups, honey AD objects |
| Discovery | T1018 Remote System Discovery | Decoy hostnames in DNS/hosts |
| Lateral Movement | T1021 Remote Services | Decoy SSH/RDP/SMB services |
| Lateral Movement | T1550.002 Pass the Hash | Honey NTLM hashes in memory |
| Credential Access | T1110 Brute Force | SSH/FTP honeypots with credential logging |
| Credential Access | T1555 Credentials from Password Stores | Honeytokens in password manager vaults |
| Credential Access | T1558.003 Kerberoasting | Honey SPNs with fake service accounts |
| Collection | T1039 Data from Network Shared Drive | Honeytoken files on shares |
| Collection | T1074 Data Staged | Decoy staging directories |
| Exfiltration | T1041 Exfiltration Over C2 | DNS canary tokens triggering on exfil |
| Persistence | T1098 Account Manipulation | Honey admin accounts (logon alert) |

---

## Honeypots

### Low-Interaction Honeypots

Emulate network services without running a full operating system. Lightweight, low risk,
easy to deploy at scale.

#### OpenCanary

Open-source multi-protocol honeypot from Thinkst.

```bash
pip install opencanary
opencanaryd --copyconfig   # creates /etc/opencanaryd/opencanary.conf
opencanaryd --start
```

Sample `opencanary.conf` (abbreviated):
```json
{
  "device.node_id": "opencanary-1",
  "logging.file": "/var/tmp/opencanary.log",
  "ssh.enabled": true,
  "ssh.port": 22,
  "http.enabled": true,
  "http.port": 80,
  "ftp.enabled": true,
  "ftp.port": 21,
  "smb.enabled": true,
  "telnet.enabled": true,
  "mysql.enabled": true,
  "mysql.port": 3306,
  "redis.enabled": true,
  "redis.port": 6379,
  "alerting.email.enabled": false,
  "alerting.slack.webhook": "https://hooks.slack.com/services/YOUR/WEBHOOK"
}
```

Supported alert channels: syslog, email, Slack webhook, HipChat, PagerDuty, MS Teams.

#### Honeyd

Virtual honeypot daemon — simulates thousands of virtual hosts with configurable
personalities.

```bash
apt-get install honeyd
honeyd -f /etc/honeyd.conf -i eth0 10.0.0.0/24
```

Sample config entry:
```
create template
set template personality "Windows XP Professional SP1"
set template default tcp action reset
add template tcp port 80 open
add template tcp port 445 open
bind 10.0.0.200 template
```

#### Cowrie (SSH/Telnet Honeypot)

Medium-interaction SSH and Telnet honeypot. Records all commands, credentials, and
uploaded files.

```bash
docker run -d -p 22:2222 --name cowrie cowrie/cowrie:latest
docker exec cowrie tail -f /home/cowrie/cowrie-git/var/log/cowrie/cowrie.json
```

Key log fields: `eventid`, `src_ip`, `username`, `password`, `input` (commands typed).
All sessions are fully recorded and can be replayed.

---

### Medium-Interaction Honeypots

#### Dionaea

Malware-capture honeypot. Emulates vulnerable services to lure and capture malware payloads.

- Supported protocols: SMB, SIP, HTTP, FTP, TFTP, MSSQL, MySQL, MongoDB
- Captures binaries, shellcode, and exploit attempts
- Submits samples to VirusTotal automatically

```bash
docker run -d -p 21:21 -p 42:42 -p 135:135 -p 443:443 -p 445:445 \
  -p 1433:1433 -p 1723:1723 -p 1883:1883 -p 3306:3306 \
  -v /opt/dionaea:/opt/dionaea dinotools/dionaea
```

#### Conpot (ICS/SCADA Honeypot)

Low-interaction ICS honeypot simulating industrial control system protocols.

- Protocols: Modbus, BACnet, IPMI, S7comm, EtherNet/IP, SNMP, HTTP
- Simulates PLCs, HMIs, and engineering workstations
- Designed for OT network deception

```bash
pip install conpot
conpot --template default
```

---

### High-Interaction Honeypots

Real operating systems and applications, fully monitored. Higher fidelity but higher risk.

**Design principles:**
- Place on isolated network segment (honeypot VLAN) with no route to production
- Full packet capture on ingress/egress (tcpdump or Zeek)
- Host-based behavioral monitoring (auditd, Sysmon, osquery)
- Read-only golden image with tripwire monitoring for filesystem changes
- Automated shutdown on certain trigger events (prevent pivoting)

**HoneyDrive** — Ubuntu-based Linux distro pre-loaded with 10+ honeypot packages:
Kippo, Dionaea, Honeyd, LaBrea, Thug, PhoneyC, Glastopf, and analysis tools.

**Legal considerations:**
- Entrapment: honeypots are legal in most jurisdictions; they do not induce crime,
  they merely observe attackers already committing it
- Employee monitoring: ensure acceptable use policy and employment agreements cover
  monitoring of all network resources
- Data protection: captured attacker data (IPs, credentials) may be subject to GDPR/CCPA
  depending on jurisdiction

---

### Distributed Honeypot Networks

#### T-Pot (All-in-One Honeypot Platform)

Docker-compose deployment with 20+ honeypot services and an ELK stack for analysis.

```bash
git clone https://github.com/telekom-security/tpotce
cd tpotce
./install.sh --type=T_MOBILE
```

Included honeypots: Cowrie, Dionaea, Honeytrap, Mailoney, Rdpy, Glutton, ADBHoney,
CitrixHoneypot, ElasticPot, Log4Pot, RedisHoneypot, and more.
Dashboard: Kibana at `https://<host>:64297`

#### Modern Honey Network (MHN)

Centralized honeypot management platform using hpfeeds protocol.

- Deploy sensor nodes from central server with one-line scripts
- Aggregates events from Snort, Cowrie, Dionaea, p0f, Kippo, Glastopf
- REST API and web dashboard for alert management

---

### Cloud Honeypots

#### AWS

```hcl
# Terraform: decoy S3 bucket with CloudTrail alert
resource "aws_s3_bucket" "honeytoken_bucket" {
  bucket = "corp-backup-archive-2019-do-not-delete"
  tags   = { Purpose = "Honeytoken" }
}

resource "aws_cloudwatch_metric_alarm" "honey_bucket_access" {
  alarm_name          = "honeytoken-s3-access"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "NumberOfObjects"
  namespace           = "AWS/S3"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

Other AWS decoy resources: EC2 instances in unused subnets with no legitimate traffic,
RDS instances with fake database names, unused IAM roles and access keys.

#### Azure

```bash
az storage account create --name corparchiveold2018 \
  --resource-group HoneypotRG --location eastus --sku Standard_LRS

az monitor diagnostic-settings create --name honeytoken-diag \
  --resource /subscriptions/{sub}/resourceGroups/HoneypotRG/providers/... \
  --logs '[{"category":"StorageRead","enabled":true}]' \
  --workspace /subscriptions/{sub}/resourceGroups/.../workspaces/sentinel-ws
```

Decoy Azure resources: Storage accounts, Key Vaults (alert on any secret access),
App Registrations with fake credentials, unused subscriptions.

---

## Honeytokens

### What Are Honeytokens

Honeytokens are fake digital artifacts — credentials, files, records, or tokens —
that have no legitimate use and generate an alert when touched. Unlike honeypots
(which are systems), honeytokens are individual data objects planted wherever
attackers are likely to look.

---

### CanaryTokens (canarytokens.org)

Free hosted service from Thinkst for generating and managing honeytokens.

**Token types:**

| Type | Use Case |
|---|---|
| URL / Web bug | Embed in documents, wikis, email drafts |
| DNS | Detect DNS-based data exfiltration |
| AWS credentials | Detect cloud credential theft |
| Azure login | Detect Azure credential use |
| Word / Excel document | Phone home when opened |
| PDF document | Detect document exfiltration |
| WireGuard config | Detect VPN credential theft |
| Custom image | Web bug in image format |
| Cloned website | Detect phishing clone setup |
| MySQL | Detect database dump + use |
| Slack API key | Detect Slack token theft |
| Fast redirect | Track link sharing |
| Executable (.exe) | Detect execution of fake tools |

**Creating a token via API:**
```bash
curl -X POST https://canarytokens.org/generate \
  -d "type=dns&email=soc@example.com&memo=AWS+config+honeytoken"
```

**Alert delivery:** HTTP callback, email, Slack/Teams/PagerDuty webhook.

**Deployment locations:**
- Password manager vault (fake entry named "AWS Production Root")
- Email drafts folder (fake credentials doc)
- Cloud storage (fake configuration files)
- Internal wikis (embed as invisible image)
- USB drives left in parking lots (Word doc with embedded token)
- Browser bookmarks (URL token)
- `/home/user/.bash_history` (URL token in a fake curl command)

---

### AWS Honeytoken Credentials

#### Manual Setup

```bash
# 1. Create IAM user with no permissions
aws iam create-user --user-name svc-backup-legacy

# 2. Generate access key (this IS the honeytoken)
aws iam create-access-key --user-name svc-backup-legacy

# 3. Deny all actions
aws iam put-user-policy --user-name svc-backup-legacy \
  --policy-name DenyAll \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# 4. Plant credentials in likely discovery locations:
#    ~/.aws/credentials on developer workstations
#    Hardcoded in a fake script on a shared drive
#    In a Confluence page accessible to most users
```

#### CloudTrail Alert via Lambda

```python
import boto3, json, os

def lambda_handler(event, context):
    HONEYTOKEN_USER = "svc-backup-legacy"
    SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK_URL"]

    for record in event.get("Records", []):
        body = json.loads(record["body"])
        detail = body.get("detail", {})
        user_identity = detail.get("userIdentity", {})

        if HONEYTOKEN_USER in str(user_identity):
            import urllib.request
            msg = {
                "text": (
                    ":rotating_light: *HONEYTOKEN ALERT*\n"
                    f"User: `{HONEYTOKEN_USER}`\n"
                    f"Action: `{detail.get('eventName')}`\n"
                    f"Source IP: `{detail.get('sourceIPAddress')}`\n"
                    f"Region: `{detail.get('awsRegion')}`\n"
                    f"Time: `{detail.get('eventTime')}`"
                )
            }
            req = urllib.request.Request(
                SLACK_WEBHOOK,
                data=json.dumps(msg).encode(),
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req)
```

#### SpaceSiren

Serverless canary token infrastructure on AWS. Deploys a full API + CloudFront +
Lambda stack for honeytoken management at scale.
GitHub: `https://github.com/spacesiren/spacesiren`

---

### Document Honeytokens

**Word/Excel with embedded URL (phone-home on open):**

Use CanaryTokens.org Word token, or manually embed a URL in a DDEAUTO field or
linked image that loads from a canary URL when the document is opened.

```python
import requests
resp = requests.post("https://canarytokens.org/generate", data={
    "type": "ms_word",
    "email": "soc@example.com",
    "memo": "HR salary spreadsheet honeytoken - SharePoint"
})
# Download and deploy the returned document
```

**Filename lures (effective names):**
- `2024_salary_bands.xlsx`
- `board_presentation_Q4_confidential.pdf`
- `vpn_credentials_emergency.txt`
- `aws_root_credentials_backup.txt`
- `ssh_keys_all_servers.zip`

---

### Database Honeytokens

**Fake high-value records in production database:**

```sql
-- MySQL: insert honeytoken credit card record
INSERT INTO payment_cards (card_number, cvv, expiry, cardholder, is_honeytoken)
VALUES ('4111111111111111', '999', '2099-12', 'CANARY TOKEN DO NOT USE', 1);

-- Create audit trigger on honeytoken access
DELIMITER //
CREATE TRIGGER honeytoken_access_alert
AFTER SELECT ON payment_cards
FOR EACH ROW
BEGIN
  IF OLD.is_honeytoken = 1 THEN
    INSERT INTO security_alerts (alert_time, alert_type, detail)
    VALUES (NOW(), 'HONEYTOKEN_ACCESS',
            CONCAT('Card: ', OLD.card_number, ' User: ', USER()));
  END IF;
END//
DELIMITER ;
```

**Fake admin credentials table:**
```sql
CREATE TABLE admin_credentials_backup (
  username VARCHAR(64),
  password_hash VARCHAR(256),
  last_updated DATETIME
);
INSERT INTO admin_credentials_backup VALUES
  ('admin', '$2y$10$fakehashforcanarytokendetection', NOW()),
  ('root', '$2y$10$anotherfakehashfordetection', NOW());
-- Audit trigger alerts on any SELECT from this table
```

---

### File System Honeytokens

#### Windows — Object Access Auditing

```powershell
# Enable object access auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

# Set SACL on honeytoken file (alerts on read)
$file = "C:\Shares\Finance\passwords_master.xlsx"
$acl = Get-Acl $file
$audit = New-Object System.Security.AccessControl.FileSystemAuditRule(
  "Everyone", "Read", "None", "None", "Success"
)
$acl.AddAuditRule($audit)
Set-Acl $file $acl

# Event ID 4663 fires when the file is read
# Splunk: index=wineventlog EventCode=4663 ObjectName="*passwords_master*"
```

#### Linux — inotifywait and auditd

```bash
# inotifywait monitoring
inotifywait -m -e access,open /opt/secrets/admin_credentials.txt |
while read path action file; do
  echo "HONEYTOKEN ACCESSED: $path$file ($action) at $(date)" | \
    mail -s "ALERT: Honeytoken Access" soc@example.com
done

# auditd rule for honeytoken file
auditctl -w /home/shared/ssh_private_keys.tar.gz -p r -k honeytoken_access
# Search: ausearch -k honeytoken_access
```

---

### Active Directory Honeytokens

#### Honey Users (Accounts That Must Never Authenticate)

```powershell
New-ADUser -Name "svc-legacy-backup" `
  -SamAccountName "svc-legacy-backup" `
  -UserPrincipalName "svc-legacy-backup@corp.local" `
  -AccountPassword (ConvertTo-SecureString "Honeypot!2024" -AsPlainText -Force) `
  -Enabled $true `
  -Description "Legacy backup service account - do not use"

# Any logon = Event ID 4768 (Kerberos TGT) or 4624 (NTLM)
# Alert rule: any auth event for this account = P1 incident
```

**Detection in Splunk:**
```splunk
index=wineventlog (EventCode=4768 OR EventCode=4769 OR EventCode=4624)
  Account_Name="svc-legacy-backup"
| table _time, host, Account_Name, Client_Address, Service_Name, Failure_Code
| sort -_time
```

#### Honey Service Accounts (Kerberoasting Detection)

```powershell
# Add SPN to honey account — bait for Kerberoasting
Set-ADUser "svc-legacy-backup" `
  -ServicePrincipalNames @{Add="HTTP/legacy-intranet.corp.local"}

# Event ID 4769 with ticket encryption type 0x17 (RC4) = Kerberoast attempt
# Any 4769 for this SPN = immediate alert
```

#### Honey Group Memberships

```powershell
# Create honey group that should never be queried by non-admins
New-ADGroup -Name "Domain Admins Backup Shadow" -GroupScope Global -GroupCategory Security
Add-ADGroupMember -Identity "Domain Admins Backup Shadow" -Members "svc-legacy-backup"

# Alert on LDAP queries for this group (Event ID 4662, Object Type = group)
```

---

## Deception Platforms

### Commercial Platforms Comparison

| Platform | Deployment | Token Types | SIEM Integration | ATT&CK Coverage | Tier |
|---|---|---|---|---|---|
| SentinelOne Singularity Hologram (formerly Attivo) | On-prem / Cloud | AD, file, network, cloud, endpoint | Splunk, Sentinel, QRadar | TA0007–TA0008 | Enterprise |
| Palo Alto Cortex (formerly Illusive Networks) | SaaS | AD objects, credentials, network | Cortex XSOAR native | Heavy AD/identity focus | Enterprise |
| TrapX DeceptionGrid | On-prem appliance | Network decoys, endpoint, OT/ICS | Splunk, ArcSight | Broad OT coverage | Enterprise |
| Acalvio ShadowPlex | SaaS / hybrid | AD, cloud, network, file, OT | Splunk, Sentinel, XSOAR | High | Enterprise |
| Zscaler Deception | SaaS (ZIA add-on) | Network, AD, credential | Zscaler ecosystem | Medium | Mid-market |

### When to Use Each

| Scenario | Recommended |
|---|---|
| Budget constrained, starting out | CanaryTokens.org (free) |
| Small team, physical office | Thinkst Canary devices |
| Enterprise, AD-heavy environment | SentinelOne Hologram or Acalvio ShadowPlex |
| Cloud-native organization | AWS/Azure native honeytokens + CanaryTokens |
| OT/ICS environment | TrapX DeceptionGrid |
| Already in Palo Alto ecosystem | Cortex Deception |

### Thinkst Canary Devices

Physical or VM hardware appliances that auto-discover the environment and mimic local
services (file shares, printers, SSH servers, Active Directory).

- **Form factors:** Physical device (PoE), AWS AMI, VMware OVA, Azure VM image, GCP image
- **Auto-configuration:** Listens passively, adopts environment naming conventions
- **Alert delivery:** Email, Slack, Teams, PagerDuty, webhook, syslog
- **Whitelisting:** IP-based and token-based to suppress scanner noise
- **Management:** Cloud console at `canary.tools`; API for bulk management

---

## Deception Deployment Strategy

### Breadcrumb Strategy

Breadcrumbs are fake artifacts planted in locations attackers commonly search,
designed to guide them to decoys rather than real assets.

**Browser history breadcrumbs:**
Plant a fake internal URL in browser history that resolves via a DNS canary token.
Attacker dumping browser history finds `http://vpn-admin.corp.local:8443`;
the DNS canary for `vpn-admin.corp.local` fires on lookup.

**SSH config breadcrumbs:**
```bash
cat >> ~/.ssh/config << 'EOF'
Host prod-bastion
  HostName prod-bastion-01.internal.corp.local
  User deploy
  IdentityFile ~/.ssh/id_prod_deploy
EOF
# id_prod_deploy does not exist — canary DNS fires when attacker resolves hostname
```

**AWS credentials breadcrumbs:**
```ini
# ~/.aws/credentials — plant honeytoken key alongside real profiles
# (Replace placeholders with real key IDs generated for your honeytoken IAM user)
[default]
aws_access_key_id = <REAL_KEY_ID>
aws_secret_access_key = <REAL_SECRET_KEY>

[legacy-prod]
aws_access_key_id = <HONEYTOKEN_KEY_ID>
aws_secret_access_key = <HONEYTOKEN_SECRET_KEY>
```

**Environment variable breadcrumbs:**
```bash
# /etc/environment or ~/.bashrc
# Use real honeytokens generated via canarytokens.org or your deception platform.
# Variable names that are highly attractive to attackers:
export STRIPE_API_KEY="<honeytoken-value-from-provider>"
export INTERNAL_API_TOKEN="<jwt-honeytoken-value>"
export GITHUB_TOKEN="<honeytoken-pat-value>"
export DATABASE_URL="<honeytoken-dsn-value>"
```

**Hosts file breadcrumbs:**
```
# /etc/hosts — fake server addresses pointing to honeypots
10.0.100.50  password-vault.internal.corp.local
10.0.100.51  secrets-server.internal.corp.local
```

---

### Decoy Density

- **Recommended ratio:** 1 decoy per 10 real assets (minimum)
- **Subnet coverage:** Every /24 should have at least 2 decoy IPs
- **Credential stores:** Every password manager, browser, and config file should have
  at least one honeytoken credential
- **Active Directory:** Minimum 3–5 honey users and 2–3 honey SPNs per domain
- **File shares:** Honeytoken files in every major share root

---

### Decoy Realism

- Match OS fingerprint to real environment (Windows Server 2022 if prod is 2022)
- Match service banner versions exactly (`Apache/2.4.57` not generic)
- Use realistic hostnames (`CORP-FS04`, `PROD-SQL-02`)
- Assign IP addresses that follow the same scheme as real assets
- Simulate background traffic (scheduled tasks generating fake SMB activity)
- Include realistic open ports matching environment baseline

---

### Alert Pipeline

Deception events should bypass normal SOC triage queues and escalate immediately:

```
Deception Alert Fired
  -> SIEM ingestion (< 30 seconds)
  -> Auto-create P1 incident in ticketing system
  -> Page on-call analyst (PagerDuty / OpsGenie)
  -> Capture full context: source IP, credential, path, timestamp
  -> Preserve forensic snapshot (VM snapshot, PCAP)
  -> Begin IR playbook
```

No false positive tuning is needed. Every alert from a deception system is a true positive.

---

### Threat Hunting with Deception

**Use honeytoken access as a hunt pivot:**

1. Honeytoken fires for `svc-legacy-backup` at 02:17 UTC from `10.1.45.22`
2. Hunt: what other activity came from `10.1.45.22` in the 4 hours prior?
3. Hunt: what accounts authenticated FROM the system at `10.1.45.22`?
4. Hunt: what systems did `10.1.45.22` connect TO after the honeytoken access?
5. Hunt: are there other honeytoken or decoy interactions from adjacent IPs?

**Lateral movement detection via decoy-to-decoy hops:**
If an attacker moves from Decoy A to Decoy B, you have a full map of their lateral
movement path with timestamps — before they reach any real asset.

---

## Detection Rules for Deception

### Splunk SPL — AWS Honeytoken CloudTrail Alert

```splunk
index=aws_cloudtrail sourcetype=aws:cloudtrail
  userIdentity.arn="arn:aws:iam::123456789012:user/svc-backup-legacy"
| eval alert_type="HONEYTOKEN_AWS_CREDENTIAL_USE"
| table _time, userIdentity.arn, eventName, sourceIPAddress, awsRegion, requestParameters
| sort -_time
```

### KQL — Honeytoken User Logon (Microsoft Sentinel)

```kql
SecurityEvent
| where EventID in (4768, 4769, 4624, 4625)
| where TargetUserName == "svc-legacy-backup"
| project TimeGenerated, EventID, TargetUserName, IpAddress, WorkstationName, LogonType
| order by TimeGenerated desc
```

### KQL — Azure Honeytoken Key Vault Access

```kql
AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName contains "SecretGet"
| where Resource == "corp-archive-vault-honeytoken"
| project TimeGenerated, CallerIPAddress, identity_claim_oid_g, OperationName
| order by TimeGenerated desc
```

### SIEM Correlation Rule (Sigma Format)

```yaml
title: Deception System Access - Any Protocol
status: production
description: Any connection to a known decoy system IP or hostname
logsource:
  category: network_connection
detection:
  selection_ip:
    DestinationIp|contains:
      - '10.0.100.50'
      - '10.0.100.51'
      - '10.0.100.52'
  selection_host:
    DestinationHostname|contains:
      - 'legacy-backup'
      - 'honeynet'
  condition: selection_ip or selection_host
falsepositives:
  - None (deception assets should have zero legitimate traffic)
level: critical
tags:
  - attack.discovery
  - attack.lateral_movement
```

### Slack Alert Integration (Python)

```python
import requests, json

def send_deception_alert(token_type: str, source_ip: str, detail: str):
    webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
    payload = {
        "text": ":rotating_light: *DECEPTION ALERT -- HONEYTOKEN TRIGGERED*",
        "attachments": [{
            "color": "#FF0000",
            "fields": [
                {"title": "Token Type", "value": token_type, "short": True},
                {"title": "Source IP", "value": source_ip, "short": True},
                {"title": "Detail", "value": detail, "short": False},
            ]
        }]
    }
    requests.post(webhook_url, data=json.dumps(payload),
                  headers={"Content-Type": "application/json"})
```

### PagerDuty API Trigger

```python
import requests, json, os

def page_oncall(summary: str, severity: str = "critical"):
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": os.environ["PAGERDUTY_INTEGRATION_KEY"],
        "event_action": "trigger",
        "payload": {
            "summary": f"[DECEPTION] {summary}",
            "severity": severity,
            "source": "deception-platform",
            "custom_details": {
                "auto_escalate": True,
                "false_positive_rate": "~0%"
            }
        }
    }
    resp = requests.post(url, json=payload)
    return resp.status_code, resp.json()
```

---

## Metrics

### Coverage Metrics

| Metric | Target | Calculation |
|---|---|---|
| Subnet decoy coverage | > 90% of /24s | Subnets with decoy / total subnets |
| Credential store coverage | 100% | Stores with honeytoken / total stores |
| File share coverage | > 80% of share roots | Shares with honeyfile / total share roots |
| AD honey account ratio | Min 5 per domain | Count of honey users in AD |
| Cloud honeytoken coverage | 100% of AWS accounts | Accounts with honeytoken IAM key |

### Alert Quality

By design, deception alerts have a ~100% true positive rate. Track:

- **Total deception alerts per month** — increasing trend indicates attacker activity
- **Alerts by token type** — which breadcrumbs are most effective?
- **Time-to-alert** — deception event timestamp to SOC notification (target: < 2 minutes)
- **False positive count** — should be 0; any FP indicates misconfiguration
  (legitimate process touching a decoy)

### Dwell Time Reduction

Deception technology is the most effective dwell time reduction control available.
Industry benchmark: median attacker dwell time without deception is 16–21 days.
With mature deception deployment, lateral movement is typically detected within hours.

| Scenario | Without Deception | With Deception |
|---|---|---|
| Credential theft detection | 16+ days avg | Hours (honeytoken fired) |
| Lateral movement detection | Days to weeks | Minutes to hours (decoy hop) |
| Kerberoasting detection | Often never | Immediate (honey SPN) |
| Data staging detection | Often never | Immediate (honeyfile access) |

### Mean Time to Detect (MTTD) Improvement

Track MTTD separately for deception-detected incidents vs. traditional detection:

```splunk
index=incident_management source=ticketing
  detection_method IN ("honeytoken","honeypot","deception_platform")
| eval dwell_hours = (detection_time - compromise_time) / 3600
| stats avg(dwell_hours) as avg_dwell, min(dwell_hours) as min_dwell,
        max(dwell_hours) as max_dwell by detection_method
```

---

## ATT&CK and Compliance Mapping

### MITRE ATT&CK Techniques Detected by Deception

| ATT&CK ID | Name | Deception Control |
|---|---|---|
| T1046 | Network Service Discovery | Decoy services on common ports |
| T1083 | File and Directory Discovery | Honeytoken files with file auditing |
| T1069 | Permission Groups Discovery | Honey AD groups |
| T1018 | Remote System Discovery | Decoy DNS/hosts entries |
| T1021.001 | Remote Desktop Protocol | Decoy RDP server |
| T1021.002 | SMB/Windows Admin Shares | Decoy SMB share with honeyfiles |
| T1021.004 | SSH | Cowrie SSH honeypot |
| T1110 | Brute Force | SSH/FTP honeypot with credential logging |
| T1555 | Credentials from Password Stores | Honeytokens in password managers |
| T1558.003 | Kerberoasting | Honey SPNs |
| T1539 | Steal Web Session Cookie | CanaryToken in session storage |
| T1039 | Data from Network Shared Drive | Honeyfiles on SMB shares |
| T1074 | Data Staged | Decoy staging directories |
| T1041 | Exfiltration Over C2 Channel | DNS canary tokens |
| T1098 | Account Manipulation | Honey admin accounts |
| T1550.002 | Pass the Hash | Honey NTLM hashes |

### NIST SP 800-53 Control Mapping

| Control Family | Control | Deception Mapping |
|---|---|---|
| DE — Detect | DE-2 | Honeypots and honeytokens as detection sensors |
| DE — Detect | DE-3 | Continuous deception monitoring |
| SI — System Integrity | SI-3 | Honeytoken-based malware behavior detection |
| IR — Incident Response | IR-4 | Deception alerts trigger IR procedures |
| AU — Audit | AU-12 | Audit logging on all honeytoken accesses |
| SC — System and Communications | SC-26 | Honeypots as deceptive components |

> **NIST SP 800-53 SC-26 (Decoys):** "Employ a diverse set of information technologies and
> practices to detect, identify, and analyze attacker tactics, techniques, and procedures."
> Deception technology directly satisfies SC-26.

---

*Part of the [TeamStarWolf](https://github.com/TeamStarWolf/TeamStarWolf) cybersecurity reference library.*
