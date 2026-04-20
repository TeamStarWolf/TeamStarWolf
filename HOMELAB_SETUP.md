# Home Lab Setup Guide

A practical guide to building a cybersecurity home lab for hands-on learning across penetration testing, detection engineering, malware analysis, incident response, and Active Directory security.

---

## 1. Hardware Options

### Budget Tier ($0-$300)
Repurposed desktops and old laptops are the cheapest starting point. A machine with a quad-core CPU and 8-16 GB RAM can run 2-4 VMs simultaneously.

| Option | Notes |
|---|---|
| Repurposed desktop/tower | Core i5/i7, upgrade RAM to 16 GB, add an SSD |
| Old laptop | Useful for a dedicated Kali machine or network sensor |
| Raspberry Pi 4 (8 GB) | Great for network tap, Pi-hole DNS sinkhole, or lightweight Zeek sensor |
| Old workstation (eBay) | Dell OptiPlex / HP EliteDesk -- often under $100 |

### Mid Tier ($300-$800)
Sufficient for a full VLAN-segmented lab with an AD domain, attack machine, and a basic SIEM.

| Option | Notes |
|---|---|
| Intel NUC / mini PC | Compact, low power, supports 32-64 GB RAM |
| Used HP ProLiant DL360/380 G8/G9 | ECC RAM, IPMI/iLO remote management, dual PSU |
| Used Dell PowerEdge R620/R630 | Similar to HP; check noise levels before buying |
| 16-32 GB RAM | Minimum for running 6-8 VMs comfortably |
| NVMe or SSD storage | Faster VM snapshots and disk I/O |

### Enthusiast Tier ($800+)
Dedicated lab server with enough resources to run a full enterprise simulation.

| Option | Notes |
|---|---|
| Dual-socket server (E5-2600 v3/v4) | 128-256 GB RAM possible; very loud/power-hungry |
| 64 GB+ RAM | Run 15+ VMs simultaneously |
| SSD storage array (ZFS/RAID) | Fast snapshots, data integrity |
| Netgate pfSense appliance | Dedicated hardware firewall with VLAN support |
| 24-port managed switch (TP-Link/Cisco SG) | VLAN trunking for lab network segmentation |

### Cloud Alternative (Free/Low Cost)
Use cloud free tiers to practice without hardware. Good for learning specific skills but has networking constraints.

| Provider | Free Tier Notes |
|---|---|
| AWS Free Tier | 750 hrs/mo t2.micro (12 months), good for EC2/IAM/S3 labs |
| Azure Free Tier | $200 credit + 12-month free services |
| Google Cloud (GCP) | $300 credit, Always Free f1-micro |
| VPS providers (Vultr, Linode, Hetzner) | $5-$10/mo for practice boxes; destroy when done |
| CloudGoat / FLAWS.cloud | Dedicated vulnerable cloud environments (see Section 6) |

---

## 2. Hypervisor Options

| Hypervisor | Type | Cost | Best For |
|---|---|---|---|
| **Proxmox VE** | Bare metal (Type 1) | Free | Dedicated home lab server; web UI, LXC + KVM, ZFS, VLANs |
| **VMware ESXi (free)** | Bare metal (Type 1) | Free (limited) | Home lab on spare hardware; limited vCPU/RAM on free tier |
| **VMware Workstation / Fusion** | Hosted (Type 2) | Commercial | Desktop VM management; best hardware compatibility |
| **VirtualBox** | Hosted (Type 2) | Free | Beginners; cross-platform; some performance overhead |
| **KVM/QEMU** | Bare metal / hosted | Free | Linux-native; powerful; CLI-heavy; use `virt-manager` for GUI |
| **Hyper-V** | Bare metal (Type 1) | Free (Windows Pro/Ent) | Windows-first labs; nested virtualization for AD |

**Recommendation:**
- Dedicated server -> **Proxmox VE** (best balance of features, cost, and community support)
- Desktop/laptop -> **VMware Workstation** (Windows/Linux) or **VMware Fusion** (macOS) for performance, or **VirtualBox** for free option
- Windows-only host -> **Hyper-V** is built in and capable

---

## 3. Essential VMs to Build

| VM | Purpose | Recommended RAM | Notes |
|---|---|---|---|
| Kali Linux | Primary pentesting platform | 4-8 GB | Full offensive toolkit pre-installed |
| Parrot OS Security | Alternative pentesting OS | 4 GB | Lighter than Kali; also has Home edition |
| REMnux | Linux malware analysis | 4 GB | Pre-loaded with reverse engineering tools |
| FlareVM (Windows 10) | Windows malware / RE analysis | 8 GB | FLARE team Chocolatey-based toolset overlay |
| Windows Server 2019/2022 | Active Directory domain controller | 4-8 GB | Use Microsoft eval license (free, 180 days) |
| Windows 10/11 | Domain-joined workstation target | 4 GB | Join to lab domain for realistic AD attacks |
| Ubuntu Server 22.04 | Linux target, web app hosting | 2-4 GB | Run DVWA, LAMP stack, or custom apps |
| Metasploitable 2 | Intentionally vulnerable Linux | 512 MB-1 GB | Classic target; many known CVEs |
| Metasploitable 3 | Intentionally vulnerable Linux/Windows | 2-4 GB | More modern, build with Vagrant/Packer |
| VulnHub machines | Various vulnerable targets | Varies | Download `.ova` files; see vulnhub.com |
| pfSense / OPNsense | Network firewall and inter-VLAN routing | 1-2 GB | Manages VLAN segmentation in the lab |
| Security Onion 2.x | Full NSM / SIEM stack | 16 GB | Zeek, Suricata, Elastic, SOC tools all-in-one |
| Wazuh (all-in-one) | SIEM + EDR agent manager | 4-8 GB | Deploy agents on Windows/Linux targets |
| DetectionLab | Pre-configured AD + logging environment | 24 GB total | Vagrant-based; fastest AD+logging lab spinup |

---

## 4. Network Architecture

### Recommended VLANs

| VLAN | Name | Hosts | Purpose |
|---|---|---|---|
| 10 | Management | Proxmox/ESXi host, pfSense LAN | Hypervisor and firewall management; tightly restricted |
| 20 | Attack | Kali, Parrot OS | Offensive machines; can reach Victim and AD VLANs |
| 30 | Victim | Metasploitable, Ubuntu, Windows 10 | Target machines; no outbound internet except through pfSense |
| 40 | Active Directory | Windows Server DC, domain workstations | AD lab environment |
| 50 | DMZ | Web servers, DVWA | Exposed services; partial internet access |
| 60 | Security / Monitoring | Security Onion, Wazuh, ELK | Receives logs/mirror traffic; management access only |
| 99 | Internet Uplink | pfSense WAN | NAT gateway to physical network / internet |

### Segmentation Setup
1. Use a **managed switch** that supports 802.1Q VLANs (TP-Link TL-SG108E ~$30, or Cisco SG series).
2. Configure **trunk ports** between the switch and the hypervisor host (carries all VLANs tagged).
3. In **Proxmox/ESXi**, create a virtual switch (vSwitch/Linux bridge) per VLAN, or use a single trunk bridge with VLAN-aware VMs.
4. **pfSense/OPNsense** handles inter-VLAN routing. Assign one interface (or sub-interface) per VLAN.
5. Write **firewall rules** in pfSense to enforce segmentation:
   - Attack VLAN -> Victim/AD VLAN: Allow
   - Attack VLAN -> Management VLAN: Block
   - Victim VLAN -> Management VLAN: Block
   - Monitoring VLAN -> All: Allow (for log collection)

### Logical Diagram
```
[ Physical Internet ]
        |
  [ pfSense WAN ]
        |
  [ pfSense LAN / VLAN trunk ]
        |
[ Managed Switch ]
  |      |      |       |        |
VLAN20 VLAN30 VLAN40 VLAN50  VLAN60
Attack Victim  AD     DMZ   Monitoring
 Kali  Msf2  WinSrv  DVWA  Sec.Onion
        Win10  Win10         Wazuh
```

---

## 5. Logging & Detection Stack

| Tool | Role | Notes |
|---|---|---|
| **Security Onion 2.x** | All-in-one NSM/IDS/SIEM | Bundles Zeek, Suricata, Elastic Stack, SOC tools; best for full lab SIEM |
| **Wazuh** | SIEM + EDR | Agent-based; monitors Windows/Linux endpoints; integrates with Elastic |
| **Elastic Stack (ELF)** | Log aggregation and visualization | Elasticsearch + Logstash + Filebeat + Kibana; build custom pipelines |
| **Velociraptor** | Endpoint forensics and threat hunting | Deploys agents; VQL query language; live response and artifact collection |
| **Graylog** | Log aggregation (alternative to Elastic) | Lighter on resources; uses MongoDB + OpenSearch |
| **HELK** | Pre-configured threat hunting ELK | Adds Jupyter notebooks and pre-built dashboards for hunt workflows |
| **Zeek** | Network protocol analysis / metadata | Generates rich logs from PCAP or live traffic; integrates with all SIEMs |
| **Suricata** | IDS/IPS with rule-based alerting | ET Open / ET Pro rulesets; integrates with Security Onion and Wazuh |
| **Sysmon** | Windows endpoint telemetry | Deploy via GPO; use SwiftOnSecurity or Olaf Hartong config |

### Recommended Minimal Stack for Beginners
1. Deploy **Wazuh all-in-one** VM (handles ingestion, search, and dashboard).
2. Install the **Wazuh agent** on every Windows/Linux target.
3. Deploy **Sysmon** on Windows hosts with a community config.
4. Forward pfSense logs (syslog) to Wazuh.
5. Graduate to **Security Onion** when you want full packet capture and NSM.

---

## 6. Vulnerable Target Environments

| Environment | Type | Notes |
|---|---|---|
| **Metasploitable 2** | VM (Linux) | Download from SourceForge; classic intentionally vulnerable |
| **Metasploitable 3** | VM (Linux + Windows) | Build via Vagrant; more services and CVEs |
| **DVWA** | Web app (Docker/VM) | PHP/MySQL; SQL injection, XSS, CSRF, file upload, and more |
| **VulnHub** | VM library | Hundreds of free `.ova` machines at vulnhub.com |
| **HackTheBox** | Remote (VPN) | Structured labs; no local hosting needed |
| **TryHackMe** | Remote (VPN/browser) | Beginner-friendly guided rooms |
| **FLAWS.cloud** | AWS misconfig | Level-based AWS misconfiguration challenges (free) |
| **FLAWS2.cloud** | AWS misconfig | Attacker + defender perspectives |
| **CloudGoat** | AWS (Terraform) | Rhino Security Labs; deploy a vulnerable AWS environment |
| **VulnAD** | Windows AD (PowerShell) | Quickly builds a vulnerable Active Directory |
| **BadBlood** | Windows AD population | Fills AD with realistic users, groups, and ACL misconfigs |
| **DetectionLab** | Full AD + logging (Vagrant) | Windows Server + Win10 + Splunk/ELK + Sysmon pre-configured |

---

## 7. Active Directory Lab Setup

### Prerequisites
- Windows Server 2019 or 2022 evaluation ISO ([download free 180-day eval](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server))
- Windows 10/11 evaluation ISO
- Hypervisor with at least 12 GB RAM available for the AD segment

### Step 1 - Install Windows Server

Install Windows Server 2022 Evaluation in a VM (Desktop Experience). Assign a static IP in the AD VLAN (e.g., `192.168.40.10`). Set the DNS server to itself (`127.0.0.1`).

### Step 2 - Promote to Domain Controller

```powershell
# Install the AD DS role
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to a new forest/domain controller
Install-ADDSForest `
  -DomainName "lab.local" `
  -DomainNetBiosName "LAB" `
  -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
  -Force
```

Server will reboot. Log in as `LAB\Administrator`.

### Step 3 - Create Domain Users and Groups

```powershell
# Create OUs
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "LabAdmins" -Path "DC=lab,DC=local"

# Create a user
New-ADUser -Name "Alice Smith" -SamAccountName "asmith" `
  -UserPrincipalName "asmith@lab.local" -Path "OU=LabUsers,DC=lab,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) `
  -Enabled $true

# Create a group and add the user
New-ADGroup -Name "IT Admins" -GroupScope Global -Path "OU=LabAdmins,DC=lab,DC=local"
Add-ADGroupMember -Identity "IT Admins" -Members "asmith"
```

### Step 4 - Join Windows 10 Workstation to Domain

On the Windows 10 VM (set DNS to the DC IP):

```powershell
Add-Computer -DomainName "lab.local" `
  -Credential (Get-Credential) `
  -Restart
```

### Step 5 - Install ADCS (Optional: Certificate Services)

Enables attacks like ESC1-ESC8 (ADCS abuse), golden/silver ticket scenarios.

```powershell
Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa `
  -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
  -KeyLength 2048 -HashAlgorithmName SHA256 -Force
```

### Step 6 - Populate with BadBlood

[BadBlood](https://github.com/davidprowe/BadBlood) fills the domain with thousands of realistic users, groups, OUs, and randomized ACL misconfigs -- mimicking real enterprise AD.

```powershell
git clone https://github.com/davidprowe/BadBlood
cd BadBlood
.\Invoke-BadBlood.ps1
```

After running, use **BloodHound + SharpHound** to enumerate attack paths:

```powershell
# Run SharpHound collector on a domain-joined machine
.\SharpHound.exe -c All --zipfilename lab_bloodhound.zip
# Import .zip into BloodHound GUI to visualize paths to Domain Admin
```

### Step 7 - Enable Logging

```powershell
# Download and install Sysmon (use Olaf Hartong or SwiftOnSecurity config)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Enable PowerShell Script Block Logging via GPO or registry
Set-ItemProperty `
  -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name "EnableScriptBlockLogging" -Value 1

# Enable command-line auditing
auditpol /set /subcategory:"Process Creation" /success:enable
```

---

## 8. Malware Analysis Lab

### Safety Rules (Read First)

- **Never** run malware on your host OS.
- **Always** use a dedicated, isolated VM. Take a snapshot before analysis and revert after.
- **Disable** shared clipboard and shared folders between host and analysis VM.
- **Never** allow the analysis VM unrestricted internet access. Route through INetSim or FakeNet-NG.

### Network Isolation Setup

| Option | How |
|---|---|
| **No internet** | Set VM network to "Host-only" or "Isolated" with no gateway |
| **INetSim** | Run on REMnux; simulates DNS, HTTP, SMTP, etc. for malware callbacks |
| **FakeNet-NG** | Run on Windows (FlareVM); intercepts and simulates network services |
| **INetSim + Wireshark** | REMnux as gateway; FlareVM routes through REMnux for full capture |

### Recommended Analysis VMs

| VM | OS | Key Tools |
|---|---|---|
| **FlareVM** | Windows 10 | x64dbg, OllyDbg, Ghidra, PE-bear, CFF Explorer, PEiD, FakeNet-NG, ProcMon, Wireshark |
| **REMnux** | Ubuntu (custom) | YARA, Ghidra, Volatility, radare2, INetSim, Zeek, oledump, pdfid, Cutter |

### Analysis Workflow

1. Snapshot the clean VM state before touching the sample.
2. **(Static)** Examine the file: hashes, strings, PE headers, imports, packer detection.
3. **(Dynamic)** Run the sample inside the VM; monitor with ProcMon, Process Hacker, Wireshark.
4. **(Network)** Capture traffic through FakeNet-NG / INetSim to identify C2 patterns.
5. **(Disassembly/Decompilation)** Load into Ghidra or x64dbg for deeper analysis.
6. Document IOCs: file hashes, registry keys, mutex names, network indicators.
7. Revert VM to clean snapshot when finished.

### Optional: Automated Sandbox

| Sandbox | Notes |
|---|---|
| **CAPE Sandbox** | Open source; automated detonation with memory dumps and config extraction |
| **Cuckoo Sandbox** | Classic; largely superseded by CAPE but still widely referenced |
| **Any.run** | Cloud-based interactive sandbox (free tier available) |
| **Hybrid Analysis** | Free cloud sandbox by CrowdStrike |

---

## 9. Resources and References

| Resource | URL |
|---|---|
| DetectionLab | https://github.com/clong/DetectionLab |
| HELK (Hunting ELK) | https://github.com/Cyb3rWard0g/HELK |
| Proxmox VE | https://www.proxmox.com |
| Security Onion | https://securityonionsolutions.com |
| Wazuh | https://wazuh.com |
| VulnHub | https://vulnhub.com |
| BadBlood | https://github.com/davidprowe/BadBlood |
| Sysmon (SwiftOnSecurity config) | https://github.com/SwiftOnSecurity/sysmon-config |
| Sysmon (Olaf Hartong modular config) | https://github.com/olafhartong/sysmon-modular |
| BloodHound | https://github.com/BloodHoundAD/BloodHound |
| FLARE VM | https://github.com/mandiant/flare-vm |
| REMnux | https://remnux.org |
| CAPE Sandbox | https://github.com/kevoreilly/CAPEv2 |
| CloudGoat | https://github.com/RhinoSecurityLabs/cloudgoat |
| DVWA | https://github.com/digininja/DVWA |
| Impacket | https://github.com/fortra/impacket |
| Microsoft Evaluation Center | https://www.microsoft.com/en-us/evalcenter |

---

## 10. Learning Path Integration

The home lab is the foundation for every practical cybersecurity discipline. Use the environment you build here to develop skills in:

| Discipline | What to Practice in the Lab |
|---|---|
| **Penetration Testing** | Attack Kali -> Metasploitable/Windows targets; exploit, post-exploit, pivot |
| **Active Directory Security** | Enumerate with BloodHound; perform Kerberoasting, AS-REP roasting, DCSync, ADCS abuse |
| **Detection Engineering** | Write Sigma rules, Suricata rules, Wazuh decoders triggered by your own attacks |
| **Incident Response** | Simulate attacks, then triage alerts in Security Onion/Wazuh; build runbooks |
| **Threat Hunting** | Use HELK / Velociraptor to hunt through Sysmon and Zeek logs for anomalies |
| **Malware Analysis** | Analyze samples in FlareVM/REMnux; document IOCs; write YARA rules |
| **Digital Forensics** | Image VM disks, analyze with Autopsy/Volatility; practice memory forensics |
| **Cloud Security** | Use CloudGoat / FLAWS.cloud to practice AWS privilege escalation and misconfig exploitation |

### Suggested Progression

1. **Start**: VirtualBox + Kali + Metasploitable 2. Run basic Nmap scans, use Metasploit.
2. **Intermediate**: Add pfSense + Windows Server DC + Windows 10. Practice AD attacks and defense.
3. **Advanced**: Add Security Onion or Wazuh. Attack your own lab, detect your own attacks.
4. **Expert**: Automate with DetectionLab, add CAPE sandbox, build custom Sigma/Suricata rules.

---

## Active Directory Lab (Windows Domain)

This section is a deep-dive into building a **deliberately vulnerable Active Directory environment** — the closest thing to a real enterprise target you can build at home. Most real-world breaches involve AD at some stage, so this lab is essential for both attackers and defenders.

### Why Build a Vulnerable AD Lab?

Active Directory is the authentication and authorization backbone of virtually every Windows enterprise network. Attackers target it because:

- Compromising a single Domain Admin account grants control over the entire domain.
- Misconfigurations (Kerberoastable service accounts, unconstrained delegation, weak ACLs) are extremely common in real environments.
- Attacks like Pass-the-Hash, Kerberoasting, and BloodHound path abuse are difficult to understand without hands-on practice.

By building your own AD lab, you can attack it freely, break things, reset to a snapshot, and try again — learning far more than any guided exercise allows.

### Hypervisor Requirements

**VMware (recommended for AD labs)**

VMware Workstation Pro (Windows/Linux) or VMware Fusion Pro (macOS) offer the best performance for Windows VMs and stable nested virtualization. As of 2024, VMware Workstation Pro and Fusion Pro are free for personal use.

- Download: https://www.vmware.com/products/workstation-pro.html

**VirtualBox (free alternative)**

VirtualBox works but has slightly higher overhead on Windows VMs and can be finicky with audio/USB. It is fully adequate for an AD lab.

- Download: https://www.virtualbox.org/

**Minimum host resources for a basic AD lab:**

| Component | Minimum | Recommended |
|---|---|---|
| RAM | 12 GB | 24+ GB |
| CPU | 4 cores | 8+ cores |
| Disk | 100 GB free | 200+ GB (SSD preferred) |

### Getting Free Windows ISOs

Microsoft provides **180-day evaluation versions** of Windows Server and Windows 10/11 Enterprise — completely free, no license key needed. Evaluations can be extended with `slmgr /rearm` for additional time.

| Download | URL |
|---|---|
| Windows Server 2022 Evaluation | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022 |
| Windows Server 2019 Evaluation | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019 |
| Windows 11 Enterprise Evaluation | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise |
| Windows 10 Enterprise Evaluation | https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise |

> **Tip:** Always choose "Desktop Experience" (GUI) for Windows Server if you want the familiar interface. "Server Core" is CLI-only and harder to work with when first learning AD.

### Building the Lab: Manual Step-by-Step

#### VM Configuration

Create three VMs:

| VM | Role | RAM | Disk | IP (example) |
|---|---|---|---|---|
| `DC01` | Domain Controller (Win Server 2022) | 4 GB | 60 GB | 192.168.40.10 |
| `WRK01` | Workstation (Windows 10/11) | 4 GB | 60 GB | 192.168.40.20 |
| `WRK02` | Second workstation (optional) | 4 GB | 60 GB | 192.168.40.21 |

Place all three VMs on the same **Host-Only** or **Internal** network (no internet access for the AD segment). This isolates the domain from your real network.

#### Domain Controller Setup

After installing Windows Server 2022:

```powershell
# 1. Set a static IP (adjust interface name as needed)
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.40.10 `
  -PrefixLength 24 -DefaultGateway 192.168.40.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 127.0.0.1

# 2. Rename the computer
Rename-Computer -NewName "DC01" -Restart
# (Wait for reboot, log back in)

# 3. Install AD DS and DNS roles
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools

# 4. Promote to Domain Controller (creates a new forest)
Import-Module ADDSDeployment
Install-ADDSForest `
  -DomainName "corp.local" `
  -DomainNetBiosName "CORP" `
  -ForestMode "WinThreshold" `
  -DomainMode "WinThreshold" `
  -InstallDns `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "SafeMode@123" -AsPlainText -Force) `
  -Force
# Server reboots automatically. Log back in as CORP\Administrator
```

> **Why it matters:** The `-InstallDns` flag installs DNS on the DC itself. In AD, DNS is critical — domain-joined machines use the DC as their DNS server to find domain resources via SRV records.

#### Creating Users, Groups, and OUs

Realistic AD labs need multiple users with varying privilege levels:

```powershell
# Create Organizational Units for structure
New-ADOrganizationalUnit -Name "Corp Users"    -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Corp Computers" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "IT Admins"     -Path "DC=corp,DC=local"

# Create regular domain users
$users = @(
  @{Name="Bob Jones";   Sam="bjones";  Pass="Summer2024!"},
  @{Name="Carol Davis"; Sam="cdavis";  Pass="Winter2024!"},
  @{Name="Dave Wilson"; Sam="dwilson"; Pass="Password123"}
)
foreach ($u in $users) {
  New-ADUser -Name $u.Name -SamAccountName $u.Sam `
    -UserPrincipalName "$($u.Sam)@corp.local" `
    -Path "OU=Corp Users,DC=corp,DC=local" `
    -AccountPassword (ConvertTo-SecureString $u.Pass -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true
}

# Create a service account with a weak password (Kerberoastable target)
New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" `
  -UserPrincipalName "svc_sql@corp.local" `
  -Path "OU=Service Accounts,DC=corp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "SqlService1" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

# Register an SPN on the service account (makes it Kerberoastable)
setspn -A MSSQLSvc/dc01.corp.local:1433 CORP\svc_sql

# Create groups
New-ADGroup -Name "IT Helpdesk" -GroupScope Global -Path "DC=corp,DC=local"
New-ADGroup -Name "IT Admins"   -GroupScope Global -Path "DC=corp,DC=local"

# Add users to groups
Add-ADGroupMember -Identity "IT Helpdesk" -Members bjones, cdavis
Add-ADGroupMember -Identity "IT Admins"   -Members dwilson
```

#### Configuring Group Policy Objects (GPOs)

GPOs control security settings across the domain. Creating a few vulnerable GPOs makes the lab realistic:

```powershell
# Import the GroupPolicy module
Import-Module GroupPolicy

# Create a GPO that disables Windows Defender (intentionally insecure for lab)
$gpo = New-GPO -Name "Lab - Disable Defender"
Set-GPRegistryValue -Name "Lab - Disable Defender" `
  -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" `
  -ValueName "DisableAntiSpyware" -Type DWord -Value 1
New-GPLink -Name "Lab - Disable Defender" -Target "DC=corp,DC=local"

# Create a GPO to deploy Sysmon via startup script (for logging)
# (After creating, link the GPO and add a computer startup script pointing to Sysmon installer)
$gpo2 = New-GPO -Name "Lab - Deploy Sysmon"
New-GPLink -Name "Lab - Deploy Sysmon" -Target "OU=Corp Computers,DC=corp,DC=local"
```

> **Why GPOs matter for attackers:** Misconfigured GPOs are a goldmine. If a low-privileged user has write permissions on a GPO linked to Domain Controllers, they can achieve Domain Admin. Tools like BloodHound specifically enumerate GPO misconfigurations.

#### Joining Workstations to the Domain

On each Windows 10/11 workstation VM:

```powershell
# Set DNS to the DC's IP (critical — must be done before joining)
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 192.168.40.10

# Rename the machine
Rename-Computer -NewName "WRK01" -Restart

# After reboot — join the domain
Add-Computer -DomainName "corp.local" `
  -OUPath "OU=Corp Computers,DC=corp,DC=local" `
  -Credential (Get-Credential) `
  -Restart
```

Log in as `CORP\bjones` or another domain user to simulate a real workstation session.

### Pre-Built AD Lab Options

Building manually is educational, but pre-built options save significant time for focused attack practice:

#### GOAD (Game of Active Directory)

GOAD is a multi-domain, multi-forest AD lab with intentionally vulnerable configurations, modelled on Game of Thrones. It is one of the most realistic and comprehensive free AD labs available.

```bash
# Prerequisites: Vagrant + VirtualBox or VMware
git clone https://github.com/Orange-Cyberdefense/GOAD
cd GOAD/ad/GOAD

# Install with VirtualBox provider
vagrant up
# This spins up 5 VMs: 2 DCs + 3 workstations across 2 domains
# Requires ~24 GB RAM; takes 30-60 minutes first run
```

GOAD includes: Kerberoastable accounts, AS-REP roastable users, unconstrained delegation, ACL misconfigurations, ADCS vulnerable templates, and more.

#### DetectionLab

DetectionLab builds a complete AD lab **plus** a full logging stack (Splunk, Fleet, Zeek, Sysmon) in one automated deployment. Ideal for practicing attack AND detection simultaneously.

```bash
git clone https://github.com/clong/DetectionLab
cd DetectionLab/Vagrant
vagrant up
# Provisions: DC, 2 Windows workstations, Logger VM (Ubuntu + Splunk + Fleet)
# Total RAM: ~24 GB; first build takes 1-2 hours
```

#### BadBlood (AD Population Tool)

If you have an existing domain, BadBlood populates it with thousands of realistic users, groups, and ACL misconfigurations to simulate an enterprise-scale environment.

```powershell
# Run on the Domain Controller
git clone https://github.com/davidprowe/BadBlood
cd BadBlood
.\Invoke-BadBlood.ps1
# Creates ~2,500 users, ~500 groups, nested group memberships,
# and randomized ACL misconfigurations across OUs
```

### What to Practice in the AD Lab

Once the lab is built, these are the core AD attack techniques to practice:

#### Kerberoasting

Request service tickets for accounts with SPNs, then crack the ticket offline:

```bash
# From Kali/attack machine (Impacket)
impacket-GetUserSPNs corp.local/bjones:Summer2024! -dc-ip 192.168.40.10 -request -outputfile kerberoast_hashes.txt

# Crack with hashcat
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

> **Why it matters:** Kerberoasting doesn't require elevated privileges — any domain user can request a service ticket. Service accounts often have weak passwords and high privileges, making this a high-value technique.

#### AS-REP Roasting

Target accounts with "Do not require Kerberos preauthentication" enabled:

```bash
# Find AS-REP roastable accounts and get hashes
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 192.168.40.10 -no-pass -format hashcat

# Crack
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

#### Pass-the-Hash

After obtaining an NTLM hash (via Mimikatz, secretsdump, etc.), authenticate as that user without knowing the plaintext password:

```bash
# Dump hashes from DC (requires DA or local admin on DC)
impacket-secretsdump corp.local/Administrator:P@ssw0rd123!@192.168.40.10

# Pass-the-Hash to get a shell
impacket-wmiexec -hashes :aad3b435b51404eeaad3b435b51404ee:ntlm_hash_here corp.local/Administrator@192.168.40.20
```

#### BloodHound Enumeration

BloodHound visualizes attack paths through AD using graph theory:

```powershell
# Collect data with SharpHound (run on domain-joined machine)
.\SharpHound.exe -c All --zipfilename bloodhound_data.zip
```

```bash
# Start Neo4j and BloodHound on Kali
sudo neo4j start
bloodhound &
# Import the .zip, then run queries:
# - "Find Shortest Paths to Domain Admins"
# - "Find AS-REP Roastable Users"
# - "Find Kerberoastable Users with most privileges"
```

---

## Cloud Lab (AWS Free Tier)

Cloud security is one of the fastest-growing areas of offensive and defensive security. AWS is the dominant cloud provider and the most common target in bug bounty programs and real-world breaches. This section walks you through building a practical cloud attack lab at zero cost (with careful management).

> **Cost Warning:** AWS can generate unexpected charges if resources are left running. Set up billing alerts (covered below) BEFORE deploying anything. The free tier has specific limits — exceeding them results in charges. Always destroy resources when done.

### AWS Free Tier — What You Actually Get

The free tier has three categories:

| Category | Details | Key Services |
|---|---|---|
| **Always Free** | Never expires | Lambda (1M requests/mo), DynamoDB (25 GB), SNS (1M publishes) |
| **12-Month Free** | From account creation date | EC2 t2.micro (750 hrs/mo), S3 (5 GB), RDS (750 hrs/mo), CloudTrail (1 trail) |
| **Trials** | Short-term trials | GuardDuty (30 days), Macie (30 days), Security Hub (30 days) |

> **Key free tier caveat:** The 750 EC2 hours covers ONE t2.micro running 24/7 for a month. If you run two t2.micros simultaneously, you burn through the free hours in 15 days and get charged for the second instance.

### Step 1 — Create an AWS Account

1. Go to https://aws.amazon.com and create an account (credit card required for verification, but you won't be charged if you stay in free tier).
2. Immediately enable **MFA** on the root account: IAM Console → Security Credentials → Assign MFA device.
3. **Create an IAM admin user** — never use the root account for daily work:

```bash
# Using AWS CLI (after installing: https://aws.amazon.com/cli/)
aws iam create-user --user-name lab-admin
aws iam attach-user-policy --user-name lab-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-login-profile --user-name lab-admin --password 'LabAdmin@2024!' --password-reset-required
```

> **Why create a separate IAM user?** The root account has unrestricted access to everything, including billing and account closure. If you accidentally expose root credentials (e.g., push them to GitHub), an attacker could do irreversible damage. IAM users can have permissions scoped to only what you need.

### Step 2 — Set Up Billing Alerts (Do This First)

This is the most important step before deploying anything:

```bash
# Enable billing alerts (only needs to be done once per account, in us-east-1)
aws cloudwatch put-metric-alarm \
  --alarm-name "BillingAlert-$5" \
  --alarm-description "Alert when estimated charges exceed $5" \
  --namespace "AWS/Billing" \
  --metric-name "EstimatedCharges" \
  --dimensions Name=Currency,Value=USD \
  --statistic Maximum \
  --period 86400 \
  --evaluation-periods 1 \
  --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:billing-alerts \
  --region us-east-1
```

Or via the console: Billing Dashboard → Billing Preferences → Enable "Receive Billing Alerts" → CloudWatch → Alarms → Create Alarm → Billing.

Also enable **AWS Budgets** (free for 2 budgets/month):
- Billing Console → Budgets → Create Budget → Zero spend budget (alerts at $0.01)

### Step 3 — Basic VPC and EC2 Setup

Understanding VPC networking is foundational to cloud security. A VPC is your private network within AWS:

```bash
# Create a VPC for the lab
aws ec2 create-vpc --cidr-block 10.0.0.0/16 \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=lab-vpc}]'

# Create a public subnet
aws ec2 create-subnet --vpc-id vpc-XXXXXXXXX \
  --cidr-block 10.0.1.0/24 \
  --availability-zone us-east-1a \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=lab-public}]'

# Create and attach an internet gateway
aws ec2 create-internet-gateway \
  --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=lab-igw}]'
aws ec2 attach-internet-gateway --vpc-id vpc-XXXXXXXXX --internet-gateway-id igw-XXXXXXXXX

# Launch a free tier EC2 instance (Amazon Linux 2023)
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --instance-type t2.micro \
  --key-name my-lab-key \
  --subnet-id subnet-XXXXXXXXX \
  --security-group-ids sg-XXXXXXXXX \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=lab-target}]'
```

> **Why understand VPCs?** Most cloud attack scenarios involve exploiting misconfigured security groups, exposed S3 buckets, or SSRF vulnerabilities that let you reach the EC2 metadata service. Understanding how VPCs, subnets, and routing work makes these attacks comprehensible.

### Step 4 — IAM Configuration for Practice

IAM (Identity and Access Management) misconfigurations are the root cause of most AWS breaches. Set up intentionally misconfigured IAM roles to practice enumeration and privilege escalation:

```bash
# Create an overly permissive IAM role (intentionally misconfigured for lab)
cat > lab-role-trust.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
EOF

aws iam create-role --role-name lab-ec2-role \
  --assume-role-policy-document file://lab-role-trust.json

# Attach S3 full access (intentionally over-privileged)
aws iam attach-role-policy --role-name lab-ec2-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

# Create a user with no permissions (for privilege escalation practice)
aws iam create-user --user-name low-priv-user
aws iam create-access-key --user-name low-priv-user
```

### Step 5 — Enable CloudTrail Logging

CloudTrail records every API call made in your account. It is the foundation of AWS forensics and detection:

```bash
# Create an S3 bucket for CloudTrail logs
aws s3 mb s3://my-lab-cloudtrail-logs-$(date +%s) --region us-east-1

# Create a trail that logs all regions
aws cloudtrail create-trail \
  --name lab-trail \
  --s3-bucket-name my-lab-cloudtrail-logs-TIMESTAMP \
  --is-multi-region-trail \
  --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name lab-trail
```

> **Why CloudTrail matters:** Every attacker action in AWS generates a CloudTrail event. Understanding what actions leave traces (and which don't) is essential for both red and blue team work. Practice by attacking your lab environment, then reviewing CloudTrail logs to see exactly what was recorded.

### Step 6 — Deploy CloudGoat (Intentionally Vulnerable AWS)

[CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) by Rhino Security Labs is the premier intentionally vulnerable AWS environment. It uses Terraform to spin up realistic attack scenarios.

```bash
# Prerequisites: Python 3, Terraform, AWS CLI configured
pip3 install cloudgoat

# Configure with your AWS credentials
cloudgoat config profile default

# List available scenarios
cloudgoat list

# Deploy a scenario (example: IAM privilege escalation)
cloudgoat create iam_privesc_by_attachment

# When done — ALWAYS destroy to avoid charges
cloudgoat destroy iam_privesc_by_attachment
```

Key CloudGoat scenarios:

| Scenario | Attack Technique | Difficulty |
|---|---|---|
| `iam_privesc_by_attachment` | IAM privilege escalation via policy attachment | Beginner |
| `cloud_breach_s3` | S3 bucket exposure + credential theft | Beginner |
| `ec2_ssrf` | SSRF to EC2 metadata service for credential theft | Intermediate |
| `lambda_privesc` | Lambda function abuse for privilege escalation | Intermediate |
| `codebuild_secrets` | Secret extraction from CodeBuild environment | Intermediate |
| `cicd` | CI/CD pipeline attack chain | Advanced |

> **Always destroy CloudGoat environments when done.** Even small deployments can incur charges if left running. `cloudgoat destroy <scenario>` tears down all Terraform-managed resources.

### Free Alternatives and Supplementary Resources

| Resource | Description | Cost |
|---|---|---|
| FLAWS.cloud | Level-based AWS misconfig challenges | Free (uses attacker-provided credentials) |
| FLAWS2.cloud | Attacker + defender dual-perspective | Free |
| AWS Well-Architected Labs | Defensive labs from AWS | Free |
| Pacu | AWS exploitation framework (like Metasploit for AWS) | Free/open source |
| Prowler | AWS security assessment tool | Free/open source |

---

## Azure Lab (Free Tier)

Azure is the second-largest cloud provider and the dominant platform for enterprise Microsoft environments. Entra ID (formerly Azure Active Directory) is deeply integrated with Microsoft 365, making it a critical target in enterprise attacks and a required skill for modern red and blue teamers.

> **Cost Warning:** Azure's free account is generous but has limits. The $200 credit expires after 30 days. After that, only "Always Free" services remain. Services like Azure VMs are NOT free after the credit is used. Set up cost alerts before deploying anything beyond free-tier services.

### Azure Free Account — What You Get

| Tier | What's Included | Duration |
|---|---|---|
| **$200 credit** | Any Azure service | 30 days from signup |
| **Always Free** | 750 hrs B1s VM, 5 GB Blob Storage, Azure Functions (1M executions), Cosmos DB (1,000 RUs) | Permanent |
| **12-Month Free** | B1s VMs, 64 GB managed disk, SQL Database (250 GB) | 12 months from signup |
| **Entra ID Free Tier** | User management, SSO, MFA (up to 50,000 objects) | Permanent |

Sign up at: https://azure.microsoft.com/en-us/free/

### Step 1 — Create an Azure Free Account and Entra ID Tenant

When you create an Azure account, you automatically get a free Entra ID (Azure AD) tenant. This is the identity provider for your entire Azure environment.

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Log in (opens browser)
az login

# Check your subscription
az account show

# Set a cost alert immediately
az consumption budget create \
  --budget-name "lab-budget" \
  --amount 10 \
  --category Cost \
  --time-grain Monthly \
  --start-date $(date +%Y-%m-01) \
  --end-date 2026-12-31 \
  --resource-group-name "" \
  --notifications "[{\"enabled\":true,\"operator\":\"GreaterThan\",\"threshold\":80,\"contactEmails\":[\"youremail@example.com\"],\"thresholdType\":\"Actual\"}]"
```

### Step 2 — Set Up Test Users, Groups, and Roles

The free Entra ID tier supports up to 50,000 objects — more than enough for a lab:

```bash
# Create test users
az ad user create \
  --display-name "Lab User 1" \
  --user-principal-name labuser1@YOURTENANT.onmicrosoft.com \
  --password "LabUser@2024!" \
  --force-change-password-next-sign-in false

az ad user create \
  --display-name "Lab Admin" \
  --user-principal-name labadmin@YOURTENANT.onmicrosoft.com \
  --password "LabAdmin@2024!" \
  --force-change-password-next-sign-in false

# Create a security group
az ad group create \
  --display-name "Lab Security Team" \
  --mail-nickname "lab-security"

# Add user to group
az ad group member add \
  --group "Lab Security Team" \
  --member-id $(az ad user show --id labuser1@YOURTENANT.onmicrosoft.com --query id -o tsv)

# Assign a role (Global Reader — read-only to everything in Entra)
az role assignment create \
  --assignee labuser1@YOURTENANT.onmicrosoft.com \
  --role "Global Reader" \
  --scope /subscriptions/YOUR_SUBSCRIPTION_ID
```

> **Why Entra ID matters:** Entra ID is the identity backbone for all Microsoft 365 services (Teams, SharePoint, Exchange, Defender). In a real enterprise attack, compromising an Entra ID account can grant access to email, files, and enterprise applications — not just Azure resources.

### Step 3 — Deploy AzureGoat (Intentionally Vulnerable Azure)

[AzureGoat](https://github.com/ine-labs/AzureGoat) by INE Labs mirrors CloudGoat but for Azure, with realistic privilege escalation and misconfiguration scenarios:

```bash
# Prerequisites: Terraform, Azure CLI
git clone https://github.com/ine-labs/AzureGoat
cd AzureGoat

# Initialize Terraform
terraform init

# Deploy (uses your Azure CLI credentials)
terraform apply

# When done — ALWAYS destroy
terraform destroy
```

AzureGoat includes scenarios for:
- Storage account (Blob) exposure
- Managed Identity abuse for privilege escalation
- Azure Function exploitation
- Key Vault secret extraction
- SSRF via Azure metadata service (`169.254.169.254`)

### Step 4 — Microsoft 365 Developer Program (Free E5 License)

This is one of the best-kept secrets in cybersecurity education. Microsoft offers a **free Microsoft 365 E5 developer subscription** (normally ~$57/user/month) for 90 days, renewable if you actively use it for development/learning.

**What's included (25 user licenses):**
- Microsoft 365 E5 (Word, Excel, Teams, SharePoint, Exchange, etc.)
- Microsoft Defender for Office 365 (P2)
- Microsoft Defender for Endpoint (P2)
- Microsoft Sentinel (free data ingestion up to 10 GB/day during trial)
- Microsoft Purview (eDiscovery, Compliance)
- Entra ID P2 (Conditional Access, PIM, Identity Protection)

**Sign up:** https://developer.microsoft.com/en-us/microsoft-365/dev-program

```
1. Click "Join now" and sign in with a Microsoft account
2. Choose "Security" or "Development" as your focus area
3. Select "Instant sandbox" for fastest setup
4. Wait ~2 minutes for provisioning
5. Note the admin credentials provided — these are your E5 tenant credentials
```

> **Why this is valuable:** Practicing with Sentinel, Defender XDR, and Entra ID P2 features normally costs hundreds of dollars per month. The developer program gives you a full enterprise security stack for free.

### Step 5 — Microsoft Sentinel Lab Setup

Once you have the E5 dev subscription:

```bash
# Connect to your dev tenant
az login --tenant YOUR_DEV_TENANT_ID

# Create a Log Analytics Workspace (required by Sentinel)
az monitor log-analytics workspace create \
  --resource-group lab-rg \
  --workspace-name lab-sentinel-workspace \
  --location eastus

# Enable Microsoft Sentinel on the workspace
az security insights workspace create \
  --resource-group lab-rg \
  --workspace-name lab-sentinel-workspace

# Connect Microsoft 365 Defender data connector (ingests Defender XDR events)
# This is done in the Sentinel portal: Content Hub -> Microsoft 365 Defender -> Install
```

Key things to practice in Sentinel:
- Write KQL (Kusto Query Language) queries to hunt for suspicious activity
- Create custom Analytics Rules (detection rules) triggered by your own attack simulations
- Build Workbooks (dashboards) for visualizing security data
- Use Threat Intelligence to enrich alerts with IOC data

### Step 6 — AzureHound and ROADtools for Enumeration Practice

Just as BloodHound enumerates on-premises AD, **AzureHound** and **ROADtools** map Entra ID attack paths:

```bash
# Install AzureHound
git clone https://github.com/BloodHoundAD/AzureHound
cd AzureHound
go build .

# Enumerate the tenant (uses Azure CLI credentials)
./azurehound -u labadmin@YOURTENANT.onmicrosoft.com -p "LabAdmin@2024!" list --tenant YOURTENANT.onmicrosoft.com -o azurehound_output.json

# Import into BloodHound (supports both on-prem AD and Entra ID data)
```

```bash
# ROADtools for deeper Entra ID enumeration
pip3 install roadtools
roadrecon auth --username labadmin@YOURTENANT.onmicrosoft.com --password "LabAdmin@2024!"
roadrecon gather
roadrecon gui  # Launches a web interface for exploring the data
```

> **Why these tools matter:** AzureHound reveals the same type of attack paths that BloodHound does for on-prem AD — but in the cloud. You can find paths like "User A can reset User B's password → User B is a Global Admin" and practice exploiting them in your own tenant.

---

## Self-Hosting a Website / VPS Setup

Running your own VPS is a practical skill that bridges web security, Linux administration, and bug bounty reconnaissance practice. Hosting your own vulnerable web apps gives you a realistic target that you fully control — no rate limits, no legal concerns, no downtime.

### Choosing a VPS Provider

| Provider | Cheapest Plan | Notes |
|---|---|---|
| **DigitalOcean** | $4/mo (512 MB RAM, 10 GB SSD) | Excellent docs; $200 credit for 60 days via referral links |
| **Linode / Akamai** | $5/mo (1 GB RAM, 25 GB SSD) | Solid performance; good free credit offers |
| **Vultr** | $2.50/mo (512 MB RAM, 10 GB SSD) | Cheapest option; many datacenter locations |
| **Hetzner** | €3.79/mo (2 vCPU, 4 GB RAM) | Exceptional value; EU-based |
| **Oracle Cloud Free Tier** | Free permanently | 2 AMD VMs (1 GB RAM each) + 4 ARM cores + 24 GB RAM (Ampere A1); genuinely free |

> **Free option:** Oracle Cloud's Always Free tier is remarkably generous — you get ARM-based VMs with 4 cores and 24 GB RAM total at no cost. The catch: account creation can be difficult, and support is limited. See: https://www.oracle.com/cloud/free/

**Recommended for beginners:** DigitalOcean or Vultr — both have clean interfaces, good documentation, and hourly billing so you only pay for what you use.

### Step 1 — Initial Server Setup

After spinning up a fresh Ubuntu 22.04 LTS VPS:

```bash
# Connect via SSH (use the IP from your provider's dashboard)
ssh root@YOUR_SERVER_IP

# Update system packages first (always do this on a fresh server)
apt update && apt upgrade -y

# Create a non-root user for daily operations
adduser labuser
usermod -aG sudo labuser

# Switch to the new user
su - labuser
```

> **Why not use root?** Running as root means a single misconfiguration or exploited vulnerability gives an attacker full control immediately. A non-root user with sudo requires an extra step, limiting blast radius.

### Step 2 — SSH Key Authentication

Password-based SSH is vulnerable to brute force. Switch to key authentication:

```bash
# On YOUR LOCAL MACHINE — generate an SSH key pair
ssh-keygen -t ed25519 -C "lab-vps-key" -f ~/.ssh/lab_vps_key

# Copy the public key to the server
ssh-copy-id -i ~/.ssh/lab_vps_key.pub labuser@YOUR_SERVER_IP

# Verify key login works, THEN disable password auth
ssh -i ~/.ssh/lab_vps_key labuser@YOUR_SERVER_IP
```

Once key login is confirmed, disable password authentication:

```bash
# On the server — edit SSH config
sudo nano /etc/ssh/sshd_config
# Change these lines:
#   PasswordAuthentication no
#   PermitRootLogin no
#   PubkeyAuthentication yes

sudo systemctl restart sshd
```

### Step 3 — Firewall with UFW

UFW (Uncomplicated Firewall) is the easiest way to manage iptables rules on Ubuntu:

```bash
# Install UFW (usually pre-installed on Ubuntu)
sudo apt install ufw -y

# Default policies: deny all incoming, allow all outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (do this BEFORE enabling or you'll lock yourself out)
sudo ufw allow ssh       # Same as: ufw allow 22/tcp

# Allow HTTP and HTTPS (for web apps)
sudo ufw allow http      # Port 80
sudo ufw allow https     # Port 443

# Enable the firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

> **Critical:** Always `ufw allow ssh` before `ufw enable`. Forgetting this locks you out of your own server. Most cloud providers have a web-based console as a fallback, but it's still a headache.

### Step 4 — Fail2ban (Brute Force Protection)

Fail2ban monitors log files and automatically bans IP addresses that show signs of brute force attacks:

```bash
sudo apt install fail2ban -y

# Create a local config (don't edit jail.conf directly — it gets overwritten on updates)
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local

# Key settings to adjust in [sshd] section:
# enabled = true
# bantime = 1h      # How long to ban (1 hour)
# findtime = 10m    # Window to count failures
# maxretry = 5      # Failures before ban

sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check active bans
sudo fail2ban-client status sshd
```

> **Why fail2ban matters for learning:** It's a practical example of a detection and response system — it reads logs, identifies patterns, and takes automated action. This is conceptually identical to how a SIEM + SOAR works at enterprise scale.

### Step 5 — Install Docker and Docker Compose

Docker makes it trivial to deploy and tear down vulnerable web applications:

```bash
# Install Docker
curl -fsSL https://get.docker.com | sudo sh

# Add your user to the docker group (avoid using sudo with every docker command)
sudo usermod -aG docker labuser
newgrp docker  # Apply group change without logout

# Install Docker Compose plugin
sudo apt install docker-compose-plugin -y

# Verify
docker --version
docker compose version
```

### Step 6 — Deploy Vulnerable Web Applications

#### DVWA (Damn Vulnerable Web Application)

```bash
mkdir ~/dvwa && cd ~/dvwa

cat > docker-compose.yml << 'EOF'
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8080:80"
    restart: unless-stopped
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
EOF

docker compose up -d
# Access at http://YOUR_SERVER_IP:8080
# Default credentials: admin / password
# First login: click "Create / Reset Database"
```

DVWA covers: SQL Injection, XSS (Reflected/Stored/DOM), CSRF, File Upload, File Inclusion, Command Injection, Brute Force, CAPTCHA bypass.

#### OWASP Juice Shop

```bash
mkdir ~/juiceshop && cd ~/juiceshop

cat > docker-compose.yml << 'EOF'
version: '3'
services:
  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
    restart: unless-stopped
EOF

docker compose up -d
# Access at http://YOUR_SERVER_IP:3000
```

Juice Shop has 100+ challenges covering the entire OWASP Top 10, plus advanced topics like XXE, SSRF, JWT manipulation, and broken cryptography. It includes a built-in scoreboard.

#### OWASP WebGoat

```bash
mkdir ~/webgoat && cd ~/webgoat

cat > docker-compose.yml << 'EOF'
version: '3'
services:
  webgoat:
    image: webgoat/webgoat
    ports:
      - "8888:8080"
      - "9090:9090"
    restart: unless-stopped
EOF

docker compose up -d
# Access at http://YOUR_SERVER_IP:8888/WebGoat
```

WebGoat is lesson-based with guided hints — good for learning the WHY behind each vulnerability.

#### Multi-App Stack (Run All Three)

```bash
mkdir ~/vulnlab && cd ~/vulnlab

cat > docker-compose.yml << 'EOF'
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8080:80"
    restart: unless-stopped

  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
    restart: unless-stopped

  webgoat:
    image: webgoat/webgoat
    ports:
      - "8888:8080"
    restart: unless-stopped
EOF

docker compose up -d
docker compose ps  # Verify all are running
```

> **Security note:** If you expose these apps to the internet (not just localhost), anyone can access them. Either restrict access with UFW (`ufw allow from YOUR_HOME_IP to any port 8080`) or use a VPN to access your VPS privately.

### Step 7 — Domain Setup with Cloudflare

If you want a real domain name (useful for bug bounty practice and SSL certificates):

1. Buy a cheap domain from Namecheap, Porkbun (~$1-$10/year for `.xyz`, `.io` domains).
2. Add the domain to **Cloudflare** (free): https://dash.cloudflare.com — Cloudflare provides free DNS, DDoS protection, and SSL.
3. In Cloudflare, create DNS A records pointing to your VPS IP.

```
Type: A
Name: @          (root domain)
Value: YOUR_VPS_IP
Proxy: Enabled (orange cloud)

Type: A
Name: www
Value: YOUR_VPS_IP
Proxy: Enabled
```

### Step 8 — Nginx or Caddy as a Reverse Proxy

A reverse proxy sits in front of your Docker containers and handles SSL termination:

#### Option A: Caddy (Easier — Automatic HTTPS)

Caddy automatically obtains and renews Let's Encrypt certificates:

```bash
sudo apt install caddy -y

sudo nano /etc/caddy/Caddyfile
```

```
# /etc/caddy/Caddyfile
yourdomain.com {
    reverse_proxy localhost:3000  # Juice Shop
}

dvwa.yourdomain.com {
    reverse_proxy localhost:8080
}
```

```bash
sudo systemctl reload caddy
# Caddy automatically provisions TLS certs — no certbot needed
```

#### Option B: Nginx + Let's Encrypt Certbot

```bash
sudo apt install nginx certbot python3-certbot-nginx -y

sudo nano /etc/nginx/sites-available/juiceshop
```

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/juiceshop /etc/nginx/sites-enabled/
sudo nginx -t  # Test config
sudo systemctl reload nginx

# Obtain SSL certificate (free via Let's Encrypt)
sudo certbot --nginx -d yourdomain.com
# Certbot automatically modifies the Nginx config for HTTPS and sets up auto-renewal
```

---

## Defensive Home Lab

Detection engineering and blue team skills are built by practicing detection on your own attacks. This section covers tools and setups specifically designed for defenders: log analysis, alerting, threat hunting, and endpoint forensics.

> **The key principle of defensive lab work:** Attack your own environment, then go looking for what you generated. Seeing the log output of a specific attack technique is far more educational than reading about it.

### Option 1: DetectionLab (Fastest Full-Stack Setup)

[DetectionLab](https://github.com/clong/DetectionLab) is the most complete pre-built lab for detection engineering. It automatically provisions a full Windows AD domain with enterprise logging infrastructure.

**What it includes:**
- `dc.windomain.local` — Windows Server 2019 Domain Controller
- `wef.windomain.local` — Windows Event Forwarding server
- `win10.windomain.local` — Windows 10 workstation (domain-joined)
- `logger` — Ubuntu VM running Splunk, Fleet (osquery), Zeek, Suricata, and Velociraptor

**Prerequisites:** Vagrant + VirtualBox or VMware (see Section 2), ~24 GB RAM.

```bash
git clone https://github.com/clong/DetectionLab
cd DetectionLab/Vagrant

# For VirtualBox
vagrant up --provider=virtualbox

# For VMware (requires vagrant-vmware-desktop plugin)
vagrant plugin install vagrant-vmware-desktop
vagrant up --provider=vmware_desktop

# First build takes 60-90 minutes (downloading ISOs, installing software)
# Splunk is accessible at https://192.168.56.105:8000 (admin/changeme)
# Fleet (osquery) at https://192.168.56.105:8412
```

Once up, practice detection by:
1. Running Mimikatz or SharpHound on the Windows VMs.
2. Switching to Splunk and searching for the resulting event IDs (4624, 4688, 7045).
3. Writing Splunk SPL detection rules for what you find.

### Option 2: Security Onion

[Security Onion](https://securityonionsolutions.com) is a Linux distro purpose-built for network security monitoring, IDS, and SIEM. It bundles Zeek, Suricata, Elastic Stack, and a custom SOC interface (Security Onion Console).

**Deployment options:**

| Mode | RAM | Use Case |
|---|---|---|
| Standalone | 16 GB min | All-in-one on a single VM or physical machine |
| Evaluation | 8 GB min | Trimmed-down version for learning; not for production |
| Distributed | Multiple nodes | Enterprise simulation with separate manager/sensor/storage nodes |

```bash
# Download the Security Onion ISO
# https://github.com/Security-Onion-Solutions/securityonion/blob/2.4/main/DOWNLOAD.md

# After booting the ISO and completing the installer:
# Run the setup wizard
sudo so-setup

# Choose: Standalone installation
# Choose: Management interface (your VM's NIC connected to the lab network)
# Choose: Sniffing interface (the NIC connected to your victim VLAN or a SPAN port)
# Set credentials for the web console

# Access the console at https://YOUR_SECURITYONION_IP
```

Key things to practice in Security Onion:
- Visualize network connections in the **Hunt** interface
- Review **Suricata IDS alerts** triggered by attack traffic
- Analyze **Zeek logs** (dns.log, http.log, conn.log, ssl.log) to understand what was happening on the wire
- Use **PCAP replay** to analyze captured traffic from HackTheBox or CTF challenges

### Option 3: Elastic SIEM (Free Tier) with Sysmon

Building your own Elastic SIEM from scratch gives you deep understanding of how SIEMs work under the hood — ingestion pipelines, index mappings, detection rules, and alert workflows.

```bash
# Deploy Elasticsearch + Kibana with Docker Compose
mkdir ~/elastic-siem && cd ~/elastic-siem

cat > docker-compose.yml << 'EOF'
version: '3'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - ES_JAVA_OPTS=-Xms2g -Xmx2g
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=ChangeMe123!
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=ChangeMe123!
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  esdata:
EOF

docker compose up -d
# Kibana: http://localhost:5601 (elastic / ChangeMe123!)
```

**Install Elastic Agent on Windows targets (forwards Sysmon + Windows Event Logs):**

```powershell
# Download Elastic Agent on your Windows VM
# In Kibana: Fleet -> Agent policies -> Create policy -> Add agent
# Follow the enrollment command shown in the UI, e.g.:
.\elastic-agent.exe install --url=https://YOUR_KIBANA:8220 --enrollment-token=TOKEN_FROM_UI

# Install Sysmon with a community config for rich event telemetry
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# The Elastic Agent will automatically pick up Sysmon events (EventID 1, 3, 7, 8, etc.)
```

**Enable pre-built detection rules in Kibana:**

```
Security -> Rules -> Detection Rules (SIEM) -> Load Elastic prebuilt rules and timeline templates
```

Elastic ships with 700+ pre-built detection rules covering MITRE ATT&CK techniques. Enable the rules relevant to your lab (Windows process execution, credential access, lateral movement) and then simulate those techniques to trigger alerts.

### Option 4: Velociraptor for Endpoint Forensics and Threat Hunting

[Velociraptor](https://github.com/Velocidex/velociraptor) is an open-source endpoint detection and response (EDR) platform built for forensics and threat hunting. It uses a powerful query language called VQL (Velociraptor Query Language) to collect and analyze endpoint data in real time.

```bash
# Download the latest release from https://github.com/Velocidex/velociraptor/releases
# On your server VM (Ubuntu):
chmod +x velociraptor-linux-amd64

# Generate a self-signed config (for lab use)
./velociraptor-linux-amd64 config generate > server.config.yaml

# Create an admin user
./velociraptor-linux-amd64 --config server.config.yaml user add admin --role administrator

# Start the server
./velociraptor-linux-amd64 --config server.config.yaml frontend
# Web UI at https://YOUR_SERVER_IP:8889
```

**Deploy the Windows client:**

```powershell
# Generate a client config from the server (download from Velociraptor UI: Clients -> Add client)
# Then on the Windows target VM:
.\velociraptor-windows-amd64.exe --config client.config.yaml service install
```

**Key Velociraptor capabilities to practice:**

```vql
-- Hunt for persistence mechanisms across all endpoints
SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()

-- Collect all scheduled tasks
SELECT * FROM Artifact.Windows.System.ScheduledTasks()

-- Find recently modified files in temp directories (common malware indicator)
SELECT FullPath, Mtime, Atime, Ctime, Size
FROM glob(globs="C:\\Users\\*\\AppData\\Local\\Temp\\*.exe")
WHERE Mtime > now() - 86400  -- Last 24 hours

-- Check for common credential dumping artifacts
SELECT * FROM Artifact.Windows.Detection.Amcache()
```

> **Why Velociraptor for beginners:** Unlike full SIEMs, Velociraptor has a gentle learning curve while teaching fundamental EDR concepts. You can immediately run forensic artifacts against live endpoints and see results — no complex ingestion pipeline required.

### Building a Detection Engineering Workflow

Combine the above tools into a repeatable workflow for developing detections:

```
1. ATTACK  → Perform a specific technique (e.g., Kerberoasting, LSASS dump, WMI persistence)
2. COLLECT → Gather logs from Sysmon, Windows Event Log, Zeek network logs, EDR telemetry
3. IDENTIFY → Find what log events were generated by the attack
4. WRITE   → Create a detection rule (Sigma, Splunk SPL, KQL, Suricata rule)
5. TEST    → Replay the attack, confirm the rule fires; tune to reduce false positives
6. SHARE   → Convert Sigma rules to platform-specific formats and share on GitHub
```

**Sigma rule example** (generic format, converts to Splunk/Elastic/QRadar):

```yaml
title: Suspicious LSASS Access (Credential Dumping)
id: 5ef4b701-0b16-4d74-b4e4-b96f07c58f24
status: experimental
description: Detects a process opening LSASS memory with access rights typical of credential dumping
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: YourName
date: 2024/01/01
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x147a'
      - '0x1fffff'
  filter_legitimate:
    SourceImage|contains:
      - '\MsMpEng.exe'        # Windows Defender
      - '\csrss.exe'
      - '\wininit.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - Legitimate security software
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
```

Convert with `sigma convert -t splunk -p sysmon rule.yml` (using the sigma-cli tool).

---

*Guide maintained as part of the TeamStarWolf cybersecurity education repository.*
