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

*Guide maintained as part of the TeamStarWolf cybersecurity education repository.*
