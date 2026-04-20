# Enterprise Infrastructure Reference

> A practical reference for security practitioners covering the operating systems, server roles, networking components, and technology stacks present in enterprise environments. Understanding what you are working with — and what it does — is a prerequisite for both attacking and defending it effectively.

---

## Table of Contents

- [1. Enterprise Operating Systems](#1-enterprise-operating-systems)
- [2. Server Roles & Functions](#2-server-roles--functions)
- [3. Network Infrastructure Components](#3-network-infrastructure-components)
- [4. Directory Services & Identity](#4-directory-services--identity)
- [5. Virtualization & Cloud Platforms](#5-virtualization--cloud-platforms)
- [6. Database Systems](#6-database-systems)
- [7. Enterprise Applications](#7-enterprise-applications)
- [8. Security Relevance by Component](#8-security-relevance-by-component)

---

## 1. Enterprise Operating Systems

### Windows Server

Windows Server is the dominant server operating system in enterprise environments globally, particularly in organizations using Microsoft's identity, email, and collaboration stack. It is the primary platform for Active Directory, DNS, DHCP, file sharing, and enterprise application hosting on Windows.

| Version | Released | Support Status | Notes |
|---|---|---|---|
| **Windows Server 2025** | 2024 | Current (mainstream support) | Latest release; enhanced AD DS, improved security baselines, Credential Guard by default |
| **Windows Server 2022** | 2021 | Current (mainstream support) | Secured-core server features; improved TLS 1.3 enforcement; the current standard in new deployments |
| **Windows Server 2019** | 2018 | Current (extended support until 2029) | Windows Defender ATP integration; highly deployed; common target in pentest engagements |
| **Windows Server 2016** | 2016 | Extended support until 2027 | First version with Windows Defender built-in; Nano Server introduced |
| **Windows Server 2012 / R2** | 2012/2013 | Extended support ended October 2023 | Still present in legacy environments; no longer receiving security updates |
| **Windows Server 2008 / R2** | 2008/2009 | End of life (ESU available) | Common in air-gapped or legacy OT environments; high-value pentest target |

**Security relevance:**
- Windows Server hosts Active Directory Domain Services (AD DS), making it the primary target for credential attacks (Pass-the-Hash, Kerberoasting, DCSync)
- EOL versions (2008/2012) run without security patches and are often the path of least resistance in internal networks
- Default configurations change significantly between versions — understanding which version is running informs which attacks are likely to succeed

---

### Windows Client

Windows workstations represent the most common end-user computing platform in enterprise environments and are the primary initial access target.

| Version | Notes |
|---|---|
| **Windows 11** | Current consumer and enterprise desktop; hardware TPM 2.0 required; Credential Guard enabled by default on supported hardware |
| **Windows 10** | Most widely deployed enterprise desktop; long-term support variants (LTSC) in specialized environments; mainstream support ended October 2025 |
| **Windows 7** | End of life January 2020; still present in kiosk, industrial, and legacy environments; no security patches without ESU |

---

### Linux Distributions in Enterprise

Linux is the dominant platform for web servers, containerized workloads, databases, and cloud infrastructure. Security practitioners encounter several major distributions, each with distinct package management, service management, and hardening toolchains.

| Distribution | Family | Common Use Case | Package Manager |
|---|---|---|---|
| **Red Hat Enterprise Linux (RHEL)** | RPM/DNF | Enterprise servers; financial, government, healthcare environments requiring long-term support and vendor certification | `dnf` / `yum` |
| **CentOS Stream** | RPM/DNF | RHEL-adjacent; rolling update model; replaced traditional CentOS 7/8 | `dnf` |
| **Rocky Linux** | RPM/DNF | RHEL binary-compatible replacement for CentOS; popular after CentOS 8 EOL; stable long-term | `dnf` |
| **AlmaLinux** | RPM/DNF | Another RHEL binary-compatible fork; enterprise-grade; CloudLinux foundation | `dnf` |
| **Ubuntu Server (LTS)** | Debian/APT | Cloud instances, DevOps tooling, Kubernetes nodes, web servers; 5-year LTS releases | `apt` |
| **Debian** | Debian/APT | Base for Ubuntu and many container images; extremely stable; common in hosting environments | `apt` |
| **SUSE Linux Enterprise Server (SLES)** | RPM/Zypper | SAP workloads; European enterprise and regulated environments; strong SLES 12/15 deployments | `zypper` |
| **openSUSE Leap / Tumbleweed** | RPM/Zypper | Community equivalent to SLES; Leap tracks SLES releases; common in European organizations | `zypper` |
| **Oracle Linux** | RPM/DNF | Oracle Database hosting; RHEL-compatible with Oracle-specific kernel features | `dnf` |
| **Amazon Linux 2 / AL2023** | RPM | AWS EC2 default image; optimized for AWS performance and integration | `yum` / `dnf` |
| **Alpine Linux** | musl/apk | Container base images; minimal attack surface; distroless-adjacent; Kubernetes pods | `apk` |

**Security relevance:**
- Different distributions use different init systems (systemd vs. SysV init), package managers, SELinux/AppArmor configurations, and default firewall configurations — attackers and defenders must know which they are operating on
- RHEL-family systems use SELinux by default; Debian/Ubuntu use AppArmor — both enforce mandatory access controls that affect privilege escalation paths
- Container base images (Alpine, Distroless) minimize the available tooling for living-off-the-land; attackers must bring their own binaries

---

### macOS in Enterprise

macOS is prevalent in technology companies, creative industries, and organizations that have adopted Apple Business Manager for fleet management. It is increasingly common as a developer workstation.

| Version | Notes |
|---|---|
| **macOS Sequoia (15)** | Current release; new security features; Gatekeeper improvements |
| **macOS Sonoma (14)** | Widely deployed; improved MDM management; common in tech companies |
| **macOS Ventura (13)** | First with Rapid Security Response updates |

**Management stack:** Most enterprises manage macOS via Jamf Pro, Mosyle, or Microsoft Intune with Apple Business Manager enrollment.

**Security relevance:**
- macOS systems are often lightly monitored compared to Windows in mixed environments
- EDR coverage varies; not all enterprise EDR platforms have full macOS parity
- Gatekeeper, SIP (System Integrity Protection), and TCC (Transparency, Consent, and Control) provide meaningful defensive layers but have been bypassed in multiple CVEs
- Developer credentials (SSH keys, cloud tokens, GitHub personal access tokens) are frequently stored in macOS Keychain or `~/.ssh/`

---

### Unix Variants

Legacy and specialized Unix systems appear in financial services, telecommunications, manufacturing, and high-performance computing environments.

| System | Notes |
|---|---|
| **IBM AIX** | POWER architecture Unix; common in banking and financial institutions; unique filesystem (JFS2) and service management |
| **Oracle Solaris** | SPARC and x86 Unix; Zones (containers), ZFS, DTrace; legacy deployments in telecommunications and financial firms |
| **HP-UX** | HPE Integrity/Itanium servers; rare but present in legacy healthcare and manufacturing |
| **FreeBSD** | Used in network appliances (pfSense, OPNsense, some firewalls); Netflix CDN nodes; Sony PlayStation OS |

---

### Embedded & Specialized Operating Systems

| System | Context |
|---|---|
| **VxWorks** | Real-time OS in industrial control systems, medical devices, aerospace; common ICS/OT target |
| **QNX** | RTOS in automotive systems, medical devices; POSIX-compliant |
| **Windows Embedded / IoT** | Point-of-sale terminals, ATMs, kiosks, medical devices; often runs Windows XP or Windows 7 codebase |
| **Cisco IOS / IOS-XE / NX-OS** | Cisco network device operating systems; CLI-based management; common in enterprise routing and switching |
| **Junos OS** | Juniper Networks OS; routing, switching, security gateways |
| **FortiOS** | Fortinet firewall/UTM appliance OS |
| **Palo Alto PAN-OS** | Palo Alto Networks NGFW OS |

---

## 2. Server Roles & Functions

### Domain Controller (DC)

The **Domain Controller** is the most critical server in a Windows Active Directory environment. It authenticates users and computers, enforces Group Policy, and hosts the AD database (NTDS.DIT). Every Windows domain has at least two DCs for redundancy.

**What it runs:** Windows Server with Active Directory Domain Services (AD DS)
**Why it is targeted:** Compromising a DC provides access to every credential hash in the domain (via DCSync), the ability to create persistence tickets (Golden/Silver Tickets), and full control over every domain-joined machine.
**Key ports:** 389 (LDAP), 636 (LDAPS), 88 (Kerberos), 135/445 (RPC/SMB), 464 (Kerberos password change), 3268/3269 (Global Catalog)

---

### Web Server

Web servers host applications accessible over HTTP/HTTPS, serving static content, dynamic applications, and APIs. They represent one of the largest internet-exposed attack surfaces in any organization.

| Software | Platform | Notes |
|---|---|---|
| **Apache HTTP Server** | Linux/Unix | The most widely deployed open source web server; `mod_*` architecture; config in `/etc/apache2/` or `/etc/httpd/` |
| **Nginx** | Linux/Unix | Event-driven architecture; high performance; commonly used as reverse proxy in front of application servers; config in `/etc/nginx/` |
| **Microsoft IIS (Internet Information Services)** | Windows | Windows-native web server; integrated Windows authentication; hosts .NET and ASP.NET applications; managed via IIS Manager |
| **Caddy** | Linux/Windows | Modern web server with automatic HTTPS via Let's Encrypt; growing in DevOps deployments |
| **Apache Tomcat** | Java/Cross-platform | Java Servlet container; hosts Java web applications (WAR files); the application server behind many enterprise Java stacks |
| **JBoss / WildFly** | Java/Cross-platform | Red Hat enterprise Java application server; common in financial and healthcare enterprise Java deployments |
| **WebLogic** | Java/Cross-platform | Oracle enterprise Java application server; frequent CVE target; common in large enterprise and government |
| **WebSphere** | Java/Cross-platform | IBM enterprise Java application server; common in financial services and large enterprise |

**Security relevance:** Web servers are almost always internet-exposed, making them the primary target for initial access. Configuration errors (directory traversal, server-side includes), application vulnerabilities, and outdated versions account for a significant portion of external breaches.

---

### Database Server

Database servers store and serve structured data. They are the ultimate target for data exfiltration and are frequently attacked through SQL injection, credential theft, and misconfigured network access.

| Database | Type | Common Use Case |
|---|---|---|
| **Microsoft SQL Server (MSSQL)** | Relational | Windows enterprise applications; ERP systems; can execute OS commands via `xp_cmdshell` — a critical misconfiguration to audit |
| **MySQL / MariaDB** | Relational | Web application backends; LAMP/LEMP stacks; most common open source RDBMS |
| **PostgreSQL** | Relational | Modern applications; JSON support; increasing enterprise adoption; `COPY TO/FROM` allows file system interaction |
| **Oracle Database** | Relational | Financial services, ERP (Oracle E-Business Suite, SAP); high-value target; complex privilege model |
| **IBM Db2** | Relational | IBM mainframe and enterprise environments; financial services; complex but high-value target |
| **MongoDB** | Document (NoSQL) | Unstructured/semi-structured data; web applications; historically misconfigured with no authentication in default installs |
| **Redis** | Key-Value (In-Memory) | Caching layer; session storage; frequently exposed without authentication on internal networks; supports arbitrary file writes |
| **Elasticsearch** | Search/Analytics | Log storage, SIEM backends, full-text search; historically exposed with no authentication in default configurations |
| **Apache Cassandra** | Wide-Column (NoSQL) | High-scale distributed data; telecommunications, IoT; CQL interface similar to SQL |

---

### File Server / Storage

File servers provide shared storage accessed by workstations and servers over network protocols. They are repositories for sensitive documents, configuration files, and credentials.

| Role | Protocol | Notes |
|---|---|---|
| **Windows File Server** | SMB (445), NetBIOS (139) | Windows sharing via SMB; subject to NTLM relay attacks, Pass-the-Hash, and SMBGhost (CVE-2020-0796) on unpatched servers |
| **NFS Server** | NFS (2049) | Unix/Linux file sharing; `no_root_squash` misconfiguration allows privilege escalation from mounted shares |
| **SharePoint** | HTTPS/SMB | Microsoft document management and collaboration; often stores sensitive data and credentials in plaintext lists |
| **Samba** | SMB | Linux/Unix SMB server; joins Windows domains; SambaCry (CVE-2017-7494) was a critical RCE vulnerability |

---

### Email Server

Email infrastructure is a primary attack vector for phishing and a target for data exfiltration.

| System | Notes |
|---|---|
| **Microsoft Exchange** | On-premises email; directly connected to Active Directory; ProxyLogon (CVE-2021-26855) and ProxyShell (CVE-2021-34473) were mass-exploited |
| **Microsoft 365 (Exchange Online)** | Cloud email; MFA bypass via legacy protocols (SMTP AUTH, IMAP, POP) is a persistent misconfiguration issue |
| **Postfix / Sendmail** | Linux MTA; internet-facing mail relays; open relay misconfiguration allows spam/phishing through trusted infrastructure |
| **Zimbra** | Open source email suite; multiple critical CVEs; common in mid-market organizations |

---

### DNS Server

The Domain Name System is fundamental to every network operation. DNS servers translate hostnames to IP addresses and are targets for cache poisoning, zone transfer enumeration, and DNS tunneling.

| System | Notes |
|---|---|
| **Microsoft DNS** | Integrated with Active Directory; zone transfers reveal internal host inventory; DNS dynamic update abuse (ADIDNS) |
| **BIND (Berkeley Internet Name Domain)** | The most widely deployed DNS server on Linux; `named`; zone transfer (AXFR) allowed from any host is a common misconfiguration |
| **Unbound** | Validating, recursive resolver; common as an internal resolver |
| **PowerDNS** | Feature-rich DNS server with database backends; common in MSP and hosting environments |

---

### DHCP Server

The Dynamic Host Configuration Protocol server assigns IP addresses, subnet masks, default gateways, and DNS servers to network clients. DHCP starvation and rogue DHCP attacks exploit this role.

| System | Notes |
|---|---|
| **Windows DHCP Server** | Microsoft DHCP role; integrated with DNS for dynamic updates; DHCP logs are valuable for incident response |
| **ISC DHCP / Kea** | Linux DHCP servers; common in mixed or Linux-heavy environments |
| **Cisco IOS DHCP** | DHCP built into Cisco routers and switches for smaller deployments |

---

### Authentication & Identity Servers

| System | Purpose | Notes |
|---|---|---|
| **Active Directory Domain Services** | Windows domain authentication and authorization | The central identity authority for Windows environments; Kerberos and NTLM authentication |
| **LDAP Server (OpenLDAP)** | Lightweight Directory Access Protocol | Linux identity directory; provides authentication for Linux systems, applications, VPNs, and network devices |
| **RADIUS Server (FreeRADIUS, NPS)** | Remote Authentication Dial-In User Service | Network access authentication; WiFi, VPN, 802.1X — credential capture via rogue AP attacks |
| **CAS / SAML / OAuth IdP** | Web single sign-on | Okta, Shibboleth, Keycloak, ADFS — federated identity for web applications; target for token theft and SSO bypass |
| **PKI / Certificate Authority** | Certificate issuance and management | Microsoft ADCS, Let's Encrypt, HashiCorp Vault PKI; ESC1-ESC8 vulnerabilities in misconfigured ADCS allow privilege escalation |

---

### VPN & Remote Access Servers

| System | Protocol | Notes |
|---|---|---|
| **Cisco ASA / FTD** | SSL VPN, IPsec | Widely deployed enterprise VPN; multiple critical CVEs (ASA heap overflow, ASDM web interface vulnerabilities) |
| **Palo Alto GlobalProtect** | SSL VPN | Pan-OS vulnerabilities; CVE-2024-3400 (PAN-OS command injection) was mass-exploited |
| **Fortinet FortiGate SSL VPN** | SSL VPN | CVE-2023-27997, CVE-2022-42475 exploited by threat actors; high-value initial access target |
| **Pulse Secure / Ivanti Connect Secure** | SSL VPN | Multiple credential theft CVEs widely exploited by APTs; CVE-2021-22893 was a zero-day |
| **Citrix NetScaler / ADC** | SSL VPN, load balancing | CVE-2023-3519 (Citrix Bleed) was mass-exploited for credential extraction |
| **OpenVPN** | SSL/TLS VPN | Open source; common in SMB and DevOps environments |
| **WireGuard** | Modern VPN | Lightweight; kernel-integrated on Linux; growing enterprise adoption |

---

### Monitoring & Logging Infrastructure

| System | Purpose | Notes |
|---|---|---|
| **Splunk** | SIEM / log management | Enterprise standard for security operations; SPL query language; stores security events from across the environment |
| **Microsoft Sentinel** | Cloud-native SIEM | Azure-hosted; KQL queries; cost-effective for Microsoft-heavy environments |
| **Elastic SIEM** | SIEM / log management | ELK stack; open source with commercial tiers; high deployment volume |
| **IBM QRadar** | SIEM | Dominant in financial and regulated industries |
| **Prometheus / Grafana** | Infrastructure monitoring | Metric collection and visualization; common in DevOps; rarely security-monitored but contains sensitive infrastructure data |
| **Nagios / Zabbix / PRTG** | Network monitoring | Infrastructure health monitoring; often under-secured; contains network topology and credentials |
| **Syslog servers** | Log aggregation | Rsyslog, syslog-ng; collect system logs from Linux/network devices; tampering with syslog is a defense evasion technique |

---

## 3. Network Infrastructure Components

| Device | Function | Security Notes |
|---|---|---|
| **Firewall (NGFW)** | Stateful packet filtering, application control, IPS | The network perimeter; Palo Alto, Fortinet, Cisco ASA; misconfigured rules are the primary weakness |
| **Router** | Layer 3 packet forwarding between networks | Cisco IOS, Junos; routing protocol attacks (BGP hijacking, OSPF manipulation) in advanced intrusions |
| **Switch** | Layer 2 frame forwarding within networks | VLAN segmentation; VLAN hopping, 802.1Q double-tagging, MAC flooding attack vectors |
| **Load Balancer** | Distributes traffic across backend servers | F5 BIG-IP, Nginx, HAProxy; vulnerabilities in management interfaces; TMC vulnerability (CVE-2022-1388) was critical |
| **Proxy Server** | Intermediary for outbound web traffic | Blue Coat, Squid, Zscaler; SSL inspection breaks end-to-end encryption for DLP; proxy bypass via alternative ports/protocols |
| **WAF (Web Application Firewall)** | Filters malicious HTTP traffic | Imperva, Cloudflare, AWS WAF, ModSecurity; bypass techniques include encoding, chunked transfer, and HTTP/2 |
| **IDS/IPS** | Intrusion Detection/Prevention System | Suricata, Snort, Cisco Firepower; signature-based detection; NIDS generates high false positive volumes without tuning |
| **Email Gateway** | Filters inbound and outbound email | Proofpoint, Mimecast, Microsoft Defender for O365; SPF/DKIM/DMARC validation; email sandbox analysis |

---

## 4. Directory Services & Identity

### Active Directory

Active Directory (AD) is Microsoft's directory service, providing authentication, authorization, and policy enforcement for Windows domain environments. It is the backbone of identity in the majority of enterprise networks.

**Key components:**
- **Domain**: Logical grouping of AD objects (users, computers, groups) sharing a common namespace and security policy
- **Forest**: The highest-level AD container; multiple domains can share a forest; forest trusts are a critical attack path
- **Organizational Unit (OU)**: Container for organizing AD objects; Group Policy is applied at the OU level
- **Group Policy (GPO)**: Configuration and security policy applied to users and computers; script execution, software deployment, security settings
- **NTDS.DIT**: The Active Directory database file stored on Domain Controllers at `%SystemRoot%\NTDS\NTDS.DIT`; contains all user account password hashes
- **SYSVOL**: Shared folder replicated across all DCs containing Group Policy templates; historically contained plaintext passwords in GPP XML files

**Attack surface summary:** AD is the most comprehensively attacked component in enterprise environments. BloodHound (attack path mapping), Mimikatz (credential extraction), and Impacket (Kerberos and NTLM attacks) represent the standard offensive toolkit.

---

### Azure Active Directory / Microsoft Entra ID

Microsoft Entra ID is the cloud identity platform that extends (and in cloud-only organizations, replaces) on-premises Active Directory. It provides authentication for Microsoft 365, Azure, and thousands of third-party SaaS applications via SAML, OAuth 2.0, and OpenID Connect.

**Key concepts:**
- **Tenant**: An organization's Entra ID instance; globally unique; associated with a primary domain
- **Managed Identity**: Azure resource (VM, function app, etc.) with an automatically managed identity; no stored credentials; eliminates secret sprawl
- **Conditional Access**: Policy-based access control that evaluates context (device compliance, location, risk score) before granting access
- **Privileged Identity Management (PIM)**: Just-in-time privileged access; requires activation with approval and justification for sensitive roles

---

## 5. Virtualization & Cloud Platforms

### Hypervisors

| Platform | Type | Notes |
|---|---|---|
| **VMware vSphere / ESXi** | Type 1 (bare-metal) | Dominant enterprise hypervisor; vCenter for centralized management; ESXiArgs ransomware exploited CVE-2021-21974 at scale |
| **Microsoft Hyper-V** | Type 1 (bare-metal / Type 2 hybrid) | Built into Windows Server; Azure uses Hyper-V at its foundation; Hyper-V escape vulnerabilities are critical severity |
| **KVM (Kernel-based Virtual Machine)** | Type 1 (Linux kernel) | Linux hypervisor; foundation for OpenStack, most cloud providers; managed via libvirt/virt-manager |
| **Proxmox VE** | Type 1 (KVM + LXC) | Popular open source virtualization platform; common in home labs and SMB environments |
| **Citrix Hypervisor (XenServer)** | Type 1 (Xen-based) | Used in Citrix DaaS environments; VDI infrastructure |

### Cloud Platforms

| Platform | Notes |
|---|---|
| **Amazon Web Services (AWS)** | Dominant public cloud; EC2, S3, IAM, VPC, Lambda; GuardDuty for threat detection; 200+ services |
| **Microsoft Azure** | Second-largest cloud; tight Microsoft ecosystem integration; Entra ID, Sentinel, Defender for Cloud |
| **Google Cloud Platform (GCP)** | Third-largest; strong in AI/ML workloads; Security Command Center; BeyondCorp zero trust model |
| **Oracle Cloud Infrastructure (OCI)** | Oracle Database workloads; strong in regulated industries |
| **IBM Cloud** | Financial services and mainframe workloads; IBM Z hybrid integration |

---

## 6. Database Systems

See [Server Roles & Functions — Database Server](#database-server) for the full database reference.

**Quick security reference:**

| Database | Default Port | Key Attack Surface |
|---|---|---|
| MSSQL | 1433 | `xp_cmdshell`, linked server abuse, NTLM relay via UNC path injection |
| MySQL / MariaDB | 3306 | Weak credentials, User-Defined Functions (UDF) for OS command execution |
| PostgreSQL | 5432 | `COPY TO/FROM PROGRAM` OS command execution, `pg_read_file()` |
| Oracle | 1521 | TNS listener abuse, Java stored procedures, UTL_FILE |
| MongoDB | 27017 | No authentication by default in older versions; exposed on public internet |
| Redis | 6379 | No authentication by default; `SLAVEOF` replication to attacker; file write via `CONFIG SET dir` |
| Elasticsearch | 9200 | No authentication by default in versions prior to 6.x; exposed on public internet historically |

---

## 7. Enterprise Applications

| Application | Category | Security Notes |
|---|---|---|
| **Microsoft 365 (Exchange, SharePoint, Teams)** | Productivity suite | Business email compromise target; OAuth app consent phishing; sensitive data in Teams channels and SharePoint |
| **SAP ERP** | Enterprise Resource Planning | Stores financial, HR, and operational data; SAP Message Server and ICM web services have been exploited; RFC calls can execute OS commands |
| **Salesforce** | CRM | Contains customer PII and sales data; over-permissive sharing rules expose records to any authenticated user |
| **ServiceNow** | IT Service Management | Access request data, configuration items (CMDB); unauthenticated ACL misconfigurations have exposed sensitive records publicly |
| **Confluence / Jira (Atlassian)** | Collaboration / Issue Tracking | CVE-2023-22518, CVE-2022-26134 were critical RCEs exploited at scale; often contains passwords, network diagrams, and architecture documentation |
| **Jenkins** | CI/CD | Frequently misconfigured with no authentication; `Script Console` allows arbitrary Groovy code execution; holds deployment credentials |
| **GitLab / GitHub Enterprise** | Source Code Management | Source code, secrets in repositories, CI/CD pipeline tokens; SSRF and authentication bypass CVEs have been exploited |
| **Kubernetes** | Container Orchestration | See [Container & Kubernetes Security](disciplines/container-kubernetes-security.md) |

---

## 8. Security Relevance by Component

| Component | Primary Risk | Key ATT&CK Techniques |
|---|---|---|
| Domain Controller | Credential theft, domain compromise | T1003.006 (DCSync), T1558 (Kerberos), T1550.002 (Pass-the-Hash) |
| Web Server | Initial access via vulnerability | T1190 (Exploit Public-Facing Application), T1059 (Command Execution) |
| Database Server | Data exfiltration, command execution | T1190, T1005 (Data from Local System), T1041 (Exfiltration over C2) |
| VPN/Remote Access | Initial access via credential or CVE | T1133 (External Remote Services), T1078 (Valid Accounts) |
| Email Server | Phishing delivery, BEC | T1566 (Phishing), T1114 (Email Collection) |
| File Server | Sensitive data discovery | T1039 (Data from Network Shared Drive), T1021.002 (SMB/Windows Admin Shares) |
| Hypervisor | VM escape, ransomware | T1611 (Escape to Host), T1486 (Data Encrypted for Impact) |
| Identity Server (AD/Entra) | Privilege escalation, persistence | T1078.002 (Domain Accounts), T1484 (Domain Policy Modification) |
| Monitoring Infrastructure | Defense evasion (log tampering) | T1562.001 (Disable or Modify Tools), T1070 (Indicator Removal) |
| CI/CD Pipeline | Supply chain compromise | T1195.002, T1552.001 (Credentials In Files) |

---

## Related Resources

- [CLOUD_ATTACK_REFERENCE.md](CLOUD_ATTACK_REFERENCE.md) — Cloud-specific attack techniques for AWS, Azure, and GCP
- [PRIVESC_REFERENCE.md](PRIVESC_REFERENCE.md) — Privilege escalation techniques by platform
- [disciplines/active-directory.md](disciplines/active-directory.md) — Active Directory security discipline
- [disciplines/network-security.md](disciplines/network-security.md) — Network security discipline
- [disciplines/cloud-security.md](disciplines/cloud-security.md) — Cloud security discipline
- [disciplines/identity-access-management.md](disciplines/identity-access-management.md) — Identity and access management discipline
- [HOMELAB_SETUP.md](HOMELAB_SETUP.md) — Building lab environments to practice with these systems
