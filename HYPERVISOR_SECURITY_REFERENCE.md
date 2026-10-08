# Hypervisor & Virtualization Hardening Reference

> In one minute: The hypervisor is the single most valuable ransomware pivot in the modern enterprise: one compromised ESXi host or vCenter can encrypt every VM at once, below the guest OS where EDR cannot see. This reference maps the virtualization attack surface (VMware ESXi/vSphere, Microsoft Hyper-V, Proxmox VE, KVM/QEMU), walks the ESXi ransomware kill chain end to end, catalogs the CVEs actually exploited in the wild (2019-2026), and gives concrete, defender-framed hardening: lockdown mode, management-plane isolation, MFA/RBAC, Secure Boot/TPM, VM encryption, patch/lifecycle, and backup/recovery for virtual estates. Use it to harden a virtual estate before an incident and to answer "is our hypervisor a soft target?"

| | |
|---|---|
| Read this when | you are hardening a VMware/Hyper-V/Proxmox estate, a ransomware IR touched the hypervisor layer, you are scoping vCenter/ESXi patch exposure, or you are designing management-plane isolation and backup immutability for virtual infrastructure |
| Start at | [Why the Hypervisor Is the Bullseye](#why-the-hypervisor-is-the-bullseye), [The ESXi Ransomware Kill Chain](#the-esxi-ransomware-kill-chain), [Exploited Hypervisor CVEs](#exploited-hypervisor-cves-2019-2026), [ESXi / vSphere Hardening](#vmware-esxi--vsphere-hardening) |
| Pairs with | [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md), [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md), [ENTERPRISE_INFRASTRUCTURE.md](ENTERPRISE_INFRASTRUCTURE.md), [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md), [CONTAINER_SECURITY_REFERENCE.md](CONTAINER_SECURITY_REFERENCE.md) |

---

## Why the Hypervisor Is the Bullseye

Type-1 (bare-metal) hypervisors run *beneath* every guest OS. That position is exactly what makes them the highest-leverage target in a modern intrusion:

- One host, many victims. Encrypting a datastore or the underlying VMDK files takes down every VM on that host or cluster in a single action: dozens to hundreds of servers at once. Attackers describe vSphere as offering "immediate and widespread infrastructure paralysis."
- Below the security stack. EDR/AV runs *inside* guests. A locker that runs on the ESXi hypervisor shell shuts VMs down and encrypts virtual disks directly, "bypassing all Windows OS security"; no in-guest agent ever sees it.
- Flat, under-monitored management plane. vCenter, ESXi host management, IPMI/iLO/iDRAC, and backup consoles are frequently reachable from the same network as workstations, rarely have MFA, and are often excluded from patch SLAs.
- Sparse native logging. Host-to-guest operations and hypervisor shell activity historically produce little telemetry, and attackers actively delete core dumps and logs to hide (e.g., removing `vmdird` core dumps after a vCenter crash).

Ransomware groups have made the hypervisor a primary objective since ~2020, and the pattern accelerated through 2023-2026 as edge/identity intrusions increasingly pivot straight to vSphere. Defenders should treat the virtualization control plane as Tier-0 infrastructure, on par with Active Directory.

---

## Attack Surface at a Glance

| Layer | Examples | Primary exposure | Defender priority |
|---|---|---|---|
| Management plane | vCenter Server, ESXi host UI/API, Hyper-V Manager/SCVMM, Proxmox web UI (8006) | Unauthenticated RCE, auth bypass, weak/no MFA | Isolate to a management VLAN/PAW; MFA; patch fast |
| Hypervisor host | ESXi hostd/vpxa, SLP (427), CIM, DCUI, SSH/ESXi Shell | RCE via exposed services; VM escape; malicious VIBs | Lockdown mode; Secure Boot; disable SLP/SSH; execInstalledOnly |
| Guest <-> host channel | VMware Tools guest ops, `StartProgramInGuest` APIs | Auth-bypass command execution into guests (T1675) | Patch Tools; restrict vSphere API roles; log guest ops |
| Storage / datastores | VMFS/NFS datastores, VMDK files, vSAN | Direct encryption of virtual disks | Immutable backups; storage segmentation; snapshots |
| Identity integration | ESXi/vCenter AD or SSO join, Kerberos | AD-group auth bypass; harvested admin creds | Decouple from prod AD; least privilege; MFA on SSO |

---

## The ESXi Ransomware Kill Chain

A composite of real campaigns (ESXiArgs, Akira, Black Basta, Scattered Spider/DragonForce, RansomHub, Qilin). Each stage lists the defense that breaks it.

| # | Attacker stage | Representative technique | Break it with |
|---|---|---|---|
| 1 | Initial access: phishing, help-desk social engineering, or edge/VPN exploit | T1566, T1190, T1133, T1078 | Phishing-resistant MFA; help-desk identity-proofing; patch edge |
| 2 | Foothold & recon: find vCenter/ESXi, dump creds | T1087, T1003, T1018 | EDR on jump hosts; segment mgmt discovery; LAPS |
| 3 | Reach the control plane: pivot to vCenter / management VLAN | T1021, T1210 | Management-plane isolation; deny flat access; jump/PAW only |
| 4 | Gain hypervisor admin: valid vCenter creds, or AD-group auth bypass (CVE-2024-37085) | T1078, T1068 | Decouple ESXi from prod AD; MFA on vCenter SSO; patch |
| 5 | Impair defenses & recovery: stop services, delete snapshots/backups | T1685, T1490, T1489 | Immutable/offline backups; separate backup identity; alerting |
| 6 | Detonate: enable SSH, power off VMs, encrypt VMDK/datastore | T1675, T1529, T1486 | Lockdown mode; disable ESXi Shell/SSH; execInstalledOnly; file-integrity |
| 7 | Extort: double extortion with prior data theft | T1567, T1657 | Egress control; DLP; tested clean-room recovery |

> Key insight: stages 3-6 all live in the virtualization control plane. The controls that matter most are management-plane isolation, not joining ESXi to production AD, and immutable backups, not another in-guest agent.

---

## Exploited Hypervisor CVEs (2019-2026)

All entries below have documented in-the-wild exploitation. Verify current fixed builds against the vendor advisory before relying on any version string.

| CVE | Product | Type / vector | CVSS | In-the-wild use | Source |
|---|---|---|---|---|---|
| CVE-2025-22224 | ESXi, Workstation, Fusion | TOCTOU -> out-of-bounds write; VM->host code exec as VMX | 9.3 | Zero-day chain; ransomware & espionage (2025-2026) | [Broadcom VMSA-2025-0004](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/25390), [Tenable](https://www.tenable.com/blog/cve-2025-22224-cve-2025-22225-cve-2025-22226-zero-day-vulnerabilities-in-vmware-esxi) |
| CVE-2025-22225 | ESXi | Arbitrary write -> sandbox escape | 8.2 | CISA-confirmed ransomware exploitation (Feb 2026) | [Help Net Security](https://www.helpnetsecurity.com/2026/02/05/cisa-cve-2025-22225-ransomware-exploitation/) |
| CVE-2025-22226 | ESXi, Workstation, Fusion | Info disclosure (VMX memory leak) | 7.1 | Part of the same zero-day toolkit | [Rapid7](https://www.rapid7.com/blog/post/2025/03/04/etr-multiple-zero-day-vulnerabilities-in-broadcom-vmware-esxi-and-other-products/) |
| CVE-2024-38812 | vCenter Server | DCERPC heap overflow -> unauth RCE | 9.8 | Actively exploited; patch re-issued after incomplete fix | [Broadcom VMSA-2024-0019](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24968) |
| CVE-2024-37085 | ESXi | AD "ESX Admins" group auth bypass -> full host admin | 6.8 | Storm-0506, Storm-1175, Octo Tempest, Manatee Tempest ransomware | [Rapid7](https://www.rapid7.com/blog/post/2024/07/30/vmware-esxi-cve-2024-37085-targeted-in-ransomware-campaigns/) |
| CVE-2023-34048 | vCenter Server | DCERPC out-of-bounds write -> unauth RCE | 9.8 | UNC3886 espionage since ~late 2021 (undetected ~1.5 yrs) | [Mandiant/Security Affairs](https://securityaffairs.com/157769/apt/unc3886-exploits-vcenter-server-zero-day-cve-2023-34048.html) |
| CVE-2023-20867 | VMware Tools | Host->guest auth bypass (no guest creds needed) | 3.9 | UNC3886 to push VIRTUALPITA/VIRTUALPIE into guests | [Mandiant/Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/vmware-esxi-zero-day-bypass/) |
| CVE-2021-21974 | ESXi | OpenSLP heap overflow (port 427) -> RCE | 8.8 | ESXiArgs mass campaign, Feb 2023 (CERT-FR) | [Rapid7 VMSA-2021-0002](https://www.rapid7.com/db/vulnerabilities/vmsa-2021-0002-cve-2021-21974/) |
| CVE-2020-3992 | ESXi | OpenSLP use-after-free (port 427) -> RCE | 9.8 | RansomExx-style hypervisor encryption | [Rapid7](https://www.rapid7.com/blog/post/2020/11/11/vmware-esxi-openslp-remote-code-execution-vulnerability-cve-2020-3992-and-cve-2019-5544-what-you-need-to-know/) |
| CVE-2019-5544 | ESXi | OpenSLP heap overwrite (port 427) -> RCE | 9.8 | Early hypervisor-direct ransomware | [Rapid7](https://www.rapid7.com/blog/post/2020/11/11/vmware-esxi-openslp-remote-code-execution-vulnerability-cve-2020-3992-and-cve-2019-5544-what-you-need-to-know/) |

Pattern to remember: the OpenSLP trio (2019/2020/2021) drove the *first* wave of ESXi ransomware, which is why SLP is now disabled by default on current ESXi and should be disabled/removed everywhere it is not required. The 2023-2026 wave shifted to vCenter RCE, VMware Tools abuse, AD-integration bypass, and true VM-escape chains. See [CVE_REFERENCE.md](CVE_REFERENCE.md) for KEV status and [THREAT_GROUP_PROFILES.md](THREAT_GROUP_PROFILES.md) for actor detail (UNC3886, Scattered Spider/UNC3944).

---

## VMware ESXi / vSphere Hardening

The authoritative baseline is Broadcom's vSphere Security Configuration Guide (SCG), the renamed "Hardening Guide," published per release at [core.vmware.com/security](https://core.vmware.com/security), complemented by the CIS VMware ESXi 8.0 Benchmark (v1.0.0, Oct 2023) and the DISA vSphere 8.0 ESXi STIG. Licensing context: after Broadcom's acquisition, vSphere ships via subscription (VMware vSphere Foundation / VMware Cloud Foundation); a limited free ESXi returned with ESXi 8.0 Update 3e (2025, no vCenter, capped vCPUs, non-production).

### Access & management plane

- Lockdown mode: set hosts to Strict (or at minimum Normal) so hosts are managed only through vCenter; direct DCUI/host-client/SSH paths are denied, preventing controls from being bypassed by logging into a host directly. Maintain an explicit Exception Users list only where operationally required.
- Disable ESXi Shell and SSH; leave them stopped and set the shell/DCUI idle and availability timeouts. Alert on any enablement: attackers routinely turn SSH on right before detonation.
- Isolate the management network. vCenter, ESXi vmkernel management, IPMI/iLO/iDRAC and backup consoles belong on a dedicated, firewalled management VLAN reachable only from a Privileged Access Workstation (PAW)/jump host. Never expose management interfaces or port 427/SLP to the internet or user VLANs.
- MFA + least-privilege RBAC. Enforce MFA at vCenter SSO / the identity provider (SAML/OIDC). Replace shared root logins with named accounts; scope custom roles tightly; audit `Administrator` and `No cryptography administrator` assignments.

### Trust, boot & software integrity

- UEFI Secure Boot on every host (and for guests where supported) so only signed VIBs/kernel modules load; pair with a TPM 2.0 for host attestation.
- execInstalledOnly advanced setting: block execution of unsigned/unknown binaries on the host, a direct counter to hypervisor-resident lockers and malicious VIBs.
- VIB acceptance level set to `PartnerSupported` or stricter; forbid `CommunitySupported`. Watch for rogue VIBs (a known UNC3886 persistence trick).
- vSphere Trust Authority (vTA) for hardware-rooted remote attestation of a trusted host cluster; vSphere Native Key Provider (included in all editions, no external KMS) or an external KMS for VM Encryption and vTPM to protect guest data at rest.

### Services, patch & lifecycle

- Disable OpenSLP/CIM unless explicitly needed (it is off by default on current builds); minimize the running-service and open-port footprint on each host.
- Patch on a Tier-0 cadence. vCenter and ESXi RCEs are exploited within days and dominate CISA KEV for virtualization. Track Broadcom VMSAs, subscribe to advisories, and use vSphere Lifecycle Manager (vLCM) image-based remediation to keep clusters on a known-good, patched image.
- Retire end-of-life builds. ESXi/vCenter 7.0 reaches end of general support 2 Apr 2027; plan migration to a supported vSphere 8.x / vSphere 9 (VVF/VCF) line rather than running unsupported hosts.
- Harden logging: forward ESXi and vCenter logs to a remote syslog/SIEM so an attacker who wipes local logs/core dumps cannot erase the evidence.

---

## Microsoft Hyper-V Hardening

| Control | What it does | Notes (Windows Server 2022/2025) |
|---|---|---|
| Virtualization-Based Security (VBS) | Uses the hypervisor to isolate a secure kernel from the host OS | Active by default in Windows Server 2025 |
| HVCI (Memory Integrity) | Hypervisor-enforced code integrity: blocks unsigned kernel code | Enabled by default in Server 2025 |
| Credential Guard | VBS-isolates NTLM hashes / Kerberos TGTs from theft | Default on domain-joined, non-DC Server 2025 hosts |
| Secured-core Server | Firmware + VBS + Secure Boot + TPM baseline | Enable on capable hardware for the strongest root of trust |
| Guarded Fabric + Shielded VMs | Host Guardian Service attests hosts; Gen-2 VMs with vTPM/BitLocker only run on healthy, attested hosts | Protects tenant VMs from a rogue host/fabric admin |
| Host isolation | Dedicated management NIC/VLAN; RDP/WinRM restricted to PAWs; JEA/Just-Enough-Admin | Treat Hyper-V hosts as Tier-0 like DCs |

Also: keep hosts Server Core to shrink attack surface, apply Windows security baselines/GPO (see [WINDOWS_HARDENING_REFERENCE.md](WINDOWS_HARDENING_REFERENCE.md)), enable Secure Boot + TPM for Gen-2 guests, and patch the host on the domain-controller cadence.

---

## Proxmox VE / KVM / QEMU / libvirt Hardening

Open-source stacks (Proxmox VE: current 9.2, May 2026, on Debian 13 "Trixie"; note Proxmox VE 8 reaches EOL 31 Aug 2026) and bare KVM/libvirt need the same control-plane discipline:

- Protect the web/API console (Proxmox `:8006`): put it on a management VLAN, front it with a reverse proxy or VPN, enable built-in two-factor authentication (TOTP/WebAuthn), and use realm-based RBAC with least-privilege roles instead of shared root.
- UEFI Secure Boot for hosts and guests (Proxmox ships signed-boot support; validate shim/cert state after major upgrades) plus vTPM for guests that need measured boot/BitLocker.
- sVirt (SELinux/AppArmor) on KVM/QEMU: mandatory-access-control confinement so a compromised QEMU process cannot reach other guests or host resources; keep it enforcing, not permissive.
- seccomp sandboxing and running QEMU as a non-root, per-VM UID; disaggregate device models where possible.
- Patch QEMU/KVM and libvirt promptly for device-emulation escape bugs, and subscribe to distro security advisories. Harden the host OS per [LINUX_HARDENING_REFERENCE.md](LINUX_HARDENING_REFERENCE.md).
- Cluster/quorum hygiene: secure Corosync links, restrict migration networks, and encrypt replication/backup traffic.

---

## Management-Plane Isolation, MFA & RBAC (the non-negotiables)

If you do only five things, do these; they break the 2023-2026 ransomware playbook regardless of vendor:

1. Segment the control plane. vCenter/Hyper-V/Proxmox management, host BMCs, and backup consoles live on an isolated, firewalled network reachable only via PAW/jump hosts. No path from a user workstation to a hypervisor management port.
2. Phishing-resistant MFA on the hypervisor identity provider *and* on the help desk's identity-proofing process (Scattered Spider's initial access is help-desk social engineering, not an exploit).
3. Decouple hypervisors from production AD. ESXi's AD "ESX Admins" bypass (CVE-2024-37085) and harvested domain creds are premier pivots. Use local or dedicated identity, unique admin groups, and least privilege. See [ACTIVE_DIRECTORY_SECURITY_REFERENCE.md](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md).
4. Named accounts + least-privilege RBAC, no shared root, with alerting on new admin role grants and on lockdown-mode/SSH state changes.
5. Tier-0 patch SLA for vCenter/ESXi/host software: measured in days, tracked against CISA KEV.

---

## Backup & Recovery for Virtual Estates

Ransomware's stage 5 is *destroy recovery*, so backups are the control that decides whether an incident is an outage or an extinction event.

- Immutable, offline/air-gapped backups (object-lock/WORM or tape) that the hypervisor and its admins cannot delete. Follow 3-2-1-1-0: 3 copies, 2 media, 1 offsite, 1 immutable/offline, 0 recovery errors.
- Separate the backup identity and network. Backup systems must not authenticate against the same AD/SSO as the hypervisor; compromise of vCenter should not equal compromise of backups.
- Protect the backup console (Veeam/Commvault/Rubrik/PBS, etc.) as Tier-0: it is itself a top ransomware target.
- Test restores in a clean room, including full vCenter/host rebuild and datastore recovery, and measure real RTO/RPO. Keep offline copies of ESXi/vCenter configs and encryption keys (KMS/Native Key Provider): losing the key provider can make encrypted VMs unrecoverable.
- See [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md) and [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md).

---

## Detection & Logging

Forward everything to a SIEM ([SIEM_REFERENCE.md](SIEM_REFERENCE.md)); local logs are wiped by attackers. High-value signals:

| Signal | Why it matters | ATT&CK |
|---|---|---|
| ESXi SSH/Shell enabled, lockdown mode disabled, or new Exception User | Immediate pre-detonation setup | T1685 |
| Guest-ops API calls (`StartProgramInGuest`, `InitiateFileTransferFromGuest`) from unusual sources | Host->guest command execution | T1675 |
| New/unsigned VIB installed; `execInstalledOnly` bypass attempts | Hypervisor persistence / malicious module | T1554 |
| vCenter/ESXi service crashes then missing core dumps (e.g., `vmdird`) | Exploit + anti-forensics | T1211, T1070 |
| Mass VM power-off or snapshot/backup deletion | Recovery inhibition before encryption | T1490, T1489, T1529 |
| vpxuser/root logins from off-network, or spikes in datastore file writes/renames | Reaching the plane / encryption underway | T1078, T1486 |

Map coverage with [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md) and the enriched technique page [mitre/techniques/T1675.md](mitre/techniques/T1675.md) (ESXi Administration Command).

---

## Quick Hardening Checklist

- [ ] Management plane on isolated VLAN; no user-network path to vCenter/host/BMC/backup consoles
- [ ] Phishing-resistant MFA on hypervisor SSO and help-desk identity-proofing
- [ ] ESXi lockdown mode Strict; SSH/ESXi Shell stopped with timeouts; alert on state change
- [ ] Hypervisors not joined to production AD; unique admin group; least-privilege RBAC; no shared root
- [ ] UEFI Secure Boot + TPM; `execInstalledOnly` on; VIB acceptance ≥ PartnerSupported
- [ ] SLP/CIM disabled; minimal services/ports; port 427 never exposed
- [ ] vCenter/ESXi patched on a Tier-0 (days) SLA against CISA KEV; EOL builds retired
- [ ] VM Encryption + vTPM via Native Key Provider/KMS; vSphere Trust Authority where warranted
- [ ] Immutable/offline backups on a separate identity; console is Tier-0; clean-room restore tested
- [ ] All host/vCenter logs shipped off-box to SIEM; key detections deployed

---

## Related Resources

- [RANSOMWARE_DEFENSE_REFERENCE.md](RANSOMWARE_DEFENSE_REFERENCE.md): ransomware kill chain, extortion, and recovery this doc's hypervisor angle feeds into
- [CLOUD_SECURITY_REFERENCE.md](CLOUD_SECURITY_REFERENCE.md): cloud/IaaS controls; complements on-prem hypervisor hardening
- [ENTERPRISE_INFRASTRUCTURE.md](ENTERPRISE_INFRASTRUCTURE.md): broader datacenter/enterprise infrastructure context
- [CYBER_RESILIENCE_BCDR_REFERENCE.md](CYBER_RESILIENCE_BCDR_REFERENCE.md): immutable backup, BCDR, and recovery testing
- [CONTAINER_SECURITY_REFERENCE.md](CONTAINER_SECURITY_REFERENCE.md) / [KUBERNETES_SECURITY_REFERENCE.md](KUBERNETES_SECURITY_REFERENCE.md): the containerized side of workload isolation
- [ACTIVE_DIRECTORY_SECURITY_REFERENCE.md](ACTIVE_DIRECTORY_SECURITY_REFERENCE.md): decoupling hypervisor identity from prod AD
- [WINDOWS_HARDENING_REFERENCE.md](WINDOWS_HARDENING_REFERENCE.md) / [LINUX_HARDENING_REFERENCE.md](LINUX_HARDENING_REFERENCE.md): host-OS hardening for Hyper-V and KVM/Proxmox
- [CVE_REFERENCE.md](CVE_REFERENCE.md): KEV status for the CVEs above; [THREAT_GROUP_PROFILES.md](THREAT_GROUP_PROFILES.md): UNC3886, Scattered Spider (UNC3944)
- [DETECTION_RULES_REFERENCE.md](DETECTION_RULES_REFERENCE.md), [INCIDENT_RESPONSE_REFERENCE.md](INCIDENT_RESPONSE_REFERENCE.md), [ZERO_TRUST_REFERENCE.md](ZERO_TRUST_REFERENCE.md), [mitre/techniques/T1675.md](mitre/techniques/T1675.md)

---

*Last updated: 2026-09-29 | TeamStarWolf Cybersecurity Reference Library*
