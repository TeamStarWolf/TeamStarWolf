<!-- hub:start (written by scripts/build_site_nav.py from docs/site_nav.json; do not edit) -->

# Network security

> Network fundamentals, protocols, architecture, edge devices, packet analysis, and wireless, RF, and telecom security.

Part of the [domain hubs](/hubs/README.md). 11 reference documents in this domain; reading time is the page's words at 230 words a minute.

## References

| Reference | What it covers | Reading time |
|---|---|---|
| [Networking Fundamentals](/NETWORKING_FUNDAMENTALS.md) | OSI model, TCP/IP deep dive, subnetting, ARP/VLANs/STP, routing protocols (OSPF/BGP), DNS, and essential troubleshooting commands for security practitioners | 36 min |
| [Network Protocols Reference](/NETWORK_PROTOCOLS_REFERENCE.md) | TCP/IP, DNS, TLS, HTTP, Kerberos/NTLM, BGP/OSPF, email security protocols, ICS/OT, Wireshark/Zeek analysis | 25 min |
| [Network Protocols Security](/NETWORK_PROTOCOLS_SECURITY.md) | How attackers exploit the major network protocols: mechanics, TTPs, detection, and defenses, with ATT&CK technique IDs | 22 min |
| [Network Security Architecture](/NETWORK_SECURITY_ARCHITECTURE.md) | DMZ design, VLAN segmentation, firewall policy, IDS/IPS placement, NAC/802.1X, DDoS protection, and network monitoring | 16 min |
| [Networking Architecture Reference](/NETWORKING_ARCHITECTURE_REFERENCE.md) | Designing enterprise networks across campus, branch, data center and cloud: addressing plans, fabrics, segmentation, and trust boundaries | 19 min |
| [Edge & Network Device Security Reference](/EDGE_DEVICE_SECURITY_REFERENCE.md) | BOD 23-02 management-interface isolation, BOD 26-04 KEV patch tiers, 2023-2026 edge exploitation record, Feb 2025 joint edge-device guidance, appliance integrity checking and forensic readiness, egress monitoring | 25 min |
| [Internet-Facing Services and External Exposure](/INTERNET_FACING_SERVICES_REFERENCE.md) | The services enterprises expose externally (SMB, RDP, databases, HTTP/S, SMTP, DNS, SSH, FTP, web servers, load balancers, edge appliances): why each is risky when reachable, how to discover external exposure, and how to harden and reduce the attack surface | 5 min |
| [Packet Analysis Reference](/PACKET_ANALYSIS_REFERENCE.md) | Wireshark display filters, tcpdump BPF syntax, Zeek logs and scripting, JA3 fingerprinting, and attack pattern detection in pcaps | 9 min |
| [Wireless Security Reference](/WIRELESS_SECURITY_REFERENCE.md) | WiFi attacks (WPA2/WPA3, evil twin, PMKID), Bluetooth, SDR, RFID/NFC, and enterprise wireless hardening | 30 min |
| [SDR & RF Security Reference](/SDR_RF_SECURITY_REFERENCE.md) | Software-Defined Radio and RF security: HackRF/RTL-SDR, GNU Radio, GSM/LTE/Bluetooth/Zigbee/P25 analysis, TEMPEST | 19 min |
| [Telecom & 5G Security Reference](/TELECOM_5G_SECURITY_REFERENCE.md) | MITRE FiGHT framework, SS7/Diameter signaling defense, GSMA FS.11/FS.19, 5G SBA/SUCI/SEPP, network slicing, O-RAN WG11, Salt Typhoon advisories and CISA hardening guidance | 20 min |

## Learning paths

- [Network Security](/disciplines/network-security.md)
- [Radio Frequency (RF) Security](/disciplines/radio-frequency-security.md)
- [Zero Trust Architecture](/disciplines/zero-trust-architecture.md)

## Platforms and developer reference

| Page | What it covers |
|---|---|
| [Networking Command Reference](/commands/networking-commands.md) | ip, ss, dig, ping, traceroute, nc, and DNS and connectivity checks |
| [Nmap Command Reference](/commands/nmap.md) | Host discovery, port and service scanning, and the scripting engine |
| [tshark Command Reference](/commands/tshark.md) | Command-line packet capture and analysis for authorized network work |
| [SSH Command Reference](/commands/ssh.md) | Secure shell, key management, config, tunneling, and host verification |
| [Fortinet](/platforms/fortinet.md) | The Security Fabric: FortiGate firewall, FortiNDR, and analytics |
| [Palo Alto Networks](/platforms/palo-alto-networks.md) | Next-generation firewalls on PAN-OS, Prisma Access SASE, and the Cortex operations family |
| [Check Point](/platforms/check-point.md) | Quantum gateways with IPS virtual patching and threat prevention |
| [Cisco ISE](/platforms/cisco-ise.md) | Network access control with 802.1X, posture, and Change of Authorization |
| [Zscaler](/platforms/zscaler.md) | The Zero Trust Exchange: secure web gateway and zero-trust network access |
| [Cloudflare](/platforms/cloudflare.md) | Edge platform with a WAF, DDoS protection, and the Cloudflare One zero-trust services |

## See also

- [Network defense](/NETWORK_DEFENSE_REFERENCE.md)
- [Network forensics](/NETWORK_FORENSICS_REFERENCE.md)
- [ProFTPD mod_copy (CVE-2015-3306): a lab case study](/case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md)
- [The Ivanti Connect Secure zero-day chain (October 2026): a case study](/case-studies/IVANTI_CONNECT_SECURE_2026.md)

<!-- hub:end -->
