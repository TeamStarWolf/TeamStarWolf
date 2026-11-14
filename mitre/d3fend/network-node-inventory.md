# D3FEND: Network Node Inventory

<a id="network-node-inventory"></a>

D3FEND tactic: Model  
Digital artifacts: Network Node  

Network node inventorying identifies and records all the network nodes (hosts, routers, switches, firewalls, etc.) in the organization's architecture.

## ATT&CK techniques countered (14)

- [T0809: Data Destruction](https://attack.mitre.org/techniques/T0809): inventories
- [T0816: Device Restart/Shutdown](https://attack.mitre.org/techniques/T0816): inventories
- [T0848: Rogue Master](https://attack.mitre.org/techniques/T0848): inventories
- [T0864: Transient Cyber Asset](https://attack.mitre.org/techniques/T0864): inventories
- [T0866: Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866): inventories
- [T0867: Lateral Tool Transfer](https://attack.mitre.org/techniques/T0867): inventories
- [T1114.002: Remote Email Collection](/mitre/techniques/T1114-002.md): inventories. Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information.
- [T1505.002: Transport Agent](/mitre/techniques/T1505-002.md): inventories. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1505.003: Web Shell](/mitre/techniques/T1505-003.md): inventories. Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- [T1578.002: Create Cloud Instance](/mitre/techniques/T1578-002.md): inventories. An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses.
- [T1578.003: Delete Cloud Instance](/mitre/techniques/T1578-003.md): inventories. An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence.
- [T1578.004: Revert Cloud Instance](/mitre/techniques/T1578-004.md): inventories. An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence.
- [T1686.002: Network Device Firewall](/mitre/techniques/T1686-002.md): inventories (D3FEND maps the revoked predecessor T1562.013). Adversaries may disable network device-based firewall mechanisms entirely or add, delete, or modify particular rules in order to bypass controls limiting network usage.
- [T1693.001: System Firmware](https://attack.mitre.org/techniques/T1693/001): inventories (D3FEND maps the revoked predecessor T0857)

_D3FEND also maps T0807, deprecated in ATT&CK with no successor; not counted above._

## Related pages

- [Endpoint Health Beacon](/mitre/d3fend/endpoint-health-beacon.md), which also counters 14 of these techniques
- [Logical Link Mapping](/mitre/d3fend/logical-link-mapping.md), which also counters 14 of these techniques
- [Physical Link Mapping](/mitre/d3fend/physical-link-mapping.md), which also counters 14 of these techniques
- [Restore Network Access](/mitre/d3fend/restore-network-access.md), which also counters 13 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 4 of these techniques
- [Configuration Inventory](/mitre/d3fend/configuration-inventory.md), which also counters 3 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Healthcare Threat Actor Watchlist, 2023 to 2026: Who Hits Hospitals, How They Get In, and What the Record Says](/case-studies/HEALTHCARE_THREAT_WATCHLIST.md)
- [Water and Wastewater Networks: The Control Systems, the Chemistry and the Attacks on Them](/case-studies/WATER_TREATMENT_NETWORKS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
