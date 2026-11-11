# D3FEND: Email Removal

<a id="email-removal"></a>

D3FEND tactic: Evict  
Digital artifacts: Email, Mail Server  

The email removal technique deletes email files from system storage.

## ATT&CK techniques countered (7)

- [T0865: Spearphishing Attachment](https://attack.mitre.org/techniques/T0865): deletes
- [T1114.001: Local Email Collection](/mitre/techniques/T1114-001.md): deletes. Adversaries may target user email on local systems to collect sensitive information.
- [T1114.002: Remote Email Collection](/mitre/techniques/T1114-002.md): may-access. Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information.
- [T1505.002: Transport Agent](/mitre/techniques/T1505-002.md): may-access. Adversaries may abuse Microsoft transport agents to establish persistent access to systems.
- [T1534: Internal Spearphishing](/mitre/techniques/T1534.md): deletes. After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.
- [T1566.001: Spearphishing Attachment](/mitre/techniques/T1566-001.md): deletes. Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002: Spearphishing Link](/mitre/techniques/T1566-002.md): deletes. Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.

## Related pages

- [Content Filtering](/mitre/d3fend/content-filtering.md), which also counters 5 of these techniques
- [Content Modification](/mitre/d3fend/content-modification.md), which also counters 5 of these techniques
- [Content Quarantine](/mitre/d3fend/content-quarantine.md), which also counters 5 of these techniques
- [Data Inventory](/mitre/d3fend/data-inventory.md), which also counters 5 of these techniques
- [Decoy File](/mitre/d3fend/decoy-file.md), which also counters 5 of these techniques
- [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md), which also counters 5 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation](/case-studies/EXCHANGE_MARAUDER_2021.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
