# D3FEND: Network Resource Access Mediation

<a id="network-resource-access-mediation"></a>

D3FEND tactic: Isolate  
Digital artifacts: Network Resource  

Control of access to organizational systems and services by users or processes over a network.

## ATT&CK techniques countered (8)

- [T1037.003: Network Logon Script](/mitre/techniques/T1037-003.md): isolates. Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence.
- [T1039: Data from Network Shared Drive](/mitre/techniques/T1039.md): isolates. Adversaries may search network shares on computers they have compromised to find files of interest.
- [T1070.005: Network Share Connection Removal](/mitre/techniques/T1070-005.md): isolates. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation.
- [T1074.002: Remote Data Staging](/mitre/techniques/T1074-002.md): isolates. Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration.
- [T1080: Taint Shared Content](/mitre/techniques/T1080.md): isolates. Adversaries may deliver payloads to remote systems by adding content to shared storage locations, such as network drives or internal code repositories.
- [T1213.001: Confluence](/mitre/techniques/T1213-001.md): isolates. Adversaries may leverage Confluence repositories to mine valuable information.
- [T1213.002: Sharepoint](/mitre/techniques/T1213-002.md): isolates. Adversaries may leverage the SharePoint repository as a source to mine valuable information.
- [T1491.002: External Defacement](/mitre/techniques/T1491-002.md): isolates. An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users.

## Related pages

- [Decoy Network Resource](/mitre/d3fend/decoy-network-resource.md), which also counters 8 of these techniques
- [Content Filtering](/mitre/d3fend/content-filtering.md), which also counters 1 of these techniques
- [Content Modification](/mitre/d3fend/content-modification.md), which also counters 1 of these techniques
- [Content Quarantine](/mitre/d3fend/content-quarantine.md), which also counters 1 of these techniques
- [Decoy File](/mitre/d3fend/decoy-file.md), which also counters 1 of these techniques
- [Dynamic Analysis](/mitre/d3fend/dynamic-analysis.md), which also counters 1 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)
- [The ATF Major Incident of 2026: A Case Study](/case-studies/ATF_MAJOR_INCIDENT_2026.md)
- [The DentaQuest Health-Data Breach of May 2026: A Case Study](/case-studies/DENTAQUEST_BREACH_2026.md)
- [The Shadow Brokers and Vault 7: The NSA and CIA Tool Leaks, 2016 to 2017](/case-studies/NSA_CIA_TOOL_LEAKS.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
