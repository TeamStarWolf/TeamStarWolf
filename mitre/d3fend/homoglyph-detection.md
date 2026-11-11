# D3FEND: Homoglyph Detection

<a id="homoglyph-detection"></a>

D3FEND tactic: Detect  
Digital artifacts: Email, URL  

Comparing strings using a variety of techniques to determine if a deceptive or malicious string is being presented to a user.

## ATT&CK techniques countered (9)

- [T0817: Drive-by Compromise](https://attack.mitre.org/techniques/T0817): analyzes
- [T0865: Spearphishing Attachment](https://attack.mitre.org/techniques/T0865): analyzes
- [T1114.001: Local Email Collection](/mitre/techniques/T1114-001.md): analyzes. Adversaries may target user email on local systems to collect sensitive information.
- [T1189: Drive-by Compromise](/mitre/techniques/T1189.md): analyzes. Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.
- [T1204.001: Malicious Link](/mitre/techniques/T1204-001.md): analyzes. An adversary may rely upon a user clicking a malicious link in order to gain execution.
- [T1534: Internal Spearphishing](/mitre/techniques/T1534.md): analyzes. After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.
- [T1566.001: Spearphishing Attachment](/mitre/techniques/T1566-001.md): analyzes. Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002: Spearphishing Link](/mitre/techniques/T1566-002.md): analyzes. Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.
- [T1566.003: Spearphishing via Service](/mitre/techniques/T1566-003.md): analyzes. Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 6 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 6 of these techniques
- [Content Filtering](/mitre/d3fend/content-filtering.md), which also counters 6 of these techniques
- [Content Modification](/mitre/d3fend/content-modification.md), which also counters 6 of these techniques
- [Content Quarantine](/mitre/d3fend/content-quarantine.md), which also counters 6 of these techniques
- [Decoy File](/mitre/d3fend/decoy-file.md), which also counters 6 of these techniques
- [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md)
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
