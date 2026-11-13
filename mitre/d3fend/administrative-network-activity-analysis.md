# D3FEND: Administrative Network Activity Analysis

<a id="administrative-network-activity-analysis"></a>

D3FEND tactic: Detect  
Digital artifacts: Intranet Administrative Network Traffic  

Detection of unauthorized use of administrative network protocols by analyzing network activity against a baseline.

## ATT&CK techniques countered (8)

- [T1003.006: DCSync](/mitre/techniques/T1003-006.md): analyzes. Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.
- [T1047: Windows Management Instrumentation](/mitre/techniques/T1047.md): analyzes. Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
- [T1098.001: Additional Cloud Credentials](/mitre/techniques/T1098-001.md): analyzes. Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): analyzes. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1110.004: Credential Stuffing](/mitre/techniques/T1110-004.md): analyzes. Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap.
- [T1207: Rogue Domain Controller](/mitre/techniques/T1207.md): analyzes. Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.
- [T1546.003: Windows Management Instrumentation Event Subscription](/mitre/techniques/T1546-003.md): analyzes. Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
- [T1546.008: Accessibility Features](/mitre/techniques/T1546-008.md): analyzes. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.

## Related pages

- [Application Protocol Command Analysis](/mitre/d3fend/application-protocol-command-analysis.md), which also counters 8 of these techniques
- [Client-server Payload Profiling](/mitre/d3fend/client-server-payload-profiling.md), which also counters 8 of these techniques
- [Connection Attempt Analysis](/mitre/d3fend/connection-attempt-analysis.md), which also counters 8 of these techniques
- [Network Traffic Community Deviation](/mitre/d3fend/network-traffic-community-deviation.md), which also counters 8 of these techniques
- [Network Traffic Filtering](/mitre/d3fend/network-traffic-filtering.md), which also counters 8 of these techniques
- [Network Traffic Signature Analysis](/mitre/d3fend/network-traffic-signature-analysis.md), which also counters 8 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Able2Shell and the RMM Attack Surface: The N-able N-central Disclosure of November 2026](/case-studies/NABLE_NCENTRAL_ABLE2SHELL_2026.md)
- [China-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_CHINA.md)
- [The European Commission Cloud Breach of 2026: AWS Data Theft Through the Poisoned Trivy Scanner](/case-studies/EUROPEAN_COMMISSION_CLOUD_BREACH_2026.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2026 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
