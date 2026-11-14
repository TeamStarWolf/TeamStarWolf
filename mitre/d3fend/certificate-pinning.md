# D3FEND: Certificate Pinning

<a id="certificate-pinning"></a>

D3FEND tactic: Harden  
Digital artifacts: Certificate  

Persisting either a server's X.509 certificate or their public key and comparing that to server's presented identity to allow for greater client confidence in the remote server's identity for SSL connections.

## ATT&CK techniques countered (1)

- [T1649: Steal or Forge Authentication Certificates](/mitre/techniques/T1649.md): hardens. Adversaries may steal or forge certificates used for authentication to access remote systems or resources.

## Related pages

- [Asset Vulnerability Enumeration](/mitre/d3fend/asset-vulnerability-enumeration.md), which also counters 1 of these techniques
- [Certificate Analysis](/mitre/d3fend/certificate-analysis.md), which also counters 1 of these techniques
- [Certificate Rotation](/mitre/d3fend/certificate-rotation.md), which also counters 1 of these techniques
- [Certificate-based Authentication](/mitre/d3fend/certificate-based-authentication.md), which also counters 1 of these techniques
- [Content Filtering](/mitre/d3fend/content-filtering.md), which also counters 1 of these techniques
- [Content Modification](/mitre/d3fend/content-modification.md), which also counters 1 of these techniques
- [MITRE D3FEND Countermeasure Reference](/D3FEND_REFERENCE.md)
- [All D3FEND countermeasures](/mitre/d3fend/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [The eMudhra Certificate Authority Key Compromise: A 2026 Case Study](/case-studies/EMUDHRA_CA_COMPROMISE_2026.md)
- [The Year 2012 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2012.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
