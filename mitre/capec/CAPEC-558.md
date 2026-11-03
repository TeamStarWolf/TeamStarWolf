# CAPEC-558: Replace Trusted Executable

<a id="capec-558"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Low  
Status: Stable  

An adversary exploits weaknesses in privilege management or access control to replace a trusted executable with a malicious version and enable the execution of malware when that trusted executable is called.

## Mapped ATT&CK techniques (2)

- [T1505.005: Terminal Services DLL](/mitre/techniques/T1505-005.md): Adversaries may abuse components of Terminal Services to enable persistent access to systems.
- [T1546.008: Accessibility Features](/mitre/techniques/T1546-008.md): Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Related pages

- [CAPEC-19: Embedding Scripts within Scripts](/mitre/capec/CAPEC-19.md), also related to CWE-284
- [CAPEC-441: Malicious Logic Insertion](/mitre/capec/CAPEC-441.md), also related to CWE-284
- [CAPEC-478: Modification of Windows Service Configuration](/mitre/capec/CAPEC-478.md), also related to CWE-284
- [CAPEC-479: Malicious Root Certificate](/mitre/capec/CAPEC-479.md), also related to CWE-284
- [CAPEC-502: Intent Spoof](/mitre/capec/CAPEC-502.md), also related to CWE-284
- [CAPEC-503: WebView Exposure](/mitre/capec/CAPEC-503.md), also related to CWE-284
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
