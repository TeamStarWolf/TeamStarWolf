# CAPEC-550: Install New Service

<a id="capec-550"></a>

Abstraction: Detailed  
Status: Draft  

When an operating system starts, it also starts programs called services or daemons. Adversaries may install a new service which will be executed at startup (on a Windows system, by modifying the registry). The service name may be disguised by using a name from a related operating system or benign software. Services are usually run with elevated privileges.

## Mapped ATT&CK techniques (1)

- [T1543: Create or Modify System Process](/mitre/techniques/T1543.md): Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Mitigations

- Limit privileges of user accounts so new service creation can only be performed by authorized administrators.

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
