# CAPEC-552: Install Rootkit

<a id="capec-552"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary exploits a weakness in authentication to install malware that alters the functionality and information provide by targeted operating system API calls. Often referred to as rootkits, it is often used to hide the presence of programs, files, network connections, services, drivers, and other system components.

## Mapped ATT&CK techniques (3)

- [T1014: Rootkit](/mitre/techniques/T1014.md): Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.
- [T1542.003: Bootkit](/mitre/techniques/T1542-003.md): Adversaries may use bootkits to persist on systems.
- [T1547.006: Kernel Modules and Extensions](/mitre/techniques/T1547-006.md): Adversaries may modify the kernel to automatically execute programs on system boot.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Mitigations

- Prevent adversary access to privileged accounts necessary to install rootkits.

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

- [APT41: The Public Record, 2012 to 2026](/case-studies/APT41_PUBLIC_RECORD.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)
- [Stuxnet: The Case Study](/case-studies/STUXNET.md)
- [The Year 1994 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1994.md)
- [The Year 2005 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2005.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [United States-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_UNITED_STATES.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
