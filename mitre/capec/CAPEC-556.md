# CAPEC-556: Replace File Extension Handlers

<a id="capec-556"></a>

Abstraction: Detailed  
Status: Draft  
OpenCRE: [CAPEC-556](https://opencre.org/smartlink/standard/CAPEC/556)  

When a file is opened, its file handler is checked to determine which program opens the file. File handlers are configuration properties of many operating systems. Applications can modify the file handler for a given file extension to call an arbitrary program when a file with the given extension is opened.

## Mapped ATT&CK techniques (1)

- [T1546.001: Change Default File Association](/mitre/techniques/T1546-001.md): Adversaries may establish persistence by executing malicious content triggered by a file type association.

## Related CWE (1)

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html): The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

## Mitigations

- Inspect registry for changes. Limit privileges of user accounts so changes to default file handlers can only be performed by authorized administrators.

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
