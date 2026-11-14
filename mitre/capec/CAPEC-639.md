# CAPEC-639: Probe System Files

<a id="capec-639"></a>

Abstraction: Detailed  
Typical severity: Medium  
Status: Stable  

An adversary obtains unauthorized information due to improperly protected files. If an application stores sensitive information in a file that is not protected by proper access control, then an adversary can access the file and search for sensitive information.

## Mapped ATT&CK techniques (5)

- [T1039: Data from Network Shared Drive](/mitre/techniques/T1039.md): Adversaries may search network shares on computers they have compromised to find files of interest.
- [T1552.001: Credentials In Files](/mitre/techniques/T1552-001.md): Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials.
- [T1552.003: Shell History](/mitre/techniques/T1552-003.md): Adversaries may search the command history on compromised systems for insecurely stored credentials.
- [T1552.004: Private Keys](/mitre/techniques/T1552-004.md): Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials.
- [T1552.006: Group Policy Preferences](/mitre/techniques/T1552-006.md): Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP).

## Related CWE (1)

- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html): The product makes files or directories accessible to unauthorized actors, even though they should not be.

## Prerequisites

- An adversary has access to the file system of a system.

## Consequences

- Confidentiality / Read Data

## Mitigations

- Verify that files have proper access controls set, and reduce the storage of sensitive information to only what is necessary.

## Related pages

- [CAPEC-150: Collect Data from Common Resource Locations](/mitre/capec/CAPEC-150.md), also related to CWE-552
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [The Cuckoo's Egg Intrusion: Lawrence Berkeley Laboratory, 1986](/case-studies/CUCKOOS_EGG_1986.md)
- [The Year 2014 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2014.md)
- [Thirty Days of Exposure Checks: Version and Configuration Evidence from the Lab](/case-studies/EXPOSURE_CHECKS_2026_11.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
