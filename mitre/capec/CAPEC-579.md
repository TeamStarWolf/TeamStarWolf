# CAPEC-579: Replace Winlogon Helper DLL

<a id="capec-579"></a>

Abstraction: Detailed  
Status: Draft  

Winlogon is a part of Windows that performs logon actions. In Windows systems prior to Windows Vista, a registry key can be modified that causes Winlogon to load a DLL on startup. Adversaries may take advantage of this feature to load adversarial code at startup.

## Mapped ATT&CK techniques (1)

- [T1547.004: Winlogon Helper DLL](/mitre/techniques/T1547-004.md): Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in.

## Related CWE (1)

- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html): One or more system settings or configuration elements can be externally controlled by a user.

## Mitigations

- Changes to registry entries in "HKLM\Software\Microsoft\Windows NT\Winlogon\Notify" that do not correlate with known software, patch cycles, etc are suspicious. New DLLs written to System32 which do not correlate with known good software or patching may be suspicious.

## Related pages

- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-15
- [CAPEC-69: Target Programs with Elevated Privileges](/mitre/capec/CAPEC-69.md), also related to CWE-15
- [CAPEC-76: Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md), also related to CWE-15
- [CAPEC-77: Manipulating User-Controlled Variables](/mitre/capec/CAPEC-77.md), also related to CWE-15
- [CAPEC-146: XML Schema Poisoning](/mitre/capec/CAPEC-146.md), also related to CWE-15
- [CAPEC-176: Configuration/Environment Manipulation](/mitre/capec/CAPEC-176.md), also related to CWE-15
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
