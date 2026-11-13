# CAPEC-176: Configuration/Environment Manipulation

<a id="capec-176"></a>

Abstraction: Meta  
Typical severity: Medium  
Status: Draft  

An attacker manipulates files or settings external to a target application which affect the behavior of that application. For example, many applications use external configuration files and libraries - modification of these entities or otherwise affecting the application's ability to use them would constitute a configuration/environment manipulation attack.

## Related CWE (5)

- [CWE-15: External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html): One or more system settings or configuration elements can be externally controlled by a user.
- [CWE-1233: Security-Sensitive Hardware Controls with Missing Lock Bit Protection](https://cwe.mitre.org/data/definitions/1233.html): The product uses a register lock bit protection mechanism, but it does not ensure that the lock bit prevents modification of system registers or controls that perform changes to important hardware system configuration.
- [CWE-1234: Hardware Internal or Debug Modes Allow Override of Locks](https://cwe.mitre.org/data/definitions/1234.html): System configuration protection may be bypassed during debug mode.
- [CWE-1304: Improperly Preserved Integrity of Hardware Configuration State During a Power Save/Restore Operation](https://cwe.mitre.org/data/definitions/1304.html): The product performs a power save/restore operation, but it does not ensure that the integrity of the configuration state is maintained and/or verified between the beginning and ending of the operation.
- [CWE-1328: Security Version Number Mutable to Older Versions](https://cwe.mitre.org/data/definitions/1328.html): The security version number in the hardware product is mutable, resulting in the ability to downgrade (roll-back) the boot firmware to vulnerable code versions.

## Prerequisites

- The target application must consult external files or configuration controls to control its execution. All but the very simplest applications meet this requirement.

## Related pages

- [CAPEC-680: Exploitation of Improperly Controlled Registers](/mitre/capec/CAPEC-680.md), also related to CWE-1233
- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-15
- [CAPEC-69: Target Programs with Elevated Privileges](/mitre/capec/CAPEC-69.md), also related to CWE-15
- [CAPEC-76: Manipulating Web Input to File System Calls](/mitre/capec/CAPEC-76.md), also related to CWE-15
- [CAPEC-77: Manipulating User-Controlled Variables](/mitre/capec/CAPEC-77.md), also related to CWE-15
- [CAPEC-146: XML Schema Poisoning](/mitre/capec/CAPEC-146.md), also related to CWE-15
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Refrigeration-Controller Attacks on European Supermarkets and Blood Services, 2026: A Case Study](/case-studies/EUROPEAN_REFRIGERATION_ATTACKS_2026.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
