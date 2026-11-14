# CAPEC-310: Scanning for Vulnerable Software

<a id="capec-310"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An attacker engages in scanning activity to find vulnerable software versions or types, such as operating system versions or network services. Vulnerable or exploitable network configurations, such as improperly firewalled systems, or misconfigured systems in the DMZ or external network, provide windows of opportunity for an attacker. Common types of vulnerable software include unpatched operating systems or services (e.g FTP, Telnet, SMTP, SNMP) running on open ports that the attacker has identified. Attackers usually begin probing for vulnerable software once the external network has been port scanned and potential targets have been revealed.

## Related CWE (1)

- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html): The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- Access to the network on which the targeted system resides.
- Software tools used to probe systems over a range of ports and protocols.

## Skills required

- [Medium] To probe a system remotely without detection requires careful planning and patience.

## Consequences

- Confidentiality / Other
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism, Hide Activities

## Related pages

- [CAPEC-13: Subverting Environment Variable Values](/mitre/capec/CAPEC-13.md), also related to CWE-200
- [CAPEC-22: Exploiting Trust in Client](/mitre/capec/CAPEC-22.md), also related to CWE-200
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-200
- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-200
- [CAPEC-79: Using Slashes in Alternate Encoding](/mitre/capec/CAPEC-79.md), also related to CWE-200
- [CAPEC-116: Excavation](/mitre/capec/CAPEC-116.md), also related to CWE-200
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Ghostcat, CVE-2020-1938: The Tomcat AJP File Read in the Lab](/case-studies/GHOSTCAT_CVE_2020_1938.md)
- [The Year 1993 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1993.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
