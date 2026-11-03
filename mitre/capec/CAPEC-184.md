# CAPEC-184: Software Integrity Attack

<a id="capec-184"></a>

Abstraction: Meta  
Typical severity: Low  
Status: Draft  

An attacker initiates a series of events designed to cause a user, program, server, or device to perform actions which undermine the integrity of software code, device data structures, or device firmware, achieving the modification of the target's integrity to achieve an insecure state.

## Related CWE (1)

- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html): The product downloads source code or an executable from a remote location and executes the code without sufficiently verifying the origin and integrity of the code.

## Skills required

- [Medium] Manual or user-assisted attacks require deceptive mechanisms to trick the user into clicking a link or downloading and installing software. Automated update attacks require the attacker to host a payload and then trigger the installation of the payload code.

## Related pages

- [CAPEC-185: Malicious Software Download](/mitre/capec/CAPEC-185.md), also related to CWE-494
- [CAPEC-186: Malicious Software Update](/mitre/capec/CAPEC-186.md), also related to CWE-494
- [CAPEC-187: Malicious Automated Software Update via Redirection](/mitre/capec/CAPEC-187.md), also related to CWE-494
- [CAPEC-533: Malicious Manual Software Update](/mitre/capec/CAPEC-533.md), also related to CWE-494
- [CAPEC-538: Open-Source Library Manipulation](/mitre/capec/CAPEC-538.md), also related to CWE-494
- [CAPEC-657: Malicious Automated Software Update via Spoofing](/mitre/capec/CAPEC-657.md), also related to CWE-494
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
