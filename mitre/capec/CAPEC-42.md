# CAPEC-42: MIME Conversion

<a id="capec-42"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attacker exploits a weakness in the MIME conversion routine to cause a buffer overflow and gain control over the mail server machine. The MIME system is designed to allow various different information formats to be interpreted and sent via e-mail. Attack points exist when data are converted to MIME compatible format and back.

## Related CWE (4)

- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html): The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html): The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary.
- [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component](https://cwe.mitre.org/data/definitions/74.html): The product constructs all or part of a command, data structure, or record using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify how it is parsed or interpreted when it is sent to a downstream component.
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html): The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.

## Prerequisites

- The target system uses a mail server.
- Mail server vendor has not released a patch for the MIME conversion routine, the patch itself has a security hole or does not fix the original problem, or the patch has not been applied to the user's system.

## Skills required

- [Low] It may be trivial to cause a DoS via this attack pattern
- [High] Causing arbitrary code to execute on the target system.

## Consequences

- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Integrity / Modify Data
- Availability / Unreliable Execution
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Stay up to date with third party vendor patches
- Disable the 7 to 8 bit conversion. This can be done by removing the F=9 flag from all Mailer specifications in the sendmail.cf file. For example, a sendmail.cf file with these changes applied should look similar to (depending on your system and configuration): Mlocal, P=/usr/libexec/mail.local, F=lsDFMAw5:/|@qrmn, S=10/30, R=20/40,T=DNS/RFC822/X-Unix,A=mail -d $u Mprog, P=/bin/sh, F=lsDFMoqeu, S=10/30, R=20/40,D=$z:/,T=X-Unix,A=sh -c $u This can be achieved for the "Mlocal" and "Mprog" Mailers by modifying the ".mc" file to include the following lines: define(`LOCAL_MAILER_FLAGS',ifdef(`LOCAL_MAILER_FLAGS',`translit(LOCAL_MAILER_FLAGS, `9')',`rmn')) define(`LOCAL_SHELL_FLAGS',ifdef(`LOCAL_SHELL_FLAGS',`translit(LOCAL_SHELL_FLAGS, `9')',`eu')) and then rebuilding the sendmail.cf file using m4(1). From "Exploiting Software", please see reference below.
- Use the sendmail restricted shell program (smrsh)
- Use mail.local

## Related pages

- [CAPEC-8: Buffer Overflow in an API Call](/mitre/capec/CAPEC-8.md), also related to CWE-20, CWE-74 and 2 more
- [CAPEC-9: Buffer Overflow in Local Command-Line Utilities](/mitre/capec/CAPEC-9.md), also related to CWE-20, CWE-74 and 2 more
- [CAPEC-10: Buffer Overflow via Environment Variables](/mitre/capec/CAPEC-10.md), also related to CWE-20, CWE-74 and 2 more
- [CAPEC-14: Client-side Injection-induced Buffer Overflow](/mitre/capec/CAPEC-14.md), also related to CWE-20, CWE-74 and 2 more
- [CAPEC-24: Filter Failure through Buffer Overflow](/mitre/capec/CAPEC-24.md), also related to CWE-20, CWE-74 and 2 more
- [CAPEC-45: Buffer Overflow via Symbolic Links](/mitre/capec/CAPEC-45.md), also related to CWE-20, CWE-74 and 2 more
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
