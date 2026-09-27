# CAPEC-42 — MIME Conversion

<a id="capec-42"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

An attacker exploits a weakness in the MIME conversion routine to cause a buffer overflow and gain control over the mail server machine. The MIME system is designed to allow various different information formats to be interpreted and sent via e-mail. Attack points exist when data are converted to MIME compatible format and back.

## Related CWE (4)

[CWE-120](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md)

**Prerequisites:** ::The target system uses a mail server.::Mail server vendor has not released a patch for the MIME conversion routine, the patch itself has a security hole or does not fix the original problem, or the 

**Skills required:** ::SKILL:It may be trivial to cause a DoS via this attack pattern:LEVEL:Low::SKILL:Causing arbitrary code to execute on the target system.:LEVEL:High::

**Mitigations:** ::Stay up to date with third party vendor patches::Disable the 7 to 8 bit conversion. This can be done by removing the F=9 flag from all Mailer specifications in the sendmail.cf file. For example, a sendmail.cf file with these changes applied should 


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
