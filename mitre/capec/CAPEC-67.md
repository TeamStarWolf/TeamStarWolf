# CAPEC-67 — String Format Overflow in syslog()

<a id="capec-67"></a>

**Abstraction:** Detailed  
**Typical severity:** Very High  
**Likelihood:** High

This attack targets applications and software that uses the syslog() function insecurely. If an application does not explicitely use a format string parameter in a call to syslog(), user input can be placed in the format string parameter leading to a format string injection attack. Adversaries can then inject malicious format string commands into the function call leading to a buffer overflow. The

## Related CWE (6)

[CWE-120](/CWE_REFERENCE.md) [CWE-134](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The Syslog function is used without specifying a format string argument, allowing user input to be placed direct into the function call as a format string.::

**Mitigations:** ::The code should be reviewed for misuse of the Syslog function call. Manual or automated code review can be used. The reviewer needs to ensure that all format string functions are passed a static string which cannot be controlled by the user and tha


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
