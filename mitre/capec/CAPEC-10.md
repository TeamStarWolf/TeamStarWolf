# CAPEC-10 — Buffer Overflow via Environment Variables

<a id="capec-10"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High

This attack pattern involves causing a buffer overflow through manipulation of environment variables. Once the adversary finds that they can modify an environment variable, they may try to overflow associated buffers. This attack leverages implicit trust often placed in environment variables.

## Related CWE (10)

[CWE-120](/CWE_REFERENCE.md) [CWE-302](/CWE_REFERENCE.md) [CWE-118](/CWE_REFERENCE.md) [CWE-119](/CWE_REFERENCE.md) [CWE-74](/CWE_REFERENCE.md) [CWE-99](/CWE_REFERENCE.md) [CWE-20](/CWE_REFERENCE.md) [CWE-680](/CWE_REFERENCE.md) [CWE-733](/CWE_REFERENCE.md) [CWE-697](/CWE_REFERENCE.md)

**Prerequisites:** ::The application uses environment variables.::An environment variable exposed to the user is vulnerable to a buffer overflow.::The vulnerable environment variable uses untrusted data.::Tainted data u

**Skills required:** ::SKILL:An attacker can simply overflow a buffer by inserting a long string into an attacker-modifiable injection vector. The result can be a DoS.:LEV

**Mitigations:** ::Do not expose environment variable to the user.::Do not use untrusted data in your environment variables.::Use a language or compiler that performs automatic bounds checking::There are tools such as Sharefuzz [REF-2] which is an environment variabl


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
