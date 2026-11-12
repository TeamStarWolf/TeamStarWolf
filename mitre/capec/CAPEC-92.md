# CAPEC-92: Forced Integer Overflow

<a id="capec-92"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Draft  

This attack forces an integer variable to go out of range. The integer variable is often used as an offset such as size of memory allocation or similarly. The attacker would typically control the value of such variable and try to get it out of range. For instance the integer in question is incremented past the maximum possible value, it may wrap to become a very small, or negative number, therefore providing a very incorrect value which can lead to unexpected behavior. At worst the attacker can execute arbitrary code.

## Related CWE (7)

- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html): The product performs a calculation that can produce an integer overflow or wraparound when the logic assumes that the resulting value will always be larger than the original value.
- [CWE-128: Wrap-around Error](https://cwe.mitre.org/data/definitions/128.html): Wrap around errors occur whenever a value is incremented past the maximum value for its type and therefore "wraps around" to a very small, negative, or undefined value.
- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html): The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html): The product writes past the end of a buffer that was allocated on the heap.
- [CWE-196: Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html): The product uses an unsigned primitive and performs a cast to a signed primitive, which can produce an unexpected value if the value of the unsigned primitive can not be represented using a signed primitive.
- [CWE-680: Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html): The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.
- [CWE-697: Incorrect Comparison](https://cwe.mitre.org/data/definitions/697.html): The product compares two entities in a security-relevant context, but the comparison is incorrect.

## Prerequisites

- The attacker can manipulate the value of an integer variable utilized by the target host.
- The target host does not do proper range checking on the variable before utilizing it.
- When the integer variable is incremented or decremented to an out of range value, it gets a very different value (e.g. very small or negative number)

## Skills required

- [Low] An attacker can simply overflow an integer by inserting an out of range value.
- [High] Exploiting a buffer overflow by injecting malicious code into the stack of a software system or even the heap can require a higher skill level.

## Consequences

- Integrity / Modify Data
- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality / Read Data
- Availability / Unreliable Execution

## Mitigations

- Use a language or compiler that performs automatic bounds checking.
- Carefully review the service's implementation before making it available to user. For instance you can use manual or automated code review to uncover vulnerabilities such as integer overflow.
- Use an abstraction library to abstract away risky APIs. Not a complete solution.
- Always do bound checking before consuming user input data.

## Related pages

- [CAPEC-8: Buffer Overflow in an API Call](/mitre/capec/CAPEC-8.md), also related to CWE-120, CWE-680 and 1 more
- [CAPEC-9: Buffer Overflow in Local Command-Line Utilities](/mitre/capec/CAPEC-9.md), also related to CWE-120, CWE-680 and 1 more
- [CAPEC-10: Buffer Overflow via Environment Variables](/mitre/capec/CAPEC-10.md), also related to CWE-120, CWE-680 and 1 more
- [CAPEC-14: Client-side Injection-induced Buffer Overflow](/mitre/capec/CAPEC-14.md), also related to CWE-120, CWE-680 and 1 more
- [CAPEC-24: Filter Failure through Buffer Overflow](/mitre/capec/CAPEC-24.md), also related to CWE-120, CWE-680 and 1 more
- [CAPEC-45: Buffer Overflow via Symbolic Links](/mitre/capec/CAPEC-45.md), also related to CWE-120, CWE-680 and 1 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [GitLab, CVE-2026-97229: Lab-Verified Exposure and Fix](/case-studies/GITLAB_CVE_2026_97229.md)
- [The Year 2021 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2021.md)
- [The Year 2022 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2022.md)
- [The Year 2023 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2023.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
