# CAPEC-100: Overflow Buffers

<a id="capec-100"></a>

Abstraction: Standard  
Typical severity: Very High  
Likelihood: High  
Status: Draft  

Buffer Overflow attacks target improper or missing bounds checking on buffer operations, typically triggered by input injected by an adversary. As a consequence, an adversary is able to write past the boundaries of allocated buffer regions in memory, causing a program crash or potentially redirection of execution as per the adversaries' choice.

## Related CWE (6)

- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html): The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.
- [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html): The product performs operations on a memory buffer, but it reads from or writes to a memory location outside the buffer's intended boundary.
- [CWE-131: Incorrect Calculation of Buffer Size](https://cwe.mitre.org/data/definitions/131.html): The product does not correctly calculate the size to be used when allocating a buffer.
- [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html): The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position within the array.
- [CWE-805: Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html): The product uses a sequential operation to read or write a buffer, but it uses an incorrect length value that causes it to access memory that is outside of the bounds of the buffer.
- [CWE-680: Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html): The product performs a calculation to determine how much memory to allocate, but an integer overflow can occur that causes less memory to be allocated than expected, leading to a buffer overflow.

## Prerequisites

- Targeted software performs buffer operations.
- Targeted software inadequately performs bounds-checking on buffer operations.
- Adversary has the capability to influence the input to buffer operations.

## Skills required

- [Low] In most cases, overflowing a buffer does not require advanced skills beyond the ability to notice an overflow and stuff an input variable with content.
- [High] In cases of directed overflows, where the motive is to divert the flow of the program or application as per the adversaries' bidding, high level skills are required. This may involve detailed knowledge of the target system architecture and kernel.

## Consequences

- Availability / Unreliable Execution
- Confidentiality, Integrity, Availability / Execute Unauthorized Commands
- Confidentiality, Access Control, Authorization / Gain Privileges

## Mitigations

- Use a language or compiler that performs automatic bounds checking.
- Use secure functions not vulnerable to buffer overflow.
- If you have to use dangerous functions, make sure that you do boundary checking.
- Compiler-based canary mechanisms such as StackGuard, ProPolice and the Microsoft Visual Studio /GS flag. Unless this provides automatic bounds checking, it is not a complete solution.
- Use OS-level preventative functionality. Not a complete solution.
- Utilize static source code analysis tools to identify potential buffer overflow weaknesses in the software.

## Related pages

- [CAPEC-47: Buffer Overflow via Parameter Expansion](/mitre/capec/CAPEC-47.md), also related to CWE-119, CWE-120 and 2 more
- [CAPEC-8: Buffer Overflow in an API Call](/mitre/capec/CAPEC-8.md), also related to CWE-119, CWE-120 and 1 more
- [CAPEC-9: Buffer Overflow in Local Command-Line Utilities](/mitre/capec/CAPEC-9.md), also related to CWE-119, CWE-120 and 1 more
- [CAPEC-10: Buffer Overflow via Environment Variables](/mitre/capec/CAPEC-10.md), also related to CWE-119, CWE-120 and 1 more
- [CAPEC-14: Client-side Injection-induced Buffer Overflow](/mitre/capec/CAPEC-14.md), also related to CWE-119, CWE-120 and 1 more
- [CAPEC-24: Filter Failure through Buffer Overflow](/mitre/capec/CAPEC-24.md), also related to CWE-119, CWE-120 and 1 more
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [Before the Internet: Computer Threats, 1960 to 1990](/case-studies/PRE_INTERNET_THREATS.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Five Hacks and Why They Worked: The Cases in Fancy Bear Goes Phishing](/case-studies/FANCY_BEAR_GOES_PHISHING_CASES.md)
- [Industrial Control System Attacks and Advisories, 2024 to 2026: Incidents, CVEs and Attribution](/case-studies/ICS_ATTACKS_AND_ADVISORIES_2024_2026.md)
- [The Citrix NetScaler Zero-Days of September and October 2026 (CVE-2026-88771, CVE-2026-88772, CVE-2026-88779): A Case Study](/case-studies/CITRIX_NETSCALER_SEPTEMBER_2026.md)
- [The Dot-Com Era: Cyber Events, 1994 to 2003](/case-studies/DOTCOM_ERA_CYBER_EVENTS.md)
- [The Ransomware Ecosystem: The Public Record, 2019 to 2026](/case-studies/RANSOMWARE_ECOSYSTEM.md)
- [The Year 1995 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1995.md)
- [The Year 1996 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1996.md)
- [The Year 1997 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1997.md)
- [The Year 1998 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1998.md)
- [The Year 1999 in Intrusions: A Dated Record](/case-studies/CHRONICLE_1999.md)
- [The Year 2001 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2001.md)
- [The Year 2002 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2002.md)
- [The Year 2003 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2003.md)
- [The Year 2004 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2004.md)
- [The Year 2005 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2005.md)
- [The Year 2006 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2006.md)
- [The Year 2007 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2007.md)
- [The Year 2010 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2010.md)
- [The Year 2011 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2011.md)
- [The Year 2016 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2016.md)
- [The Year 2017 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2017.md)
- [The Year 2018 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2018.md)
- [The Year 2019 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2019.md)
- [The Year 2020 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2020.md)
- [The Year 2025 in Intrusions: A Dated Record](/case-studies/CHRONICLE_2025.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
