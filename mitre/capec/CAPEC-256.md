# CAPEC-256 — SOAP Array Overflow

<a id="capec-256"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Status:** Draft  

An attacker sends a SOAP request with an array whose actual length exceeds the length indicated in the request. If the server processing the transmission naively trusts the specified size, then an attacker can intentionally understate the size of the array, possibly resulting in a buffer overflow if the server attempts to read the entire data set into the memory it allocated for a smaller array.

## Related CWE (1)

- [CWE-805 — Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html) — The product uses a sequential operation to read or write a buffer, but it uses an incorrect length value that causes it to access memory that is outside of the bounds of the buffer.

## Prerequisites

- The targeted SOAP server must trust that the array size as stated in messages it receives is correct, but read through the entire content of the message regardless of the stated size of the array.

## Mitigations

- If the server either verifies the correctness of the stated array size or if the server stops processing an array once the stated number of elements have been read, regardless of the actual array size, then this attack will fail. The former detects the malformed SOAP message while the latter ensures that the server does not attempt to load more data than was allocated for.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
