# CAPEC-636 — Hiding Malicious Data or Code within Files

<a id="capec-636"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Status:** Draft  

Files on various operating systems can have a complex format which allows for the storage of other data, in addition to its contents. Often this is metadata about the file, such as a cached thumbnail for an image file. Unless utilities are invoked in a particular way, this data is not visible during the normal use of the file. It is possible for an attacker to store malicious data or code using th

## Mapped ATT&CK techniques (5)

- [T1001.002 — Steganography](/mitre/techniques/T1001-002.md) — Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult.
- [T1027.003 — Steganography](/mitre/techniques/T1027-003.md) — Adversaries may use steganography techniques in order to prevent the detection of hidden information.
- [T1027.004 — Compile After Delivery](/mitre/techniques/T1027-004.md) — Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code.
- [T1218.001 — Compiled HTML File](/mitre/techniques/T1218-001.md) — Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code.
- [T1221 — Template Injection](/mitre/techniques/T1221.md) — Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts.

## Related CWE (1)

- [CWE-506 — Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html) — The product contains code that appears to be malicious in nature.

## Prerequisites

- The operating system must support a file system that allows for alternate data storage for a file.

## Mitigations

- Many tools are available to search for the hidden data. Scan regularly for such data using one of these tools.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
