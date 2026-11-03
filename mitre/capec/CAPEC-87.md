# CAPEC-87: Forceful Browsing

<a id="capec-87"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: High  
Status: Draft  

An attacker employs forceful browsing (direct URL entry) to access portions of a website that are otherwise unreachable. Usually, a front controller or similar design pattern is employed to protect access to portions of a web application. Forceful browsing enables an attacker to access information, perform privileged operations and otherwise reach sections of the web application that have been improperly protected.

## Related CWE (3)

- [CWE-425: Direct Request](https://cwe.mitre.org/data/definitions/425.html): The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html): The product does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html): The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

## Prerequisites

- The forcibly browseable pages or accessible resources must be discoverable and improperly protected.

## Skills required

- [Low] Forcibly browseable pages can be discovered by using a number of automated tools. Doing the same manually is tedious but by no means difficult.

## Consequences

- Confidentiality / Read Data
- Confidentiality, Access Control, Authorization / Bypass Protection Mechanism

## Mitigations

- Authenticate request to every resource. In addition, every page or resource must ensure that the request it is handling has been made in an authorized context.
- Forceful browsing can also be made difficult to a large extent by not hard-coding names of application pages or resources. This way, the attacker cannot figure out, from the application alone, the resources available from the present context.

## Related pages

- [CAPEC-127: Directory Indexing](/mitre/capec/CAPEC-127.md), also related to CWE-285, CWE-425 and 1 more
- [CAPEC-668: Key Negotiation of Bluetooth Attack (KNOB)](/mitre/capec/CAPEC-668.md), also related to CWE-285, CWE-425 and 1 more
- [CAPEC-1: Accessing Functionality Not Properly Constrained by ACLs](/mitre/capec/CAPEC-1.md), also related to CWE-285 and CWE-693
- [CAPEC-17: Using Malicious Files](/mitre/capec/CAPEC-17.md), also related to CWE-285 and CWE-693
- [CAPEC-51: Poison Web Service Registry](/mitre/capec/CAPEC-51.md), also related to CWE-285 and CWE-693
- [CAPEC-59: Session Credential Falsification through Prediction](/mitre/capec/CAPEC-59.md), also related to CWE-285 and CWE-693
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
