# CAPEC-117 — Interception

<a id="capec-117"></a>

**Abstraction:** Meta  
**Typical severity:** Medium  
**Likelihood:** Low  
**Status:** Stable  

An adversary monitors data streams to or from the target for information gathering purposes. This attack may be undertaken to solely gather sensitive information or to support a further attack against the target. This attack pattern can involve sniffing network traffic as well as other types of data streams (e.g. radio). The adversary can attempt to initiate the establishment of a data stream or p

## Related CWE (1)

- [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

## Prerequisites

- The target must transmit data over a medium that is accessible to the adversary.

## Mitigations

- Leverage encryption to encode the transmission of data thus making it accessible only to authorized parties.

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
