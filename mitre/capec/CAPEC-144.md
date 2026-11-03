# CAPEC-144: Detect Unpublicized Web Services

<a id="capec-144"></a>

Abstraction: Detailed  
Typical severity: Low  
Status: Draft  

An adversary searches a targeted web site for web services that have not been publicized. This attack can be especially dangerous since unpublished but available services may not have adequate security controls placed upon them given that an administrator may believe they are unreachable.

## Related CWE (1)

- [CWE-425: Direct Request](https://cwe.mitre.org/data/definitions/425.html): The web application does not adequately enforce appropriate authorization on all restricted URLs, scripts, or files.

## Prerequisites

- The targeted web site must include unpublished services within its web tree. The nature of these services determines the severity of this attack.

## Related pages

- [CAPEC-87: Forceful Browsing](/mitre/capec/CAPEC-87.md), also related to CWE-425
- [CAPEC-127: Directory Indexing](/mitre/capec/CAPEC-127.md), also related to CWE-425
- [CAPEC-143: Detect Unpublicized Web Pages](/mitre/capec/CAPEC-143.md), also related to CWE-425
- [CAPEC-668: Key Negotiation of Bluetooth Attack (KNOB)](/mitre/capec/CAPEC-668.md), also related to CWE-425
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
