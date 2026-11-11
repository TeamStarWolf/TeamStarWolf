# CAPEC-701: Browser in the Middle (BiTM)

<a id="capec-701"></a>

Abstraction: Standard  
Typical severity: High  
Likelihood: Medium  
Status: Draft  

An adversary exploits the inherent functionalities of a web browser, in order to establish an unnoticed remote desktop connection in the victim's browser to the adversary's system. The adversary must deploy a web client with a remote desktop session that the victim can access.

## Related CWE (2)

- [CWE-294: Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html): A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the original message (or with minor changes).
- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html): The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Prerequisites

- The adversary must create a convincing web client to establish the connection. The victim then needs to be lured onto the adversary's webpage. In addition, the victim's machine must not use local authentication APIs, a hardware token, or a Trusted Platform Module (TPM) to authenticate.

## Skills required

- [Medium]

## Consequences

- Confidentiality, Access Control, Authentication / Gain Privileges
- Confidentiality, Authorization / Read Data
- Integrity / Modify Data

## Mitigations

- Implementation: Use strong, mutual authentication to fully authenticate with both ends of any communications channel

## Related pages

- [CAPEC-60: Reusing Session IDs (aka Session Replay)](/mitre/capec/CAPEC-60.md), also related to CWE-294
- [CAPEC-94: Adversary in the Middle (AiTM)](/mitre/capec/CAPEC-94.md), also related to CWE-294
- [CAPEC-102: Session Sidejacking](/mitre/capec/CAPEC-102.md), also related to CWE-294
- [CAPEC-509: Kerberoasting](/mitre/capec/CAPEC-509.md), also related to CWE-294
- [CAPEC-555: Remote Services with Stolen Credentials](/mitre/capec/CAPEC-555.md), also related to CWE-294
- [CAPEC-561: Windows Admin Shares with Stolen Credentials](/mitre/capec/CAPEC-561.md), also related to CWE-294
- [CWE Weakness Reference](/CWE_REFERENCE.md)
- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [Russia-Attributed Threat Actors: The Public Record](/case-studies/THREAT_ACTORS_RUSSIA.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
