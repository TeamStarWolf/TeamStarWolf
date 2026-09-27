# CAPEC-701 — Browser in the Middle (BiTM)

<a id="capec-701"></a>

**Abstraction:** Standard  
**Typical severity:** High  
**Likelihood:** Medium  
**Status:** Draft  

An adversary exploits the inherent functionalities of a web browser, in order to establish an unnoticed remote desktop connection in the victim's browser to the adversary's system. The adversary must deploy a web client with a remote desktop session that the victim can access.

## Related CWE (2)

- [CWE-294 — Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html) — A capture-replay flaw exists when the design of the product makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the…
- [CWE-345 — Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html) — The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

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

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
