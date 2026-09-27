# CAPEC-651 — Eavesdropping

<a id="capec-651"></a>

**Abstraction:** Standard  
**Typical severity:** Medium  
**Status:** Draft  

An adversary intercepts a form of communication (e.g. text, audio, video) by way of software (e.g., microphone and audio recording application), hardware (e.g., recording equipment), or physical means (e.g., physical proximity). The goal of eavesdropping is typically to gain unauthorized access to sensitive information about the target for financial, personal, political, or other gains. Eavesdropp

## Mapped ATT&CK techniques (1)

- [T1111 — Multi-Factor Authentication Interception](/mitre/techniques/T1111.md) — Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources.

## Related CWE (1)

- [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html) — The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

## Prerequisites

- The adversary typically requires physical proximity to the target's environment, whether for physical eavesdropping or for placing recording equipment. This is not always the case for software-based

## Mitigations

- Be mindful of your surroundings when discussing sensitive information in public areas.
- Implement proper software restriction policies to only allow authorized software on your environment. Use of anti-virus and other security monitoring and detect

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
