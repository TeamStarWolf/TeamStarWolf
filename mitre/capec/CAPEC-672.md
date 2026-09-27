# CAPEC-672 — Malicious Code Implanted During Chip Programming

<a id="capec-672"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** Low

During the programming step of chip manufacture, an adversary with access and necessary technical skills maliciously alters a chip’s intended program logic to produce an effect intended by the adversary when the fully manufactured chip is deployed and in operational use. Intended effects can include the ability of the adversary to remotely control a host system to carry out malicious acts.

## Mapped ATT&CK techniques (1)

- [T1195.003](/mitre/techniques/T1195-003.md)

**Prerequisites:** ::An adversary would need to have access to a foundry’s or chip maker’s development/production environment where programs for specific chips are developed, managed and uploaded into targeted chips pri

**Skills required:** ::SKILL:An adversary needs to be skilled in microprogramming, manipulation of configuration management systems, and in the operation of tools used for

**Mitigations:** ::Utilize DMEA’s (Defense Microelectronics Activity) Trusted Foundry Program members for acquisition of microelectronic components.::Ensure that each supplier performing hardware development implements comprehensive, security-focused configuration ma


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
