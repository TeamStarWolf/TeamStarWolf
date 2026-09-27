# CAPEC-112 — Brute Force

<a id="capec-112"></a>

**Abstraction:** Meta  
**Typical severity:** High  
**Likelihood:** 

In this attack, some asset (information, functionality, identity, etc.) is protected by a finite secret value. The attacker attempts to gain access to this asset by using trial-and-error to exhaustively explore all the possible secret values in the hope of finding the secret (or a value that is functionally equivalent) that will unlock the asset.

## Mapped ATT&CK techniques (1)

- [T1110](/mitre/techniques/T1110.md)

## Related CWE (3)

[CWE-330](/CWE_REFERENCE.md) [CWE-326](/CWE_REFERENCE.md) [CWE-521](/CWE_REFERENCE.md)

**Prerequisites:** ::The attacker must be able to determine when they have successfully guessed the secret. As such, one-time pads are immune to this type of attack since there is no way to determine when a guess is cor

**Skills required:** ::SKILL:The attack simply requires basic scripting ability to automate the exploration of the search space. More sophisticated attackers may be able t

**Mitigations:** ::Select a provably large secret space for selection of the secret. Provably large means that the procedure by which the secret is selected does not have artifacts that significantly reduce the size of the total secret space.::Use a secret space that


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
