# CAPEC-98 — Phishing

<a id="capec-98"></a>

**Abstraction:** Standard  
**Typical severity:** Very High  
**Likelihood:** High

Phishing is a social engineering technique where an attacker masquerades as a legitimate entity with which the victim might do business in order to prompt the user to reveal some confidential information (very frequently authentication credentials) that can later be used by an attacker. Phishing is essentially a form of information gathering or fishing for information.

## Mapped ATT&CK techniques (2)

- [T1566](/mitre/techniques/T1566.md)
- [T1598](/mitre/techniques/T1598.md)

## Related CWE (1)

[CWE-451](/CWE_REFERENCE.md)

**Prerequisites:** ::An attacker needs to have a way to initiate contact with the victim. Typically that will happen through e-mail.::An attacker needs to correctly guess the entity with which the victim does business a

**Skills required:** ::SKILL:Basic knowledge about websites: obtaining them, designing and implementing them, etc.:LEVEL:Medium::

**Mitigations:** ::Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also


---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
