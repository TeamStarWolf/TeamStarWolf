# CAPEC-163 — Spear Phishing

<a id="capec-163"></a>

**Abstraction:** Detailed  
**Typical severity:** High  
**Likelihood:** High  
**Status:** Draft  

An adversary targets a specific user or group with a Phishing (CAPEC-98) attack tailored to a category of users in order to have maximum relevance and deceptive capability. Spear Phishing is an enhanced version of the Phishing attack targeted to a specific user or group. The quality of the targeted email is usually enhanced by appearing to come from a known or trusted entity. If the email account

## Mapped ATT&CK techniques (7)

- [T1534 — Internal Spearphishing](/mitre/techniques/T1534.md) — After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization.
- [T1566.001 — Spearphishing Attachment](/mitre/techniques/T1566-001.md) — Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002 — Spearphishing Link](/mitre/techniques/T1566-002.md) — Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.
- [T1566.003 — Spearphishing via Service](/mitre/techniques/T1566-003.md) — Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems.
- [T1598.001 — Spearphishing Service](/mitre/techniques/T1598-001.md) — Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting.
- [T1598.002 — Spearphishing Attachment](/mitre/techniques/T1598-002.md) — Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting.
- [T1598.003 — Spearphishing Link](/mitre/techniques/T1598-003.md) — Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting.

## Related CWE (1)

- [CWE-451 — User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html) — The user interface (UI) does not properly represent critical information to the user, allowing the information - or its source - to be obscured or spoofed.

## Prerequisites

- None. Any user can be targeted by a Spear Phishing attack.

## Skills required

- Spear phishing attacks require specific knowledge of the victims being targeted, such as which bank is being used by the victims, or websites

## Mitigations

- Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also

---

*Source: MITRE ATT&CK® / D3FEND™ / CAPEC™ / ATLAS™ — trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
