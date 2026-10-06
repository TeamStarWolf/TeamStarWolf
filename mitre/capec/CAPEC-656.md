# CAPEC-656: Voice Phishing

<a id="capec-656"></a>

Abstraction: Detailed  
Typical severity: High  
Likelihood: High  
Status: Stable  

An adversary targets users with a phishing attack for the purpose of soliciting account passwords or sensitive information from the user. Voice Phishing is a variation of the Phishing social engineering technique where the attack is initiated via a voice call, rather than email. The user is enticed to provide sensitive information by the adversary, who masquerades as a legitimate employee of the alleged organization. Voice Phishing attacks deviate from standard Phishing attacks, in that a user doesn't typically interact with a compromised website to provide sensitive information and instead provides this information verbally. Voice Phishing attacks can also be initiated by either the adversary in the form of a "cold call" or by the victim if calling an illegitimate telephone number.

## Prerequisites

- An adversary needs phone numbers to initiate contact with the victim, in addition to a legitimate-looking telephone number to call the victim from.
- An adversary needs to correctly guess the entity with which the victim does business and impersonate it. Most of the time phishers just use the most popular banks/services and send out their "hooks" to many potential victims.
- An adversary needs to have a sufficiently compelling call to action to prompt the user to take action.
- If passively conducting this attack via a spoofed website, replicated website needs to look extremely similar to the original website and the URL used to get to that website needs to look like the real URL of the said business entity.

## Skills required

- [Medium] Basic knowledge about websites: obtaining them, designing and implementing them, etc.

## Consequences

- Confidentiality, Access Control, Authorization / Gain Privileges
- Confidentiality / Read Data
- Integrity / Modify Data

## Mitigations

- Do not accept calls from unknown numbers or from numbers that may be flagged as spam. Also, do not call numbers that appear on-screen after being unexpectedly redirected to potentially malicious websites. In either case, do not provide sensitive information over voice calls that are not legitimately initiated. Instead, call your Bank, PayPal, eBay, etc., via the number on their public-facing website and inquire about the problem.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
