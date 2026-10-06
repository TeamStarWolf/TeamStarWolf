# CAPEC-631: SoundSquatting

<a id="capec-631"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: Low  
Status: Draft  

An adversary registers a domain name that sounds the same as a trusted domain, but has a different spelling. A SoundSquatting attack takes advantage of a user's confusion of the two words to direct Internet traffic to adversary-controlled destinations. SoundSquatting does not require an attack against the trusted domain or complicated reverse engineering.

## Prerequisites

- An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.

## Skills required

- [Low] Adversaries must be able to register DNS hostnames/URL’s.

## Consequences

- Other / Other

## Mitigations

- Authenticate all servers and perform redundant checks when using DNS hostnames.
- Purchase potential SoundSquatted domains and forward to legitimate domain.

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
