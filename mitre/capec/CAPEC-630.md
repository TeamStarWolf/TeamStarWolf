# CAPEC-630: TypoSquatting

<a id="capec-630"></a>

Abstraction: Detailed  
Typical severity: Medium  
Likelihood: Low  
Status: Draft  

An adversary registers a domain name with at least one character different than a trusted domain. A TypoSquatting attack takes advantage of instances where a user mistypes a URL (e.g. www.goggle.com) or not does visually verify a URL before clicking on it (e.g. phishing attack). As a result, the user is directed to an adversary-controlled destination. TypoSquatting does not require an attack against the trusted domain or complicated reverse engineering.

## Prerequisites

- An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.

## Skills required

- [Low] Adversaries must be able to register DNS hostnames/URL’s.

## Consequences

- Other / Other

## Mitigations

- Authenticate all servers and perform redundant checks when using DNS hostnames.
- Purchase potential TypoSquatted domains and forward to legitimate domain.

## Related pages

- [CAPEC Attack Pattern Reference](/CAPEC_REFERENCE.md)
- [All CAPEC attack patterns](/mitre/capec/README.md)

<!-- library-refs:start (written by scripts/build_crosslinks.py; do not edit) -->

## Library references

Hand-written pages in this library that link to this page or to this object's entry on the MITRE site:

- [npm Supply-Chain Attacks, 2018 to 2026: The Record and the Defenses](/case-studies/NPM_SUPPLY_CHAIN_ATTACKS.md)

<!-- library-refs:end -->

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
