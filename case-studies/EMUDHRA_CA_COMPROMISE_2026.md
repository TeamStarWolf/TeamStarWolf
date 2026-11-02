# The eMudhra Certificate Authority Key Compromise: A 2026 Case Study

*A TeamStarWolf case study. Published 2 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Method reference: [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md)

## Executive summary

In October 2026 a researcher showed that eight intermediate certificate authority private keys operated by eMudhra (its emSign brand) could be recovered from their public certificates. The keys were elliptic-curve keys that should have been chosen from a space of about 10^115 values; instead they were guessable in at most 256 tries, and one was effectively the number 4. Anyone could reconstruct the private keys and sign certificates that chained to a publicly trusted root. Browsers responded within hours to days, but the clients that software uses to make outbound connections (curl, Python, Node.js, Go, Git, container images) lagged, because they carry their own trust bundles and do not check revocation by default. That split, a fixed browser in front of an unfixed client, is the lesson for a vulnerability-management program.

Evidence grade: **Confirmed** (a researcher proved key control to the browser root programs, multiple root programs acted, and eMudhra admitted the cause).

### Key findings

- **The failure was in key generation, not in a broken algorithm.** eMudhra traced it to a key ceremony on 30 April 2025: an approved deviation to test key wrap and unwrap ran code that produced a weaker second key pair, and similar key labels led to that pair being used for the certificate signing request.
- **Eight intermediates were affected, sixteen certificates in all.** Six were TLS CAs and two were code-signing CAs. Each key appears in two certificates: one issued by eMudhra's own root and one cross-certificate from Sectigo's AAA Certificate Services.
- **No end-entity certificates had been issued from the eight.** The exposure was the ability to forge new certificates, not a set of mis-issued ones already in use.
- **Browsers were fast; software clients were slow.** Chrome and Firefox blocked the certificates within hours; Mozilla removed the emSign ECC Root CA G3 from NSS on 20 October (NSS 3.131.1) and Chrome removed it from its root store on 27 October. Non-browser trust bundles updated on their own schedules.
- **The CA exited the business.** On 22 October eMudhra announced it would leave the global SSL/TLS certificate market, while keeping its digital-signature, eSign, and CertiNext lines.

### Top recommendations

1. Inventory where each outbound client gets its trust: the operating system store, or a bundle shipped with the language runtime or container image.
2. Patch the client path, not only the browser. Update `ca-certificates`, Python `certifi`, Node.js, and base images, and rebuild and redeploy.
3. Pin and verify by key, not by CA name. Block the eight affected public-key hashes rather than trusting that a name-level distrust has reached every client.
4. Treat a CA distrust as a standing runbook. See [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md).

## Scope and method

This study covers the eMudhra (emSign) intermediate-CA key compromise disclosed in October 2026, from primary vendor and root-program sources. Each claim carries one of three evidence grades, so that what happened stays separate from what is merely possible.

| Grade | Meaning |
|---|---|
| Confirmed | An observed, attributed event with technical detail from the party involved, a root program, or a government agency |
| Reported | A single vendor's account, not independently corroborated |
| Demonstrated | A research proof of concept with no known in-the-wild use |

## What happened

A properly generated P-384 elliptic-curve key is drawn from a space of roughly 10^115 values, which is why a public key does not reveal its private counterpart. The eight eMudhra intermediate keys were not drawn from that space. Reporting describes them as recoverable in at most 256 guesses, with one key effectively equal to 4 (**Confirmed**: eMudhra's own account plus independent researcher analysis). A private key that can be guessed from its public certificate lets anyone issue certificates that chain to a trusted root, which defeats the purpose of the hierarchy.

eMudhra attributed the flaw to a single key ceremony on 30 April 2025 that produced a batch of 24 intermediates (**Confirmed**: eMudhra statement). The ceremony was an approved deviation from the normal process, intended to test key wrap and unwrap, and a code flaw in that path generated a weaker second key pair. Because the key labels were similar, that weaker pair was used for the certificate signing request. eMudhra states that its root keys and its other intermediates were not affected.

## Scope of the compromise

The affected set is eight intermediate CAs: six TLS and two code-signing (**Confirmed**). Each key is present in two certificates, one issued by eMudhra's emSign root and one cross-certificate issued by Sectigo's AAA Certificate Services, so sixteen certificates carry the weak keys. The cross-certificates matter because a client that distrusts only the eMudhra root can still build a trusted path through the Sectigo cross-signature, which is one reason the root programs moved to block the keys directly rather than relying on a single root removal.

eMudhra states that none of the eight intermediates had issued any end-entity (leaf) certificate (**Confirmed**: eMudhra statement). The risk was therefore forward-looking: an attacker in possession of a reconstructed key could mint new, valid-looking certificates for any name, not that existing sites were already impersonated.

## How it was found

A researcher known as Wayne identified the weak keys on 17 October 2026 while running a check against the Common CA Database (CCADB) (**Confirmed**: root-program records). To prove the keys were genuinely recoverable, the researcher produced valid signed attestations with all eight private keys and submitted them to the browser root programs and to eMudhra. A signed attestation is direct proof of key possession, which moved the response from suspicion to action immediately.

## The response

| Party | Action | Date |
|---|---|---|
| Chrome | Blocked the intermediates via CRLSet; removed the emSign ECC Root CA G3 from the Chrome Root Store | within hours; root removal 27 October 2026 |
| Mozilla | Removed emSign ECC Root CA G3 from NSS (3.131.1) | 20 October 2026 |
| Microsoft | Blocked the eight intermediates | from 20 October 2026 |
| Apple | Blocks the affected TLS certificates; trust store removing or blocking the parent root | October 2026 |
| Go project | Tracks the block in `crypto/x509` (CVE-2026-111943) | October 2026 |
| Okta and Auth0 | Removing trust in the emSign ECC Root CA G3 across their services | October 2026 |
| Downstream bundles | Python `certifi`, Debian, and Ubuntu dropped the root | October 2026 |
| eMudhra | Announced exit from the global SSL/TLS certificate business | 22 October 2026 |

Browser action was effectively complete within days through a mix of blocklists and root removal. The clients that applications use for outbound TLS followed on their own release cadences.

## The client-path exposure gap

The defensive lesson is not that browsers were slow, because they were not. It is that a browser and a server's outbound HTTP client are different trust stores with different update paths. A web browser checks revocation signals and receives fast-pushed blocklists; `curl`, a language runtime's HTTP library, `git`, and a container base image usually do not check revocation by default and carry a trust bundle that changes only when the bundle is updated and the workload is rebuilt. During the window between the browser fix and the bundle update, a server that calls an API, a webhook, or a package registry over TLS would still trust a forged certificate chaining to the affected keys.

This is why the remediation is an inventory of trust sources per client, a patch of the client path, and a block keyed on the eight public-key hashes rather than on the CA's name. The full method, including per-platform and per-runtime trust-store locations and an assessment decision model, is in [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md).

## Sources

- eMudhra incident statement and the Mozilla CCADB bug record (Bugzilla 2083449).
- Chrome Root Store, Mozilla NSS, and Apple trust-store announcements.
- Go project `crypto/x509` advisory (CVE-2026-111943).
- Vendor analyses from Kudelski Security, Cloudflare, Help Net Security, Keyfactor, and Qualys.
- Reporting from The Hacker News.

## Related references

- [Certificate Trust Incident Response](/CERTIFICATE_TRUST_INCIDENT_RESPONSE_REFERENCE.md) (the method this incident illustrates)
- [Cryptography Reference](/CRYPTOGRAPHY_REFERENCE.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [Notable Incidents](/NOTABLE_INCIDENTS.md)
