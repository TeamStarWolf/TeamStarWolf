# Slide plan: DROWN: How an Obsolete Protocol Extended the Reach of a Shared Private Key

- Study: case-studies/DROWN_2016.md
- Cover title: DROWN 2016 / One key, two services / The reach of reuse
- Subtitle: A modern site inherited risk from a legacy SSLv2 service because both used the same RSA private key, so remediation follows key use, not the app name.
- Published: 15 November 2026
- Notes: Cover frames DROWN as a boundary mismatch between key use and asset inventory; a research demonstration, no invented incident.

## EXECUTIVE SUMMARY | The security boundary followed the key, not the inventory

DROWN is a 2016 case about a boundary that did not match the organization's inventory.

- A modern-looking website could inherit risk from a separate legacy service sharing its RSA private key.
- Improving the front door alone could leave the important dependency untouched.
- This was a research demonstration: no invented victim, threat actor, ransom or stolen-record count.
- Obsolete-protocol retirement and key ownership belong in one program.
Caption: Evidence grade: a research demonstration, not an observed incident.
Notes: Executive assessment; the attack assists session exposure, not key theft. [1]

## KEY FACTS | A session attack with Internet-scale reach, bounded to 2016

Stat: 33% | HTTPS servers vulnerable to general DROWN
Stat: 22% | Vulnerable with browser-trusted certs
Stat: 17% | Directly supporting SSLv2
- CVE-2016-0800, publicly disclosed 1 March 2016; the USENIX paper followed August 2016.
- Name: Decrypting RSA with Obsolete and Weakened eNcryption.
- The attack exposes a session; it does not recover the server's long-term private key.
- Percentages are 2016 measurements of 36 million servers, not current prevalence or confirmed loss.
Caption: Evidence grade: Confirmed measurement; figures bounded to 2016.
Notes: Scope and measurements; preserve the source denominator. [1][3][4][5]

## PART 1 | Deprecation is a governance task, not an automatic disappearance

RFC 6176 (March 2011) already barred negotiating SSLv2; DROWN showed continued support could endanger other connections years after the prohibition.

- A standard can change while firmware, app bundles and recovery environments stay unchanged.
- An exception should name who needs the behavior, how it was established and when it ends.
- Administrator intention differs from system behavior; evidence must show what actually runs.
Caption: Evidence grade: a Confirmed standard [2]; surrounding analysis original.
Notes: The standard had already rejected SSLv2; deprecation starts a migration obligation. [2]

## PART 1 | Inherited exposure, not direct support, is the durable finding

The August 2016 USENIX study reported the measurements; the lasting point is the distinction between direct support and inherited exposure.

- Counting only individually vulnerable listeners underestimates the relationship between services.
- Measurement units differ: server, IP, website, domain, certificate and organization are not interchangeable.
- Multiplying a server percentage by a global user count creates an unsupported new claim.
- Vulnerability means an attack condition exists, not that an adversary observed useful traffic.
Caption: Evidence grade: Confirmed measurement; keep exposure and loss separate.
Notes: What the research established; exposure and loss need separate columns. [3]

## PART 1 | The old protocol's responses help decrypt a newer session

A padding oracle reveals whether encrypted material has an expected structure; DROWN uses the older protocol to assist decryption associated with a newer one.

- CERT/CC: the attack risks individual sessions and does not yield the server's private key.
- Three objects matter: an observed connection, a vulnerable service and the shared key relationship.
- Reading the customer-facing TLS version describes that connection, not every use of the key.
- The article omits exploit messages and interception instructions by design.
Caption: Evidence grade: a Demonstrated mechanism [4]; no exploitation recipe.
Notes: Mechanism without a recipe; CERT/CC advises disabling SSLv2 and avoiding key reuse. [1][4]

## PART 1 | General and special DROWN need separate descriptions

OpenSSL's 1 March advisory: a shared RSA key on another service, including mail, can expose traffic; a faster variant affects versions before the 19 March 2015 fixes.

- Releases 1.0.2g and 1.0.1s disabled SSLv2 by default at build time and removed EXPORT ciphers.
- Do not collapse this into "all OpenSSL was broken the same way."
- A worksheet should record product, package identity, service, protocol availability and key links.
- A high vendor rating signals urgency in its own system; it is not proof of a breach.
Caption: Evidence grade: a Confirmed advisory [5]; worksheet guidance original.
Notes: General and special DROWN differ by implementation, features and topology. [5]

## PART 2 | Disabling SSLv2 ciphers was not the same as disabling SSLv2

OpenSSL warned that disabling SSLv2 ciphers was insufficient without the CVE-2015-3197 fix while SSLv2 stayed enabled; 1.0.1r and 1.0.2f were the earlier fixes.

- Configuration intention and a system's effective behavior could differ.
- Control descriptions should be testable: observed behavior excludes the obsolete protocol.
- Verify with approved assessment methods, not an improvised attack on production.
- One passing hostname may miss a DR address, alternate port or reachable backend.
Caption: Evidence grade: a Confirmed advisory [5]; acceptance criteria original.
Notes: Why nominally disabled ciphers could mislead; name the tested endpoint, service, time and method. [5]

## PART 2 | Key reuse makes the key, not the product name, the unit of fix

Red Hat: an application using an unaffected library can still be exposed through shared RSA key use elsewhere, so a product name cannot establish the wider relationship's security.

- Represent a key as an owned security asset linked to its authorized uses.
- Correlate with a fingerprint or approved identifier; never collect private keys in a register.
- Record owner, environment, deployment and recovery path per use, including standby and hosting.
- If two teams share a key, neither can certify the full exposure boundary alone.
Caption: Evidence grade: Confirmed guidance [6]; register design original.
Notes: Key reuse changes the unit of remediation; someone must reconcile both teams' evidence. [6]

## PART 2 | Certificate renewal and key replacement are different actions

The researchers' FAQ: certificate replacement is not automatically required because DROWN does not recover the private key; use a fresh key when SSLv2 cannot be confirmed disabled everywhere.

- A new certificate that keeps the old key preserves the same dependency.
- Session confidentiality is a separate property from preventing future use.
- An exposure finding does not establish that all historical sessions were decrypted.
- Credential response follows evidence; do not claim every password was stolen.
Caption: Evidence grade: Reported by researchers [1], bounded to their context.
Notes: Certificates, private keys and session secrets are distinct properties. [1]

## PART 2 | Forward secrecy depends on the mechanism actually negotiated

The paper reports a fast active variant that could impersonate a server under its conditions; this does not mean correctly negotiated ephemeral exchanges are passively decrypted the same way.

- Preference, permission and observed negotiation are three different questions.
- Do not conclude forward secrecy is useless; attribute properties to the negotiated mechanism.
- A historical QUIC design does not apply to every later protocol of that name.
- RFC 9001 (May 2021) specifies TLS 1.3 or later for QUIC.
Caption: Evidence grade: Reported and Demonstrated [3]; a later standard [7].
Notes: Forward secrecy and protocol names need careful wording. [3][7]

## DEFENDER VIEW | Track unresolved risk, not just completed patches

Left: Build the exposure register
- Start from a service register with an owner; add crypto identifiers and retirement evidence.
- Separate known facts from open questions; give unknown an owner and a deadline.
- Include the path by which a retired config could return via images, backups or scripts.
Right: Prioritize and investigate
- Rank by exposed capability, service value and key uncertainty, not traffic volume.
- Choose a supported remediation path; a 2016 fix release is not a valid destination today.
- Ask what evidence separates exposure from misuse before collecting every log.
Caption: Evidence grade: original defensive analysis built on the sources.
Notes: Exposure register, safe prioritization and possible-exploitation review. [4][6]

## MITRE MAPPINGS | No ATT&CK mapping: a research demonstration, not an intrusion

The study maps no ATT&CK techniques because it documents vulnerability research, Internet measurement and disclosure, not an observed campaign.

| Element | Why not mapped |
|---|---|
| Threat actor | None identified; the study invents no adversary |
| Initial access | No observed intrusion to attribute |
| Impact | Session exposure demonstrated, no confirmed loss |
| Private-key theft | Out of scope; DROWN does not recover the key |
Caption: Evidence grade: a Confirmed boundary; the study declines to map ATT&CK.
Notes: Boundary kept where the study declines to map; exposure is not confirmed misuse. [1][3]

## CROSS-CUTTING THEMES | What DROWN is routinely overstated and understated

Left: Often overstated
- "Every user's password was stolen" drawn from a mere vulnerability report.
- A server percentage multiplied into a global user count.
- Forward secrecy declared useless across all conditions.
Right: Often understated
- Inherited exposure through a shared key on a legacy service.
- Paths that let a retired config return via images or failover.
- Unknown key distribution quietly filed as not vulnerable.
Caption: Evidence grade: a synthesis of the study's exposure-versus-loss distinctions.
Notes: Keeps the overstated-versus-understated reading of the evidence. [1][3][6]

## CLOSE | Make the next shared-dependency problem easier to investigate

- Combine retirement of insecure capability with an account of the wider key relationship.
- Distinguish session decryption from key theft, 2016 measurement from current prevalence, vulnerability from loss.
- Assign ownership to keys as well as machines; put retirement in the deployment process.
- Measure unresolved risk: ownerless key uses, unverified recovery environments, exceptions past review.
Caption: Evidence grade: original recommendations; later guidance [9].
Notes: Final assessment and lasting-program recommendations; keep history separate from present config advice. [9]
