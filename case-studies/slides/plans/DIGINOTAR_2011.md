# Slide plan: DigiNotar 2011

- Study: case-studies/DIGINOTAR_2011.md
- Cover title: One issuer / Every relying party / Broken trust
- Subtitle: How the 2011 DigiNotar compromise turned one certificate authority's failure into a trust-infrastructure crisis for everyone who trusted it.
- Published: 18 November 2026
- Notes: The cover frames a single CA compromise as a shared trust-root failure, not an isolated vendor outage.

## FAILURE MODE | A valid signature is not a trustworthy issuer
- A certificate can carry a valid signature while making an unauthorized identity claim.
- Browser checks can pass while the organization behind the certificate has lost control of issuance.
- Repairing a server does not retract credentials already copied into other systems.
- The subscriber whose name was impersonated did nothing wrong yet carried the risk.
Caption: Evidence grade: Confirmed (Fox-IT final report; Dutch Safety Board)
Notes: This reframes the event as an authorization failure rather than a broken algorithm.

## EVIDENCE | What the record separates, and cannot settle
- Primary findings come from named investigators, not independent reproduction of forensic images.
- Fox-IT dates initial entry to June 17 across eight CA servers, with key activation left uncertain.
- Outstanding-certificate counts, OCSP-request counts, and affected-user estimates are distinct measures.
- Keep rogue issuance separate from confirmed interception rather than summing them into one victim total.
Caption: Evidence grade: Confirmed (Source 1, pp. 3 to 6, 37 to 46)
Notes: The study's discipline is naming the measurement before citing any number.

## TIMELINE | Separate clocks, no single end date
These developments belong to different actors and should not be collapsed onto one date.

| Date | Recorded development | How to read it |
|---|---|---|
| June 17 | Earliest entry in the final reconstruction | Not the same as earlier reconnaissance |
| Around July 1 | Protected-network intrusion | Distinct from initial web access |
| July 10 | Earliest surviving rogue-issuance evidence | Does not prove the full issuance history |
| July 19 | Internal detection reported by VASCO | Detection, not the start of the intrusion |
| August 29 | Google reports attempted interception in Iran | Public response, not protection of every client |
| September 3 | Google rejects DigiNotar-operated authorities | A broader vendor trust decision |
| September 19 to 20 | Bankruptcy petition, then court declaration | Corporate outcome, not technical proof |
Caption: Evidence grade: Confirmed (sources 1 to 9, 13, 14)
Notes: The chronology deliberately avoids a single date on which the Netherlands became safe again.

## MEASUREMENT | Counting abuse without inventing victims
Stat: 298,140 | Unique IPs behind Google-cert GOOD replies
Stat: 654,313 | GOOD OCSP responses, not account takeovers
Stat: 95% | Of 665,974 requests that came from Iran
Caption: Evidence grade: Reported (Source 1, pp. 60 to 66)
Notes: These are observations from a measurement process, not a direct headcount; an IP count is legitimate, but renaming it people creates false precision.

## TWO LEDGERS | Fraudulent issuance versus interception
Left: What was fraudulently issued
- July 19 reconciliation flagged 128 SSL certificates with no application record.
- The next day it flagged a further 129 unmatched certificates.
- A rogue *.google.com certificate was among those produced.
- A name in a rogue certificate shows intended impersonation, not a breach of that organization.
Right: What interception evidence supports
- OCSP GOOD responses concentrated on users primarily in Iran.
- Google reported attempted interception and said Chrome detected the certificate.
- GOOD responses indicate query activity, not verified account takeovers.
- DNS poisoning as the delivery method remains an assessment.
Caption: Evidence grade: Reported (Source 1; Google, source 3)
Notes: Strong interception evidence at scale still does not convert request counts into a victim census.

## DETECTION | The reconciliation control that had lapsed
- DigiNotar compared issued certificates against legitimate request records to catch rogue issuance.
- That comparison job had stopped running for an unexplained period, with no substitute covering the gap.
- Restored on July 19, it immediately produced useful detections of unmatched certificates.
- A dashboard reporting zero unmatched certificates is worthless if the comparison job is not running.
Caption: Evidence grade: Confirmed (Source 14, printed p. 43)
Notes: The availability of a detective process is itself a security signal to monitor.

## SEPTEMBER 2 | Missing records changed the guarantee
Stat: 531 | Certificates lacking application records
Stat: 333 | Of those that could still be revoked
Stat: 198 | Serial numbers that could not be recovered
- DigiNotar used an OCSP whitelist to respond from the set it still trusted, not only a revoked list.
- A server-side policy change and effective rejection across all clients are separate verification tasks.
Caption: Evidence grade: Confirmed (Source 14, printed pp. 46 to 47)
Notes: Altered records meant some known rogue issuance lacked the serial needed for normal revocation, so the inability to guarantee separation, not a confirmed count, drove the trust withdrawal.

## MODEL | A certificate is a signed assertion, not a badge
- Five roles: subject, issuer, validating software, software operator, and relying party.
- RFC 5280 path validation checks a chain against trust anchors but keeps the business trust decision alive.
- A compromised issuing workflow produces output that is mathematically consistent yet operationally false.
- Ask which property failed: key secrecy, authorization, binding integrity, policy, or distrust delivery.
Caption: Evidence grade: Inferred (original analysis; RFC 5280, source 10)
Notes: Naming the failed property determines the evidence and remedy an incident actually needs.

## THREE OPERATIONS | Revoke, distrust and replace differ
Left: What each operation does
- Revoking a credential targets a bounded, reliably identified certificate.
- Withdrawing trust decides whether an issuer's assertions are accepted at all.
- Replacing a service certificate lets legitimate communication survive that withdrawal.
- Completing only replacement can leave malicious assertions still accepted.
Right: Why removal was blunt but decisive
- Mozilla's first root removal and later explicit distrust were not identical controls.
- Cross-signed and intermediate paths meant removing one root left acceptance behavior intact.
- The real test is what the relying application accepts under its current policy.
- Trust distribution has timing: announce, package, retrieve, load, then connect.
Caption: Evidence grade: Confirmed (Mozilla advisories, sources 4 to 6)
Notes: Trust-store revocation was the blunt remedy, but only an application-level negative test proves it worked.

## VENDOR RESPONSE | A staged sequence, not one revocation
Vendor actions arrived on different dates with different scopes and implementations.

| Vendor | Key dates | Scope of action |
|---|---|---|
| Google | September 3 | Rejected all authorities operated by DigiNotar |
| Mozilla | August 30, September 6 | Removed root, then explicit distrust of intermediates |
| Microsoft | August 29, 6, 13 | Trust-list change, then expanded blocked coverage |
Caption: Evidence grade: Confirmed (sources 3 to 7)
Notes: An advisory proves a released fix, never that every endpoint installed it.

## CONTINUITY | BAPI, a dependency outside the framework
- Logius first treated withdrawal as a simple PKIoverheid swap to other providers.
- The Tax Administration used BAPI certificates supplied by DigiNotar outside that framework.
- Broad vendor distrust risked making those certificates unusable, endangering tax-return processing.
- Dependency discovery itself consumed scarce response time, forcing continuity over immediate removal.
Caption: Evidence grade: Confirmed (Source 14, printed pp. 47 to 48)
Notes: A non-PKIoverheid credential was still a critical government dependency nobody had inventoried.

## ATTRIBUTION | Bounded claims, assessed intent
- The "ComodoHacker" identity is a self-claim in the record, not an adjudicated attribution.
- A singular "intruder" in a forensic report does not establish one person performed every action.
- Infrastructure location, self-description, and similarity to other incidents are not proof of a state actor.
- Interception concentrated on Iranian users is strong evidence of reach, not a named decision-maker.
Caption: Evidence grade: Reported (Source 1; source 14, printed p. 47)
Notes: Any state-interest reading stays an assessment, held separate from the technical findings.

## CONTROLS | A defensive architecture for trust incidents
- Separate boundaries for requesting, approving, signing, publishing, status, and acceptance.
- Store reconciliation evidence where the issuing workload cannot silently rewrite it.
- Monitor business output, not only perimeter movement, and make the monitor report its own health.
- Maintain a tested way to prove both rejection of a bad path and use of a legitimate replacement.
Caption: Evidence grade: Inferred (original control model)
Notes: These are proposed controls, not measures proven sufficient against the 2011 event.

## LIMITS | What this case does not prove
- It does not establish a confidently ordered attack chain for every internal system.
- It does not prove every credential from the issuer was maliciously used; uncertainty alone justified distrust.
- It does not establish that a national public-service collapse occurred, only serious risk averted by improvisation.
- It does not prove one modern control would have solved every failure mode at once.
Caption: Evidence grade: Confirmed (Source 14; Safety Board summary, source 9)
Notes: The durable lesson is that distrust must be an executable, verifiable capability before a crisis.
