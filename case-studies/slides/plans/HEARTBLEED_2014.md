# Slide plan: Heartbleed 2014: When Repairing the Library Was Only the Beginning

- Study: case-studies/HEARTBLEED_2014.md
- Cover title: Heartbleed, CVE-2014-0160 / When Repairing the Library / Was Only the Beginning
- Subtitle: A memory-disclosure defect, and why patching the code was not the same as recovering trust
- Published: 15 November 2026
- Notes: Slide plan for the deck of case-studies/HEARTBLEED_2014.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Patching OpenSSL was the start of recovery, not the end

- Heartbleed was not a broken cipher or one central breach; it was a memory-disclosure defect in certain OpenSSL releases that created many separate exposure and recovery problems.
- The 7 April 2014 advisory described a missing bounds check that could reveal up to 64k of process memory to a connected peer.
- Finding a vulnerable library did not establish what an adversary had taken, and installing a fix did not invalidate a key, password or session already copied.
- The real work was a series of linked but independently testable transitions, not one moment when the Internet was fixed.
Caption: Evidence grade: Confirmed for the defect and the fix; the recovery framing is this study's analysis.
Notes: Advisory, affected 1.0.1 through 1.0.1f and 1.0.2-beta1, fix 1.0.1g [1]. The mismatch between the patched object and the trust relationships is the study's central finding.

## KEY FACTS | One defect, many separate recovery problems

Stat: 64k | Most process memory one request could disclose
Stat: 17.5% | SSL sites Netcraft found supporting heartbeat
Stat: 1.0.1g | The OpenSSL release that fixed the defect
Stat: ~900 | Taxpayers in the Canada Revenue Agency breach
- CVE-2014-0160, commonly called Heartbleed, was disclosed with its fix on 7 April 2014.
- Affected OpenSSL 1.0.1 through 1.0.1f and 1.0.2-beta1; the flaw reached clients as well as servers, and hid inside suppliers' products and appliances.
Notes: CVE, advisory and the 64k disclosure [1]. Heartbeat on 17.5% of SSL sites, about half a million trusted certificates [20]. The CRA incident affected about 900 taxpayers [10][11].

## PART 1 | A peer's claim about its message was trusted too far

- RFC 6520's heartbeat let a peer check that a connection was still alive by echoing back a payload it supplied.
- The implementation had to check that the claimed payload length matched what actually arrived; the affected versions did not.
- A request could then be answered with memory beyond the request, across the boundary between peer-controlled input and the process's private data.
- The encryption around the connection did not make the peer's claimed length trustworthy.
Caption: The defect was a missing bounds check, not an inherent flaw in a keepalive.
Notes: RFC 6520 and the size constraint it required [2]. The trust boundary and the envelope model are the study's framing; the fix and the disable-heartbeat option [1].

## PART 1 | Three quantities that should not be confused

Left: The sizes
- The protocol's valid message constraints.
- The most one malformed exchange could disclose, up to 64k.
- The total an adversary might accumulate over many requests.
Right: Why it matters
- A per-response limit is not a lifetime ceiling; repetition adds observations, not guaranteed fresh value.
- Counting requests is not counting stolen records.
- A private key, a session token and a password differ in structure, use and persistence.
Caption: Multiplying a request count by 64k is not a defensible breach-size estimate.
Notes: The three quantities and the capability-versus-result ladder are the study's analysis, grounded in the advisory [1].

## PART 2 | Disclosure was a process, not one timestamp

| Date | Recorded development |
|---|---|
| Feb 2012 | RFC 6520 defines the heartbeat extension |
| 1 Apr 2014 | Google's details and patch reach OpenSSL participants |
| 7 Apr | OpenSSL publishes the advisory and the 1.0.1g fix |
| 8 Apr | GitHub and Twilio publish response accounts |
| 10 Apr | Canada restricts unpatched public sites; the FFIEC alerts banks |
| 11-12 Apr | Cloudflare's challenge reports successful key extraction |
| 14 Apr | Canada's privacy commissioner discusses the CRA incident |
Caption: Some rows are disclosure, some experiments, some precaution, one confirmed harm.
Notes: Cox's coordination timeline [4]; Codenomicon's independent discovery [5]. The study uses 7 April for the public advisory and avoids a single universal timestamp.

## PART 3 | Finding the dependency meant finding responsibility

- A vulnerable library sat behind familiar service names, inside suppliers' products, and in software acting as a client.
- GitHub described a layered service response; Google noted that a cloud patch was not every customer's patch; Twilio showed supplier exposure and a later client-library update.
- A provider repairing its own service did not mean its customers' application hosts were repaired.
- Distribution packages, appliances and bundled libraries each needed a restart before a replacement became active.
Caption: Repairing one service and repairing every dependent host are different claims.
Notes: GitHub [6], Google product remediation [8], Twilio [19], distribution and appliance boundaries and the restart requirement [3].

## PART 4 | The private-key question changed in public

- Cloudflare first reported failing to recover keys and offered a memory-layout argument, then corrected that belief at the top of the same page.
- Its challenge server then yielded four private-key recoveries, strong evidence the extraction was feasible.
- That is a possibility proof, not an incidence estimate: four successes are not a sampled percentage of all servers.
- A failed search had several explanations, so the absence of an observed theft was not assurance a key stayed secret.
Caption: Read a revised response page as a record with revisions; the correction is evidence.
Notes: The corrected 11 April post [14]; the 12 April results, four recoveries, reboot described as possible not required [7].

## PART 5 | Confirmed harm and precaution were different records

- On 10 April Canada disabled unpatched public government sites until patched and tested, an availability tradeoff accepted to reduce exposure, not proof those sites were breached.
- On 14 April the privacy commissioner recorded the compromise of personal information for about 900 taxpayers at the Canada Revenue Agency.
- The CRA record names social insurance numbers and protective measures; it is confirmed reported harm, not a challenge server or an estimate.
- The victims were people associated with disclosed records, not 900 vulnerable servers.
Caption: Separate adversary-caused loss from defensive, self-imposed interruption.
Notes: Canada's shutdown directive [9]; the CRA incident [10] and the annual-report detail [11].

## PART 6 | Certificates made recovery a distributed problem

Left: Four objects, four meanings
- A private key is a secret; a certificate binds a public key to an identity.
- A replacement certificate does not by itself prove a new key was generated.
- Revocation concerns the old certificate's status; sessions and passwords are separate again.
Right: Two sides to retiring an identity
- Removing an old certificate did not erase copies already held elsewhere.
- Issuing a new one did not guarantee every client rejected the old.
- Netcraft found inconsistent revocation handling among then-current browsers.
Caption: Renewing the certificate was not, on its own, a complete recovery statement.
Notes: The four objects are the study's framing; Netcraft's 23 April tests on stolen-key reuse and browser revocation [22]. Cloudflare's reissue and revocation and its modeled, not billed, costs [12].

## PART 7 | Measurement gave scale, but not omniscience

- Netcraft found heartbeat support on 17.5% of SSL sites, about half a million trusted certificates, and noted that not every server ran the vulnerable configuration.
- Web-server share, heartbeat support, vulnerability and successful theft are different predicates; a headline that two-thirds of the Internet was hacked changes both the denominator and the event.
- The main empirical study scanned only after disclosure, so earlier exposure was inferred, and notification success is not the same as fleet repair.
- A certificate is not automatically one machine, one organization or one person.
Caption: A precise number attached to the wrong population is less informative than a bounded one.
Notes: Netcraft's survey [20]; The Matter of Heartbleed on post-disclosure scanning, notification versus remediation, and its limits [21].

## CROSS-CUTTING THEMES | The lesson is not that open source failed

- The records show organizations relying on a shared implementation, a disclosed defect, vendors turning a fix into products, and researchers examining the response, not a controlled test of development models.
- The real question is whether dependency criticality was matched by knowledge, ownership and response capacity: who knew which services used the component, who could ship the fix, who held the credentials and certificates, who funded maintenance.
- Repairing a capability is not the same as remedying a consequence: once the read is closed, information already copied still carries whatever authority it held.
Caption: The Linux Foundation's later CII funding addressed maintenance capacity, not one defect.
Notes: The open-source framing and the dependency questions are the study's analysis; CII support for OpenSSL and others announced 29 May [18].

## CLOSE | Recovery was many linked transitions, not one moment

- Heartbleed generated many local incident-response timelines inside one wider vulnerability-response event.
- The useful questions are object-specific: which key was exposed, what it was used for, which connections depended on it, and whether data was still encrypted when disclosed.
- Patching the library closed the defect; recovering trust meant running processes, credentials, certificates, integrations, suppliers and users.
Caption: Full study and sources: teamstarwolf.github.io, the Heartbleed 2014 case study.
Notes: Closing synthesis of the study's state model and central finding; no new claims.
