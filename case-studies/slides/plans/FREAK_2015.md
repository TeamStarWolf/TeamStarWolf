# Slide plan: FREAK 2015: When Export-Grade RSA Returned Through a Client State Machine

- Study: case-studies/FREAK_2015.md
- Cover title: FREAK 2015 / Export-Grade RSA / Through a Client State Machine
- Subtitle: A client state-machine defect let export RSA activate outside the mode the client intended, so strong certificates did not guarantee strong session setup.
- Published: 15 November 2026
- Notes: House-style deck plan; every claim stays bounded to the study's cited sources [1]-[9].

## EXECUTIVE SUMMARY | A request for strong encryption could still accept a weak key

FREAK showed a client could appear to request strong encryption while accepting a weak key from a different negotiation path.

- Significance came from legacy export cryptography, incorrectly enforced handshake rules, and still-deployed compatible servers.
- It was neither a universal break of RSA nor simply a site with an expired certificate.
- The record supports a technical and response history, not a worldwide breach census.
- No reviewed source establishes an aggregate loss total or one attacker behind all exploitation.
Caption: Evidence grade: a response history, not a breach census.
Notes: Framed from the study's executive assessment; the arc runs from the Oct 2014 report to the March 2015 responses. [1][2][4]

## KEY FACTS | One behavior, three CVEs, and a January fix before a March name

Stat: 512-bit | Export RSA key length factored in research
Stat: ~7.5 hrs | Reported time to factor one such key
Stat: US$104 | Reported 2015 EC2 cost per key
Stat: Low | OpenSSL's original severity label
- CVE-2015-0204 (OpenSSL): a client accepts a temporary RSA key during a non-export RSA exchange.
- CVE-2015-1637 (Microsoft Schannel) and CVE-2015-1067 (Apple Secure Transport) are related but distinct defects.
- Reported Oct 22, 2014; fixed Jan 8, 2015 (1.0.1k, 1.0.0p, 0.9.8zd); named publicly March 3, 2015.
- A separate CVE per implementation means one identifier is not a complete inventory.
Caption: Grades: advisory facts Confirmed; research cost Reported.
Notes: The severity label is the vendor's classification at that date, not proof later work exaggerated it. [1][3][4][5][6][7]

## PART 1 | The upstream fix was available before the public name existed

- OpenSSL's Jan 8, 2015 advisory recorded Bhargavan's Oct 22, 2014 report and credited Stephen Henson with the fix.
- A March news event does not imply a March first report or a March first fix.
- A January patch does not prove every dependent product shipped it before March.
- Other advisory items (a DTLS crash, a memory leak, a cert-verification issue) are not automatically part of FREAK.
Caption: Evidence grade: Confirmed from the advisory record.
Notes: Release bundles are administrative groupings; the mechanism and affected role decide what belongs to this case. [1]

## PART 1 | Discovery, fix, naming and measurement sat on different dates

| Date | Event |
|---|---|
| Oct 22, 2014 | Private report to OpenSSL |
| Jan 8, 2015 | OpenSSL publishes CVE-2015-0204 fix |
| Mar 3, 2015 | Public FREAK announcement and research |
| Mar 5, 2015 | Microsoft advisory 3046015 |
| Mar 10, 2015 | Microsoft MS15-031 bulletin |
| Mar 11, 2015 | OpenStack OSSN-0045 note |
Caption: The 2015 IEEE S&P paper also documents FREAK.
Notes: Apple's iOS 8.2 release day is not fixed here; its page now shows Nov 2023 metadata. [1][2][4][5][6][7][9]

## PART 1 | Discovery, coordination and measurement were separate roles

- Michigan's tracking site dates the announcement to March 3, 2015 and credits discovery to Bhargavan and miTLS.
- Matthew Green coordinated disclosure; Michigan researchers ran ongoing measurement.
- The attack needs a vulnerable client and a server accepting RSA_EXPORT together, not either alone.
- Shared provenance means agreeing sources are not wholly independent replications.
- TLS-intercepting software can change the result an otherwise unaffected browser sees.
Caption: Evidence grade: roles Confirmed; exposure Reported.
Notes: A vulnerability inventory on both sides is not a victim list without evidence of real sessions. [2]

## PART 2 | The client accepted a message its chosen mode should reject

- In A Messy State of the Union, FREAK is a TLS state-machine composition flaw.
- Affected clients accepted a ServerKeyExchange carrying a weak temporary RSA key during ordinary RSA.
- The session kept a strong certificate key while using the weak temporary key.
- Well-formed is not enough: a message must also be valid for the current handshake state.
- Changing a visible preference may not fix the parser path; enforcement must reach the receiving logic.
Caption: Evidence grade: Demonstrated in the research paper.
Notes: The study does not reproduce the step-by-step exploit; tests must cover prohibited transitions, not only valid ones. [3]

## PART 2 | Reusing a temporary key amortized the factoring cost

Stat: 512-bit | RSA key factored in Green's account
Stat: ~7.5 hrs | Reported time per key
Stat: US$104 | Reported EC2 cost per key
- Reuse of a temporary export key spreads one expensive computation across many sessions.
- "Temporary" names a protocol role; it does not guarantee a fresh one-use object.
- The dollar figure is a reported 2015 research cost, not a current price or a guaranteed budget.
- The demo altered what a client saw from an NSA public site via Akamai; it was not an intrusion into NSA systems.
Caption: Evidence grade: a Reported demonstration, not reproduced.
Notes: The cost excludes expertise and does not establish an identical runtime for every key or environment. [4]

## PART 2 | Three populations, not one worldwide risk number

Stat: 9.6% | Alexa top-million HTTPS, Mar 3 baseline
Stat: 36.7% | Trusted-cert servers, Mar 3 baseline
Stat: 26.3% | All HTTPS servers, Mar 3 baseline
- Ranked domains, trusted-cert endpoints and all HTTPS endpoints are not interchangeable populations.
- The trusted-cert series falls 30.2 points, about 82.3% of baseline; this is arithmetic, not a victim count.
- The popular-domain list is timestamped March 10, 8:00 AM EST; one timestamp does not date every table.
- "Currently vulnerable" labels are historical page language, not a scan performed for this study.
Caption: Evidence grade: Reported exposure, a mixed historical page.
Notes: The study did not retrieve the raw longitudinal data, so it does not assign every change to patching. [2]

## DEFENDER VIEW | A Windows Server can be the vulnerable client, not the server

- MS15-031 identifies CVE-2015-1637 in Schannel: a client accepting a shorter RSA key than negotiated.
- Advisory 3046015 ran March 5, updated March 10; its later metadata is not a new disclosure.
- Microsoft reported no information of public attacks on customers at original bulletin release.
- An exploitable connection still needs server-side RSA export support, off by default in Vista and later.
- A product's "server" name can hide that it also makes outbound client connections.
Caption: Evidence grade: bounded vendor awareness.
Notes: A lack of received reports at one date is not proof no attack occurred anywhere. [5][6]

## DEFENDER VIEW | Installing the update is not the same as closing the capability

- Microsoft's cipher-restriction workaround can break peers lacking a mutually supported suite.
- Export ciphers can stay enabled on Windows Server 2003 after the update, per the bulletin FAQ.
- Red Hat disabled export ciphers by default, but applications could re-enable them.
- Replacing a file on disk is not replacing code already loaded; restart or reboot running services.
- An openssl097a compatibility package had no planned fix under the stated lifecycle policy.
Caption: Closure is three tests, not one installer message.
Notes: The three tests are: the client rejects the key, the service drops the capability, and workarounds are reviewed. [6][8]

## DEFENDER VIEW | Client acceptance and server offering are opposite repair ends

Left: Apple Secure Transport
- CVE-2015-1067: short ephemeral RSA keys accepted during full-strength RSA.
- The fix removed ephemeral RSA-key support on the client side.
- Vulnerable only against servers offering export-strength RSA suites.
Right: OpenStack OSSN-0045
- Weakness can sit in web servers, TLS terminators or proxies, not just the app.
- Recommends server-side removal of weak export choices.
- The TLS boundary may be owned outside the application repository.
Caption: Evidence grade: Confirmed vendor fixes.
Notes: The iOS 8.2 page now shows Nov 2023 metadata, not the 2015 date; the downgrade here is RSA export, not TLS-version fallback. [7][9]

## CROSS-CUTTING THEMES | What the record overstates, and what it understates

Left: Overstated if unchecked
- "The NSA was breached" read off a client-side demo on a public site.
- One CVE standing in for every affected implementation.
- A single exposure percentage read as a worldwide victim count.
- "Browser X was always safe" ignoring platform library and interception.
Right: Understated if omitted
- A January fix existed before the March name.
- Vendor "no known attacks" statements are bounded but real evidence.
- "Temporary" keys that get reused across many sessions.
- Loaded libraries and workarounds outlive the installer run.
Caption: Keep the original severity and later findings side by side.
Notes: FREAK did not require a forged CA or factoring of an ordinary modern certificate key. [1][2][4][6]

## CLOSE | Strong certificates did not guarantee strong session setup

- Export cryptography stayed dangerous because an implementation could activate it outside the intended mode.
- Remediation needed both correct client enforcement and removal of weak server choices.
- Attend to loaded libraries and temporary workarounds, not just a package success message.
- A deeper follow-up needs dated deployment data and reproducible scan methodology, not hypothetical losses.
Caption: From a state-machine bug to ecosystem exposure.
Notes: The study claims no full audit of the paper, no scan of public targets and no attack tooling run. [3][8][9]
