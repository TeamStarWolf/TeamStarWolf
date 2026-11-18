# Slide plan: Zoom and the FTC 2020

- Study: case-studies/ZOOM_FTC_2020.md
- Cover title: Zoom and the FTC / Marketed vs Delivered / 2020 Consent Order
- Subtitle: The FTC alleged Zoom overstated its encryption and settled by consent order in 2020, with no admission of wrongdoing.
- Published: 18 November 2026
- Notes: The cover frames a security-claims enforcement case, not a breach, and signals the gap between what was marketed and what was delivered.

## POSTURE | A settlement, not a verdict
- The FTC charged misrepresentation; Zoom neither admitted nor denied it.
- The allegations remain allegations, not findings from a contested trial.
- A consent order is a settlement, so no wrongdoing was adjudicated.
- The complaint and the order serve different functions and stay distinct.
Caption: Evidence grade: Confirmed (FTC complaint and order, C-4731)
Notes: This slide fixes the legal posture so later claims are read as allegations settled by consent.

## TIMELINE | From 2015 claims to 2021 order
Each dated event belongs to a distinct phase of the case.

| Date | Event |
| --- | --- |
| June 2015 | 256-bit encryption claims alleged to begin |
| June 2016 | End-to-end encryption claims alleged to begin |
| July 2018 | ZoomOpener local web server introduced |
| July 2019 | Local-server problem disclosed and patched |
| April 2020 | Citizen Lab publishes encryption analysis |
| Oct 26 2020 | Zoom announces end-to-end encryption preview |
| Nov 9 2020 | FTC announces proposed settlement |
| Jan 19 2021 | Commission votes final approval |
Caption: Evidence grade: Confirmed (dated FTC and vendor documents)
Notes: The chronology keeps an earlier claim from being defended by a later feature and keeps an old defect from condemning a redesign.

## MARKETED VS DELIVERED | The gap at the center
Left: Marketed
- End-to-end encryption for meetings.
- 256-bit encryption strength.
- Immediate encrypted storage of recordings.
Right: Delivered, as alleged
- Transport encryption with Zoom holding the keys.
- 128-bit AES in ECB mode, per the complaint.
- Some recordings unencrypted for up to 60 days.
Caption: Evidence grade: Reported (FTC complaint allegations)
Notes: The whole case lives in the distance between the two columns, and the right column states allegations rather than proven facts.

## ENCRYPTION | End-to-end means only parties hold keys
- End-to-end encryption means only the communicating parties hold the keys.
- The FTC alleged Zoom kept the relevant keys on its own servers.
- That gives the provider capability to access content, not proof it did.
- A padlock shows an encrypted link, not that the provider is excluded.
Caption: Evidence grade: Reported (FTC complaint allegations)
Notes: End-to-end encryption is a precise technical claim about key custody, separate from whether traffic is encrypted at all.

## CIPHER | Three dimensions, one strength score
- Key length, cipher mode, and key custody are three separate claims.
- The complaint alleged 128-bit AES in ECB mode against a 256-bit claim.
- Citizen Lab reported observing AES-128 in ECB mode within its tests.
- A larger advertised number cannot rescue a false claim about key custody.
Caption: Evidence grade: Reported (FTC complaint) and Demonstrated (Citizen Lab tests)
Notes: Collapsing length, mode, and custody into one number hides the actual failure the case describes.

## RECORDINGS | The hidden processing interval
- The complaint alleged some recordings sat unencrypted for up to 60 days.
- The claim concerns one lifecycle interval, not every recording's treatment.
- A statement about durable storage can omit the sensitive intermediate stage.
- It does not establish that attackers downloaded any recording.
Caption: Evidence grade: Reported (FTC complaint allegations)
Notes: The alleged gap is about a temporary processing window, bounded and distinct from any claim of theft.

## ZOOMOPENER | Bypassing a browser consent prompt
- Safari required a confirmation before a site launched an application.
- ZoomOpener added a local web server that bypassed that prompt.
- The server persisted after the visible application was removed.
- A vulnerability is a possible path, not evidence of actual compromise.
Caption: Evidence grade: Reported (FTC complaint allegations)
Notes: Removing a consent prompt changed the trust relationship, which is a product-security issue separate from the encryption claims.

## COUNTS | Installations are not victims
Stat: 3.8M | US consumers with ZoomOpener installed
Stat: 0 | hijacked cameras counted in the complaint
- The 3.8 million figure is an installation population, not a victim count.
- The complaint does not confirm mass camera activation or stolen meetings.
- An accurate chart labels exposure rather than harm.
Caption: Evidence grade: Reported (FTC complaint figure)
Notes: Exposure counts answer a different question from confirmed-access counts and must not be merged.

## SCALE | Why the claims mattered more
Stat: 10M | daily meeting participants, Dec 2019
Stat: 300M | daily meeting participants, Apr 2020
- Daily participants count participations, not unique people.
- The growth explains why accurate assurance mattered more.
- The figure is not a breach count or an affected-records estimate.
Caption: Evidence grade: Reported (FTC complaint figure)
Notes: Rapid growth raised the stakes of the security claims without itself implying any compromise.

## THE ORDER | What the settlement required
- It barred misrepresenting security features, controls, and practices.
- It required a documented information-security program with board reporting.
- It mandated risk assessment, access limits, logging, and incident response.
- The FTC order itself carried no monetary fine or customer redress.
Caption: Evidence grade: Confirmed (FTC decision and order)
Notes: These are enforceable settlement obligations, not proof that each safeguard was absent across the earlier service.

## OVERSIGHT | Twenty years of assessment
Stat: 20 yrs | span of biennial independent assessments
Stat: 4x | vulnerability scans required per year
Stat: 30 | days to remediate critical vulnerabilities
Stat: 31 | days to validate deletion of all copies
Caption: Evidence grade: Confirmed (FTC decision and order)
Notes: The order traded a monetary penalty for long-running oversight with specific, time-bounded duties.

## REMEDY DEBATE | Security program vs recourse
Left: Majority
- Favored prompt, enforceable security requirements.
- Preferred immediate protections over protracted relief.
Right: Dissent
- Argued privacy choices were not sufficiently addressed.
- Said paying customers lacked recourse under the settlement.
Caption: Evidence grade: Confirmed (FTC public statements, November 2020)
Notes: The split raises whether a product can be well defended yet still make choices users would reject if they understood them.

## OCTOBER 2020 | A later change, accurately dated
- On October 26, Zoom announced an end-to-end encryption technical preview.
- It described client-side key generation that excluded the server, up to 200 participants.
- A later improvement does not make an earlier representation accurate.
- The announcement evidences a launch and its stated design, not verification.
Caption: Evidence grade: Reported (Zoom investor release, October 2020)
Notes: Dating the change turns a static accusation into a sequence of claim, scrutiny, and product response.

## LESSON | Assurance must cover the whole promise
- Security assurance must cover key ownership, storage, consent, and uninstall.
- Keep marketing claims distinct from the delivered, testable property.
- Keep settled allegations distinct from adjudicated findings.
- Demand evidence without inventing an attack the record does not establish.
Caption: Evidence grade: Inferred (original defensive analysis)
Notes: The durable takeaway is that accountability and uncertainty can be preserved together.
