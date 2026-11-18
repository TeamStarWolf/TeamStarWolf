# Slide plan: Bad Rabbit 2017

- Study: case-studies/BAD_RABBIT_2017.md
- Cover title: Bad Rabbit / One Fake Update / Many Spread Routes
- Subtitle: A 2017 ransomware outbreak: a fake Flash update a user runs, then spread by stolen credentials, SMB, and the EternalRomance exploit.
- Published: 18 November 2026
- Notes: The cover frames Bad Rabbit as one chain with several distinct transitions, each needing its own control and its own evidence.

## OVERVIEW | Why one label never fits a chain
- The first visible step was a person running a deceptive software installer.
- Later steps used credentials, remote administration, and an exploit to reach other hosts.
- Calling it a fake-update attack understates the network risk; calling it exploit-driven hides the software-trust failure.
- No exploit in the web delivery step does not mean no exploit anywhere in the spread.
Caption: Evidence grade: Confirmed (dated primary-source reporting)
Notes: The study treats these five distinctions as the basis of a defensive model rather than a single headline.

## INITIAL ACCESS | The fake Flash update a user runs
- Kaspersky described a fake Flash installer delivered through compromised websites.
- Distribution was a watering-hole on mostly Russian and Ukrainian sites, reported as the entry route.
- The installer required manual execution and elevated privileges, so a person had to run it.
- Social engineering borrowed an expected task, keeping software current, to earn that click.
Caption: Evidence grade: Confirmed (Kaspersky analysis)
Notes: Keep the social-engineered, user-executed entry distinct from the lateral-movement mechanics that followed.

## PROPAGATION | How one foothold reached its peers
- Talos described credential-assisted SMB movement between Windows hosts.
- A bundled credential tool and a hardcoded credential list amplified a single foothold.
- EternalRomance appeared in internal propagation alongside the credential route.
- Multiple routes meant removing one did not automatically remove the others.
Caption: Evidence grade: Confirmed (Talos, Kaspersky analysis)
Notes: Credential reuse and SMB turn one employee's software decision into a network-wide risk, which is the core lesson.

## EXPLOIT SCOPE | EternalRomance, not EternalBlue
Left: EternalRomance (observed)
- Identified in internal propagation by Kaspersky and Talos.
- MS17-010 addressed the underlying SMB vulnerability.
- ESET found installing MS17-010 stopped the tested IPC-share route.
Right: EternalBlue (not observed)
- Talos reported no evidence of it in the examined behavior.
- The two exploits must never be used interchangeably.
- Absence in one step is not absence across the chain.
Caption: Evidence grade: Confirmed (Talos, ESET patch test)
Notes: The most common editorial error is swapping these two names, so the plan keeps them explicitly separate.

## TIMELINE | A dated record that kept changing
Public reporting was provisional on day one and sharpened over the following weeks.

| Date | Checkpoint | Implication |
|---|---|---|
| 14 Mar 2017 | MS17-010 published | Relevant patch context predates the outbreak |
| 24 Oct 2017 | Outbreak and first reports | Early reporting was provisional; visibility differed |
| 25-26 Oct 2017 | Talos adds encryption and code analysis | Preserve update history, not an early conclusion |
| 27 Oct 2017 | ESET adds patch-test confirmation | Name the tested route, do not generalize |
| 10 Jan 2018 | Microsoft retrospective | Later synthesis is separate from first-day notes |
Caption: Evidence grade: Confirmed (dated source register)
Notes: A correction log lets a defender revise scope as evidence improves instead of freezing an early claim.

## SOURCES | Five vantage points, five questions
Each source answers a different question and none is a worldwide victim census.

| Source | Date | Vantage |
|---|---|---|
| Kaspersky | 24 Oct 2017 | Sample analysis: entry, propagation, decryption |
| Cisco Talos | 24-26 Oct 2017 | Telemetry and code-linkage confidence levels |
| ESET | 24-27 Oct 2017 | Patch test and telemetry-scope caveat |
| Microsoft retrospective | 10 Jan 2018 | Vendor view across the year's outbreaks |
| MS17-010 bulletin | 14 Mar 2017 | Authoritative SMB update context |
Caption: Evidence grade: Confirmed (primary and vendor sources)
Notes: Malware analysis, telemetry, a patch test, and a retrospective each have limits that a defender should hold separately.

## ATTRIBUTION | Code overlap is a lead, not a verdict
Left: Reported at high confidence
- Codebase and build-toolchain similarity with Nyetya (NotPetya).
- A credible technical link between the two families.
Right: Reported at low confidence
- That the same authors were responsible for both.
- These are different claims with different confidence levels.
Caption: Evidence grade: Reported (Talos, stated confidence levels)
Notes: Code similarity, shared tooling, and a named operator are separate propositions that must keep their own uncertainty.

## SCOPE | Keep the numbers traceable
Stat: 5 | primary sources reviewed for this study
Stat: 24 Oct | 2017, the outbreak observation date
Stat: Mar 2017 | MS17-010 shipped before the outbreak
Stat: 0 | EternalBlue seen in examined samples
- ESET distribution figures counted observed dropper encounters, not a global company count.
- Affected-organization totals were limited and estimated, not a verified census.
Caption: Evidence grade: Confirmed (sourced, with stated denominators)
Notes: Record the denominator so a regional telemetry figure is never read as a worldwide victim ranking.

## ENCRYPTION | Capability is not recovery
Left: What analysis showed
- File encryption plus disk encryption using DiskCryptor components.
- Kaspersky suggested a technical route to recover disk-decryption information.
- More conventional ransomware than NotPetya's wiper behavior.
Right: What real recovery still needs
- A reversible scheme does not guarantee a usable restoration.
- Compromised authority or altered configuration may persist.
- Independently controlled backups and a witnessed workflow test.
Caption: Evidence grade: Reported (Kaspersky recovery assessment)
Notes: A recovery mechanism in analysis is not a reliable service from an attacker, and the plan refuses any payment framing.

## MODEL | Five transitions, five owners
The study separates the chain into transitions, each with a distinct owner and evidence requirement.

| Transition | Owner | Evidence to request |
|---|---|---|
| Web exposure | Browser and endpoint | How software becomes trusted |
| Authorized execution | Endpoint | Controlled execution-policy test |
| Local privilege | Identity and platform | Standing-admin and exception review |
| Cross-host authority | Network and identity | Privilege and service-access review |
| Recovery | Incident and business | Isolated restore, witnessed workflow |
Caption: Evidence grade: Demonstrated (proposed analytical model)
Notes: Assigning ownership per boundary prevents one blocked download or one patch from being read as full containment.

## SOFTWARE TRUST | Make updating a known path
- A fake update wins by borrowing a legitimate task, so a ban on updating conflicts with real security work.
- Give staff a known path to obtain software and a way to verify an unexpected request.
- An ordinary task should not require standing administrative authority for convenience.
- Assume a deceptive file may reach execution, then ask what limits its consequences.
Caption: Evidence grade: Demonstrated (proposed control design)
Notes: Design shifts the analysis from blaming a careless click to bounding what a single mistake can reach.

## PATCH SCOPE | A patch closes one route
- A patch result is not a declaration that all malicious movement is impossible.
- Record the affected service, the test conditions, and what the verification did not assess.
- Removing a vulnerable route does not remove accepted credential authority.
Caption: Evidence grade: Demonstrated (proposed verification record)
Notes: MS17-010 explains the 2017 evidence; it is not a prescription to install a decade-old package today.

## LESSONS | What to carry forward
- Watering-hole distribution plus a fake-update lure defeats user-only defenses.
- Credential reuse and SMB let one foothold become a service outage.
- Code similarity is a lead to investigate, not a confirmed identity or attribution.
- Trace one important service: review software trust, admin reach, and restore together, testing each boundary separately.
Caption: Evidence grade: Demonstrated (study conclusions)
Notes: The durable value is the reasoning framework, with every historical claim kept tied to its dated source.
