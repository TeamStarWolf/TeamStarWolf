# Slide plan: NotPetya 2017: A Trusted Update Becomes a Destructive Outage

- Study: case-studies/NOTPETYA_2017.md
- Cover title: NotPetya 2017 / A Trusted Update / Becomes a Destructive Outage
- Subtitle: A legitimate software update became the entry point for a destructive 2017 outbreak; delivery, spread, recovery and attribution need separate evidence.
- Published: 15 November 2026
- Notes: The cover sets the frame of one trusted update path, then separate propagation, recovery and attribution questions.

## EXECUTIVE SUMMARY | A trusted update path became a destructive outage

Stat: 27 Jun | Outbreak date, 2017
Stat: Not real | Ransom with no recovery path
Stat: ~USD 1B | DOJ three-victim loss subtotal
- The legitimate M.E.Doc updater was observed initiating malicious execution in a subset of infections. [1]
- Initial foothold and internal spread were separate problems: SMB exploitation plus credential-enabled administration. [2][4]
- It was not working ransomware; the disk ransom screen's installation ID could not carry decryption data. [3]
- Effects outlasted the outbreak: lost business, restoration cost and manufacturing disruption. [5][9][12][13]
Caption: Evidence grade: Observed research and company reporting.
Notes: Microsoft saw the updater activate malicious code [1]; Kaspersky showed the disk ID was random, breaking the described recovery mechanism [3]; spread used credentials and admin facilities as well as SMB [2][4].

## KEY FACTS | Bounded answers, not collapsed into one claim

| Question | Bounded answer |
|---|---|
| What happened? | A June 2017 destructive outbreak via a compromised update path, then network spread [1][2][10]. |
| Just a missing patch? | No. Exploitation and credential-enabled admin were separate [2][4]. |
| Did the ransom prove payment works? | No. A broken disk-key recovery relationship [3]. |
| Universal recovery later? | No. Recovery research was conditional [17][18]. |
| Who attributed it? | UK high-confidence state attribution; US alleged GRU officers [6][7]. |
| Worldwide loss total? | Not established here; figures are not summed. |
Caption: Evidence grade: mixed; see the per-row sources.
Notes: The source's at-a-glance table, condensed. Each row keeps its own evidence basis rather than merging assessment, allegation and laboratory finding into one proof claim.

## PART 1 | The attack had more than one beginning

- ESET found a backdoored M.E.Doc component in releases dated 14 April, 15 May and 22 June 2017. [8]
- The backdoor collected organization identifiers and app-held proxy and email credentials via the update channel. [8]
- Separate at least three populations: received a suspect update, backdoor executed, destructive payload hit.
- A later clean version is evidence about files present then; it does not erase what an earlier component may have accessed.
Caption: Evidence grade: Observed research (ESET) and Inferred.
Notes: ESET dated the backdoored releases and described credential collection [8]; the three-population distinction is the study's inference, not a victim configuration.

## PART 1 | Supplier-side and legal evidence widen the picture

- Talos reached M.E.Doc staff, logs and code; found compromised admin credentials and an altered NGINX config. [10]
- That config proxied traffic to an attacker host and was reconstructed from upstream error logs, not recovered. [10]
- A web shell and the modified application component were corroborated. [10]
- The 2020 indictment alleges code access and update changes on 14 April, 15 May and 21 June. [19]
Caption: Evidence grade: Observed research (Talos) and Alleged (indictment).
Notes: Supplier-side logs are stronger than an endpoint tree alone but still bounded [10]. The June 21 allegation and June 22 researcher date are kept separate rather than normalized [19].

## PART 2 | A chronology needs explicit clocks, not one time

| Date, stated zone | What the record supports |
|---|---|
| 14 Mar 2017 | Microsoft publishes MS17-010 [14]. |
| Apr to Jun 2017 | Backdoored M.E.Doc releases identified [8]. |
| 27 Jun ~10:12 UTC | FireEye observes lateral movement [4]. |
| 27 Jun ~10:30 GMT | Microsoft observes updater malicious execution [1]. |
| 28 Jun 2017 | Kaspersky publishes the wiper and disk-ID analysis [3]. |
| 7 Nov 2017 | Maersk Q3 quantifies profitability impact [5]. |
| Oct 2020 | US indictment and announcement [7][19]. |
Caption: Evidence grade: Observed research, company reporting and Alleged.
Notes: The 10:12 versus 10:30 gap is two teams observing different populations, not a contradiction [1][4]. Patch availability is not installation on a given asset [14].

## PART 3 | A foothold is not the same as its reach

- The M.E.Doc route explains initial execution, not each remote system reached afterward.
- Model the enterprise as a set of permitted relationships, not a flat list of machines.
- Where software is installed differs from where those installations can administer other systems.
- These are illustrative failure paths, not asserted configurations of a named victim.
Caption: Evidence grade: Inferred, the study's analysis.
Notes: The study's propagation model; an inventory-only response scopes delivery but not consequence. No named victim's topology is claimed.

## PART 3 | Credentials and administration became the spread route

- Microsoft (Oct) describes discovery, admin-share reach and auth with current or recovered credentials. [2]
- Talos saw several credential sources and a Mimikatz-like but not identical component; no WannaCry-style scanner. [11]
- Admin shares, PsExec and WMI served propagation, yet also support legitimate operations. [2][4]
- FireEye found modified EternalBlue and EternalRomance use with credential-enabled spread; patching closed one class. [4]
Caption: Evidence grade: Observed research and Inferred.
Notes: Microsoft noted limits on which recovered users were tried, so not every credential was necessarily used [2]. One control addressed one class of transition [4][14].

## PART 4 | Destruction, ransom display and partial recovery

- CrowdStrike separated AES file encryption, RSA key protection and Salsa20 MFT processing. [20]
- "The disk was encrypted" hides distinct states: lost boot, lost metadata, lost files, or a mix. [20]
- Kaspersky: the displayed disk ID was random, so the described recovery mechanism could not work. [3]
- CrowdStrike later recovered the MFT via a Salsa20 implementation flaw: conditional, not universal. [17][18]
Caption: Evidence grade: Observed research and Inferred.
Notes: Laboratory success, field recovery and enterprise restoration are different claims [17][18]. A design intent of destruction and an implementation weakness can coexist.

## PART 5 | Impact measured on different clocks, not one sum

| Record | Measure | Amount |
|---|---|---|
| Maersk Q3 [5] | Profitability, mostly Q3 | USD 250-300M |
| FedEx FY2018 [9] | H1 impact, incl. TNT | USD 400M |
| Merck FY2017 [12] | Adverse sales effect | ~USD 260M |
| Merck FY2017 [12] | Mfg and remediation | ~USD 285M |
| Merck FY2018 [13] | Residual sales effect | ~USD 150M |
| DOJ 2020 [7] | Three-victim subtotal | ~USD 1B |
Caption: Evidence grade: company reporting and a prosecutor's account; rows are different measures, not additive.
Notes: Do not add the DOJ subtotal to the FedEx figure; TNT appears in both [7][9]. Forecasts, expenses and sales effects use different bases [12][13].

## PART 6 | Attribution without overstating the evidence

- UK, February 2018: an almost-certain assessment attributing NotPetya to the Russian military. [6]
- US, October 2020: six alleged GRU officers; the indictment describes Unit 74455. [7][19]
- An indictment is a record of accusations, not a conviction or a current case-status finding.
- Keep three questions distinct: who built it, what it aimed at, how each victim was reached.
Caption: Evidence grade: an official assessment and Alleged.
Notes: The UK assessment addresses origin and intent without publishing each victim's infection chain [6]. Containment does not depend on resolving attribution [7][19].

## DEFENDER VIEW | Case-derived proposals, not tested guarantees

- Inventory the update relationship: owner, channel, execution privilege and expected child processes.
- Test privilege and patching independently; keep patch freshness separate from identity evidence.
- Predefine containment authority; blocking supplier delivery may not stop internal activity.
- Restore trust first: establish a clean admin path and known-good sources before scaling rebuilds.
Caption: Evidence grade: Inferred and proposed; requires authorized validation.
Notes: Original proposals derived from the case, not assertions about examined configurations. Restore services in dependency order to the business boundary, not a server login.

## MITRE MAPPINGS | An analytical index, not a tested control set

| Observed behavior | ATT&CK technique |
|---|---|
| Compromised update distribution | T1195.002 Supply Chain [8][10] |
| LSASS credential extraction | T1003.001 LSASS Memory [20] |
| Admin-share propagation | T1021.002 SMB/Admin Shares [2] |
| WMI execution | T1047 WMI [4] |
| SMB exploitation | T1210 Exploit Remote Services [4] |
| Encryption for impact | T1486 Data Encrypted for Impact [3][20] |
Caption: Evidence grade: an Inferred mapping; software entry S0368 [15].
Notes: Not mapped as a complete Navigator layer, not proof every technique hit every victim, and not evidence a mapped control was tested [15][16]. A payload technique should not be attributed to the supplier backdoor.

## CROSS-CUTTING THEMES | What is overstated versus understated

Left: Often overstated
- "One RSA key encrypted everything," collapsing distinct components. [20]
- "Paying could recover disks," yet the displayed ID could not carry recovery data. [3]
- A later "full decryption" headline read as a universal guarantee. [18]
- Summed loss totals that double-count TNT across sources. [7][9]
Right: Often understated
- The exposure window began before the destruction window. [8]
- Credential reach, not only missing patches, drove the spread. [2][4]
- Recovery is staged: files, identity, applications, reconciled business.
- Attribution answers who and why, not how each victim was reached. [6][7]
Caption: Evidence grade: Inferred, the study's synthesis.
Notes: Precision is the study's throughline; narrow claims about observed systems are more defensible than global claims the evidence cannot support.

## CLOSE | Preserve boundaries in architecture and in analysis

- NotPetya was a chain of abused trust: supplier, update service, credentials and connected systems.
- Separate delivery from propagation, and exploit exposure from administrative reach.
- Separate technical recovery from service restoration, and official attribution from legal findings.
- Require evidence at each transition rather than settling for one headline conclusion.
Caption: Evidence grade: Inferred, the study's conclusion.
Notes: The lasting lesson is to keep boundaries in both architecture and analysis, then demand evidence at each transition. More demanding than a one-line patching or backup lesson, but more faithful.
