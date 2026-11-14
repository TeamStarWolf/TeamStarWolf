# Slide plan: The Record and the Window: A Thesis on Cybersecurity in 2026 and the Decade Ahead

- Study: case-studies/THE_RECORD_AND_THE_WINDOW.md
- Cover title: The Record / and the Window
- Subtitle: A thesis on cybersecurity in 2026 and the decade ahead
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/THE_RECORD_AND_THE_WINDOW.md. Bracketed numbers in the notes are the paper's notes, written chapter.note: [2.42] is note 42 to Chapter 2 and [F.1] is note 1 to the front matter.

## EXECUTIVE SUMMARY | Know what you run, prove what you did, act inside the window

- The era of the perimeter and the patch is giving way to the record and the window.
- The record: what an organization can prove it runs, changed and did, and when.
- The window: from the vendor's first word on a flaw to the first intrusion through it.
- In six of nine dated 2026 edge cases, exploitation came before the advisory.
- AI changes speed and cost and adds places to fail, not new kinds of failure.
Caption: Every claim is graded Confirmed, Reported or Inferred in the notes at the end of the paper.
Notes: Evidence base and the six of nine reading [F.1][1.3]. Grading [F.3]. Thesis and claims Inferred from the evidence chapters.

## THE THESIS | Five claims, each tested by the evidence chapters

| Claim | What the paper argues |
|---|---|
| 1 | The window has collapsed; on the perimeter it often went negative |
| 2 | The first hop is the vendor's own appliance |
| 3 | The record is the control |
| 4 | Trust layers fail in chains |
| 5 | AI changes speed and cost, not the kinds of failure |
Caption: Claim three is the one the public record tests least directly; the paper says so.
Notes: Claim one [1.3][1.4][1.6]. Claim two [1.8][1.9]. Claim three [1.10]. Claim five [1.11][1.12][1.13]. Limits of each claim [1.6][1.15].

## CHAPTER 2 | In 2026 the edge window was often below zero

Stat: 6 of 9 | Dated edge flaws exploited before the advisory
Stat: 15 of 34 | 2026 studies whose first hop was an edge product
Stat: 9+ | Studies that record a chain across trusted layers
- Check Point gateways: first wave 30 October; the root CVE published 12 November.
- Vendors spoke inside the window, so they spoke small.
- Most events name no actor in a primary record.
Notes: Window table [2.42]. First hop and Figure 5 [2.37][2.38]. Chains [2.39]. Check Point [2.15][1.4]. Vendor words [2.43]. Silence [2.44].

## CHAPTER 3 | Forty years of the same few failures

- Memory safety, missing authorization, injection and exposed defaults recur in every era.
- Each maps to a CWE Pillar and is still printed in 2026 advisories.
- Code Red reached 359,000 hosts in under 14 hours in 2001.
- MS08-067 was exploited the day its fix shipped in 2008.
- Five additions, each kept: reach, automation, scale, money and the state, trusted delivery.
Caption: The precondition of claim three: old classes sit somewhere in what you run.
Notes: Classes and pillars, Figure 8 [3.4][3.39][3.40]. Code Red [3.17]. MS08-067 [3.23]. The five additions [3.42]. Figure 6 [3.43].

## CHAPTER 4 | The catalog is fast; the delay sits upstream of it

Stat: 297 | KEV additions, 1 January to 13 November 2026
Stat: 128 of 164 | BOD 26-04 entries due in three days
Stat: 0.01274 | EPSS score of the Check Point Gaia flaw on KEV day
- KEV often listed an edge flaw on the day the vendor spoke.
- EPSS sees loud scanning and misses a quiet root step on an appliance.
- Able2Shell: a researcher, not an attacker, set the window to zero.
Notes: Catalog counts and Figure 3 [4.6][4.8]. BOD 26-04 tiers [4.1][10.3]. EPSS [4.17][4.18]. Able2Shell [4.21]. Figure 4 [4.4].

## CHAPTER 5 | Adversaries are named precisely and understood less certainly

- Governments now name units, bureaus and companies behind the state programs.
- ATT&CK v20.0 gives a China attribution to 47 of 178 Enterprise groups.
- An access market sells the first foothold to states and ransomware brands alike.
- States wear hacktivist personas to destroy.
- Check Point's wiper: tools point one way, behavior another; no firm attribution.
Caption: Attribution firms over months; the window is won or lost in hours.
Notes: China [5.1]. Russia and others [5.3][5.5][5.6]. Access market [5.12]. Personas [5.13][5.14]. Check Point wiper [5.16][5.17].

## CHAPTER 6 | Borrowed trust fails in chains, layer by layer

| Layer | Case | Unnoticed for |
|---|---|---|
| Build | SolarWinds | About ten months |
| Source and build | XZ Utils | 34 days in release |
| Update channel | Notepad++ | About six months |
| Certificate authority | eMudhra | About 18 months |
| Marketplace | Cursor | About eleven hours |
| Cloud tenant | Trivy and the Commission | Five days in the tenant |
Caption: Public layers now close in minutes to hours; private ones stayed open for months.
Notes: Cases [6.1][6.2][6.5][6.6][6.7][6.8]. Unnoticed intervals computed by the paper [6.10]. Figure 7 extends the layers to the appliance and hypervisor.

## CHAPTER 7 | AI makes generation cheap and verification scarce

- Attack: an AI-written kernel exploit, reported by its maker and unreproduced.
- Target: model hubs, marketplaces and agents fail at the oldest points.
- Defender: 100 library pull requests in one week, 79 of them case studies.
- The program's errors were caught by second readers, not by their authors.
- The agent's permission set is the new place to fail.
Caption: The program's account of its own week is self-report and graded Reported.
Notes: Kernel exploit [7.1][7.2]. Hugging Face and agents [7.10][7.11]. Cursor [7.13]. One week [7.14]. Checking and failures [7.15][7.16]. Verification [7.17].

## CHAPTER 8 | The controls that held shortened the window or kept the record

Left: What held
- Phishing-resistant MFA, single-purpose accounts.
- Management interfaces off the internet.
- Recovery from clean images.
- Segmentation of appliances from hypervisors.
Right: Why it mattered
- The vpxuser hop carried a firewall into ESXi.
- TSGA persisted through backups.
- An eleven-hour marketplace compromise beat a cooldown.
- PAN-OS: twelve days exposed for a catalog-waiter.
Caption: Exposure time from the vendor's first word, closed only on proof, replaces counts.
Notes: Controls [8.10][8.11][8.12]. PAN-OS dates [8.3]. Exposure time [8.1][8.8]. Backups and the ESXi hop [13.4].

## CHAPTER 9 | In critical sectors the window is measured in years

- Attacks rarely needed a new flaw: default passwords, exposed controllers, remote access.
- Four conditions: long-lived devices, flat networks, vendor access, thin public records.
- Medical devices run beyond 15 years and grid relays past 25.
- One public sabotage case at a nuclear facility.
- A 2026 wave of PLC tampering across at least seven states has no named actor.
Caption: Remove exposure and broker remote access: the controls the sector studies repeat most.
Notes: Sector studies [9.1][9.2]. Common conditions [9.17]. Healthcare [9.3][9.4]. Nuclear [9.11]. Water and the PLC wave [9.9][9.16].

## RULES AND MEASURES | Every clock starts after the attacker's

- BOD 26-04 made deadlines dynamic; BOD 26-02 retires end-of-support edge devices.
- SEC Item 1.05 filings are dated by decisions, not intrusions.
- CIRCIA is not yet in force; NIS 2 and the CRA set 24 and 72-hour clocks.
- Measure exposure-hours: dark, no-fix and fix-available.
- Worked example: 86 percent compliance over 378 hours of open root chain.
Caption: The worked example uses an invented fleet on the real Ivanti and Check Point dates.
Notes: Directives [10.3][10.5]. SEC [10.7][10.12]. CIRCIA, NIS 2, CRA [10.14][10.15][10.16]. Exposure-hours [11.5]. Worked example [11.6][11.8].

## TEN THESES | 2027 to 2036, part one

| Thesis | The 2026 baseline |
|---|---|
| 1. The window goes negative and stays there | Six of nine edge flaws exploited first |
| 2. The appliance era ends; its remnant hardens | Ten edge vendors, 64 of 297 KEV additions |
| 3. The legacy window outlasts the fix | The same CWE pillars in every decade |
| 4. Provenance becomes mandatory | A marketplace channel that looked official |
| 5. The patch stops being the unit of work | BOD 26-04's dynamic timelines |
Caption: Each thesis names its strongest objection and the observation that would falsify it.
Notes: Theses one to five [12.2][12.5][12.6][12.7][12.9][12.10]. Figure 9 sets horizon against evidence. All theses Inferred [12.20].

## TEN THESES | 2027 to 2036, part two

| Thesis | The 2026 baseline |
|---|---|
| 6. Agents on both sides; verification is scarce | An AI-written exploit, reported only |
| 7. Physical consequence becomes normal | Refrigeration controllers, a device maker's outage |
| 8. Attribution diverges and matters less | Units named months after hours-long windows |
| 9. The record becomes public infrastructure | Eight SEC filing rows in the Hub |
| 10. Judgment about evidence over tool use | One week of agent-written, human-directed work |
Caption: The objections narrowed four theses; the tenth rests on the thinnest evidence.
Notes: Theses six to ten [12.11][12.12][12.13][12.14][12.15]. Three days in 2030 are fiction [12.16].

## THE PROGRAM | Twelve months, six levers, five steps, record first

Left: An organization
- Months 1 to 3: build the record.
- Months 3 to 6: close the window.
- Months 6 to 9: control the supply chain.
- Months 9 to 12: detect and rehearse.
Right: A nation and the project
- Make vendor transparency public.
- Risk-based deadlines, mandatory provenance.
- Treat the records as infrastructure.
- For TeamStarWolf: keep the standard, teach the method.
Caption: The programs are the paper's own recommendations (Inferred); Figure 10 draws the twelve months.
Notes: Programs [13.1][13.2]. Record and window phases [13.3][13.4][13.5]. Supply chain [13.6]. Nation [13.7][13.8][13.9]. Project, an interested party [13.10].

## CONCLUSION | Everything else is a list

- The window was set by the attacker; the record was the defender's to keep.
- The classes of flaw did not change; their speed did.
- AI makes the checkable record worth more as output multiplies.
- Know what you run, prove what you did, act inside the window.
Caption: The paper's verdicts on its claims are its own judgments: Inferred.
Notes: What the record says [14.1][14.2][14.3][14.4][14.5]. What AI changes [14.6][14.7].
