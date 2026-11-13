# Slide plan: The Boston Scientific Network Outage of August 2026: A Case Study

- Study: case-studies/BOSTON_SCIENTIFIC_ATTACK_2026.md
- Cover title: The Boston Scientific / Network Outage of August 2026 / A Case Study
- Subtitle: One edge device, two weeks of disrupted production and a material quarter without encryption
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/BOSTON_SCIENTIFIC_ATTACK_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | One management device, a global outage

- From 25 August 2026 Boston Scientific could not process or ship customer orders.
- Shipping returned for most products on 3 September; full restoration came on 9 September.
- New cardiac remote-monitoring activations stopped until 8 September.
- CrowdStrike traced entry to an external-facing network management device.
- No encryption, no actor named, no CVE: and still material to the quarter.
Caption: Evidence grade: Confirmed from the company's filings, updates and the CrowdStrike summary it published.
Notes: Outage and recovery [4][8][11]. Remote monitoring [4][15]. Entry device [13]. No encryption [13]. No actor or CVE [12][20][22]. Materiality [14].

## KEY FACTS | The numbers the filings give

Stat: 15 days | From detection to full restoration
Stat: 1.7 pts | Q3 gross margin lost to idle production
Stat: +1.5% | Q3 sales growth against 3 to 5% guided
Stat: 0 | CVEs or KEV entries tied to the incident
- Victim: Boston Scientific Corporation, a medical technology company in Marlborough, Massachusetts.
- Responder: CrowdStrike; investigation from 25 August to 18 September 2026.
- No dollar cost disclosed; the 10-Q blames incident disruption and idle production.
Notes: Dates [1][11]. Margin [18]. Sales [16][17]. KEV absence [20]. Victim [17]. Responder [13]. Cost [18].

## PART 1 | From detection to the 10-Q

| Date (2026) | Event |
|---|---|
| 25 Aug | Availability issues traced to an intruder; containment begins |
| 26 Aug | 8-K Item 8.01: global disruption to processing and shipping |
| 29 Aug | CrowdStrike named; cloud unaffected; manufacturing hit |
| 3 Sep | Shipping restored for most products at major centers |
| 7 to 8 Sep | 8-K Item 1.05: likely material to Q3 and full year |
| 8 Sep | Remote-monitoring activation restored |
| 9 Sep | Manufacturing, fulfillment and shipping fully restored |
| 2 Nov | 10-Q: material Q3 effect; civil claims filed |
Caption: Disclosure ran in stages: two 8-Ks, dated updates, a forensic summary, then the 10-Q.
Notes: Detection [1][13]. Item 8.01 [1][2]. Responder [6]. Shipping [8]. Item 1.05 [2][14]. Activation [10][15]. Restoration [11]. 10-Q [18].

## PART 2 | What CrowdStrike found, and what it did not

Left: Found
- Entry through an external-facing network management device.
- Actor access limited to a portion of the on-premises environment.
- No activity after 25 August.
Right: Not found
- Encryption of data in any environment.
- Actor activity in Microsoft 365, email or collaboration tools.
- Interactive access to SCADA, manufacturing or medical device systems.
Caption: The no-exfiltration finding covers the systems reviewed, not explicitly the segment the actor reached (Inferred).
Notes: CrowdStrike Investigation Summary, 22 Sep 2026, published by Boston Scientific [13]; the company's relay [12].

## PART 2 | Containment as the summary records it

- The entry device was disconnected and decommissioned.
- Actor IP addresses and domains were blocked at the firewall.
- Passwords were reset and the environment hardened.
- Falcon coverage expanded, with OverWatch and Active Defense monitoring.
- How the device was compromised (flaw, credential or exposed service) is not stated.
Caption: The outage mechanism is also open: actor action or defensive isolation (Inferred from absence).
Notes: Containment steps, as the company reported them to CrowdStrike [13]. Method and mechanism absent from [13][14].

## PART 3 | No one is named

| Who | What the record says |
|---|---|
| Boston Scientific | "The threat actor"; no group or ransomware brand |
| SEC filings | "Unauthorized activity" only |
| BleepingComputer | No group claimed it as of 26 August |
| MedTech Dive | 2026 roundup names no actor |
Caption: With no encryption and no extortion claim on record, calling it ransomware goes beyond the evidence.
Notes: Company wording [12]. Filings [14]. Press [22][25], graded Reported. Reading is Inferred.

## PART 4 | Patients, money and the sector

Left: Patients and hospitals
- Implanted device function was not affected.
- Monitoring of enrolled devices continued.
- New communicators and ICMs could not be activated until 8 September.
Right: Money and peers
- Full-year guidance cut to about 4.25% growth.
- Competition also weighed on Q3, so not all of the gap is the incident.
- Stryker's March incident was also found material.
Caption: The chief executive later said every plant and distribution center was shut (Reported).
Notes: Devices [4][5]. Activation [15]. Guidance [17]. Other factors [17], Inferred. Stryker [26][27]. CEO remarks [24].

## PART 4 | What the quarter cost

Stat: $5.138B | Q3 net sales, up 1.5%
Stat: $0.73 | Q3 adjusted EPS against $0.80 to $0.82 guided
Stat: 4.25% | Full-year reported growth, cut from 5.5 to 6.5%
- The 10-Q blames the Q3 net income decline mainly on the incident and idle production.
- It also names civil legal claims and possible regulatory scrutiny.
- Manual processes used in the response may raise the risk of errors and data-integrity issues.
Caption: Electrophysiology competition and slower LAAC growth also weighed, so the whole gap is not the incident (Inferred).
Notes: Guidance [16]. Results [17]. 10-Q [18]. Other factors [17]; the comparison is Inferred.

## PART 5 | Containment was fast; recovery was not

- Containment began on the day of detection, 25 August.
- Shipping for most products took 9 days to return; full restoration took 15.
- Recovery of on-premises business systems is where the cost landed.
- No CVE or KEV row is attached, so a CVE queue would not have flagged the exposure.
- An asset and attack-surface inventory finds an external-facing management interface.
Caption: Dates Confirmed; the reading is Inferred.
Notes: Containment [1][13]. Shipping and restoration [8][11]. KEV absence [20]. The reading is Inferred.

## DEFENDER VIEW | The controls this record argues for

Left: The edge
- Take network management interfaces off the internet.
- Inventory every external-facing appliance as a tier-zero asset.
- Patch edge devices on a KEV clock, then hunt for footholds.
Right: Containment and continuity
- Separate manufacturing, ordering and patient services from general IT.
- Rehearse order-to-ship continuity with queued electronic orders.
- Define manual processes before an incident, not after.
Caption: A CVE queue would have flagged nothing here; an attack-surface inventory would (Inferred).
Notes: Entry device [13]. Watchlist [28]. Segmentation [13][14]. Continuity [4][18]. The recommendations are Inferred.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- "Global disruption" read as an enterprise-wide compromise.
- Calling it ransomware, or naming a group.
- "No exfiltration" read as covering every system.
Right: Understated
- One edge device preceded two weeks of disrupted production.
- Stalled cardiac monitor activations sit outside the filings.
- The device's vendor and flaw stay undisclosed.
Notes: Scope [1][13]. Ransomware [13][22]. Exfiltration scope [12][13]. Duration [11][13][18]. Patient effect [15][24]. Vendor [13][20].

## MITRE MAPPINGS | Two candidates, nothing asserted

| Id | Technique | Tie to Boston Scientific |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Entry device; flaw not stated |
| T1133 | External Remote Services | Entry device; access method not stated |
Caption: ATT&CK v20.0, both at score 40 in the layer. CAPEC-555 only if credentials were stolen. No group, software or ICS technique is bound.
Notes: Techniques [13] with [30]. T1486 left out: no encryption [13]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Outage cost does not need an encryptor

- **The edge is the front door.** One external-facing device preceded a global outage.
- **Disruption without encryption.** Boston Scientific and Stryker both found material effects.
- **Separation held the line.** Cloud, Microsoft 365 and SCADA showed no actor access.
- **The missing fact.** Without the vendor or flaw, peers cannot check their own exposure.
Notes: Edge [13][14][28]. Materiality [14][26][27]. Separation [13]. Missing vendor [13][20]. The themes are Inferred from the record.
