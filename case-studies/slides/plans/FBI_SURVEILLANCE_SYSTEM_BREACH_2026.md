# Slide plan: The FBI Surveillance System Breach of 2026: A Case Study

- Study: case-studies/FBI_SURVEILLANCE_SYSTEM_BREACH_2026.md
- Cover title: The FBI Surveillance / System Breach of 2026 / A Case Study
- Subtitle: A third party, a system of surveillance returns and a record built on unpublished notices
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/FBI_SURVEILLANCE_SYSTEM_BREACH_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The people the FBI watches were the exposed party

- An unclassified FBI system held pen register and trap and trace returns.
- It also held personal information on subjects of FBI investigations.
- Abnormal log information opened the investigation on 17 February 2026.
- The FBI says access "was obtained through a third party".
- Phone numbers of people under FBI monitoring were reported likely exposed.
Caption: Evidence grade: Reported. The notices to Congress are unpublished and known only through outlets.
Notes: System [1][10][11][13]. Detection [1][6][13]. Third party [11]. Phone numbers [11].

## KEY FACTS | A major incident with no CVE and no named actor

Stat: 17 Feb | Investigation opened
Stat: 15 days | To the first notice to Congress
Stat: 34 days | To the major-incident call
Stat: 0 | CVEs or KEV entries tied to it
- Victim: the FBI, on a system holding law enforcement sensitive information.
- Entry path: a commercial ISP vendor's infrastructure and "a third party".
- Attribution: none official; "China-linked" per anonymous officials.
Caption: The intervals are this study's arithmetic from the reported dates (Inferred).
Notes: Dates [1][9][13]. Intervals Inferred from [9][13]. No CVE or KEV [19]. Victim [1][9]. Entry [11][13]. Attribution [6][9][13].

## PART 1 | From abnormal logs to a FISMA major incident

| Date (2026) | Event |
|---|---|
| 17 February | Investigation opens on abnormal log information |
| 4 March | The FBI first tells Congress |
| 5 March | The FBI says it addressed suspicious activity |
| 6 March | WSJ: investigators suspect China-linked hackers |
| 23 March | DOJ determines a FISMA major incident |
| 3 April | The FBI says access came through a third party |
| 6 April | Forensics and remediation still ongoing |
Caption: Every row is Reported: the notices behind them were not published.
Notes: Detection [1][6][13]. Congress [9]. Statement [2][3][4]. WSJ [6][7]. Determination [13]. Third party [11]. Later notice [13].

## PART 2 | What the notices say, and what they leave out

Left: In the record
- Pen register and trap and trace returns, and PII on subjects.
- Call and internet-activity records, not content, per WSJ sources.
- A commercial ISP vendor's infrastructure used against FBI controls.
Right: Not in the record
- The vendor, the controls or how they were defeated.
- Any product, version, exploit or malware.
- When theft was confirmed, or whether access is contained.
Caption: The absences are why only two techniques are bound and no software is.
Notes: System [1][7][10][11][13]. Entry path [11][13]. Absences Inferred from [13][19].

## PART 2 | Metadata is enough to map who is being watched

- Pen register and trap and trace tools collect metadata, not content.
- WSJ sources: incoming and outgoing calls, IP and website addresses, some routing.
- Target phone numbers tell an adversary who the FBI is watching (Inferred).
- A Trellix expert: numbers can show which contacts to drop or which asset is burned.
- No count of exposed numbers has been given.
Caption: The likely value is counterintelligence; no source states a motive (Inferred).
Notes: Metadata [7][11]. Who is watched, Inferred from [11]. Expert view [11]. No count [11].

## PART 3 | Attribution here is anonymous-source reporting

| Who | What they say |
|---|---|
| FBI and DOJ | No actor named in any notice or statement |
| WSJ | Investigators believe China-linked hackers |
| Politico | "China-linked", per an aide and two officials |
| Nextgov | No definitive China link confirmed |
| CNN and WSJ | Whether Salt Typhoon is involved is unclear |
Caption: Salt Typhoon (G1045) is context only, not attribution for this incident.
Notes: Government [11][13]. WSJ [6][7]. Politico [9]. Nextgov [11]. Salt Typhoon [2][7]. ATT&CK [20].

## DISCREPANCIES | Where the accounts disagree

| Question | What the accounts say |
|---|---|
| What the system is | Notices: surveillance returns; CNN source: wiretaps |
| Its name | DCSNet only in Malwarebytes and a commentator |
| When Congress heard | Week of 30 March (Politico) or 23 March (Fox) |
| Where it happened | Virgin Islands systems, per Fox News alone |
Caption: This brief uses the notice wording as outlets quote it.
Notes: System [1][2][10][11][13]. DCSNet [8][14]. Congress [9][10]. Location [10].

## PART 4 | Response, Congress and the FISMA clock

- The FBI says it identified and addressed the activity.
- DOJ created a working group; Bloomberg reports a criminal probe.
- FISMA requires notice to Congress within seven days of a reasonable basis.
- Politico and Fox News give different weeks for the congressional notice.
- So whether the seven-day clock was met cannot be judged (Inferred).
Caption: The FISMA notice requirement is the one Confirmed primary in the response record.
Notes: FBI [3][4][11]. DOJ [13]. FISMA [16]. Congress [9][10]. Clock Inferred.

## DEFENDER VIEW | The controls this record argues for

Left: Third parties
- Inventory every vendor and carrier path into lawful-process data.
- Segment those paths from the rest of the network.
- Track third-party connectivity as an exposure in its own right.
Right: Data and detection
- Keep and review logs; logs were the only detection on record.
- Encrypt surveillance metadata, restrict access and audit reads.
- Rehearse the FISMA major-incident path and its seven-day notice.
Caption: A CVE queue would have shown nothing here (Inferred).
Notes: Entry path [11][13]. Logs [1]. Data [10][13]. FISMA [16]. The recommendations are Inferred.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- A hack of the FBI's "wiretap system".
- The name "DCSNet", from secondary writers.
- China attribution or a Salt Typhoon link stated as fact.
Right: Understated
- The third-party path, in the FBI's own words.
- The counterintelligence value of target phone numbers.
- What a major-incident determination implies about the data.
Notes: Wiretap framing [2][5][13]. DCSNet [8][14]. Attribution [13]. Third party [11]. Phone numbers [11]. Determination [9].

## MITRE MAPPINGS | Two techniques, no group bound

| Id | Technique | Tie to the FBI breach |
|---|---|---|
| T1199 | Trusted Relationship | Access through a third party and an ISP vendor |
| T1213 | Data from Information Repositories | Target phone numbers exposed from the system |
Caption: ATT&CK v20.0. D3FEND: Network Traffic Filtering, Session Termination. G1045 is context only.
Notes: Techniques [11][13] with [20]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Lawful-access data is a target class

- **Trusted third parties carry the risk,** as at SolarWinds, with no update channel here.
- **Lawful-access data draws attackers,** from the 2024 telecom compromises to this one.
- **Unpublished primaries shape the story;** framings spread faster than notice wording.
- **Attribution by leak is not attribution;** eight months on, no government names an actor.
Notes: Third parties [11][13]. Telecom 2024 [17]. Framings [2][8]. Attribution [6][13]. The themes are Inferred from the record.
