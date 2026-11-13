# Slide plan: The IDScan.net Driver's License Breach of 2026: A Case Study

- Study: case-studies/IDSCAN_DRIVERS_LICENSE_BREACH_2026.md
- Cover title: The IDScan.net / Driver's License Breach of 2026 / A Case Study
- Subtitle: An ID-scanning platform, a search service on a criminal forum, and the licenses in between
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/IDSCAN_DRIVERS_LICENSE_BREACH_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Licenses scanned at the counter, sold on a forum

- Anyone whose driver's license was scanned at a rental counter, a dispensary or another business.
- An unauthorized third party reached part of IDScan.net's cloud environment, 4 April to 2 September 2026.
- The access was limited to the VeriScan platform, per the vendor's 29 September update.
- A reporter found his own license, and senior officials' licenses, in a forum search service called Nexus.
- No source states how the attacker got in, and no CVE or KEV entry applies.
Caption: Evidence grade: Confirmed for the vendor's notice; Demonstrated and Reported for what the market showed.
Notes: People in scope [4]. Window and platform [1][2]. Nexus and the reporter's queries [4]. Entry vector and CVE, Inferred from [1][4][15].

## KEY FACTS | A vendor notice with no count

Stat: 5 months | Vendor-stated access window
Stat: 153M+ | Licenses claimed by the seller
Stat: 400K | Records added to Nexus in 24 hours
Stat: 9 | Putative class actions reported
- Vendor: IDScan.net, an identity verification company; affected system: VeriScan.
- The vendor's notice gives no count of affected people.
- Attribution stops at the Nexus seller; no group is named.
Notes: Window [1]. Seller's figure, a claim [4]. Record growth, Demonstrated [4]. Class actions, Reported [12]. No count [1]. Attribution, Inferred from [1][4][9].

## PART 1 | From the forum tip to the vendor's notice

| Date | Event |
|---|---|
| Jun 2025 | Earliest scan timestamps seen in the records |
| 4 Apr 2026 | Vendor-stated access window opens |
| 31 Aug 2026 | A source flags the Nexus listing to Krebs |
| 1 Sep 2026 | FBI probe; vendor receives information; Nexus offline |
| 2 Sep 2026 | Vendor-stated access window closes |
| 4 Sep 2026 | Vendor notice first posted |
| 29 Sep 2026 | Update: event limited to VeriScan |
Caption: Scan timestamps show how long images were retained, not when they were taken.
Notes: Timestamps [4][13]. Window [1][2]. Tip, Reported [4]. FBI, Reported [4][8]; vendor [1]; Nexus offline [4]. Notice [1]. Update [1][2].

## PART 2 | The intrusion record is short

Left: In the record
- "A portion of" the cloud environment, 4 April to 2 September 2026.
- No product other than VeriScan, per the 29 September update.
- Nearly 400,000 records added to Nexus in one 24-hour period.
Right: Not in the record
- Any vulnerability, credential, misconfiguration or entry path.
- How the data left the platform.
- Any patch or fixed version.
Caption: The absences are why no initial access or exfiltration technique is bound.
Notes: Vendor's account, Confirmed [1][2]. Record growth, Demonstrated [4]. Absences, Inferred from [1][4][5][10].

## PART 2 | What the notice lists, and what the market showed

Left: The vendor's notice
- Full name, contact information and date of birth.
- Driver's license, passport and other government ID numbers.
- Fields vary by how each customer configured VeriScan.
Right: The Nexus records
- Front and back scans, with infrared and ultraviolet versions.
- Customer photos in some records, per the reporting.
- Timestamps in filenames; no passports seen by Krebs.
Caption: A number is a record; an image is an impersonation kit (Inferred).
Notes: Vendor fields, Confirmed [1]. License scans, Demonstrated by the reporter's queries [4]. Customer photos, Reported [5][6]. Passport claim in the advert, Reported [5].

## DISCREPANCIES | Three windows, three notice dates

| Account | What it says |
|---|---|
| Vendor | Access 4 April to 2 September 2026 |
| Barracuda | June 2025 to 1 September 2026, from record timestamps it reads as theft dates |
| Seller | "Over a year" of continuous exfiltration |
| Notice dates | 4 Sep on the notice, 8 Sep per Krebs, 11 Sep on the homepage |
Caption: This study uses the vendor's window and the notice's own date.
Notes: Vendor [1]. Barracuda, Reported [13]. Seller, Reported [4]. Notice dates [1][3][4]. The choice is Inferred.

## PART 3 | Attribution stops at a seller

| Who | What the record says |
|---|---|
| Nexus seller | A new user on the Exploit forum; not named |
| Krebs | Ties Nexus to idscan.net circumstantially |
| IDScan.net | Confirms an intrusion; never names Nexus |
| Any source | Names no group, sponsor or malware |
Caption: The window closing the day after Nexus went offline makes the link very likely (Inferred).
Notes: Seller, Reported [4]. Circumstantial link, Reported [4]. Vendor, Confirmed [1]. No group [1][4][5][9][10]. Motive, Inferred from the paid search service [4].

## PART 4 | Impact and response

- The seller's figures: 153M+ licenses, 10M+ ID cards, 579,000+ medical cards (claims).
- A record count is not a count of unique people; nobody has deduplicated it.
- The vendor secured its systems, engaged specialists and offers credit monitoring.
- FBI New Orleans opened an investigation on 1 September (Reported).
- No IDScan filing on the California AG list as of 11 November.
Caption: No regulator enforcement action appears in any source opened.
Notes: Seller's figures [4]. Dedupe, Inferred. Vendor response, Confirmed [1]. FBI [4][8]. California AG [14]. Enforcement absent [10].

## PART 4 | Customers, courts and regulators

| Who | What the record says |
|---|---|
| Customers | Hertz, Target, FedEx and others were listed as clients |
| Caesars | Says it has not used VeriScan since February 2025 and had no active VeriScan accounts at the time of the incident (Reported) |
| Courts | Nine putative class actions, E.D. Louisiana |
| DoD | Evaluating the reports, 2 September |
| California AG | No IDScan filing as of 11 November |
Caption: The class-action dockets were not opened (HTTP 403); the count is Reported.
Notes: Client list, Reported [4]; Techlicious removed Target from its own list [6]. Caesars [4]. Courts [12]. DoD [5]. California AG, Confirmed [14].

## DEFENDER VIEW | Treat ID-scan vendors as identity stores

Left: Vendor and data
- Inventory where license images are captured and retained.
- Write logging, segregation, retention and notice into contracts.
- Assess resellers and downstream processors.
Right: Detection and identity
- Monitor bulk API, service and administrator reads.
- Stop accepting a license image alone at help desks.
- Replace access credentials tied to exposed IDs.
Caption: A CVE queue would have shown nothing here (Inferred).
Notes: Vendor controls, Reported advice [7]. Bulk reads [7]; 400,000 records in a day [4]. Help desk and credentials, Reported advice [13]. CVE queue, Inferred from [1][15].

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- "153 million Americans": a seller's record count, with Canadians in it.
- The advert's passport claim, against what Krebs saw.
Right: Understated
- The images, IR and UV scans and the customer photos reported, all omitted from the notice.
- Long retention, shown by 2025 scan timestamps.
- Senior officials' records in the set.
Notes: Count [1][4][11]. Passports [4][5]. Images [1][4]. Customer photos, Reported [5][6]. Retention [4][13]. National-security exposure [4][10]. The judgments are Inferred from the record.

## MITRE MAPPINGS | Three techniques, no group bound

| Id | Technique | Tie to IDScan.net |
|---|---|---|
| T1530 | Data from Cloud Storage | Access to the VeriScan cloud environment (partial fit) |
| T1597 | Search Closed Sources | What Nexus let buyers do (not observed) |
| T1589 | Gather Victim Identity Information | What the records enable (not observed) |
Caption: ATT&CK v20.0. CAPEC-407 Pretexting as a risk. D3FEND Data Inventory and User Account Permissions.
Notes: Techniques [1][4][5] with [16]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | One intermediary, many counters

- **Concentration at an intermediary.** One platform behind many businesses set the blast radius.
- **Detection came from outside.** A journalist's source flagged the listing.
- **Notices list fields; attackers sell images.** Accurate notices can still understate harm.
- **Retention is policy.** No federal law limits how ID scanners keep data (Reported).
Notes: Intermediary, compare Change Healthcare 2024 and the Cl0p file-transfer breaches [4]. Detection [1][4]. Fields and images [1][4]. Retention [11]. The themes are Inferred from the record.
