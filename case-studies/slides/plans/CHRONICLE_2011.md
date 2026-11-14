# Slide plan: The Year 2011 in Intrusions: A Dated Record

- Study: case-studies/CHRONICLE_2011.md
- Cover title: The Year 2011 / in Intrusions / A Dated Record
- Subtitle: Broken certificate authorities, a vendor's stolen secrets, and botnets taken down in court
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/CHRONICLE_2011.md, told from Comodo's incident report, Mozilla's and Google's blogs, Microsoft advisories and bulletins, US-CERT and ICS-CERT records in CISA's archive, SEC filings by EMC, VASCO, Sony and Alliance Data, Adobe's and Apache's advisories, NVD and KEV records, CrySyS Lab's and Symantec's Duqu reports, McAfee's Night Dragon report, Justice Department and FBI releases, and White House, DoD, OMB, SEC, UK government, NIST and IETF records. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The year's trust failures happened in public

- **Certificates:** Comodo's RA account was abused in March; DigiNotar was breached in July and bankrupt in September.
- **RSA:** an attack took SecurID information; EMC took a USD 66.3 million remediation charge.
- **Consumers:** Sony, Epsilon, Steam and NASDAQ OMX disclosed intrusions.
- **Duqu:** Stuxnet's code reused, a signed driver, and a kernel zero-day fixed in December.
- **Courts:** Rustock, Coreflood, Kelihos and DNSChanger were taken down by legal action.
Caption: Grades: vendor, government and court records Confirmed; charges made only in 2012 Reported.
Notes: Certificates [5][26][33]. RSA [10][11]. Consumers [17][18][14][48][3]. Duqu [39][40][44]. Courts [9][16][34][46].

## KEY FACTS | Four numbers from the primary record

Stat: 3 | CA failures, each met by a Microsoft advisory
Stat: 100 | Microsoft bulletins, MS11-001 to MS11-100
Stat: 4,172 | CVE records NVD published in 2011
Stat: 9 | CVE-2011 ids in CISA's KEV catalog today
- KEV added the Duqu kernel flaw, CVE-2011-3402, in October 2025.
- DigiNotar went from detection to bankruptcy in nine weeks.
- No 2011 record carries an ATT&CK id; every binding is later.
Notes: CA advisories [6][29][49]. Bulletins [68][53], count Inferred. CVE count [95]. KEV [54]. DigiNotar [26][33].

## PART 1 | The year in date order, from Night Dragon to MS11-100

| Date | Event |
|---|---|
| 10 Feb | McAfee publishes Night Dragon |
| 15 Mar | Comodo RA account abused |
| 16 Mar | Rustock taken offline |
| 17 Mar | EMC files RSA's open letter |
| 13 Apr | Coreflood stop commands |
| 17 to 19 Apr | PSN and Qriocity breached |
| 1 Jun | Google: Gmail phishing |
| 19 Jul | DigiNotar detects intrusion |
| 29 Aug | Google: attacks in Iran |
| 13 Oct | SEC disclosure guidance |
| 14 Oct | CrySyS reports Duqu |
| 9 Nov | DNSChanger charges |
Notes: Night Dragon [2]. Comodo [5]. Rustock [9]. RSA [10]. Coreflood [16]. Sony [17]. Gmail [22]. DigiNotar [26][28]. SEC [38]. Duqu [39]. DNSChanger [46][47].

## PART 2 | Three certificate authorities failed in one year

| Date | Event | Grade |
|---|---|---|
| 15 Mar | Comodo RA issues nine certificates | Confirmed |
| 22 to 23 Mar | Mozilla blocks; Advisory 2524375 | Confirmed |
| 19 Jul | DigiNotar detects its intrusion | Confirmed |
| 29 Aug | Man-in-the-middle in Iran reported | Confirmed |
| 3 Sep | Google rejects all DigiNotar CAs | Confirmed |
| 20 Sep | DigiNotar declared bankrupt | Confirmed |
| 10 Nov | DigiCert Sdn. Bhd. untrusted | Confirmed |
Caption: Comodo's state-driven view and DigiNotar's "politically inspired" line are the companies' assessments (Reported).
Notes: Part 2. Comodo [5][8][6]. DigiNotar [26][28][31][33]. DigiCert Sdn. Bhd. [49]. Assessments [5][32].

## PART 3 | A security vendor's secrets became its customers' risk

- **Filing:** EMC's 8-K of 17 March carried RSA's open letter on the SecurID-related theft.
- **Risk:** RSA said the information could reduce a deployment's effectiveness in a broader attack.
- **Cost:** EMC's 10-Q records a USD 66.3 million second-quarter remediation charge.
- **Fallout:** Lockheed Martin detected an attack on 21 May and named no attacker.
- **Zero-day:** Adobe's APSA11-01 reported Flash CVE-2011-0609 in an Excel attachment.
Caption: The link between RSA and Lockheed Martin, and RSA's entry point, were not checked against a primary.
Notes: Part 3. RSA [10][11]. Lockheed Martin [60]. Flash [12][13].

## PART 4 | Documents and plug-ins carried the year's exploits

Left: Exploited at release
- Flash, March and April.
- Reader U3D in December.
- TrueType, by Duqu.
- Apache, telnetd.
Right: The KEV tail
- Nine CVE-2011 entries.
- Added 2022 to 2025.
- Apache, telnetd absent.
- BEAST never exploited.
Caption: Adobe's fixes were not opened; the Adobe rows rest on the advisory and the CVE records.
Notes: Part 4. Flash [12][15]. Reader [50]. TrueType [42][43][44]. Apache [27]. Telnetd [75]. KEV [54]. BEAST [37].

## PART 5 | Duqu reused Stuxnet's code, not its target

- **Report:** CrySyS Lab found massive Stuxnet code reuse on 14 October.
- **Signed:** a new driver carried a Taiwanese hardware maker's certificate.
- **Entry:** Symantec found a Word document with a then-undisclosed kernel flaw.
- **Fix:** Advisory 2639658 on 3 November, MS11-087 on 13 December.
- **ICS:** ICS-CERT found no targeting of industrial systems or their vendors.
Caption: The Stuxnet study is the home; this deck records the 2011 dates.
Notes: Part 5. CrySyS [39]. Symantec [40]. Microsoft [42][44]. ICS-CERT [41]. Home study [103].

## PART 6 | Espionage was described, not attributed to a state

Left: The record
- Night Dragon on energy.
- APT1's 2011 victims.
- Gmail, from Jinan.
- Comodo, from Iran IPs.
Right: The limits
- McAfee: "China-based".
- Mandiant wrote in 2013.
- Google names no state.
- Comodo: circumstantial.
Caption: Night Dragon, Duqu and APT1 are bound with ATT&CK's own records and caveats.
Notes: Part 6. Night Dragon [2][1]. APT1 [56][57]. Gmail [22][23]. Comodo [5].

## PART 7 | Courts and companies took botnets down

| Date | Event | Grade |
|---|---|---|
| 16 Mar | Rustock taken offline | Confirmed |
| 13 Apr | Coreflood stop commands | Confirmed |
| 19 Jul | 16 arrests over PayPal attacks | Confirmed |
| 26 Sep | Kelihos taken down | Confirmed |
| 8 Nov | Ghost Click: six Estonians arrested | Confirmed |
| 9 Nov | Seven charged over DNSChanger | Confirmed |
Caption: The botnet sizes are Microsoft's and the FBI's estimates.
Notes: Part 9 and Part 8. Rustock [9]. Coreflood [16]. PayPal [24]. Kelihos [34]. Ghost Click [46][47].

## PART 8 | Governments wrote strategy and standards

| Date | Event | Grade |
|---|---|---|
| Mar | SP 800-39; RFC 6176 and 6125 | Confirmed |
| May | International Strategy | Confirmed |
| 27 Jun | CWE/SANS Top 25 | Confirmed |
| Jul | DoD Strategy | Confirmed |
| Sep | SP 800-137 and 800-145 | Confirmed |
| 13 Oct | SEC Topic No. 2 | Confirmed |
| 25 Nov | UK Cyber Security Strategy | Confirmed |
| 8 Dec | FedRAMP | Confirmed |
Notes: Part 11. NIST [78][79][80]. IETF [83][84]. Strategy [20]. Top 25 [88]. DoD [65]. SEC [38]. UK [92]. FedRAMP [94].

## CROSS-CUTTING THEMES | What the year's record shows

- **Trust:** certificates, two-factor product information and a code-signing certificate were stolen or abused.
- **Removal:** the fix for each CA failure was to take trust away.
- **Documents:** an Excel file and a Word file delivered two of the zero-days.
- **Places, not perpetrators:** the primaries named places; state attributions came later.
- **Filings:** breaches became 8-K and 6-K filings, and the SEC wrote guidance.
Caption: The themes are the study's reading of the record (Inferred).
Notes: Cross-cutting themes. Trust [5][26][10][39]. Removal [8][6][29][28]. Documents [12][40]. Places [5][28][22][2]. Filings [10][14][18][26][38].

## MITRE MAPPINGS | 66 Enterprise techniques, every one a later mapping

| Id | Technique | 2011 use |
|---|---|---|
| T1588.004 | Digital Certificates | Comodo, DigiNotar |
| T1557 | Adversary-in-the-Middle | Iran |
| T1566.001 | Spearphishing Attachment | Flash, Duqu |
| T1553.002 | Code Signing | Duqu |
| T1114.003 | Email Forwarding Rule | Gmail |
| T1110 | Brute Force | Morto |
| T1498 | Network Denial of Service | PayPal |
Caption: ATT&CK v20.0 ids; 54 are listed by ATT&CK for C0002, S0038 or G0006; three ICS ids for Duqu.
Notes: Part 13. Rows [5][28][12][40][39][22][67][24]. Basis scores in the layer: 100 Listed, 70 Described, 50 Reported, 40 Inferred. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | The 2011 lessons still apply

Left: What 2011 taught
- A CA you trust can fail.
- Revocation fails open.
- Pins catch forgeries.
- Suppliers are incidents.
Right: What still applies
- Filter document content.
- Audit mail forwarding.
- Strong RDP passwords.
- KEV dates lag events.
Notes: Top recommendations and Part 12. CA [6][29][49]. Revocation [6][29]. Pins [90][28]. Suppliers [10][11]. Documents [12][15]. Mail [22]. RDP [67]. KEV [43][54].

## OVERSTATED AND UNDERSTATED | Headlines outran the record

Left: Overstated
- Iran state attribution.
- RSA caused Lockheed.
- Duqu as ICS weapon.
- BEAST and botnet totals.
Right: Understated
- The CA collapse.
- Takedown remedies.
- Standards work.
- Exploits outside KEV.
Caption: The readings are the study's own (Inferred).
Notes: Overstated [5][32][28][11][60][41][45][37][9][34][16]. Understated [6][29][49][34][16][47][95][27][75][54]. Cross-cutting themes and the overstated and understated passage.
