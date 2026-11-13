# Slide plan: The Instructure Canvas Breach and ShinyHunters Extortion of 2026: A Case Study

- Study: case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md
- Cover title: The Instructure Canvas Breach / and ShinyHunters Extortion / of 2026
- Subtitle: A free teacher account, a support ticket and a learning platform held to ransom during finals
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/INSTRUCTURE_CANVAS_BREACH_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Students met a ransom note at login

- In the first week of May 2026, during finals, Canvas went into maintenance at schools and universities.
- A Free-for-Teacher account filed a support ticket carrying malicious code.
- Cross-site scripting gave the actor a support agent's token with elevated access.
- "Contained" on 2 May; on 7 May the actor returned through a sibling flaw.
- On 11 May Instructure reached an agreement: data returned, shred logs.
Caption: Evidence grade: Confirmed as Instructure's own statements; the login-page reports are Reported.
Notes: Students and finals [5][8][19]. Entry chain [2]. Contained [3]. Return [2]. Agreement [1].

## KEY FACTS | A platform-wide breach with no CVE

Stat: 8,000+ | Institutions on Canvas, per the House letter
Stat: ~300 | Organizations shown the ransom note
Stat: 5 days | From "contained" to the second intrusion
Stat: 0 | CVE or KEV entries for the flaws
- Vendor: Instructure; the hosted Canvas learning platform.
- Claimed by ShinyHunters; the vendor FAQ says the attacks "appear" to be its work.
- The fix was the vendor's, on the service: there was nothing for customers to patch.
Notes: Scale [8]. Note reach [1][2]. Contained and return [2][3]. No CVE or KEV [9][10]. Attribution [2][16]. Remediation, Inferred.

## PART 1 | From support ticket to agreement

| Date (2026) | Event |
|---|---|
| 25 to 30 Apr | Support representative accounts used by the actor |
| 29 Apr | Instructure detects unauthorized activity |
| 2 May | Incident believed contained; patches deployed |
| 3 May | ShinyHunters lists Instructure (Reported) |
| 7 May | Second XSS; ransom note on login pages |
| 8 May | Free-for-Teacher disabled |
| 11 May | Agreement; House committee letter |
| 15 May | FBI PSA on an unnamed LMS attack |
Caption: Times on the status pages are Mountain Daylight Time; delivery of the stolen data to institutions ran to 29 September.
Notes: Window [2]. Detection [1]. Contained [3]. Leak site [16][17]. Return [1][2]. FFT [1]. Agreement [1]. Letter [8]. PSA [28]. Final phase [1].

## PART 2 | How the actor got in, twice

Left: First intrusion (April)
- A Free-for-Teacher account files a support ticket with malicious code.
- An agent opens it; cross-site scripting yields an authorization token.
- Elevated access within Canvas follows from the agent's session.
Right: Second intrusion (7 May)
- A second, unpatched XSS in the discussion feature.
- The OAuth flow generates a token, sidestepping the first fix.
- Ransom note through custom-theme CSS, disabled after about 10 minutes.
Caption: Fixing one instance of a bug class left its sibling open (Inferred).
Notes: Vendor FAQ [2]; incident hub [1]. BleepingComputer reports the same vulnerability for both [21], graded Reported; the study follows the FAQ.

## PART 2 | What was taken, and how the story grew

- Early statements: names, usernames, emails, student IDs, courses, enrollments and messages.
- No evidence of passwords, birth dates, government IDs or financial data.
- July deliveries add API provisioning records, user reports and DAP messaging data.
- The actor claims DAP queries, provisioning reports and user APIs (Reported).
- No count of people or institutions has been published by the vendor.
Caption: Bulk export features were the likely collection path (Inferred from the matching categories).
Notes: Early data list [1][3]. July deliveries [1]. Actor's method claim [18]. No count [1].

## PART 3 | Attribution, as each source states it

| Who | What they say |
|---|---|
| Status pages | "A criminal threat actor" |
| Vendor FAQ | Attacks "appear" to be ShinyHunters |
| ShinyHunters | Claimed the breach on its leak site |
| House committee | ShinyHunters breached Instructure twice |
| FBI PSA, 15 May | ShinyHunters claimed an LMS attack; no platform named |
| ATT&CK G1057 | Describes ShinyHunters; does not list this incident |
Caption: Binding the incident to G1057 is the study's inference from the claim and the vendor's wording.
Notes: Status [3]. FAQ [2]. Claim [16]. Committee [8]. FBI [28]. ATT&CK [26].

## DISCREPANCIES | The actor's numbers disagree with each other

| Claim | Source |
|---|---|
| 3.65 TB, 275 million people | Leak site, 3 May |
| 280 million records, 8,809 institutions | Actor, 5 May |
| About 330 institutions' login pages, 30 minutes | Press, 7 May |
| About 300 organizations, 10 minutes | Vendor |
Caption: No count of people is published; BleepingComputer could not confirm the actor's figures.
Notes: Leak site [16][17]. Actor [18]. Press [19][23]. Vendor [1][2]. Unconfirmed [16][17][18].

## PART 4 | Response, payment and government

- CrowdStrike engaged, Falcon EDR rolled out, Parchment swept for the actor's IOCs.
- Per-institution data packets through ShareFile; Kroll coordinates notification.
- The FAQ answers "why did Instructure decide to pay the ransom" without disputing it.
- House Homeland Security asks for a briefing by 21 May.
- The FBI advises victims not to pay (Reported) and warns of follow-on spearphishing.
Caption: A shred log is the actor's attestation, not proof (Inferred).
Notes: Response [1]. Payment [2]. Committee [8]. FBI on X [24], Reported; FBI PSA [28].

## DEFENDER VIEW | The controls this record argues for

Left: For SaaS customers
- Review logs for support-account access, 25 to 30 April and 7 May.
- Enforce MFA on privileged accounts; rotate integration tokens.
- Keep an inventory of tools holding Canvas keys.
Right: For SaaS vendors
- Never render low-trust tenant content with staff privileges.
- Limit support impersonation rights and token lifetimes.
- Plan for an LMS outage during exams.
Caption: A CVE queue would have shown nothing here (Inferred).
Notes: Log guidance [2]. MFA and tokens [3]. Integration breakage [6], Reported. Vendor hardening [2]. Rutgers workarounds [13]. Recommendations are Inferred.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- The actor's counts, which disagree with one another.
- Leak-site removal read as proof of payment.
- The 7 May vector, where sources disagree.
Right: Understated
- "Contained" on 2 May, five days before a second intrusion.
- The early data list, narrower than the July deliveries.
- "About 10 minutes": service took days to recover.
Notes: Counts [16][17][18]. Removal [21][24]. Vector [2][21]. Contained [2][3]. Data list [1][3]. Recovery [2][5][13].

## MITRE MAPPINGS | Nine techniques and a claimed group

| Id | Technique | Tie to Canvas |
|---|---|---|
| T1585 | Establish Accounts | Free-for-Teacher account |
| T1190 | Exploit Public-Facing Application | XSS in ticket and discussion |
| T1528 | Steal Application Access Token | Agent's token taken |
| T1550.001 | Application Access Token | Token used for access |
| T1078.004 | Cloud Accounts | Support accounts used |
| T1213 | Data from Information Repositories | Bulk export claimed |
| T1491.002 | External Defacement | Note on login pages |
| T1657 | Financial Theft | Extortion and agreement |
| T1684 | Social Engineering | 2025 Salesforce incident |
Caption: ATT&CK v20.0. CWE-79; CAPEC-592, 63, 21 and 593. ShinyHunters G1057; C0059 as a fit.
Notes: Techniques [1][2][7][18][19] with [27]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | One intermediary, thousands of victims

- **Concentration at an intermediary.** As at Change Healthcare, one platform set the blast radius.
- **Data theft without encryption.** The pressure came from stolen data and public embarrassment.
- **Repeat targeting of education vendors.** Infinite Campus, McGraw Hill and PowerSchool came before.
- **XSS is a privilege problem.** Whose browser renders the script decides the impact.
Notes: Intermediary, Inferred. Extortion [1][19]. Education vendors [15], Reported. XSS [2], Inferred.
