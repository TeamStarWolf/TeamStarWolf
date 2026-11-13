# Slide plan: The PAN-OS GlobalProtect Authentication Bypass of 2026 (CVE-2026-0257), Qilin and INC Ransomware: A Case Study

- Study: case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md
- Cover title: The PAN-OS GlobalProtect / Authentication Bypass of 2026 / Qilin and INC Ransomware
- Subtitle: A forged cookie, a VPN past MFA, and the ransomware that followed
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/PALO_ALTO_PAN_OS_CVE_2026_0257.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The VPN let in someone who never logged in

- On 13 May Palo Alto Networks disclosed CVE-2026-0257 in GlobalProtect.
- In one configuration an unauthenticated attacker could open a VPN connection.
- Rapid7 saw the first attempts four days later, on 17 May.
- KEV listed it on 29 May with a three-day deadline.
- By June, intrusions that began at the VPN ended in Qilin ransomware.
Caption: Evidence grade: Confirmed from the vendor advisory, the KEV record and the vendors' own findings.
Notes: Disclosure [1][2]. First attempts [5]. KEV [4]. Qilin intrusions [7]. Unit 42 on Qilin and INC [6].

## KEY FACTS | One setting decided who was exposed

Stat: 7.8 | Vendor CVSS v4.0 score
Stat: 9.1 | NVD CVSS v3.1 score
Stat: 3 | Days KEV allowed to fix
Stat: 0 | Victims named in any source
- Product: GlobalProtect portal and gateway on PAN-OS, Prisma Access and Siemens RUGGEDCOM APE1808.
- Precondition: authentication override cookies on, plus a specific certificate set-up.
- Weakness: CWE-565, a cookie trusted without integrity checks.
Notes: Scores [1][3]. KEV [4]. Victims [5][6][7]. Product [1][8]. Precondition [1]. CWE [1][3][4].

## PART 1 | From disclosure to ransomware within weeks

| Date (2026) | Event |
|---|---|
| 13 May | Advisory, CVE record and NVD entry published |
| 17 May | Earliest exploitation Rapid7 observed |
| 29 May | KEV adds the CVE, due 1 Jun; Rapid7 analysis |
| Jun | Several intrusions end in Qilin ransomware |
| 20 Jul | Arctic Wolf report links the CVE to Qilin |
| 19 Oct | Unit 42 names Qilin and INC attempts |
Caption: All rows Confirmed from the vendor, KEV and vendor-research records.
Notes: Advisory [1][2][3]. Rapid7 [5]. KEV [4]. Qilin intrusions [7]. Unit 42 [6].

## PART 1 | The record disagrees with itself

- **The KEV date.** Some reports say 13 May; KEV, NVD and the CVE record say 29 May.
- **Two scores.** "Critical" is NVD's 9.1 on CVSS v3.1; the vendor's 7.8 is CVSS v4.0.
- **A moving score.** Rapid7 reports a first vendor score of 4.7, raised on 29 May.
- **The ransomware flag.** KEV shows Known; when it changed was not checked.
Caption: A triage queue keyed on one feed or one score could point the wrong way (Inferred).
Notes: KEV date [2][3][4][6][13][18]. Scores [1][3]. Score change, per Rapid7 only [5]. Flag [4][14].

## PART 2 | The flaw, at advisory level

- Authentication override cookies let GlobalProtect users skip logging in again.
- With a specific certificate set-up, a forged cookie was trusted.
- Rapid7: the cookie certificate had been reused for another feature.
- The fix regenerates cookies, so every user re-authenticates once.
- Workarounds: a certificate used only for the cookies, or override turned off.
Caption: Fixed builds span PAN-OS 12.1, 11.2, 11.1 and 10.2, and Prisma Access.
Notes: Flaw [1]. Root cause, Rapid7's analysis [5]. Fix and workarounds [1].

## PART 2 | Quiet probing, then a full ransomware chain

Left: May and early June
- Two waves from hosting providers, one actor likely.
- 8 of 10 affected Rapid7 customers: no full VPN session.
- No lateral movement in those cases.
Right: June to October
- RMM tools, LSASS and NTDS dumping, PsExec and RDP.
- Logs cleared, Defender disabled.
- Rclone to MEGA, then Qilin encryption.
- A vCenter pivot and an offline domain controller dump.
Caption: Early probing is Rapid7's finding; the intrusion chain is Arctic Wolf's and Unit 42's.
Notes: Early waves [5]. Unit 42 early activity [6]. Intrusion chain [7]. vCenter pivot and dump [6].

## PART 2 | An old backup bug finished the job

- Unit 42 says the actors chained Veeam CVE-2023-27532.
- That flaw has been in KEV since 22 August 2023, ransomware use Known.
- It is a missing-authentication flaw, CWE-306.
- Arctic Wolf saw Veeam targeted before encryption.
Caption: A three-year-old KEV entry was still open inside networks reached through a 2026 VPN flaw (Inferred).
Notes: Chain [6]. KEV entry [4]. Backup targeting [7].

## PART 3 | Qilin and INC, and a third name nobody confirmed

| Name | Who says so | Standing |
|---|---|---|
| Qilin | Arctic Wolf, Unit 42 | Two independent vendors |
| INC | Unit 42 | One vendor, no confidence level |
| Settra | ReliaQuest, second-hand | Not adopted by Unit 42 |
Caption: No government advisory opened for this study names a group for this CVE; KEV records ransomware use without one.
Notes: Qilin [6][7][10]. INC [6][9][10]. Settra, Reported [11][12]. KEV [4].

## PART 4 | No victims named, and exposure is not compromise

Stat: 167,000+ | Exposed GlobalProtect instances (Shadowserver)
Stat: 11 | Sectors Unit 42 lists, no counts
Stat: 15.39% | Qilin's leak-site share in Q3 2026
- No opened source names a victim or counts compromised organizations.
- The vulnerable feature is off by default, so exposure counts are an upper bound.
- Siemens carried the flaw onto an industrial platform; no industrial victim is described.
Notes: Exposure, Reported [14]. Sectors [6]. Kaspersky statistic [15]. Victims Inferred from [5][6][7]. Upper bound Inferred from [1][14]. Siemens [8].

## PART 5 | Inventories listed versions, not settings

- A feature setting, not a version number, decided exposure.
- Teams that ranked by the first score of 4.7 would have parked it.
- KEV and SSVC came eleven days after the first exploitation Rapid7 saw.
- Access gained before the patch can outlive it.
Caption: Inventory the cookie and certificate settings, not just the PAN-OS build (Inferred).
Notes: Setting [1]. Score [5]. KEV and SSVC timing [2][4][5]. Access outliving the patch, Reported [12].

## DEFENDER VIEW | Patch, then evict, then hunt

Left: Fix the edge
- Move every portal and gateway to a fixed build.
- Until then, a dedicated cookie certificate or override off.
- Check management ports 4443 and 3879 are not exposed.
- Patch Veeam CVE-2023-27532.
Right: Assume someone got in
- Terminate active GlobalProtect sessions.
- Rotate admin, service and cloud-storage credentials.
- Reset KRBTGT twice.
- Hunt Event ID 1102, PSEXESVC, C$ writes, hosting-provider VPN sources.
Notes: Fix [1]. Management ports and Veeam, Unit 42's guidance [4][6]. Eviction and hunting, Arctic Wolf's guidance [7].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- A 13 May KEV date.
- "Critical" without naming the scoring system.
- The Settra link.
- Exposure counts read as victim counts.
Right: Understated
- "Limited exploit attempts" beside domain-wide ransomware.
- Access that outlives the patch.
- A vCenter pivot that defeats in-guest detection.
- An industrial platform that inherited the flaw.
Notes: Overstated [6][13][1][3][14]. Understated [1][7][6][12][8]. Readings Inferred from the cited records.

## MITRE MAPPINGS | Eighteen techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | GlobalProtect exploitation |
| T1606.001 | Web Cookies | Forged override cookie |
| T1133 | External Remote Services | VPN session past MFA |
| T1003.003 | NTDS | Domain credential dumping |
| T1567.002 | Exfiltration to Cloud Storage | Rclone to MEGA |
| T1486 | Data Encrypted for Impact | Qilin encryption |
Caption: ATT&CK v20.0; the other twelve techniques are in the study's table and its Navigator layer. CWE-565, CWE-306.
Notes: Techniques [1][4][5][6][7] with library data [16]. CWE [1][3][4]. Software S1242 Qilin, S1139 INC Ransomware; groups G1050, G1032. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The VPN is the front door

- **The lock trusted a forged key.** A cookie skipped MFA on the gateway itself.
- **Edge bugs feed extortion.** A VPN flaw became a ransomware supply line in weeks.
- **Old KEV entries still matter.** A 2023 backup flaw was chained after a 2026 one.
- **Advisories keep moving.** Fixes, status, scope and named actors all changed.
Notes: Forged key [6][17]. Supply line [7]. Old KEV entry [4][6]. Moving advisories [1][6][8]. The lessons are Inferred.
