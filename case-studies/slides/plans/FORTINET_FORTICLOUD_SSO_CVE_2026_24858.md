# Slide plan: The FortiCloud SSO Authentication Bypass of 2026 (CVE-2026-24858): A Case Study

- Study: case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md
- Cover title: The FortiCloud SSO / Authentication Bypass / of 2026 (CVE-2026-24858)
- Subtitle: A second login bypass in the same feature, and why patching for December did not mean safe in January
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/FORTINET_FORTICLOUD_SSO_CVE_2026_24858.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Patched in December, logged into in January

- In December 2025 Fortinet fixed a FortiCloud SSO login bypass.
- On 22 January 2026 it saw logins to fully upgraded devices anyway.
- CVE-2026-24858: a FortiCloud account holder could log into other accounts' devices.
- Fortinet locked out two accounts and switched FortiCloud SSO off for a day.
- KEV added the CVE the day it was published, with a three-day deadline.
Caption: Evidence grade: Confirmed from Fortinet's advisories and blog, the CVE and KEV records and the CISA alerts.
Notes: December fix [8]. New path [2]. Flaw [1]. Lockout and shutdown [1][2]. KEV [5][6]. Still vulnerable after the December patch [7].

## KEY FACTS | A critical score and a three-day clock

Stat: 9.8 | CVSS 3.1 base score (Fortinet)
Stat: 3 | Days KEV allowed to fix
Stat: 7 | Fortinet product lines affected
Stat: 2 | Malicious FortiCloud accounts
- Weakness: CWE-288, authentication bypass using an alternate path or channel.
- Precondition: FortiCloud SSO administrative login enabled on the target.
- FortiOS fixed in 7.0.19, 7.2.13, 7.4.11 and 7.6.6.
Notes: Score [1][3]. KEV [5]. Products [1]. Accounts [1]. CWE [1][4][5]. Precondition [1]. Fixes [1].

## PART 1 | Six weeks from one bypass to the next

| Date | Event |
|---|---|
| 9 Dec 2025 | FG-IR-25-647: crafted-SAML SSO bypass |
| 16 Dec 2025 | KEV adds CVE-2025-59718 |
| 15 Jan 2026 | Arctic Wolf sees a new SSO login cluster |
| 22 Jan 2026 | Fortinet blog: fully upgraded devices hit |
| 26 Jan 2026 | Fortinet disables FortiCloud SSO |
| 27 Jan 2026 | CVE published; SSO back for fixed versions; KEV |
| 30 Jan 2026 | Last release updates; KEV due date |
Caption: Rows Confirmed from Fortinet, CVE and KEV records; the 15 January row is Arctic Wolf's report.
Notes: December [8][5]. Arctic Wolf, Reported [9]. Blog [2]. Shutdown and restart [1]. CVE and KEV [1][3][4][5][6]. Updates [2].

## PART 1 | The record disagrees with itself

- Lockout: 22 January in the advisory, 23 January in the blog.
- The advisory timeline omits the 30 January update.
- KEV's description names four products; the advisory names seven.
- The blog first said all SAML SSO was affected, then corrected it.
- Two malicious accounts, but four login identities listed.
Caption: Both dates are Fortinet's own words; the study gives both.
Notes: Lockout [1][2]. Timeline [1][2]. Scope [1][4][5]. SAML correction [2]. Accounts [1].

## PART 2 | The flaw, at advisory level

- FortiCloud SSO lets an administrator log in with a FortiCloud identity.
- An attacker with a FortiCloud account and a registered device could use it on others' devices.
- Off by default, but GUI registration to FortiCare switches it on unless the toggle is cleared.
- Custom IdPs, FortiAuthenticator and the cloud-hosted managers are not affected.
Caption: No exploit detail is reproduced.
Notes: Mechanism [1]. Registration toggle [1]. Not affected [1][2]. December was CWE-347, a different weakness [8].

## PART 2 | Short, fast and quiet

Left: What the intruder did
- SSO login to an administrator account.
- Customer configuration file downloaded.
- A local administrator with a generic name, in almost all cases.
- VPN changes giving the new accounts access.
Right: The trail it left
- FortiOS admin login with method sso.
- Configuration download from the GUI.
- Creation of a system.admin object.
- Steps seconds apart, read as automation.
Caption: Confirmed from Fortinet and CISA, except the automation reading, which is Arctic Wolf's (Reported).
Notes: Actions [1][2][7]. Log events [2]. Automation, Reported [9].

## PART 3 | Nobody is named

| Question | What the record says |
|---|---|
| Actor | Two FortiCloud accounts; no group or nation |
| Infrastructure | Cloudflare-protected addresses; hosting providers |
| December likeness | Similar steps; not evidence of the same operator |
| Motive | Not stated; KEV ransomware use Unknown |
Caption: Similar post-login steps are not attribution (Inferred).
Notes: Actor [1][2]. Infrastructure [2], hosting providers Reported [9]. Likeness, Reported [9][10]. KEV [5].

## PART 4 | The vendor closed the door from the cloud

- Account lockout on 22 or 23 January.
- Service-wide FortiCloud SSO shutdown on 26 January.
- Restart on 27 January that refuses vulnerable versions.
- "A small number of customers" reported logins; no count, names or sectors.
- Siemens lists RUGGEDCOM APE1808 as affected; no industrial victim is described.
Caption: A floor of reports, not a census (Inferred).
Notes: Response [1][2]. Victims [2]. Siemens [11]. Readings Inferred.

## PART 5 | Configuration, not version, set the exposure

- A version inventory said which devices could be hit.
- Only the FortiCloud SSO setting said which were exposed.
- The December patch was correct and still left this path open.
- KEV's deadline fell on the day the last fixed builds shipped.
Caption: Watch the same feature after an exploited login bug is patched (Inferred).
Notes: Exposure [1]. December [7]. Clock [2][5]. Readings Inferred.

## DEFENDER VIEW | Patch, restrict, then hunt

Left: Fix and restrict
- Upgrade every affected product to a fixed release.
- Keep admin interfaces off the internet.
- Allowlist admin sources with local-in policies.
- Disabling FortiCloud SSO login remains harmless.
Right: Assume someone got in
- Review every administrator account, not only the listed names.
- Check VPN users and policy changes.
- Restore a known-clean configuration and rotate credentials.
- Reset hashes from any exported configuration.
Notes: Fix [1][2]. Hunting and recovery [1][2][7]. Offline cracking, Reported [9].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- The "unauthenticated" label: the attacker needed a FortiCloud account and a registered device.
- The blog's first claim that every SAML SSO setup was affected.
Right: Understated
- A December patch that left devices open.
- A registration step that switched the feature on.
- KEV's narrower product list.
- Scale: no count anywhere.
Notes: Overstated [1][2]. Understated [1][2][5][7]. Readings Inferred.

## MITRE MAPPINGS | Eight techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1585.003 | Cloud Accounts | Attacker-held FortiCloud accounts |
| T1190 | Exploit Public-Facing Application | SSO login bypass |
| T1602.002 | Network Device Configuration Dump | Configuration download |
| T1136.001 | Local Account | Generic local administrators |
| T1133 | External Remote Services | VPN access for new accounts |
| T1686.002 | Network Device Firewall | Firewall configuration changes |
Caption: ATT&CK v20.0; T1090 and T1119 are in the study's table and its Navigator layer. CWE-288, CWE-347, CAPEC-115, CAPEC-475.
Notes: Techniques [1][2][5][7][9] with library data [12]. No group, software or campaign is bound. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The login path is the attack surface

- **Same feature, twice.** Two critical SSO bypasses in seven weeks.
- **Vendors can act from the cloud.** Lockout and shutdown before many could patch.
- **Edge devices keep feeding KEV.** Three earlier Fortinet bypasses carry known ransomware use.
- **Configuration export is quiet theft.** No malware needed.
Notes: SSO bypasses [1][8]. Cloud response [1][2]. KEV lineage [5]. Configuration theft Inferred from [1][9].
