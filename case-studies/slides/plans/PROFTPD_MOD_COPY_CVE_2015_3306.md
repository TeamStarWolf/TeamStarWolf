# Slide plan: ProFTPD mod_copy, CVE-2015-3306: Unauthenticated File Copy in the Lab

- Study: case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md
- Cover title: ProFTPD mod_copy, CVE-2015-3306 / Unauthenticated File Copy / in the Lab
- Subtitle: A same-day fix in 2015, a three-day KEV deadline in 2026, and logs that saw nothing
- Published: 4 November 2026
- Notes: Slide plan for the deck of the study case-studies/PROFTPD_MOD_COPY_CVE_2015_3306.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | An optional FTP module copied any file for anyone, before login

- ProFTPD's optional mod_copy module answered SITE CPFR and SITE CPTO before the client had logged in.
- Anyone who reached the FTP port could copy any file the daemon could read to any place it could write, with no account.
- The fix was merged on 7 April 2015, the day Bug 4169 was filed, and shipped in ProFTPD 1.3.5a on 27 May 2015.
- On 8 October 2026 CISA added it to KEV with a three-day due date, the day joint advisory AA26-281A listed it as successfully exploited.
- In the lab of 4 November 2026 the vulnerable build copied a file without login; the fixed build answered 530.
Caption: Evidence grade: Confirmed for the flaw, the fix and the KEV listing; Demonstrated for the exploits and the lab.
Notes: mod_copy and the two SITE commands [1][10]. Unauthenticated copy [3][4][6]. Fix date and 1.3.5a [3][4][5][8]. KEV add and due date [22][23]. AA26-281A [24]. Lab results [36].

## KEY FACTS | Every severity signal points the same way, eleven years on

Stat: 10.0 | NVD CVSS v2 base score, no login needed
Stat: 3 days | KEV due date after the 8 October 2026 add
Stat: 12 min | From Bug 4169 being filed to the fix being merged
Stat: 530 | The fixed build's reply to SITE CPFR before login
- Class: missing authentication on SITE CPFR and SITE CPTO; CWE-284 Improper Access Control.
- CVSS v3.1 10.0 Critical comes from the CISA ADP container, not from NVD; SSVC: active, automatable, total.
- Vendor ratings disagree: Ubuntu rates it Medium, SUSE rates it critical.
Notes: CVSS v2 and the ADP v3.1 score [1]. SSVC of 9 October 2026 [1]. KEV due date 11 October 2026 [22]. Filed 16:35, merged 16:47 on 7 April 2015 [3][5]. The 530 reply [36]. CWE-284 [1][2][22][24]. Vendor ratings [18][19].

## PART 1 | The module checked login for one command and forgot the other two

- mod_copy adds SITE COPY and the two-step pair SITE CPFR ("copy from") and SITE CPTO ("copy to").
- The copy runs inside the daemon, so it reaches whatever the daemon's runtime user can read and write.
- In the pre-fix source SITE COPY required a login, but the CPFR and CPTO handlers did not.
- The fix commit says the module "inadvertently allows unauthenticated copying" and had no Engine directive to switch it off.
- The vendor says mod_copy is not compiled by default, so exposure depends on how each ProFTPD was built.
Caption: Read follows because a file can be copied somewhere reachable; write follows because the destination is the attacker's choice (Inferred).
Notes: SITE commands [1][10]; the 350 reply [36]. Runtime-user reach [16][36]. Pre-fix handlers [6]. Fix commit message [4]. Not compiled by default and the build options [10]. Read and write reasoning, Inferred [1].

## PART 1 | The fix added a login check and an off switch

| Change | Effect |
|---|---|
| Login check | CPFR and CPTO answer 530 to a session that has not logged in |
| CopyEngine on or off | The module can be disabled at runtime without recompiling |
| Module version | mod_copy/0.4 becomes mod_copy/0.5 |
| Regression tests | The commands are sent without logging in |
| Releases | ProFTPD 1.3.5a (27 May 2015) and 1.3.6rc1 |
Caption: The documented code-execution path copies a PHP payload into a web root (Reported, Metasploit); the lab did not run it.
Notes: Fix commit and merge [4][5]. 1.3.5a NEWS lists Bug 4169 [8]. CopyEngine and the 530 check in the 1.3.5a source [9][10]. Metasploit description of the /proc/self/cmdline path, run as nobody by default [16]. Bug 4169's web-root PHP example [3].

## PART 2 | The fix took minutes; public exploits took six days

| Date | Event |
|---|---|
| 7 Apr 2015, 16:35 | Bug 4169 filed, reporting Vadim Melihow's finding |
| 7 Apr 2015, 16:47 | PR #109 merged; backported to the 1.3.5 branch by 16:55 |
| 13 Apr 2015 | Exploit-DB 36742, "ProFTPd 1.3.5 File Copy" |
| 15 Apr 2015 | CVE reserved; oss-security disclosure notes no fixed release yet |
| 21 to 22 Apr 2015 | Exploit-DB 36803 command execution; Metasploit module |
| 27 May 2015 | ProFTPD 1.3.5a released with the fix |
| 19 Jul 2019 | Related flaw CVE-2019-12815 published (mod_copy up to 1.3.5b) |
| 8 Oct 2026 | KEV add, due 11 October; AA26-281A released |
Notes: Bug and merge times [3][5]. Exploit-DB [14][15]. CVE reservation and oss-security [2][3][13]. Metasploit disclosure date, Reported [16]. 1.3.5a [8]. CVE-2019-12815 [20]. KEV and AA26-281A [22][23][24]. Intervals are the study's arithmetic on the dated rows.

## PART 3 | A 2026 advisory put an eleven-year-old CVE back on the desk

Left: The KEV listing
- Added 8 October 2026 as "ProFTPD Improper Access Control Vulnerability".
- Due 11 October 2026; known ransomware use Unknown.
- Forensic triage required per BOD 26-04.
Right: Joint advisory AA26-281A
- Released the same day by ten agencies in seven countries.
- Lists CVE-2015-3306 in Appendix B Table 16, "Successfully Exploited CVEs", as type "Unauthorized read".
- Ties the actors to Integrity Technology Group, consistent with Flax Typhoon, Ethereal Panda and Red Juliett.
Caption: ATT&CK has no group object for Flax Typhoon, so the study binds no ATT&CK group id.
Notes: KEV JSON feed, catalog version 2026.11.03, and catalog page [22][23]. The directive's text was not opened. AA26-281A authors, Table 16 and attribution [24]. No ATT&CK group object; G1007 is Aoqin Dragon [25].

## PART 3 | "Successfully exploited" came from scripts, not intrusions

- AA26-281A says the Table 16 CVEs were recovered from penetration-testing scripts in a tool it calls MicroScan.
- MicroScan has been used since as early as 2017 and holds over 1,300 scripts.
- The advisory dates no ProFTPD intrusion, names no ProFTPD victim and gives no host count.
- It says the actors scan ports 21, 22, 53, 80, 443 and 1080 and use dirsearch to enumerate PHP and ASP pages.
- An FTP server plus PHP pages on one host is the pairing the code-execution path needs; the advisory does not draw that link.
Caption: A strong reason to patch; a weak basis for claiming any specific intrusion (Inferred).
Notes: MicroScan, the script count and the absence of a dated intrusion [24]. Scanning ports and dirsearch, tagged T1595.002 [24]. The FTP and PHP pairing is the study's inference [16][24]. No other campaign report found; KEV ransomware field Unknown [22]. Newsletter tying KEV to the advisory, Reported [26].

## PART 4 | Two builds, one banner: only the reply code told them apart

Left: What looked identical
- Both builds greeted with 220 ProFTPD 1.3.6rc1 Server.
- proftpd -V printed 1.3.6rc1 (git) for both, with --with-modules=mod_copy.
- The build times differed by 35 seconds.
- The pre-fix commit already set the version text to 1.3.6rc1.
Right: What separated them
- SITE CPFR alone, without login and without CPTO, copies nothing.
- Vulnerable build: 350 File or directory exists, ready for destination name.
- Fixed build: 530 Please login with USER and PASS.
Caption: Lab of 4 November 2026: VulnCheck images on 127.0.0.1:2121 and 2122, loopback only, removed afterwards.
Notes: Setup, ports and digests [36] 01-setup.txt. Banner and proftpd -V [36] 02-test.txt and 03-exposure.txt. version.h at the pre-fix commit [7][5]. The read-only probe and both replies [36] 02-test.txt.

## PART 4 | The copy worked, and the default logs recorded nothing

Stat: 250 | "Copy successful" from the vulnerable build, without login
Stat: 13 bytes | Marker file written as nobody:nogroup
Stat: 0 | Lines about SITE CPFR, SITE CPTO or the copy in the default logs
- The vulnerable build copied /etc/hostname to a marker under /tmp; the fixed build answered 530 to both commands.
- docker logs showed only startup, mod_delay, session-open and session-close lines; /var/log/proftpd was empty.
- dpkg -l returned no packages, because the daemon was a source build under /usr/local.
- The fixed build still had mod_copy compiled in with no limit block: the refusal came from the code, not the configuration.
Notes: Copy replies and the marker file [36] 02-test.txt and 04-mitigation.txt. Default logs [36] 02-test.txt. dpkg and the source build [36] 03-exposure.txt. Mitigation finding; the configuration workarounds were not tested [36] 04-mitigation.txt.

## DEFENDER VIEW | Start from listeners, then trust behaviour over banners

Left: Find ProFTPD, including source builds
- Start from hosts listening on TCP 21 or running proftpd, not from the package inventory.
- proftpd -V shows the configure line; proftpd -l lists compiled-in modules.
- Search the configuration for mod_copy, SITE_CPFR and SITE_CPTO; DSO builds load the module there.
Right: Decide whether it is vulnerable
- Compare the vendor package version with the fixed versions; backports keep old version strings.
- On a host you are authorised to test, send SITE CPFR alone: 350 means open, 530 means closed.
- The nuclei template matches on "Copy successful", so it performs a real copy.
Caption: A host where proftpd -l does not list mod_copy and no configuration loads it is not exposed to this CVE.
Notes: Listener-first inventory and the commands, all run in the lab [36]. Build options [10]. Backports and the lab banner, Inferred [17][18][36]. The probe [36]. nuclei template [28]. Scoping rule, Inferred [10].

## DEFENDER VIEW | Upgrade to the vendor fix, and go past 1.3.5a

| Platform | Fixed in |
|---|---|
| Upstream source | 1.3.5a and 1.3.6rc1; prefer a current release (1.3.9e or 1.3.10rc5 on 4 Nov 2026) |
| Debian 7 and 8 | 1.3.4a-5+deb7u3 and 1.3.5-1.1+deb8u1 (DSA-3263-1) |
| Debian 12, 13, forky, sid | Fixed since 1.3.5-2 in unstable |
| Ubuntu 14.04 | 1.3.5~rc3-2.1ubuntu2.1 |
| SLES 15 SP7 | proftpd 1.3.8b-150600.13.6.1 |
| openSUSE Tumbleweed | proftpd 1.3.5b-2.5 |
Caption: CVE-2019-12815 reaches mod_copy up to 1.3.5b, so a host that stopped at 1.3.5a is still in scope. Restart the service.
Notes: Upstream and current releases [3][8][27]. Debian [17]. Ubuntu, including 12.04 and 15.04 rows in the study [18]. SUSE and openSUSE [19]. Fedora fixed versions not checked [1]. CVE-2019-12815, CVSS v3.1 9.8, CWE-755 [20].

## DEFENDER VIEW | No rule ships for this, so build the detection yourself

Left: Bridges if you cannot upgrade
- CopyEngine off disables the module on 1.3.5a and later; it does not exist on a pre-fix build.
- A Limit block denying SITE_CPFR, SITE_CPTO and SITE_COPY follows from the vendor naming; untested.
- Rebuilding without mod_copy is the only bridge that does not rely on the vulnerable code.
Right: Detect and hunt
- Alert on SITE CPFR or CPTO before a 230 login reply, and on 350 or 250 Copy successful to an unauthenticated session.
- The Emerging Threats Suricata 7.0.3 ruleset has no CPFR or CVE-2015-3306 rule.
- Hunt for files owned by the FTP runtime user in web roots and /tmp.
Caption: The KEV listing flags forensic triage: treat an exposed ProFTPD with mod_copy as a host to examine.
Notes: CopyEngine [4][9][10]. Limit naming [10][11][12], untested in the lab [36]. Module removal, Inferred [10]. Rule design, Inferred and untested [36]. Emerging Threats ruleset [29]. File hunting, Inferred [16][36]. Forensic triage [22].

## MITRE MAPPINGS | Two techniques shown in the lab, two more from the record

| Id | Technique | Tie to CVE-2015-3306 |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated client abuses the FTP daemon; Demonstrated in the lab |
| T1005 | Data from Local System | The arbitrary read; the lab copy of /etc/hostname |
| T1505.003 | Server Software Component: Web Shell | The documented PHP path; not demonstrated |
| T1595.002 | Active Scanning: Vulnerability Scanning | AA26-281A actor scanning; tie to ProFTPD Inferred |
Caption: The study's own mappings to ATT&CK v20.0; CWE-284, CAPEC-650 and CAPEC-563. MITRE notice in the notes.
Notes: No opened source names a technique for this CVE [1][22][24]. Rows [1][3][14][16][22][24][30][31][32][36]. Layer scores 100, 100, 75 and 40. CWE [1][2][33]; CAPEC [34][37]; D3FEND [35][37]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Age is not safety, and version strings are not fixes

- **Age is not safety.** An eleven-year-old CVE with a same-day fix entered KEV in 2026 with a three-day due date.
- **Version strings describe lineage, not fixes.** Behaviour and the vendor package version are the only reliable answers.
- **Optional modules are where exposure hides.** Inventory by what is compiled and loaded, not by product name.
- **Detection has to be designed.** Default logs and the open ruleset had nothing; the nuclei template performs a real copy.
- **Close the module, not the ticket.** CVE-2019-12815 hit the same module four years later.
Notes: KEV [22]. Banner finding [36]; backports [17][18]. Not compiled by default [10]. Logs [36], ruleset [29], nuclei [28]. CVE-2019-12815 [20]. The exploited-has-a-source theme [24].
