# Slide plan: Operation Exchange Marauder and the 2021 Exchange Server Mass Exploitation

- Study: case-studies/EXCHANGE_MARAUDER_2021.md
- Cover title: Operation Exchange Marauder / The 2021 Exchange Server / Mass Exploitation
- Subtitle: One request made the mail server vouch for the attacker, and the patch was only the start
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/EXCHANGE_MARAUDER_2021.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Attackers were inside Exchange before the vendor knew

- **One request, the server's own identity.** ProxyLogon's SSRF let an attacker act as the Exchange server itself.
- **Exploitation came first.** Volexity saw mailbox theft on 3 January 2021, two days before DEVCORE's report.
- **The patch widened the field.** More than ten espionage groups, then ransomware crews and miners, piled on.
- **Patched did not mean clean.** Web shells planted before 2 March survived the update.
- **The same surface kept giving:** ProxyShell was used for ransomware by August 2021.
Caption: Grades: fixes, directives and attributions Confirmed; exploit mechanics Demonstrated; relayed victim counts Reported.
Notes: SSRF and the chain [1][24]. Volexity [22]; DEVCORE report on 5 January [23]. More than ten groups [31]; widening after 2 March [1]. Responder guidance [8]. ProxyShell [13][14][52][42].

## KEY FACTS | Three of the four bugs scored 7.8 and still made a pre-auth RCE

Stat: 58 days | first observed exploitation to the fix
Stat: ~400,000 | Exchange servers in scope on 1 March
Stat: 7.8 | NVD score of three of the four CVEs
Stat: 12,700+ | US victims, the FBI's figure
- CVE-2021-26855 is the pre-auth SSRF, scored 9.8 by NVD and 9.1 by Microsoft.
- Out-of-band fixes shipped on 2 March 2021; Exchange Online was not affected.
- All four CVEs entered KEV on 2021-11-03 with known ransomware campaign use.
Notes: The 58-day window is Inferred from [22][3]. RiskIQ via Microsoft [6]. Scores [57][58][59]. FBI, quoted by DOJ in 2025 [64]. Fix [3][4]. KEV [57][56].

## PART 1 | The front end vouched for the attacker with its own ticket

- **CVE-2021-26855.** A cookie in OwaResourceProxyRequestHandler sent attacker requests to the back end with Exchange's authentication.
- **CVE-2021-27065 and CVE-2021-26858.** Post-auth file writes put code in the web root.
- **CVE-2021-26857.** Deserialization in Unified Messaging gave code execution as SYSTEM.
- **The SSRF alone was enough for espionage.** Mail was read through EWS, bypassing two-factor authentication.
Caption: Microsoft: restricting untrusted connections to port 443 protects only the first step of the chain.
Notes: Mechanics Demonstrated by DEVCORE [24]. Microsoft's description [1]. CISA's one-line chain summary [50]. Mailbox theft needed only the domain SID or an email address [22]. Port 443 [4].

## PART 1 | The same attack surface produced three more chains in 2021

| Chain | CVEs | Fixed | What stands out |
|---|---|---|---|
| ProxyLogon | 26855, 26857, 26858, 27065 | 2 Mar 2021 | Exploited before the fix |
| ProxyShell | 34473, 34523 | Apr 2021 | Published only on 13 Jul |
| ProxyShell | 31207 | May 2021 | Rated Moderate by Microsoft |
| ProxyToken | 33766 | Apr 2021 | Forwarding rule on any mailbox |
| ProxyOracle | 31195, 31196 | May, Jul 2021 | Password after one click |
Caption: DEVCORE counts eight bugs on the Client Access Service attack surface and more than 400,000 exposed servers.
Notes: ProxyLogon [3][1]. ProxyShell, shown at Pwn2Own on 6 April [27][28][13][14]. ProxyToken, with ZDI's differing July date [15][29]. ProxyOracle [25][16]. DEVCORE survey [26]. CVE numbers are CVE-2021-.

## PART 2 | Exploitation ran two months ahead of the patch

| Date | Event |
|---|---|
| 10 Dec 2020 | DEVCORE finds the pre-auth proxy bug |
| 3 Jan 2021 | Earliest SSRF mailbox theft Volexity observed |
| 5 Jan 2021 | DEVCORE reports the chain to Microsoft |
| 28 Feb 2021 | ESET sees Tick exploiting Exchange |
| 2 Mar 2021 | Out-of-band fixes; Microsoft names HAFNIUM |
| 3 Mar 2021 | CISA issues ED 21-02 and AA21-062A |
| 9 Mar 2021 | First DearCry ransom notes surface |
| 13 Apr 2021 | The FBI's web shell removal filing is unsealed |
| 19 Jul 2021 | US, UK, EU, NATO and Canada statements |
Notes: DEVCORE [23]. Volexity, revised from 6 January [22]. ESET [31]. Fixes and HAFNIUM [3][1]. CISA [51][50]. DearCry [33]. FBI [63]. Statements [66][67][69][70][71].

## PART 3 | HAFNIUM opened the door and more than ten groups followed

Left: HAFNIUM, now Silk Typhoon
- Leased US VPS; targets included disease researchers and law firms.
- ASPX web shells, Procdump on LSASS, 7-Zip staging.
- Exchange PowerShell snap-ins to export mailboxes.
- Microsoft: high confidence, state-sponsored, from China.
Right: The crowd ESET counted
- Tick on 28 February, before the patch.
- LuckyMouse, Calypso and Websiic on 1 March.
- Winnti Group hours before the fix on 2 March.
- Web shells on 5,000+ servers in 115+ countries by 10 March.
Notes: HAFNIUM [1][11]; ATT&CK G0125 [72]. ESET actors and counts, called incomplete [31]. Mandiant's three uncategorized clusters [30]. Red Canary saw no significant overlap with HAFNIUM [35].

## PART 3 | Ransomware and miners arrived within a week of the fix

- **DearCry (DoejoCrypt).** Microsoft's first ransomware seen on the bugs; ransom notes from about 9 March.
- **Black Kingdom (Pydomer).** Web shells on about 1,500 systems, mainly 18 to 20 March.
- **Lemon Duck** removed rival web shells and patched one server to keep it for itself.
- **ProxyShell era.** LockFile, a Conti affiliate and Babuk followed from July to October 2021.
Caption: The Conti affiliate went from ProxyShell entry to ransomware on day five, exfiltrating just under 1 TB.
Notes: DearCry [10][36][33]. Black Kingdom [37][10]. Lemon Duck [10][40]. LockFile [42]. Conti affiliate [39]. Tortilla and Babuk [41]. KEV known ransomware use [56].

## PART 4 | Attribution hardened from vendor naming to an extradition

| Party | Said about Exchange | Confidence |
|---|---|---|
| Microsoft, 2 Mar 2021 | HAFNIUM, state-sponsored | "high confidence" |
| United States, 19 Jul | MSS-affiliated operators | "high degree of confidence" |
| United Kingdom, 19 Jul | Chinese state-backed actor | "almost certain" |
| Canada, 19 Jul | The MSS is responsible | "confident" |
| EU and NATO, 19 Jul | No attribution of their own | None |
| DOJ, Jul 2025 | Two men, Shanghai State Security Bureau | Allegation |
Caption: Xu Zewei, arrested in Milan, appeared in US District Court in Houston on 27 April 2026; charges are not findings of guilt.
Notes: Microsoft [1]. White House [66]. UK [67]. Canada [71]. EU [69]; NATO [70]. DOJ indictment [64]; court appearance [65]. China rejected the attribution (Reported) [49].

## PART 4 | The victim counts measure different things

| Figure | Who counts | What it measures |
|---|---|---|
| Nearly 400,000 | Microsoft citing RiskIQ | Servers in scope, 1 Mar |
| 79,352 | Shadowserver | Web shell URLs, 16 to 23 Mar |
| At least 30,000 | KrebsOnSecurity (Reported) | US organizations hacked |
| Over a quarter million | UK government | Servers affected worldwide |
| 12,700+ | FBI, quoted by DOJ | US entities victimized |
Caption: None is a total of compromised organizations, so they should not be added or compared (Inferred).
Notes: RiskIQ [6]. Shadowserver [44]. KrebsOnSecurity [46]. UK [67]. FBI, over 60,000 targeted [64]. The reading is Inferred.

## PART 5 | Exposure, not score, set the priority

Left: Why scores misled
- Three 7.8 post-auth bugs sat behind a 9.8 pre-auth SSRF.
- On port 443 that chain was an unauthenticated RCE.
- ProxyShell's last link was rated Moderate and 6.6.
- KEV's 2021-11-03 date is its launch day, not exploitation.
Right: Why patching lagged
- The March fixes installed only on specific CUs.
- Older-CU SUs covered only the four CVEs.
- EOMT and Defender mitigated the first link alone.
- By 25 March, 92%+ of known IPs patched or mitigated.
Notes: Scores [58][1][57]; the exposure reading is Inferred. ProxyShell [14][60]. KEV dates [56][57]. Supported CUs [5][3][4]. Mitigations [7][9]. Patch or mitigation rate [10]; the two-clocks reading is Inferred.

## PART 5 | A patched server could still hold a web shell

Stat: 79,352 | web shell URLs found 16 to 23 March
Stat: 101,045 | hostnames behind 86,138 vulnerable IPs
Stat: 14 days | of remote access the FBI sought to delete shells
- Microsoft: the updates do not evict an adversary already on the server.
- ED 21-02 required forensic triage; compromised servers stayed off the domain until rebuilt.
- CISA said to look back to at least 1 January 2021 and assume identity compromise if exploited.
Notes: Shadowserver, honeypots excluded [44]. FBI filing, Case No. 4:21mj755 [63]. Responder guidance [8]. ED 21-02 [51]. AA21-062A [50].

## MITRE MAPPINGS | 44 techniques, with T1190 and web shells at the core

| Id | Technique | 2021 use |
|---|---|---|
| T1190 | Exploit Public-Facing Application | ProxyLogon from 3 Jan; ProxyShell |
| T1505.003 | Web Shell | SIMPLESEESHARP, China Chopper, ASPXSPY |
| T1114.002 | Remote Email Collection | EWS mailbox theft through the SSRF |
| T1003.001 | LSASS Memory | Procdump; comsvcs.dll MiniDump |
| T1003.003 | NTDS | NTDS.DIT copied |
| T1486 | Data Encrypted for Impact | DearCry, Black Kingdom; AA21-321A |
Caption: ATT&CK v20.0: group G0125 HAFNIUM, no campaign object for the event. MITRE notice in the notes.
Notes: Rows [22][30][72][54][1][10][36][37]. Technique count from the study's Part 7 tables and its Navigator layer. CWE-918, CWE-502, CWE-22 and CWE-434 [57][58][59][60]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Hunt for the shell even on a patched server

Left: What to look for
- HttpProxy logs with an empty AuthenticatedUser.
- ECP lines matching Set-OabVirtualDirectory.
- Unexpected .aspx files under aspnet_client.
- w3wp.exe spawning cmd.exe.
Right: How to remediate
- Run Test-ProxyLogon and look back to 1 January 2021.
- Preserve evidence, disconnect, remove the ASPX files.
- Update, then reset administrator credentials.
- Stay on a supported CU to stay patchable.
Caption: Volexity found the activity through large outbound transfers from two customer Exchange servers.
Notes: Indicators [1][22][50][30]. Triage [50]. Remediation steps [8]. Supported CUs and Emergency Mitigation [5][19]. Volexity [22]; egress as a signal is Inferred.

## CROSS-CUTTING THEMES | A fix is a map for the next attacker

- **The edge server is the identity system.** Exchange vouched for requests with the machine account's own ticket.
- **Disclosure does not start the clock.** Exploitation preceded the report to the vendor by two days.
- **Interim mitigations are partial by design;** EOMT-only servers were not protected against ProxyShell.
- **Research keeps paying out:** eight bugs on one surface became three named chains in a year.
- **Overstated: one actor.** HAFNIUM fits the zero-day phase; ESET, Mandiant and Red Canary saw many others.
Notes: Identity [24][22]. Disclosure [22][23][31]. Mitigations [7][9][17]. DEVCORE [26]. One actor [31][30][35]. The general lessons are Inferred.
