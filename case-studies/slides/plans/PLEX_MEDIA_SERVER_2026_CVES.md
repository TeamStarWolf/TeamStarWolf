# Slide plan: Plex Media Server, CVE-2026-96652, CVE-2026-96654, CVE-2026-96655 and CVE-2026-96656: The Plex2Shell Chain in the Lab

- Study: case-studies/PLEX_MEDIA_SERVER_2026_CVES.md
- Cover title: Plex Media Server / The Plex2Shell Chain / In the Lab
- Subtitle: Four modest bugs, one unauthenticated code-execution chain, and the checks that find it
- Published: 4 November 2026
- Notes: Slide plan for the deck of the study case-studies/PLEX_MEDIA_SERVER_2026_CVES.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Four flaws chain into code execution on a home media server

- Four Plex Media Server flaws, each Medium or High alone, chain into unauthenticated code execution.
- Plex shipped the fixed build, 1.43.3.10861, on 4 August 2026.
- The details went public on 16 October; a honeypot saw attacks the next morning.
- Compromised servers ran cryptocurrency miners and proxy software.
- CISA added all four CVEs to KEV on 20 October 2026.
Caption: Evidence grade: Confirmed for the flaws, fix and KEV listing; Reported for press accounts; Demonstrated for the lab.
Notes: The chain [9][12]. Fixed build [10]. Write-up and first sighting [12][14]. Payloads [9]. KEV [7]. Lab [38][39][40][41].

## KEY FACTS | Every build before 1.43.3.10861 is affected

Stat: 4 | CVEs in the chain, all in CISA KEV
Stat: 9.8 | The researcher's CVSS rating of the chain
Stat: 10 | Weeks from the fix to the public details
Stat: 1 | Day from the write-up to the first sighting
- Weaknesses: CWE-918 for -96652 and -96655, CWE-84 for -96654, CWE-73 for -96656.
- Individual scores: CVSS 3.1 4.3, 6.5, 4.3 and 7.2, assigned by CISA as the CNA.
- KEV due dates: 23 October for -96654 and -96656, 3 November for -96652 and -96655.
Notes: CVEs and CWEs [1][2][3][4][5]. Chain rating [12]. Ten weeks is date arithmetic from 4 August to 16 October [10][12]. First sighting [14]. KEV [7].

## PART 1 | How the four flaws chain

| Stage | What happens | CVE record |
|---|---|---|
| 1 | The server is made to send a forged request to itself | CVE-2026-96652 |
| 2 | A loopback-only plugin API trusts that request | CVE-2026-96654 |
| 3 | The server owner's token leaks to a lookalike host | Plex maps it to -96655 |
| 4 | Transcoder options write a file into the Codecs folder | CVE-2026-96656 |
| 5 | The transcoder loads the unsigned library | CVE-2026-96656 |
Caption: The primaries disagree on which CVE is which step; the study uses the CVE record wording, because CISA is the CNA.
Notes: Five stages from the researcher's write-up [12]. CVE wording [1][2][3][4]. Plex's table [9]. The disagreement is Confirmed [3][6][7][9][13].

## PART 2 | The version trap

- The advisory title says "v1.43.2 and earlier"; its first post asks for "1.43.3 or newer".
- 1.43.3.10828 is a 1.43.3 build and is still vulnerable.
- Every CVE record, the CISA advisory and Plex's October update put the fix at 1.43.3.10861.
- NVD's release-notes link points at the 1.43.3.10828 post, which lists no security fixes.
Caption: Read the version boundary from the CVE record, not the headline.
Notes: Advisory wording [9]. Fixed line [5][6][9]. NVD reference and release notes [10]. The vulnerable reading of 1.43.3.10828 is Inferred from the Confirmed records.

## PART 2 | From private report to KEV

| Date | Event |
|---|---|
| 27 Jul 2026 | The researcher reports the chain to Plex |
| 4 Aug 2026 | 1.43.3.10861 general release |
| 1 Sep 2026 | Plex announces the security update |
| 23 Sep 2026 | CVEs and CISA advisory VA-26-266-01 published |
| 16 Oct 2026 | The Plex2Shell write-up goes public |
| 17 Oct 2026 | First in-the-wild exploitation on a honeypot |
| 20 Oct 2026 | CISA adds all four CVEs to KEV |
Notes: Report [12]. Release [10]. Announcement [9]. CVEs and advisory [5][6]. Write-up [12]. Honeypot [14]. KEV [7].

## PART 3 | What attackers did with exposed servers

- Plex says the flaws were actively and widely exploited after the public proof of concept.
- Compromised servers ran cryptocurrency miners and proxy software.
- One honeypot saw a miner, a packed binary and the proxy tool myawesomeproxy downloaded.
- No source names a group, and KEV lists ransomware use as Unknown.
Caption: The honeypot indicators come from one honeypot only, and the operator says so.
Notes: Vendor account [9]. Honeypot [14]. Press, Reported [15][16][17]. Attribution and ransomware [7][9][14].

## PART 4 | The lab: matched pairs on loopback, no exploit step

Left: How the lab ran
- Official plexinc/pms-docker images in pairs, vulnerable beside 1.43.3.10861.
- Every port bound to 127.0.0.1; every server left unclaimed.
- No request reached any endpoint in the chain.
Right: What it showed
- The build number shows in /identity, the package database and the server log.
- A version gate on the package or the MediaContainer attribute tells 10828 from 10861.
- A fresh server has an empty Codecs folder and no transcoder override.
Caption: Lab of 4 November 2026 UTC. The chain itself was not reproduced.
Notes: Setup [38][39][40][41]. Version observables [38][40]. Baselines [39][41].

## PART 4 | Two traps the lab found

| Check | Lab result | Lesson |
|---|---|---|
| Host package check | No package found while two Plex servers ran | Inventory container images too |
| Version parse of /identity | Read the XML declaration, 1.0, and flagged the fixed build | Read only the MediaContainer attribute |
| docker logs | Showed no version | The banner is in Plex Media Server.log |
Caption: A version check is only as good as its parser: read the wrong attribute and a fixed host is flagged.
Notes: Package check [38]. Parser defect [38][39]. Log banner [40][41].

## DEFENDER VIEW | Find it and fix it

Left: Find
- Read the version in Plex Web, /identity, the package database or the image tag.
- Check container hosts for plexinc/pms-docker images, not only packages.
- Move Linux repository users to repo.plex.tv.
Right: Fix
- Update to 1.43.3.10861 or later and check the full build number.
- Turn Remote Access off where you do not need it.
- Do not forward port 32400 directly.
Caption: Any server older than 1.43.3.10861 that was reachable from the internet should be assumed possibly compromised.
Notes: Versions by platform [9][18][21][22]. Container gap [38]. Workaround [9][23]. Compromise guidance [9].

## DEFENDER VIEW | If the server was exposed

| Step | Action |
|---|---|
| Rebuild | Clean install, not the old data directory |
| Codecs | Delete its contents; new .so or .dll files are a finding |
| Preferences | Check for transcoder options you did not set |
| Account | Sign out all devices and change the Plex password |
| Hunt | Miner and proxy processes started by Plex; outbound to proxystream.st |
Caption: KEV flags CVE-2026-96656 for forensic triage: patching closes the door but does not clear what came through it.
Notes: Plex guidance and indicators [9]. Honeypot indicators [14]. KEV flag [7]. Clean baselines [39][41].

## PART 7 | Triage the chain, not the scores

- Three Mediums and one admin-only High add up to unauthenticated remote code execution.
- The fix date and the disclosure date are different clocks.
- Home media servers sit on networks that asset inventories may never list.
- Overstated: one honeypot's indicators. Understated: the chain's severity and the affected range.
Notes: Scores [1][2][3][4]; chain [12]; KEV chaining note [7]. Dates [10][14]. The inventory and the overstated and understated reading are Inferred from [7][9][14][17][38].

## MITRE MAPPINGS | Seven techniques from the verified record

| Id | Technique | Tie to the Plex2Shell record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Unauthenticated chain on exposed servers |
| T1528 | Steal Application Access Token | The server owner's token leaks |
| T1129 | Shared Modules | Every .so in Codecs loads at startup |
| T1105 | Ingress Tool Transfer | Attacker files and payloads fetched |
| T1496.001 | Compute Hijacking | Cryptocurrency miners |
| T1496.002 | Bandwidth Hijacking | Proxyware |
| T1059.004 | Unix Shell | Shell script fetching a miner, Reported |
Caption: ATT&CK v20.0. CWE-918, CWE-84 and CWE-73; CAPEC-664 and CAPEC-76; no group, software or campaign is bound. MITRE notice in the notes.
Notes: Techniques [4][9][12][14][17][24][25][26][27][28][30]. CWE and CAPEC [31][32][33][34][35]. D3FEND [36][37]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | What the chain teaches

- **Chains beat scores.** Four moderate CVEs became one unauthenticated code execution.
- **Loopback is not a trust boundary.** "Came from localhost" is not "came from me".
- **A plugin folder is a code path.** Monitor it like the application binary.
- **Advisory wording is part of the fix.** Read the version boundary from the CVE record.
- **Lab plans are hypotheses.** Writing the expectation down is how both lab corrections surfaced.
Notes: Chain [7][12]. Loopback pivot [12]. Unsigned load [4][12]. Advisory wording [9][10]. Lab corrections [38][41]. Lessons are Inferred.
