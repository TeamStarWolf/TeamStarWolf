# Slide plan: The cPanel and WHM Authentication Bypass of 2026 (CVE-2026-41940): A Case Study

- Study: case-studies/CPANEL_WHM_CVE_2026_41940.md
- Cover title: The cPanel and WHM / Authentication Bypass / of 2026 (CVE-2026-41940)
- Subtitle: A hosting control panel's login flow, a "session" fix, and ransomware within days
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/CPANEL_WHM_CVE_2026_41940.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Anyone who could reach the panel could skip the login

- On 28 April 2026 cPanel shipped an emergency fix for a login-flow flaw.
- An unauthenticated attacker could gain access to the control panel.
- Hosting providers reported exploitation before any fix existed.
- KEV added the flaw on 30 April with a three-day deadline.
- Mass exploitation dropped a Linux encryptor called "Sorry".
Caption: Evidence grade: Confirmed from the vendor advisory and the CVE and KEV records; exploitation before the fix and "Sorry" are Reported.
Notes: Fix and flaw [1][2]. Exploitation before the fix, Reported [12][13]. KEV [4][5]. Sorry, Reported [14].

## KEY FACTS | A critical score and a three-day deadline

Stat: 9.8 | CVSS 3.1 score (VulnCheck as CNA)
Stat: 9.3 | CVSS 4.0 score
Stat: 3 | Days KEV allowed to fix
Stat: 44,000+ | Compromised IPs, news citing Shadowserver
- Products: cPanel and WHM, including DNSOnly, and WP Squared.
- Affected: all versions after 11.40; eleven fixed builds across the tiers.
- Weakness: CWE-306, missing authentication for critical functionality.
Notes: Scores [2][3]. KEV [4]. Compromised IPs, Reported [14]. Products and versions [1][2]. CWE [2][3][4].

## PART 1 | Fixed under pressure, exploited within days

| Date (2026) | Event |
|---|---|
| 22 Apr | CVE-2026-41940 reserved |
| 28 Apr | Namecheap blocks panel ports; vendor advisory and fixes |
| 29 Apr | CVE published; CISA ADP grades exploitation active |
| 29 Apr | watchTowr analysis and proof of concept |
| 30 Apr | KEV adds the flaw, due 3 May |
| 1 May | Detection script replaced for false positives |
| 5 May | Patches for the 11.94 and 11.102 tiers |
Caption: Rows Confirmed from the vendor, CVE and KEV records; Namecheap's block is Reported.
Notes: Reservation and CVE [2]. Namecheap, Reported [12]. Advisory [1][7]. watchTowr [10]. KEV [4][5]. Script and tiers [1].

## PART 1 | The record disagrees with itself

- The advisory names 11.130.0.19; the 130 changelog shows the fix in 130.0.18.
- The advisory names 124.0.35; the 124 changelog lists no such build.
- The CVE datePublic is 28 April; Rapid7 says it was assigned on 29 April.
- KnownHost dates attempts to 23 February; Rapid7 calls that speculation.
Caption: Check the installed build against the changelog, not only the advisory (Inferred).
Notes: Builds [1][2][8]. Dates [2][11]. February claim, Reported [11][13].

## PART 2 | The flaw, at advisory level

- The CNA describes an authentication bypass in the login flow.
- watchTowr traced it to pre-authentication session files written without sanitising.
- The vendor's changelog line: a fix for "session loading and saving".
- CISA's SSVC record: exploitation active, automatable, total technical impact.
Caption: No exploit detail is reproduced; the public proof-of-concept repository is not linked.
Notes: CNA [2]. Mechanism, Demonstrated [10]. Changelog [7]. SSVC [2].

## PART 2 | Detection moved three times

- The vendor's script looks for injected authentication markers in session files.
- The first version produced false positives and was replaced on 1 May.
- It was refined again on 4 May.
- watchTowr published a detection artifact generator.
Caption: Results from the 29 April script are worth rerunning (Inferred).
Notes: Script [1]. watchTowr, Demonstrated [10].

## PART 3 | No actor is named

| Phase | Who | Standing |
|---|---|---|
| Exploitation before the fix | Unnamed | KnownHost, via news |
| "Sorry" ransomware | Unnamed; Tox contact only | BleepingComputer |
| GitHub Actions scanning | Unnamed | Socket |
| Hijacked repository cluster | Shai-Hulud descendant | JFrog, lineage only |
Caption: No ATT&CK group, campaign or software object covers the cPanel exploitation (Confirmed from the library data).
Notes: KnownHost [13]. Sorry [14]. Socket [15]. JFrog [16]. Library data [19].

## PART 3 | Hijacked CI became a scanner

- Malicious dev versions of 10 Packagist packages carried 583 workflow files.
- Workflows on GitHub-hosted runners scanned for and attempted the flaw.
- They also harvested credentials and secrets.
- JFrog ties a later cluster of 42 repositories to a Shai-Hulud descendant.
Caption: JFrog calls the npm-to-cPanel link operational rather than proven (Reported).
Notes: Packagist and workflows, Reported [15]. JFrog, Reported [16].

## PART 4 | One IP can be many tenants

Stat: 1.5M | Exposed instances, naive Shodan query
Stat: 44,000+ | Compromised IPs (Shadowserver, via news)
Stat: 70M+ | Domains behind cPanel (vendor figure, via watchTowr)
- No source opened gives a sector breakdown.
- One server hosts many customers' sites, so IP counts understate owners.
- KEV marks ransomware use as Known.
Notes: Exposure, Reported [11]. Compromised IPs, Reported [14]. Domains, Reported [10]. KEV [4]. Tenant reading Inferred.

## PART 4 | Hosting providers moved first

- Namecheap blocked ports 2083 and 2087 hours before the vendor bulletin.
- KnownHost reported exploitation on disclosure day.
- The advisory was revised on nine days through 11 May.
- KEV later added three more cPanel-ecosystem plugin flaws.
Caption: Hosting providers are first responders for their tenants (Inferred).
Notes: Namecheap, Reported [12]. KnownHost, Reported [13]. Advisory revisions [1]. Ecosystem KEV entries [4].

## DEFENDER VIEW | Patch, block, then assume compromise

Left: Fix the host
- Run a fixed build on every cPanel, WHM, DNSOnly and WP Squared host.
- Update pinned servers by hand; hard-restart cpsrvd.
- Where patching waits, block 2083, 2087, 2095 and 2096.
Right: Assume someone got in
- Treat any host reachable before the fix as possibly compromised.
- Rerun the current detection script.
- On any indicator, purge sessions and reset root and WHM passwords.
- Rebuild root-compromised servers rather than clean them.
Notes: Vendor guidance [1]. Port block [1][12]. Compromise reading Inferred from [13].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- 1.5 million exposed read as vulnerable.
- 6,100 workflow file matches read as victims.
- A 23 February start from one host.
- Downstream cPanel compromise from the GitHub cluster.
Right: Understated
- A changelog line that reads as a routine session fix.
- An advisory that never states exploitation.
- 44,000 IPs that each carry many tenants.
- Two tiers patched a week after disclosure.
Notes: Overstated [11][13][15][16]. Understated [1][4][7][14]. Readings Inferred from the cited records.

## MITRE MAPPINGS | Six techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1595.002 | Vulnerability Scanning | Workflows scan for the flaw |
| T1584.006 | Web Services | Hijacked repositories and runners |
| T1190 | Exploit Public-Facing Application | Login-flow exploitation |
| T1195.002 | Compromise Software Supply Chain | Packagist delivery |
| T1552 | Unsecured Credentials | Secrets harvested (inexact) |
| T1486 | Data Encrypted for Impact | "Sorry" encryptor |
Caption: ATT&CK v20.0; CWE-306; no CAPEC bound; Navigator layer in the study.
Notes: Techniques [2][4][5][13][14][15][16] with library data [19]. Software S9008 and S9043 named for lineage only. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Management planes are edge devices

- **Panels are the new file-transfer servers.** Zero-day, then mass exploitation.
- **Changelog wording is not severity.** Key triage on KEV and SSVC.
- **Hosts respond first.** Providers acted before the bulletin.
- **Worms carry exploits.** Hijacked CI scanned other people's servers.
Notes: Pattern Inferred from [1][4][7][10][12][13][15][16]. The lessons are Inferred.
