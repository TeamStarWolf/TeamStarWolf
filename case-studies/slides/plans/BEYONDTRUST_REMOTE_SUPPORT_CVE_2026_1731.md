# Slide plan: The BeyondTrust Remote Support and PRA Command Injection of 2026 (CVE-2026-1731): A Case Study

- Study: case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md
- Cover title: The BeyondTrust Remote Support / and PRA Command Injection / of 2026 (CVE-2026-1731)
- Subtitle: A pre-authentication flaw in a remote-support tool, and why the update service decided who was hurt
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/BEYONDTRUST_REMOTE_SUPPORT_CVE_2026_1731.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Anyone who could reach the appliance could run commands

- In February 2026 BeyondTrust disclosed CVE-2026-1731 in Remote Support and older PRA.
- An unauthenticated attacker could run OS commands as the site user.
- SaaS tenants were patched on 2 February, four days before the advisory.
- The first exploitation attempt came on 10 February; KEV followed on 13 February.
- By August, AA25-071A listed the flaw among those Medusa exploits.
Caption: Evidence grade: Confirmed from the vendor advisory, the CVE and KEV records and the government advisory.
Notes: Disclosure and flaw [1][2]. SaaS patch [1]. First attempt [1]. KEV [5][6]. Medusa [17].

## KEY FACTS | A critical score and a three-day deadline

Stat: 9.9 | CNA CVSS v4.0 score
Stat: 9.8 | NVD CVSS v3.1 score
Stat: 3 | Days KEV allowed to fix
Stat: 6 | Threat clusters within a week (Google)
- Affected: RS 25.3.1 and earlier; PRA 24.3.4 and earlier.
- Fixed: RS 25.3.2 or later, PRA 25.1.1 or later (the advisory's table lists 25.1 and greater), or the BT26-02 patches.
- Weakness: CWE-78, OS command injection.
Notes: Scores [2][3]. KEV [5][6]. Clusters, Reported [15]. Versions [1][2]. CWE [2][6].

## PART 1 | Patched before the advisory, exploited after it

| Date (2026) | Event |
|---|---|
| 31 Jan | Anomalous activity on one appliance; Hacktron reports the flaw |
| 2 Feb | Patches pushed; SaaS fully patched |
| 6 Feb | Advisory BT26-02 and the CVE published |
| 10 Feb | First exploitation attempt BeyondTrust records |
| 11 Feb | Public proof of concept; reconnaissance surges |
| 13 Feb | KEV adds the CVE, due 16 Feb |
| 18 Aug | AA25-071A names Medusa |
Caption: Rows Confirmed from the vendor, CVE, KEV and government records; the 11 February surge is GreyNoise's report.
Notes: Vendor timeline [1]. CVE [2]. Hacktron [8][9]. Proof of concept [10][11]. KEV [5][6]. Medusa [17].

## PART 1 | This was a repeat

- CVE-2024-12356 was an unauthenticated command injection in the same products.
- It was found in BeyondTrust's 2024 SaaS investigation and entered KEV on 19 Dec 2024.
- Law enforcement tied that incident to China-nexus actors.
- GreyNoise calls the 2026 bug a variant; Hacktron found it through variant analysis.
Caption: A product with one KEV entry is worth hunting for siblings (Inferred).
Notes: Precedent [18][19][6]. Attribution of 2024 [18][20]. Variant, Reported [8][10][14].

## PART 2 | The flaw, at advisory level

- Specially crafted requests let an unauthenticated attacker run OS commands.
- CISA's SSVC record: exploitation active, automatable, total technical impact.
- Unit 42: earlier fixes added checks that did not cover every case.
- The 2024 and 2026 flaws sit in different code paths.
Caption: No exploit detail is reproduced; the public proof of concept is cited without a link.
Notes: Mechanism [2]. SSVC [2]. Code paths, Reported [14].

## PART 2 | What the attackers did after

Left: Arctic Wolf, 13 Feb
- Renamed SimpleHelp started by appliance processes.
- New accounts in Domain Admins and Enterprise Admins.
- Active Directory discovery, PsExec, Impacket SMB.
Right: Unit 42 and Google
- SparkRAT and VShell backdoors.
- AnyDesk installs and Cloudflare tunnels.
- PHP web shells and out-of-band DNS callbacks.
- Configuration files and a PostgreSQL dump staged; cryptominers.
Caption: All Reported by named research firms; Arctic Wolf calls its activity suspected exploitation.
Notes: Arctic Wolf [13]. Unit 42 [14]. Google [15].

## PART 3 | Medusa is named; no state actor is

| Name | Who says so | Standing |
|---|---|---|
| Medusa | FBI, CISA and HHS (AA25-071A) | Government advisory, no dated intrusion |
| Six clusters | Google | Unnamed |
| Silk Typhoon, APT27 | Unit 42, GreyNoise | The 2024 incident only |
Caption: No source opened attributes the 2026 exploitation to a state actor (Inferred).
Notes: Medusa [17]. Clusters, Reported [15]. Lineage [10][14][18][20][24].

## PART 4 | A limited number of customers, and no count

Stat: 16,400+ | Potentially vulnerable instances (Unit 42)
Stat: 11,000 | Internet-exposed RS instances (Hacktron)
Stat: 500+ | Medusa victims overall, April 2026
- BeyondTrust says it is supporting a limited number of self-hosted customers.
- Unit 42 lists finance, legal, technology, higher education, retail and healthcare.
- Medusa's total is not a count of victims reached through this CVE.
Notes: Exposure, Reported [8][14]. Medusa total [17]. Vendor statement [1]. Sectors, Reported [14]. Reading Inferred.

## PART 5 | The update service decided who was hurt

- Auto-updating appliances were patched eight days before the first attempt.
- Exploitation the vendor saw is limited to self-hosted instances not patched before 9 February.
- Most reconnaissance went to non-standard ports.
- The first cluster came four days after disclosure; KEV came after seven.
Caption: Count the clock from disclosure, not from the KEV listing (Inferred).
Notes: Auto-update and scope [1]. Ports, Reported [10]. Clusters [15]. KEV [6].

## DEFENDER VIEW | Patch, scope, then hunt

Left: Fix the appliance
- RS 25.3.2 or later, PRA 25.1.1 or later (the advisory's table lists 25.1 and greater), or BT26-02.
- Upgrade RS older than 21.3 and PRA older than 22.1 first.
- Keep the update service on.
- Patch CVE-2026-102764 too.
Right: Assume someone got in
- Treat any instance unpatched by 9 February as possibly compromised.
- Alert on admin-group changes and new domain accounts.
- Block unapproved remote-management tools.
- Watch for web shells and outbound DNS from the appliance.
Notes: Fix [1][6][16]. Scope [1][6]. Hunting, from the research firms' findings [13][14].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- A state actor behind the 2026 activity.
- Unit 42's alias chain for Silk Typhoon.
- An agent that found the flaw on its own.
- A KEV ransomware flag read as a named family.
Right: Understated
- A "limited number" beside 16,400 exposed instances.
- Six clusters in a week.
- A ransomware operation named by three agencies.
- Known incidents as a floor, not a count.
Notes: Overstated [14][24][15][1][6][17]. Understated [1][14][15][17]. Readings Inferred from the cited records.

## MITRE MAPPINGS | Sixteen techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Pre-authentication exploitation |
| T1136.002 | Domain Account | New domain accounts |
| T1098.007 | Additional Local or Domain Groups | Domain Admins additions |
| T1219.002 | Remote Desktop Software | SimpleHelp and AnyDesk |
| T1505.003 | Web Shell | PHP web shells |
| T1572 | Protocol Tunneling | Cloudflare tunnels |
Caption: ATT&CK v20.0; the other ten techniques are in the study's table and its Navigator layer. CWE-78, CAPEC-88, CAPEC-248.
Notes: Techniques [1][6][13][14][15][17] with library data [23]. Group G1051 Medusa Group; software S1244, S0029, S0357. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Remote-access tools are edge devices

- **Trusted paths inward.** A remote-support appliance faces out and reaches in.
- **Incomplete fixes come back.** The 2026 bug followed the 2024 one.
- **Discovery cuts both ways.** Variant analysis is open to attackers too.
- **Disclosures become deadlines.** Medusa uses new exploits within a day.
Notes: Edge pattern Inferred. Variants [10][14]. Discovery [1][15]. Medusa [17]. The lessons are Inferred.
