# Slide plan: The Dell RecoverPoint for Virtual Machines Hard-Coded Credential Zero-Day of 2026 (CVE-2026-22769): A Case Study

- Study: case-studies/DELL_RECOVERPOINT_CVE_2026_22769.md
- Cover title: The Dell RecoverPoint / Hard-Coded Credential / Zero-Day of 2026 (CVE-2026-22769)
- Subtitle: A shipped password on a replication appliance, used for about twenty months before the fix
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/DELL_RECOVERPOINT_CVE_2026_22769.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The bug was a password, not a code path

- RecoverPoint for VMs protects VMware workloads from deep inside the network.
- It shipped with a hard-coded credential that gave root-level persistence.
- GTIG dates the earliest exploitation it found to mid-2024.
- Dell's advisory and the CVE arrived on 17 February 2026.
- KEV added it the next day, with three days to fix.
Caption: Evidence grade: Confirmed from Dell, the CVE and KEV records; exploitation dates are GTIG's (Reported).
Notes: Flaw and impact [1]. Earliest exploitation [6]. Advisory and CVE [1][3]. KEV [5]. Twenty months is Inferred from the two dates.

## KEY FACTS | Every risk signal at its maximum

Stat: 10.0 | CVSS 3.1 base score
Stat: 3 | Days KEV allowed to fix
Stat: 20 | Months as a zero-day, roughly
Stat: 0 | Victim counts published
- Weakness: CWE-798, use of hard-coded credentials (CNA, NVD and KEV).
- SSVC: exploitation active, automatable yes, technical impact total.
- Fix: 6.0.3.1 HF1, or the remediation script in KB 000426742.
Notes: Score and CWE [3][4]. KEV [5]. SSVC [3][4]. Fix [1][2]. Months Inferred from [1][6]. No count in [1][6].

## PART 1 | Exploited long before anyone knew

| Date | Event |
|---|---|
| Mid-2024 | Earliest exploitation GTIG identifies |
| Sep 2025 | GRIMBOLT starts replacing BRICKSTORM |
| 4 Dec 2025 | CISA, NSA and Cyber Centre report AR25-338A |
| 11 Feb 2026 | AR25-338A adds Sample 12 |
| 17 Feb 2026 | Dell advisory, CVE, NVD and GTIG report |
| 18 Feb 2026 | KEV adds it, due 21 Feb |
| 18 Mar 2026 | Remediation script revised to version 2 |
| 16 Apr 2026 | ATT&CK creates S9015 BRICKSTORM |
Caption: Rows Confirmed from Dell, CISA, the CVE record and ATT&CK; the 2024 and 2025 rows are GTIG's (Reported).
Notes: Exploitation and GRIMBOLT [6]. AR25-338A [8]. Publication [1][3][4][6]. KEV [5]. Script [2]. ATT&CK [9].

## PART 1 | Where the record disagrees

- Dell does not name the component; GTIG names the Tomcat Manager admin user.
- "CVE-2026-22796" appears once in Dell's advisory, an apparent typo.
- One CVSS link on Dell's page points to a local vector, not the scored one.
- CISA's Sample 12 and GTIG's GRIMBOLT share one hash and two names.
Caption: The study does not reproduce the hash or any indicator value.
Notes: Component [1][2][6]. Typo and CVSS link [1][4], observed. Same hash [6][8]; the naming reading is Inferred.

## PART 2 | The flaw, at advisory level

- A credential built into every unit of the product.
- GTIG: it belonged to the Apache Tomcat Manager admin user.
- With it the actor deployed a WAR carrying the SLAYSTYLE web shell.
- Commands then ran as root on the appliance.
Caption: No credential value, request or exploit step is reproduced.
Notes: Dell's description [1]. Tomcat Manager, WAR and root commands [6], Reported. No memory-corruption chain needed (Inferred).

## PART 2 | From the appliance into VMware

Left: On the appliance
- SLAYSTYLE JSP web shell.
- BRICKSTORM backdoor, ATT&CK S9015.
- GRIMBOLT, a UPX-packed Native AOT backdoor.
- A modified rc.local boot script.
Right: Beyond the appliance
- "Ghost NICs" added to ESXi-hosted virtual machines.
- Pivots into internal and SaaS environments.
- iptables single packet authorization on vCenter.
- Hidden in layers endpoint agents rarely cover.
Caption: GTIG's intrusion record (Reported).
Notes: Families and persistence [6]. S9015 [9]. VMware moves [6]. Agent coverage is Inferred.

## PART 3 | A suspected cluster, not a named state actor

| Question | What the record says |
|---|---|
| Actor | UNC6201, suspected PRC-nexus (GTIG) |
| Overlap | Notable overlaps with UNC5221 |
| Same cluster? | GTIG says not currently |
| Dell | Names no actor |
| ATT&CK | No UNC6201 group; S9015 lists it as a user |
| Lineage only | G0125 HAFNIUM, C0029 Cutting Edge |
Caption: Calling this Silk Typhoon or HAFNIUM goes further than the discoverer does (Inferred).
Notes: Attribution [6], Reported. Dell [1]. ATT&CK objects [9][11]. Lineage reading Inferred.

## PART 4 | Limited, unnamed and still unmeasured

- Dell: "limited active exploitation" reported by Google and Mandiant.
- No victim count, sector or geography in any source.
- KEV marks ransomware use as Unknown.
- The script rotates the Tomcat admin credential and limits the Manager to localhost.
- Rerun the script on reimaged or newly added appliances.
Caption: The engagements GTIG describes are a floor, not a measure of reach (Inferred).
Notes: Victims [1][6]. KEV [5]. Script [2].

## PART 5 | The gap was the asset list, not the score

- Backup and replication appliances often sit outside scanner scope.
- They rarely carry an endpoint agent.
- This flaw sat next to vCenter with root access.
- CVSS, KEV and SSVC all said emergency.
Caption: Prioritization readings Inferred from Confirmed scores and deadlines.
Notes: Inventory gap Inferred. Scores and deadlines [3][4][5]. Lateral movement and persistence [6].

## DEFENDER VIEW | Patch, then hunt

Left: Fix and restrict
- Upgrade to 6.0.3.1 HF1 or run the KB 000426742 script.
- Rerun the script on reimaged and new appliances.
- Keep the appliance on a segmented, trusted network.
- Count replication appliances as tier-0 assets.
Right: Assume someone got in
- Review Tomcat Manager logs for deploy activity.
- Look for unexpected WAR files and cache artifacts.
- Check boot scripts against a known-good build.
- Audit ESXi guest interfaces and vCenter iptables rules.
Notes: Fix [1][2]. Hunt [6]. Tier-0 Inferred from [3][5].

## OVERSTATED AND UNDERSTATED | Both directions at once

Left: Overstated
- "Mass exploitation": Dell says limited.
- Silk Typhoon or HAFNIUM as the actor.
- Ransomware: KEV says Unknown.
Right: Understated
- About twenty months as a zero-day.
- Patching does not remove a boot-script implant.
- No victim count, so reach is unknown.
Notes: Overstated [1][5][6]. Understated [1][6]. Readings Inferred.

## MITRE MAPPINGS | Eight techniques, all the study's own reading

| Id | Technique | Tie to the record |
|---|---|---|
| T1078.001 | Default Accounts | Shipped Tomcat Manager credential |
| T1505.003 | Web Shell | SLAYSTYLE in a WAR |
| T1059.004 | Unix Shell | Root commands, GRIMBOLT shell |
| T1037.004 | RC Scripts | Modified rc.local boot script |
| T1105 | Ingress Tool Transfer | BRICKSTORM, then GRIMBOLT |
| T1027.002 | Software Packing | GRIMBOLT packed with UPX |
| T1205.001 | Port Knocking | Single packet authorization on vCenter |
| T1071.001 | Web Protocols | WebSocket indicator, inexact fit |
Caption: ATT&CK v20.0 with S9015 BRICKSTORM; CWE-798; CAPEC-70, CAPEC-191; layer in the study.
Notes: Techniques [1][5][6] with library data [11]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | Infrastructure appliances have no edge

- **Appliances defenders do not instrument.** BRICKSTORM's whole record lives there.
- **Shipped credentials outlive patch cycles.** One value served from 2024 to 2026.
- **Patch, then hunt.** KEV deadlines measure only the fix.
- **Attribution is overlapping clusters.** UNC6201 is not UNC5221 in the sources.
Notes: Appliances [6][7][8]. Credentials [1][6]. Hunt [6]. Clusters [6][11]. All readings Inferred.
