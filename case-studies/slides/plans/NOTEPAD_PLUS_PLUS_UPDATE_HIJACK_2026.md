# Slide plan: The Notepad++ Update-Channel Hijack (CVE-2025-15556): A Case Study

- Study: case-studies/NOTEPAD_PLUS_PLUS_UPDATE_HIJACK_2026.md
- Cover title: The Notepad++ / Update-Channel Hijack / CVE-2025-15556
- Subtitle: A hosting compromise, a selective redirect and an updater that did not check
- Published: 11 November 2026
- Notes: Slide plan for the deck of the study case-studies/NOTEPAD_PLUS_PLUS_UPDATE_HIJACK_2026.md, published 11 November 2026. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | The delivery path was hijacked, not the editor

- Notepad++ updates itself through a helper program, WinGUp.
- Attackers on its former shared host redirected chosen users' updates.
- Those users received a malicious installer for about six months in 2025.
- The editor's own code was not changed, the vendor says.
- The updater's missing check became CVE-2025-15556, now in KEV.
Caption: Evidence grade: the vendor statement and CVE record are Confirmed; the window is Reported.
Notes: Redirection [1]. Code not changed [1][2]. CVE [10]. KEV [13]. Window [1].

## KEY FACTS | A narrow campaign behind a KEV entry

Stat: 7.7 | CVSS v4.0, High (VulnCheck)
Stat: ~12 | Targeted machines, per Kaspersky
Stat: 6 mo | June to December 2025 window
Stat: 12 Feb | Added to the KEV catalog
- Affected: Notepad++ before 8.8.9, through WinGUp; CWE-494.
- Payloads: Cobalt Strike, Metasploit downloaders and the Chrysalis backdoor.
- Attribution: Lotus Blossom at moderate confidence (Rapid7 only).
Caption: CVE, CVSS and KEV are Confirmed; scale, payloads and attribution are Reported.
Notes: CVSS [11]. Scale [15]. Window [1]. KEV [13]. Affected [10][12]. Payloads [14][15]. Attribution [14].

## KEY FINDINGS | What the record supports

- The attack lived in the delivery path, at the hosting provider.
- The targeting was narrow: about a dozen machines in four countries.
- The fix arrived in three releases, from November 2025 to February 2026.
- Attribution is softer than the headlines: "likely", "moderate" or none.
- ATT&CK's Lotus Blossom entry draws no China link and no Notepad++ activity.
Caption: Grades: vendor and CVE facts Confirmed; research findings Reported.
Notes: Delivery path [1]. Targeting [15]. Fix [3][4][6]. Attribution [1][14][15]. ATT&CK [16].

## PART 1 | From the first redirect to a signed update feed

| Date | Event |
|---|---|
| June 2025 | Incident begins, per the vendor's estimate |
| 2 Sep 2025 | Provider says server access was lost |
| 18 Nov 2025 | v8.8.8 addresses a WinGUp hijacking issue |
| 2 Dec 2025 | Attacker credentials stop working |
| 9 Dec 2025 | v8.8.9 enforces installer signatures |
| 3 Feb 2026 | CVE published; Kaspersky report |
| 12 Feb 2026 | CISA adds the CVE to KEV |
| 16 Feb 2026 | v8.9.2 signs and verifies the update metadata |
Caption: Provider and expert dates are Reported; releases, CVE and KEV are Confirmed.
Notes: Start [1]. Server access [1]. v8.8.8 [3]. Credentials [1]. v8.8.9 [4]. CVE [10][11]; Kaspersky [15]. KEV [13]. v8.9.2 [6].

## PART 2 | The weakness and the delivered chains

Left: The weakness
- WinGUp did not verify update metadata or installers.
- Whoever steers update traffic can run an installer as the user.
- CVSS records high complexity: the path must be taken first.
Right: What was delivered
- Kaspersky: three chains, each an update file the updater launched.
- Metasploit and Lua-based loaders leading to Cobalt Strike.
- DLL sideloading through a renamed security tool to Chrysalis.
Caption: Advisory level only: technique names and ids, no indicators or payload detail.
Notes: Weakness [10][11]. Chains [14][15]. Sideloading host [14].

## PART 2 | The fix came in three steps

| Release | What changed |
|---|---|
| 8.8.8, 18 Nov 2025 | A potential WinGUp hijacking issue addressed |
| 8.8.9, 9 Dec 2025 | Installer certificate and signature enforced |
| 8.9.2, 16 Feb 2026 | Update XML signed and verified |
| 8.9.2, 16 Feb 2026 | Plugin manager runs only WinGUp-signed programs |
Caption: The CVE names 8.8.9 as fixed; the vendor hardened the channel again in 8.9.2.
Notes: 8.8.8 [3]. 8.8.9 [4][8][9]. 8.9.2 [6].

## PART 3 | Three sources, three different claims

| Who | What they say |
|---|---|
| The vendor | Likely a Chinese state-sponsored group |
| Rapid7 | Lotus Blossom, moderate confidence |
| Kaspersky | No actor; a technique Chinese-speaking actors use |
| ATT&CK G0030 | Targets in Asia; no China link, no Notepad++ |
Caption: No source states a motive; a few hand-picked victims fit espionage (Inferred).
Notes: Vendor [1][2]. Rapid7 [14]. Kaspersky [15]. ATT&CK [16][17].

## PART 4 | Victims and response

Left: Who was hit
- Individuals in Vietnam, El Salvador and Australia.
- A Philippine government organization.
- A financial firm in El Salvador.
- A Vietnamese IT service provider.
Right: Who did what
- The vendor moved hosts and signed the update XML.
- VulnCheck, as CNA, published the advisory on 2 February.
- CISA set a 5 March due date; ransomware use Unknown.
Caption: Victims are Kaspersky's count (Reported); the response records are Confirmed.
Notes: Victims [15]. Vendor [1][2]. VulnCheck [12]. KEV [13].

## DEFENDER VIEW | Inventory, disable, hunt

Left: Fleet actions
- Move every install to 8.9.2 or later, not just 8.8.9.
- Deploy the MSI with the auto-updater turned off.
- Ship updates through your own software distribution.
Right: Hunting
- Alert on unexpected child processes of the updater.
- Hunt published indicators over June to November 2025.
- Retro-hunt to at least September 2025, per Kaspersky.
Caption: SSVC says automatable no: urgent inventory for all, full hunts for targeted sectors.
Notes: Versions [1][6][10]. MSI guidance [2]. Hunting [14][15]. SSVC [10]. Prioritization is Inferred.

## WHAT IS OVERSTATED | And what is understated

Left: Overstated
- "Notepad++ hacked": the code was not changed.
- "Chinese state hackers" stated as fact.
- 8.8.9 treated as the complete fix.
Right: Understated
- The weakness predates its 2025 abuse.
- Attacker credentials outlived the first fix.
- Metadata signing became mandatory only in 2026.
Notes: Code [1][2]. Attribution [1][14][15][16]. Fix [6][10]. Predates [10]. Credentials [1][3]. Metadata signing [6].

## MITRE MAPPINGS | From a hijacked update to a backdoor

| Id | Technique | Tie to the record |
|---|---|---|
| T1195.002 | Compromise Software Supply Chain | Redirected updates (study's mapping) |
| T1204.002 | Malicious File | Update installer run after the updater |
| T1574.001 | DLL | Sideloading to Chrysalis |
| T1105 | Ingress Tool Transfer | Downloaders to Cobalt Strike |
| T1547.001 | Registry Run Keys / Startup Folder | Rapid7 list; Kaspersky hunt |
Caption: ATT&CK v20.0; 21 techniques in the layer. CWE-494; CAPEC-186, CAPEC-187.
Notes: T1195.002 [1][10]. T1204.002 [14][15]. T1574.001 [14][15]. T1105 [14][15]. T1547.001 [14][15]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use, https://attack.mitre.org/resources/legal-and-branding/terms-of-use/. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## CROSS-CUTTING THEMES | The most trusted code path

- **The update channel is the product's most trusted code path,** from SolarWinds to 3CX.
- **Hosting is part of the supply chain;** a shared host was enough here.
- **Sign the instructions as well as the package:** metadata, not only installers.
- **Small, selective and long** campaigns slip past mass-exploitation telemetry.
Notes: Lineage [20][21][22][23]. Hosting [1][2]. Metadata [1][6]. Scale [1][15]. The themes are Inferred from the record.
