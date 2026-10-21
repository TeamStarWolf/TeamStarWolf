# ATT&CK Software Reference

<!-- local-id-links (written by scripts/build_crosslinks.py from docs/crosslinks.json): the "(local)" link after a MITRE ID opens that object's page in this library. Edit the MITRE link; the script rewrites the "(local)" link. -->

> The 784 software entries in MITRE ATT&CK Enterprise (v19.2), 693 malware families and 91 tools, that adversaries use to carry out techniques. Each entry lists the number of ATT&CK techniques it implements and the threat groups known to use it. Pair with [Threat Group Profiles](THREAT_GROUP_PROFILES.md), the [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md), and [Malware Families](MALWARE_FAMILIES.md).

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts, malware analysts, and detection engineers

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 46 min (10,625 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need to identify what a named malware or tool can do, you are scoping detections around the software a threat group deploys, or you want the most technique-rich software to prioritize coverage against

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[All software by technique breadth](#all-software-by-technique-breadth), [Detailed profiles - most capable software](#detailed-profiles-most-capable-software)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last corrected, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Threat Group Profiles](THREAT_GROUP_PROFILES.md), [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md), [Malware Families](MALWARE_FAMILIES.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last corrected</th><td>

2026-10-13, revoked T1070.001 re-keyed to T1685.005 ([#118](https://github.com/TeamStarWolf/TeamStarWolf/pull/118), ATT&CK v19.2)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

Machine-readable: [`data/attack/software.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software.jsonl), [`data/attack/software_to_technique.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/software_to_technique.jsonl)

## All software by technique breadth

| Software | Type | Techniques | Groups |
|---|---|--:|--:|
| [S0260 InvisiMole](#s0260-invisimole) | malware | 73 | 0 |
| [S0363 Empire](#s0363-empire) | tool | 73 | 17 |
| [S0154 Cobalt Strike](#s0154-cobalt-strike) | malware | 72 | 29 |
| [S0650 QakBot](#s0650-qakbot) | malware | 71 | 3 |
| [S1111 DarkGate](#s1111-darkgate) | malware | 58 | 0 |
| [S0266 TrickBot](#s0266-trickbot) | malware | 55 | 2 |
| [S0692 SILENTTRINITY](#s0692-silenttrinity) | tool | 53 | 0 |
| [S0534 Bazar](#s0534-bazar) | malware | 51 | 2 |
| [S0013 PlugX](#s0013-plugx) | malware | 49 | 15 |
| [S0367 Emotet](#s0367-emotet) | malware | 47 | 1 |
| [S0455 Metamorfo](#s0455-metamorfo) | malware | 46 | 0 |
| [S0198 NETWIRE](#s0198-netwire) | malware | 45 | 4 |
| [S0603 Stuxnet](#s0603-stuxnet) | malware | 44 | 0 |
| [S1239 TONESHELL](#s1239-toneshell) | malware | 43 | 1 |
| [S1160 Latrodectus](#s1160-latrodectus) | malware | 43 | 2 |
| [S0531 Grandoreiro](#s0531-grandoreiro) | malware | 43 | 0 |
| [S0409 Machete](#s0409-machete) | malware | 41 | 1 |
| [S1130 Raspberry Robin](#s1130-raspberry-robin) | malware | 41 | 0 |
| [S0192 Pupy](#s0192-pupy) | tool | 41 | 2 |
| [S0356 KONNI](#s0356-konni) | malware | 40 | 0 |
| [S1242 Qilin](#s1242-qilin) | malware | 40 | 2 |
| [S1039 Bumblebee](#s1039-bumblebee) | malware | 39 | 2 |
| [S0458 Ramsay](#s0458-ramsay) | malware | 39 | 0 |
| [S0148 RTM](#s0148-rtm) | malware | 38 | 1 |
| [S1018 Saint Bot](#s1018-saint-bot) | malware | 37 | 2 |
| [S1044 FunnyDream](#s1044-funnydream) | malware | 37 | 0 |
| [S0331 Agent Tesla](#s0331-agent-tesla) | malware | 37 | 2 |
| [S1060 Mafalda](#s1060-mafalda) | malware | 36 | 1 |
| [S0022 Uroburos](#s0022-uroburos) | malware | 36 | 1 |
| [S0559 SUNBURST](#s0559-sunburst) | malware | 36 | 1 |
| [S0373 Astaroth](#s0373-astaroth) | malware | 36 | 0 |
| [S0386 Ursnif](#s0386-ursnif) | malware | 35 | 1 |
| [S1245 InvisibleFerret](#s1245-invisibleferret) | malware | 35 | 1 |
| [S1081 BADHATCH](#s1081-badhatch) | malware | 35 | 1 |
| [S1228 PUBLOAD](#s1228-pubload) | malware | 35 | 1 |
| [S1213 Lumma Stealer](#s1213-lumma-stealer) | malware | 35 | 0 |
| [S1240 RedLine Stealer](#s1240-redline-stealer) | malware | 35 | 0 |
| [S0438 Attor](#s0438-attor) | malware | 35 | 0 |
| [S0496 REvil](#s0496-revil) | malware | 35 | 2 |
| [S0428 PoetRAT](#s0428-poetrat) | malware | 35 | 0 |
| [S0439 Okrum](#s0439-okrum) | malware | 34 | 1 |
| [S0673 DarkWatchman](#s0673-darkwatchman) | malware | 34 | 0 |
| [S0268 Bisonal](#s0268-bisonal) | malware | 34 | 1 |
| [S0660 Clambling](#s0660-clambling) | malware | 34 | 1 |
| [S1202 LockBit 3.0](#s1202-lockbit-30) | malware | 34 | 0 |
| [S1183 StrelaStealer](#s1183-strelastealer) | malware | 34 | 0 |
| [S0476 Valak](#s0476-valak) | malware | 34 | 1 |
| [S0412 ZxShell](#s0412-zxshell) | malware | 34 | 3 |
| [S0658 XCSSET](#s0658-xcsset) | malware | 33 | 0 |
| [S0666 Gelsemium](#s0666-gelsemium) | malware | 33 | 0 |
| [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063/) ([local](/mitre/software/S1063.md)) | tool | 33 | 0 |
| [S0622 AppleSeed](https://attack.mitre.org/software/S0622/) ([local](/mitre/software/S0622.md)) | malware | 32 | 1 |
| [S0378 PoshC2](https://attack.mitre.org/software/S0378/) ([local](/mitre/software/S0378.md)) | tool | 32 | 3 |
| [S0483 IcedID](https://attack.mitre.org/software/S0483/) ([local](/mitre/software/S0483.md)) | malware | 31 | 2 |
| [S0265 Kazuar](https://attack.mitre.org/software/S0265/) ([local](/mitre/software/S0265.md)) | malware | 31 | 1 |
| [S1149 CHIMNEYSWEEP](https://attack.mitre.org/software/S1149/) ([local](/mitre/software/S1149.md)) | malware | 31 | 0 |
| [S0251 Zebrocy](https://attack.mitre.org/software/S0251/) ([local](/mitre/software/S0251.md)) | malware | 31 | 1 |
| [S0663 SysUpdate](https://attack.mitre.org/software/S0663/) ([local](/mitre/software/S0663.md)) | malware | 31 | 1 |
| [S0385 njRAT](https://attack.mitre.org/software/S0385/) ([local](/mitre/software/S0385.md)) | malware | 31 | 7 |
| [S0115 Crimson](https://attack.mitre.org/software/S0115/) ([local](/mitre/software/S0115.md)) | malware | 30 | 1 |
| [S1065 Woody RAT](https://attack.mitre.org/software/S1065/) ([local](/mitre/software/S1065.md)) | malware | 30 | 0 |
| [S0240 ROKRAT](https://attack.mitre.org/software/S0240/) ([local](/mitre/software/S0240.md)) | malware | 30 | 1 |
| [S0125 Remsec](https://attack.mitre.org/software/S0125/) ([local](/mitre/software/S0125.md)) | malware | 30 | 1 |
| [S1141 LunarWeb](https://attack.mitre.org/software/S1141/) ([local](/mitre/software/S1141.md)) | malware | 30 | 1 |
| [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670/) ([local](/mitre/software/S0670.md)) | malware | 30 | 3 |
| [S1159 DUSTTRAP](https://attack.mitre.org/software/S1159/) ([local](/mitre/software/S1159.md)) | malware | 29 | 1 |
| [S1100 Ninja](https://attack.mitre.org/software/S1100/) ([local](/mitre/software/S1100.md)) | malware | 28 | 1 |
| [S0689 WhisperGate](https://attack.mitre.org/software/S0689/) ([local](/mitre/software/S0689.md)) | malware | 28 | 1 |
| [S1066 DarkTortilla](https://attack.mitre.org/software/S1066/) ([local](/mitre/software/S1066.md)) | malware | 28 | 0 |
| [S0631 Chaes](https://attack.mitre.org/software/S0631/) ([local](/mitre/software/S0631.md)) | malware | 28 | 0 |
| [S1207 XLoader](https://attack.mitre.org/software/S1207/) ([local](/mitre/software/S1207.md)) | malware | 28 | 0 |
| [S0352 OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352/) ([local](/mitre/software/S0352.md)) | malware | 28 | 1 |
| [S0447 Lokibot](https://attack.mitre.org/software/S0447/) ([local](/mitre/software/S0447.md)) | malware | 28 | 1 |
| [S1059 metaMain](https://attack.mitre.org/software/S1059/) ([local](/mitre/software/S1059.md)) | malware | 28 | 1 |
| [S0283 jRAT](https://attack.mitre.org/software/S0283/) ([local](/mitre/software/S0283.md)) | malware | 28 | 1 |
| [S0681 Lizar](https://attack.mitre.org/software/S0681/) ([local](/mitre/software/S0681.md)) | malware | 28 | 1 |
| [S0194 PowerSploit](https://attack.mitre.org/software/S0194/) ([local](/mitre/software/S0194.md)) | tool | 28 | 9 |
| [S0601 Hildegard](https://attack.mitre.org/software/S0601/) ([local](/mitre/software/S0601.md)) | malware | 27 | 1 |
| [S1016 MacMa](https://attack.mitre.org/software/S1016/) ([local](/mitre/software/S1016.md)) | malware | 27 | 1 |
| [S0223 POWERSTATS](https://attack.mitre.org/software/S0223/) ([local](/mitre/software/S0223.md)) | malware | 27 | 1 |
| [S0250 Koadic](https://attack.mitre.org/software/S0250/) ([local](/mitre/software/S0250.md)) | tool | 27 | 4 |
| [S1229 Havoc](https://attack.mitre.org/software/S1229/) ([local](/mitre/software/S1229.md)) | malware | 26 | 0 |
| [S0491 StrongPity](https://attack.mitre.org/software/S0491/) ([local](/mitre/software/S0491.md)) | malware | 26 | 1 |
| [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153/) ([local](/mitre/software/S1153.md)) | malware | 26 | 0 |
| [S1122 Mispadu](https://attack.mitre.org/software/S1122/) ([local](/mitre/software/S1122.md)) | malware | 26 | 1 |
| [S0234 Bandook](https://attack.mitre.org/software/S0234/) ([local](/mitre/software/S0234.md)) | malware | 26 | 1 |
| [S1070 Black Basta](https://attack.mitre.org/software/S1070/) ([local](/mitre/software/S1070.md)) | malware | 26 | 1 |
| [S0697 HermeticWiper](https://attack.mitre.org/software/S0697/) ([local](/mitre/software/S0697.md)) | malware | 26 | 0 |
| [S1199 LockBit 2.0](https://attack.mitre.org/software/S1199/) ([local](/mitre/software/S1199.md)) | malware | 26 | 0 |
| [S1085 Sardonic](https://attack.mitre.org/software/S1085/) ([local](/mitre/software/S1085.md)) | malware | 25 | 1 |
| [S0239 Bankshot](https://attack.mitre.org/software/S0239/) ([local](/mitre/software/S0239.md)) | malware | 25 | 1 |
| [S0629 RainyDay](https://attack.mitre.org/software/S0629/) ([local](/mitre/software/S0629.md)) | malware | 25 | 1 |
| [S0089 BlackEnergy](https://attack.mitre.org/software/S0089/) ([local](/mitre/software/S0089.md)) | malware | 25 | 1 |
| [S0484 Carberp](https://attack.mitre.org/software/S0484/) ([local](/mitre/software/S0484.md)) | malware | 25 | 0 |
| [S0632 GrimAgent](https://attack.mitre.org/software/S0632/) ([local](/mitre/software/S0632.md)) | malware | 25 | 2 |
| [S0554 Egregor](https://attack.mitre.org/software/S0554/) ([local](/mitre/software/S0554.md)) | malware | 25 | 0 |
| [S0456 Aria-body](https://attack.mitre.org/software/S0456/) ([local](/mitre/software/S0456.md)) | malware | 24 | 1 |
| [S0615 SombRAT](https://attack.mitre.org/software/S0615/) ([local](/mitre/software/S0615.md)) | malware | 24 | 0 |
| [S0532 Lucifer](https://attack.mitre.org/software/S0532/) ([local](/mitre/software/S0532.md)) | malware | 24 | 0 |
| [S0696 Flagpro](https://attack.mitre.org/software/S0696/) ([local](/mitre/software/S0696.md)) | malware | 24 | 1 |
| [S1064 SVCReady](https://attack.mitre.org/software/S1064/) ([local](/mitre/software/S1064.md)) | malware | 24 | 0 |
| [S0674 CharmPower](https://attack.mitre.org/software/S0674/) ([local](/mitre/software/S0674.md)) | malware | 24 | 1 |
| [S0032 gh0st RAT](https://attack.mitre.org/software/S0032/) ([local](/mitre/software/S0032.md)) | malware | 24 | 11 |
| [S0140 Shamoon](https://attack.mitre.org/software/S0140/) ([local](/mitre/software/S0140.md)) | malware | 24 | 0 |
| [S0461 SDBbot](https://attack.mitre.org/software/S0461/) ([local](/mitre/software/S0461.md)) | malware | 24 | 1 |
| [S0467 TajMahal](https://attack.mitre.org/software/S0467/) ([local](/mitre/software/S0467.md)) | malware | 24 | 0 |
| [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148/) ([local](/mitre/software/S1148.md)) | malware | 24 | 1 |
| [S0128 BADNEWS](https://attack.mitre.org/software/S0128/) ([local](/mitre/software/S0128.md)) | malware | 24 | 1 |
| [S0533 SLOTHFULMEDIA](https://attack.mitre.org/software/S0533/) ([local](/mitre/software/S0533.md)) | malware | 24 | 0 |
| [S0677 AADInternals](https://attack.mitre.org/software/S0677/) ([local](/mitre/software/S0677.md)) | tool | 24 | 2 |
| [S0262 QuasarRAT](https://attack.mitre.org/software/S0262/) ([local](/mitre/software/S0262.md)) | tool | 24 | 6 |
| [S0330 Zeus Panda](https://attack.mitre.org/software/S0330/) ([local](/mitre/software/S0330.md)) | malware | 23 | 0 |
| [S1246 BeaverTail](https://attack.mitre.org/software/S1246/) ([local](/mitre/software/S1246.md)) | malware | 23 | 1 |
| [S0625 Cuba](https://attack.mitre.org/software/S0625/) ([local](/mitre/software/S0625.md)) | malware | 23 | 0 |
| [S0482 Bundlore](https://attack.mitre.org/software/S0482/) ([local](/mitre/software/S0482.md)) | malware | 23 | 0 |
| [S0501 PipeMon](https://attack.mitre.org/software/S0501/) ([local](/mitre/software/S0501.md)) | malware | 23 | 1 |
| [S0449 Maze](https://attack.mitre.org/software/S0449/) ([local](/mitre/software/S0449.md)) | malware | 23 | 2 |
| [S0567 Dtrack](https://attack.mitre.org/software/S0567/) ([local](/mitre/software/S0567.md)) | malware | 23 | 1 |
| [S0045 ADVSTORESHELL](https://attack.mitre.org/software/S0045/) ([local](/mitre/software/S0045.md)) | malware | 23 | 1 |
| [S0633 Sliver](https://attack.mitre.org/software/S0633/) ([local](/mitre/software/S0633.md)) | tool | 23 | 3 |
| [S0520 BLINDINGCAN](https://attack.mitre.org/software/S0520/) ([local](/mitre/software/S0520.md)) | malware | 22 | 1 |
| [S0662 RCSession](https://attack.mitre.org/software/S0662/) ([local](/mitre/software/S0662.md)) | malware | 22 | 2 |
| [S1244 Medusa Ransomware](https://attack.mitre.org/software/S1244/) ([local](/mitre/software/S1244.md)) | malware | 22 | 1 |
| [S0381 FlawedAmmyy](https://attack.mitre.org/software/S0381/) ([local](/mitre/software/S0381.md)) | malware | 22 | 2 |
| [S0652 MarkiRAT](https://attack.mitre.org/software/S0652/) ([local](/mitre/software/S0652.md)) | malware | 22 | 1 |
| [S0091 Epic](https://attack.mitre.org/software/S0091/) ([local](/mitre/software/S0091.md)) | malware | 22 | 1 |
| [S0395 LightNeuron](https://attack.mitre.org/software/S0395/) ([local](/mitre/software/S0395.md)) | malware | 22 | 1 |
| [S1247 Embargo](https://attack.mitre.org/software/S1247/) ([local](/mitre/software/S1247.md)) | malware | 22 | 1 |
| [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094/) ([local](/mitre/software/S0094.md)) | malware | 22 | 1 |
| [S0446 Ryuk](https://attack.mitre.org/software/S0446/) ([local](/mitre/software/S0446.md)) | malware | 22 | 2 |
| [S0182 FinFisher](https://attack.mitre.org/software/S0182/) ([local](/mitre/software/S0182.md)) | malware | 22 | 1 |
| [S0348 Cardinal RAT](https://attack.mitre.org/software/S0348/) ([local](/mitre/software/S0348.md)) | malware | 22 | 0 |
| [S0236 Kwampirs](https://attack.mitre.org/software/S0236/) ([local](/mitre/software/S0236.md)) | malware | 22 | 1 |
| [S0141 Winnti for Windows](https://attack.mitre.org/software/S0141/) ([local](/mitre/software/S0141.md)) | malware | 22 | 2 |
| [S1196 Troll Stealer](https://attack.mitre.org/software/S1196/) ([local](/mitre/software/S1196.md)) | malware | 22 | 1 |
| [S0377 Ebury](https://attack.mitre.org/software/S0377/) ([local](/mitre/software/S0377.md)) | malware | 22 | 1 |
| [S0126 ComRAT](https://attack.mitre.org/software/S0126/) ([local](/mitre/software/S0126.md)) | malware | 22 | 1 |
| [S1145 Pikabot](https://attack.mitre.org/software/S1145/) ([local](/mitre/software/S1145.md)) | malware | 21 | 1 |
| [S1212 RansomHub](https://attack.mitre.org/software/S1212/) ([local](/mitre/software/S1212.md)) | malware | 21 | 0 |
| [S1030 Squirrelwaffle](https://attack.mitre.org/software/S1030/) ([local](/mitre/software/S1030.md)) | malware | 21 | 0 |
| [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376/) ([local](/mitre/software/S0376.md)) | malware | 21 | 2 |
| [S1068 BlackCat](https://attack.mitre.org/software/S1068/) ([local](/mitre/software/S1068.md)) | malware | 21 | 1 |
| [S0512 FatDuke](https://attack.mitre.org/software/S0512/) ([local](/mitre/software/S0512.md)) | malware | 21 | 1 |
| [S0444 ShimRat](https://attack.mitre.org/software/S0444/) ([local](/mitre/software/S0444.md)) | malware | 21 | 1 |
| [S0038 Duqu](https://attack.mitre.org/software/S0038/) ([local](/mitre/software/S0038.md)) | malware | 21 | 0 |
| [S0661 FoggyWeb](https://attack.mitre.org/software/S0661/) ([local](/mitre/software/S0661.md)) | malware | 21 | 1 |
| [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649/) ([local](/mitre/software/S0649.md)) | malware | 21 | 0 |
| [S1090 NightClub](https://attack.mitre.org/software/S1090/) ([local](/mitre/software/S1090.md)) | malware | 21 | 1 |
| [S1180 BlackByte Ransomware](https://attack.mitre.org/software/S1180/) ([local](/mitre/software/S1180.md)) | malware | 21 | 1 |
| [S0687 Cyclops Blink](https://attack.mitre.org/software/S0687/) ([local](/mitre/software/S0687.md)) | malware | 21 | 1 |
| [S1020 Kevin](https://attack.mitre.org/software/S1020/) ([local](/mitre/software/S1020.md)) | malware | 21 | 1 |
| [S0596 ShadowPad](https://attack.mitre.org/software/S0596/) ([local](/mitre/software/S0596.md)) | malware | 21 | 8 |
| [S0170 Helminth](https://attack.mitre.org/software/S0170/) ([local](/mitre/software/S0170.md)) | malware | 21 | 1 |
| [S1091 Pacu](https://attack.mitre.org/software/S1091/) ([local](/mitre/software/S1091.md)) | tool | 21 | 0 |
| [S1050 PcShare](https://attack.mitre.org/software/S1050/) ([local](/mitre/software/S1050.md)) | tool | 21 | 1 |
| [S0184 POWRUNER](https://attack.mitre.org/software/S0184/) ([local](/mitre/software/S0184.md)) | malware | 20 | 1 |
| [S0113 Prikormka](https://attack.mitre.org/software/S0113/) ([local](/mitre/software/S0113.md)) | malware | 20 | 0 |
| [S1178 ShrinkLocker](https://attack.mitre.org/software/S1178/) ([local](/mitre/software/S1178.md)) | malware | 20 | 0 |
| [S1086 Snip3](https://attack.mitre.org/software/S1086/) ([local](/mitre/software/S1086.md)) | malware | 20 | 1 |
| [S0612 WastedLocker](https://attack.mitre.org/software/S0612/) ([local](/mitre/software/S0612.md)) | malware | 20 | 1 |
| [S0495 RDAT](https://attack.mitre.org/software/S0495/) ([local](/mitre/software/S0495.md)) | malware | 20 | 1 |
| [S0448 Rising Sun](https://attack.mitre.org/software/S0448/) ([local](/mitre/software/S0448.md)) | malware | 20 | 0 |
| [S0504 Anchor](https://attack.mitre.org/software/S0504/) ([local](/mitre/software/S0504.md)) | malware | 20 | 1 |
| [S0085 S-Type](https://attack.mitre.org/software/S0085/) ([local](/mitre/software/S0085.md)) | malware | 20 | 0 |
| [S0044 JHUHUGIT](https://attack.mitre.org/software/S0044/) ([local](/mitre/software/S0044.md)) | malware | 20 | 1 |
| [S0526 KGH_SPY](https://attack.mitre.org/software/S0526/) ([local](/mitre/software/S0526.md)) | malware | 20 | 1 |
| [S0431 HotCroissant](https://attack.mitre.org/software/S0431/) ([local](/mitre/software/S0431.md)) | malware | 20 | 1 |
| [S1015 Milan](https://attack.mitre.org/software/S1015/) ([local](/mitre/software/S1015.md)) | malware | 20 | 1 |
| [S0011 Taidoor](https://attack.mitre.org/software/S0011/) ([local](/mitre/software/S0011.md)) | malware | 20 | 0 |
| [S0688 Meteor](https://attack.mitre.org/software/S0688/) ([local](/mitre/software/S0688.md)) | malware | 20 | 0 |
| [S0201 JPIN](https://attack.mitre.org/software/S0201/) ([local](/mitre/software/S0201.md)) | malware | 20 | 1 |
| [S0669 KOCTOPUS](https://attack.mitre.org/software/S0669/) ([local](/mitre/software/S0669.md)) | malware | 20 | 1 |
| [S0584 AppleJeus](https://attack.mitre.org/software/S0584/) ([local](/mitre/software/S0584.md)) | malware | 20 | 1 |
| [S0354 Denis](https://attack.mitre.org/software/S0354/) ([local](/mitre/software/S0354.md)) | malware | 20 | 1 |
| [S0488 CrackMapExec](https://attack.mitre.org/software/S0488/) ([local](/mitre/software/S0488.md)) | tool | 20 | 5 |
| [S0237 GravityRAT](https://attack.mitre.org/software/S0237/) ([local](/mitre/software/S0237.md)) | malware | 19 | 0 |
| [S0050 CosmicDuke](https://attack.mitre.org/software/S0050/) ([local](/mitre/software/S0050.md)) | malware | 19 | 1 |
| [S0180 Volgmer](https://attack.mitre.org/software/S0180/) ([local](/mitre/software/S0180.md)) | malware | 19 | 1 |
| [S0659 Diavol](https://attack.mitre.org/software/S0659/) ([local](/mitre/software/S0659.md)) | malware | 19 | 1 |
| [S1124 SocGholish](https://attack.mitre.org/software/S1124/) ([local](/mitre/software/S1124.md)) | malware | 19 | 1 |
| [S0062 DustySky](https://attack.mitre.org/software/S0062/) ([local](/mitre/software/S0062.md)) | malware | 19 | 1 |
| [S0203 Hydraq](https://attack.mitre.org/software/S0203/) ([local](/mitre/software/S0203.md)) | malware | 19 | 2 |
| [S0081 Elise](https://attack.mitre.org/software/S0081/) ([local](/mitre/software/S0081.md)) | malware | 19 | 1 |
| [S0657 BLUELIGHT](https://attack.mitre.org/software/S0657/) ([local](/mitre/software/S0657.md)) | malware | 19 | 1 |
| [S0264 OopsIE](https://attack.mitre.org/software/S0264/) ([local](/mitre/software/S0264.md)) | malware | 19 | 1 |
| [S1099 Samurai](https://attack.mitre.org/software/S1099/) ([local](/mitre/software/S1099.md)) | malware | 19 | 1 |
| [S0023 CHOPSTICK](https://attack.mitre.org/software/S0023/) ([local](/mitre/software/S0023.md)) | malware | 19 | 1 |
| [S0267 FELIXROOT](https://attack.mitre.org/software/S0267/) ([local](/mitre/software/S0267.md)) | malware | 19 | 0 |
| [S1022 IceApple](https://attack.mitre.org/software/S1022/) ([local](/mitre/software/S1022.md)) | malware | 19 | 0 |
| [S0340 Octopus](https://attack.mitre.org/software/S0340/) ([local](/mitre/software/S0340.md)) | malware | 19 | 1 |
| [S0604 Industroyer](https://attack.mitre.org/software/S0604/) ([local](/mitre/software/S0604.md)) | malware | 19 | 1 |
| [S0244 Comnie](https://attack.mitre.org/software/S0244/) ([local](/mitre/software/S0244.md)) | malware | 19 | 0 |
| [S1105 COATHANGER](https://attack.mitre.org/software/S1105/) ([local](/mitre/software/S1105.md)) | malware | 18 | 0 |
| [S0647 Turian](https://attack.mitre.org/software/S0647/) ([local](/mitre/software/S0647.md)) | malware | 18 | 1 |
| [S1138 Gootloader](https://attack.mitre.org/software/S1138/) ([local](/mitre/software/S1138.md)) | malware | 18 | 0 |
| [S0334 DarkComet](https://attack.mitre.org/software/S0334/) ([local](/mitre/software/S0334.md)) | malware | 18 | 3 |
| [S0690 Green Lambert](https://attack.mitre.org/software/S0690/) ([local](/mitre/software/S0690.md)) | malware | 18 | 0 |
| [S0588 GoldMax](https://attack.mitre.org/software/S0588/) ([local](/mitre/software/S0588.md)) | malware | 18 | 1 |
| [S0387 KeyBoy](https://attack.mitre.org/software/S0387/) ([local](/mitre/software/S0387.md)) | malware | 18 | 1 |
| [S0595 ThiefQuest](https://attack.mitre.org/software/S0595/) ([local](/mitre/software/S0595.md)) | malware | 18 | 0 |
| [S0030 Carbanak](https://attack.mitre.org/software/S0030/) ([local](/mitre/software/S0030.md)) | malware | 18 | 2 |
| [S0457 Netwalker](https://attack.mitre.org/software/S0457/) ([local](/mitre/software/S0457.md)) | malware | 18 | 0 |
| [S0168 Gazer](https://attack.mitre.org/software/S0168/) ([local](/mitre/software/S0168.md)) | malware | 18 | 1 |
| [S1210 Sagerunex](https://attack.mitre.org/software/S1210/) ([local](/mitre/software/S1210.md)) | malware | 18 | 1 |
| [S0270 RogueRobin](https://attack.mitre.org/software/S0270/) ([local](/mitre/software/S0270.md)) | malware | 18 | 1 |
| [S0021 Derusbi](https://attack.mitre.org/software/S0021/) ([local](/mitre/software/S0021.md)) | malware | 18 | 4 |
| [S0589 Sibot](https://attack.mitre.org/software/S0589/) ([local](/mitre/software/S0589.md)) | malware | 18 | 1 |
| [S0335 Carbon](https://attack.mitre.org/software/S0335/) ([local](/mitre/software/S0335.md)) | malware | 18 | 1 |
| [S0379 Revenge RAT](https://attack.mitre.org/software/S0379/) ([local](/mitre/software/S0379.md)) | malware | 18 | 2 |
| [S0587 Penquin](https://attack.mitre.org/software/S0587/) ([local](/mitre/software/S0587.md)) | malware | 18 | 1 |
| [S0084 Mis-Type](https://attack.mitre.org/software/S0084/) ([local](/mitre/software/S0084.md)) | malware | 18 | 0 |
| [S0477 Goopy](https://attack.mitre.org/software/S0477/) ([local](/mitre/software/S0477.md)) | malware | 18 | 1 |
| [S0451 LoudMiner](https://attack.mitre.org/software/S0451/) ([local](/mitre/software/S0451.md)) | malware | 18 | 0 |
| [S0570 BitPaymer](https://attack.mitre.org/software/S0570/) ([local](/mitre/software/S0570.md)) | malware | 18 | 1 |
| [S1025 Amadey](https://attack.mitre.org/software/S1025/) ([local](/mitre/software/S1025.md)) | malware | 17 | 2 |
| [S1078 RotaJakiro](https://attack.mitre.org/software/S1078/) ([local](/mitre/software/S1078.md)) | malware | 17 | 1 |
| [S0153 RedLeaves](https://attack.mitre.org/software/S0153/) ([local](/mitre/software/S0153.md)) | malware | 17 | 1 |
| [S1226 BOOKWORM](https://attack.mitre.org/software/S1226/) ([local](/mitre/software/S1226.md)) | malware | 17 | 1 |
| [S0342 GreyEnergy](https://attack.mitre.org/software/S0342/) ([local](/mitre/software/S0342.md)) | malware | 17 | 1 |
| [S0257 VERMIN](https://attack.mitre.org/software/S0257/) ([local](/mitre/software/S0257.md)) | malware | 17 | 0 |
| [S0640 Avaddon](https://attack.mitre.org/software/S0640/) ([local](/mitre/software/S0640.md)) | malware | 17 | 0 |
| [S0196 PUNCHBUGGY](https://attack.mitre.org/software/S0196/) ([local](/mitre/software/S0196.md)) | malware | 17 | 1 |
| [S0147 Pteranodon](https://attack.mitre.org/software/S0147/) ([local](/mitre/software/S0147.md)) | malware | 17 | 1 |
| [S0269 QUADAGENT](https://attack.mitre.org/software/S0269/) ([local](/mitre/software/S0269.md)) | malware | 17 | 1 |
| [S0256 Mosquito](https://attack.mitre.org/software/S0256/) ([local](/mitre/software/S0256.md)) | malware | 17 | 1 |
| [S1019 Shark](https://attack.mitre.org/software/S1019/) ([local](/mitre/software/S1019.md)) | malware | 17 | 1 |
| [S1146 MgBot](https://attack.mitre.org/software/S1146/) ([local](/mitre/software/S1146.md)) | malware | 17 | 1 |
| [S1142 LunarMail](https://attack.mitre.org/software/S1142/) ([local](/mitre/software/S1142.md)) | malware | 17 | 1 |
| [S1017 OutSteel](https://attack.mitre.org/software/S1017/) ([local](/mitre/software/S1017.md)) | malware | 17 | 1 |
| [S0611 Clop](https://attack.mitre.org/software/S0611/) ([local](/mitre/software/S0611.md)) | malware | 17 | 1 |
| [S0599 Kinsing](https://attack.mitre.org/software/S0599/) ([local](/mitre/software/S0599.md)) | malware | 17 | 0 |
| [S0002 Mimikatz](https://attack.mitre.org/software/S0002/) ([local](/mitre/software/S0002.md)) | tool | 17 | 51 |
| [S0353 NOKKI](https://attack.mitre.org/software/S0353/) ([local](/mitre/software/S0353.md)) | malware | 16 | 1 |
| [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093/) ([local](/mitre/software/S0093.md)) | malware | 16 | 1 |
| [S0083 Misdat](https://attack.mitre.org/software/S0083/) ([local](/mitre/software/S0083.md)) | malware | 16 | 0 |
| [S0453 Pony](https://attack.mitre.org/software/S0453/) ([local](/mitre/software/S0453.md)) | malware | 16 | 0 |
| [S0468 Skidmap](https://attack.mitre.org/software/S0468/) ([local](/mitre/software/S0468.md)) | malware | 16 | 0 |
| [S0575 Conti](https://attack.mitre.org/software/S0575/) ([local](/mitre/software/S0575.md)) | malware | 16 | 1 |
| [S1185 LightSpy](https://attack.mitre.org/software/S1185/) ([local](/mitre/software/S1185.md)) | malware | 16 | 1 |
| [S0024 Dyre](https://attack.mitre.org/software/S0024/) ([local](/mitre/software/S0024.md)) | malware | 16 | 1 |
| [S0341 Xbash](https://attack.mitre.org/software/S0341/) ([local](/mitre/software/S0341.md)) | malware | 16 | 0 |
| [S0366 WannaCry](https://attack.mitre.org/software/S0366/) ([local](/mitre/software/S0366.md)) | malware | 16 | 1 |
| [S0586 TAINTEDSCRIBE](https://attack.mitre.org/software/S0586/) ([local](/mitre/software/S0586.md)) | malware | 16 | 1 |
| [S0339 Micropsia](https://attack.mitre.org/software/S0339/) ([local](/mitre/software/S0339.md)) | malware | 16 | 1 |
| [S0576 MegaCortex](https://attack.mitre.org/software/S0576/) ([local](/mitre/software/S0576.md)) | malware | 16 | 0 |
| [S0583 Pysa](https://attack.mitre.org/software/S0583/) ([local](/mitre/software/S0583.md)) | malware | 16 | 0 |
| [S0187 Daserf](https://attack.mitre.org/software/S0187/) ([local](/mitre/software/S0187.md)) | malware | 16 | 1 |
| [S0475 BackConfig](https://attack.mitre.org/software/S0475/) ([local](/mitre/software/S0475.md)) | malware | 16 | 1 |
| [S0635 BoomBox](https://attack.mitre.org/software/S0635/) ([local](/mitre/software/S0635.md)) | malware | 16 | 1 |
| [S0582 LookBack](https://attack.mitre.org/software/S0582/) ([local](/mitre/software/S0582.md)) | malware | 16 | 0 |
| [S0414 BabyShark](https://attack.mitre.org/software/S0414/) ([local](/mitre/software/S0414.md)) | malware | 16 | 1 |
| [S0375 Remexi](https://attack.mitre.org/software/S0375/) ([local](/mitre/software/S0375.md)) | malware | 16 | 1 |
| [S0344 Azorult](https://attack.mitre.org/software/S0344/) ([local](/mitre/software/S0344.md)) | malware | 16 | 1 |
| [S0698 HermeticWizard](https://attack.mitre.org/software/S0698/) ([local](/mitre/software/S0698.md)) | malware | 16 | 0 |
| [S0039 Net](https://attack.mitre.org/software/S0039/) ([local](/mitre/software/S0039.md)) | tool | 16 | 32 |
| [S0445 ShimRatReporter](https://attack.mitre.org/software/S0445/) ([local](/mitre/software/S0445.md)) | tool | 16 | 1 |
| [S0332 Remcos](https://attack.mitre.org/software/S0332/) ([local](/mitre/software/S0332.md)) | tool | 16 | 3 |
| [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434/) ([local](/mitre/software/S0434.md)) | tool | 16 | 2 |
| [S0695 Donut](https://attack.mitre.org/software/S0695/) ([local](/mitre/software/S0695.md)) | tool | 16 | 1 |
| [S0139 PowerDuke](https://attack.mitre.org/software/S0139/) ([local](/mitre/software/S0139.md)) | malware | 15 | 1 |
| [S0238 Proxysvc](https://attack.mitre.org/software/S0238/) ([local](/mitre/software/S0238.md)) | malware | 15 | 1 |
| [S0248 yty](https://attack.mitre.org/software/S0248/) ([local](/mitre/software/S0248.md)) | malware | 15 | 0 |
| [S1053 AvosLocker](https://attack.mitre.org/software/S1053/) ([local](/mitre/software/S1053.md)) | malware | 15 | 0 |
| [S0466 WindTail](https://attack.mitre.org/software/S0466/) ([local](/mitre/software/S0466.md)) | malware | 15 | 1 |
| [S0082 Emissary](https://attack.mitre.org/software/S0082/) ([local](/mitre/software/S0082.md)) | malware | 15 | 1 |
| [S0630 Nebulae](https://attack.mitre.org/software/S0630/) ([local](/mitre/software/S0630.md)) | malware | 15 | 1 |
| [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606/) ([local](/mitre/software/S0606.md)) | malware | 15 | 1 |
| [S1184 BOLDMOVE](https://attack.mitre.org/software/S1184/) ([local](/mitre/software/S1184.md)) | malware | 15 | 0 |
| [S1031 PingPull](https://attack.mitre.org/software/S1031/) ([local](/mitre/software/S1031.md)) | malware | 15 | 1 |
| [S0514 WellMess](https://attack.mitre.org/software/S0514/) ([local](/mitre/software/S0514.md)) | malware | 15 | 1 |
| [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598/) ([local](/mitre/software/S0598.md)) | malware | 15 | 2 |
| [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201/) ([local](/mitre/software/S1201.md)) | malware | 15 | 1 |
| [S0053 SeaDuke](https://attack.mitre.org/software/S0053/) ([local](/mitre/software/S0053.md)) | malware | 15 | 1 |
| [S1026 Mongall](https://attack.mitre.org/software/S1026/) ([local](/mitre/software/S1026.md)) | malware | 15 | 1 |
| [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572/) ([local](/mitre/software/S0572.md)) | malware | 15 | 1 |
| [S0263 TYPEFRAME](https://attack.mitre.org/software/S0263/) ([local](/mitre/software/S0263.md)) | malware | 15 | 1 |
| [S1073 Royal](https://attack.mitre.org/software/S1073/) ([local](/mitre/software/S1073.md)) | malware | 15 | 0 |
| [S0015 Ixeshe](https://attack.mitre.org/software/S0015/) ([local](/mitre/software/S0015.md)) | malware | 15 | 1 |
| [S0380 StoneDrill](https://attack.mitre.org/software/S0380/) ([local](/mitre/software/S0380.md)) | malware | 15 | 1 |
| [S0538 Crutch](https://attack.mitre.org/software/S0538/) ([local](/mitre/software/S0538.md)) | malware | 15 | 1 |
| [S0641 Kobalos](https://attack.mitre.org/software/S0641/) ([local](/mitre/software/S0641.md)) | malware | 15 | 0 |
| [S0241 RATANKBA](https://attack.mitre.org/software/S0241/) ([local](/mitre/software/S0241.md)) | malware | 15 | 1 |
| [S0149 MoonWind](https://attack.mitre.org/software/S0149/) ([local](/mitre/software/S0149.md)) | malware | 15 | 0 |
| [S0374 SpeakUp](https://attack.mitre.org/software/S0374/) ([local](/mitre/software/S0374.md)) | malware | 15 | 0 |
| [S0396 EvilBunny](https://attack.mitre.org/software/S0396/) ([local](/mitre/software/S0396.md)) | malware | 15 | 0 |
| [S0382 ServHelper](https://attack.mitre.org/software/S0382/) ([local](/mitre/software/S0382.md)) | malware | 15 | 1 |
| [S1172 OilBooster](https://attack.mitre.org/software/S1172/) ([local](/mitre/software/S1172.md)) | malware | 15 | 1 |
| [S0012 PoisonIvy](https://attack.mitre.org/software/S0012/) ([local](/mitre/software/S0012.md)) | malware | 15 | 14 |
| [S0435 PLEAD](https://attack.mitre.org/software/S0435/) ([local](/mitre/software/S0435.md)) | malware | 15 | 1 |
| [S1132 IPsec Helper](https://attack.mitre.org/software/S1132/) ([local](/mitre/software/S1132.md)) | malware | 15 | 1 |
| [S0274 Calisto](https://attack.mitre.org/software/S0274/) ([local](/mitre/software/S0274.md)) | malware | 15 | 0 |
| [S0493 GoldenSpy](https://attack.mitre.org/software/S0493/) ([local](/mitre/software/S0493.md)) | malware | 15 | 0 |
| [S0517 Pillowmint](https://attack.mitre.org/software/S0517/) ([local](/mitre/software/S0517.md)) | malware | 15 | 1 |
| [S1150 ROADSWEEP](https://attack.mitre.org/software/S1150/) ([local](/mitre/software/S1150.md)) | malware | 15 | 0 |
| [S0284 More_eggs](https://attack.mitre.org/software/S0284/) ([local](/mitre/software/S0284.md)) | malware | 15 | 3 |
| [S0279 Proton](https://attack.mitre.org/software/S0279/) ([local](/mitre/software/S0279.md)) | malware | 15 | 0 |
| [S1200 StealBit](https://attack.mitre.org/software/S1200/) ([local](/mitre/software/S1200.md)) | malware | 15 | 0 |
| [S0610 SideTwist](https://attack.mitre.org/software/S0610/) ([local](/mitre/software/S0610.md)) | malware | 15 | 1 |
| [S1027 Heyoka Backdoor](https://attack.mitre.org/software/S1027/) ([local](/mitre/software/S1027.md)) | malware | 15 | 1 |
| [S0607 KillDisk](https://attack.mitre.org/software/S0607/) ([local](/mitre/software/S0607.md)) | malware | 15 | 2 |
| [S0384 Dridex](https://attack.mitre.org/software/S0384/) ([local](/mitre/software/S0384.md)) | malware | 15 | 2 |
| [S0402 OSX/Shlayer](https://attack.mitre.org/software/S0402/) ([local](/mitre/software/S0402.md)) | malware | 15 | 0 |
| [S1139 INC Ransomware](https://attack.mitre.org/software/S1139/) ([local](/mitre/software/S1139.md)) | malware | 15 | 1 |
| [S1034 StrifeWater](https://attack.mitre.org/software/S1034/) ([local](/mitre/software/S1034.md)) | malware | 15 | 1 |
| [S0242 SynAck](https://attack.mitre.org/software/S0242/) ([local](/mitre/software/S0242.md)) | malware | 14 | 0 |
| [S0226 Smoke Loader](https://attack.mitre.org/software/S0226/) ([local](/mitre/software/S0226.md)) | malware | 14 | 0 |
| [S0665 ThreatNeedle](https://attack.mitre.org/software/S0665/) ([local](/mitre/software/S0665.md)) | malware | 14 | 1 |
| [S0668 TinyTurla](https://attack.mitre.org/software/S0668/) ([local](/mitre/software/S0668.md)) | malware | 14 | 1 |
| [S0634 EnvyScout](https://attack.mitre.org/software/S0634/) ([local](/mitre/software/S0634.md)) | malware | 14 | 1 |
| [S1198 Gomir](https://attack.mitre.org/software/S1198/) ([local](/mitre/software/S1198.md)) | malware | 14 | 1 |
| [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365/) ([local](/mitre/software/S0365.md)) | malware | 14 | 1 |
| [S0600 Doki](https://attack.mitre.org/software/S0600/) ([local](/mitre/software/S0600.md)) | malware | 14 | 0 |
| [S0623 Siloscape](https://attack.mitre.org/software/S0623/) ([local](/mitre/software/S0623.md)) | malware | 14 | 0 |
| [S1147 Nightdoor](https://attack.mitre.org/software/S1147/) ([local](/mitre/software/S1147.md)) | malware | 14 | 1 |
| [S0441 PowerShower](https://attack.mitre.org/software/S0441/) ([local](/mitre/software/S0441.md)) | malware | 14 | 1 |
| [S0368 NotPetya](https://attack.mitre.org/software/S0368/) ([local](/mitre/software/S0368.md)) | malware | 14 | 1 |
| [S0667 Chrommme](https://attack.mitre.org/software/S0667/) ([local](/mitre/software/S0667.md)) | malware | 14 | 0 |
| [S0644 ObliqueRAT](https://attack.mitre.org/software/S0644/) ([local](/mitre/software/S0644.md)) | malware | 14 | 1 |
| [S0638 Babuk](https://attack.mitre.org/software/S0638/) ([local](/mitre/software/S0638.md)) | malware | 14 | 0 |
| [S0127 BBSRAT](https://attack.mitre.org/software/S0127/) ([local](/mitre/software/S0127.md)) | malware | 14 | 0 |
| [S0172 Reaver](https://attack.mitre.org/software/S0172/) ([local](/mitre/software/S0172.md)) | malware | 14 | 0 |
| [S1135 MultiLayer Wiper](https://attack.mitre.org/software/S1135/) ([local](/mitre/software/S1135.md)) | malware | 14 | 1 |
| [S0568 EVILNUM](https://attack.mitre.org/software/S0568/) ([local](/mitre/software/S0568.md)) | malware | 14 | 1 |
| [S1013 ZxxZ](https://attack.mitre.org/software/S1013/) ([local](/mitre/software/S1013.md)) | malware | 14 | 1 |
| [S1190 Kapeka](https://attack.mitre.org/software/S1190/) ([local](/mitre/software/S1190.md)) | malware | 14 | 1 |
| [S0136 USBStealer](https://attack.mitre.org/software/S0136/) ([local](/mitre/software/S0136.md)) | malware | 14 | 1 |
| [S1014 DanBot](https://attack.mitre.org/software/S1014/) ([local](/mitre/software/S1014.md)) | malware | 14 | 1 |
| [S0249 Gold Dragon](https://attack.mitre.org/software/S0249/) ([local](/mitre/software/S0249.md)) | malware | 14 | 1 |
| [S0487 Kessel](https://attack.mitre.org/software/S0487/) ([local](/mitre/software/S0487.md)) | malware | 14 | 0 |
| [S0516 SoreFang](https://attack.mitre.org/software/S0516/) ([local](/mitre/software/S0516.md)) | malware | 14 | 1 |
| [S1037 STARWHALE](https://attack.mitre.org/software/S1037/) ([local](/mitre/software/S1037.md)) | malware | 14 | 1 |
| [S0046 CozyCar](https://attack.mitre.org/software/S0046/) ([local](/mitre/software/S0046.md)) | malware | 14 | 1 |
| [S0492 CookieMiner](https://attack.mitre.org/software/S0492/) ([local](/mitre/software/S0492.md)) | malware | 14 | 0 |
| [S0499 Hancitor](https://attack.mitre.org/software/S0499/) ([local](/mitre/software/S0499.md)) | malware | 14 | 0 |
| [S0579 Waterbear](https://attack.mitre.org/software/S0579/) ([local](/mitre/software/S0579.md)) | malware | 14 | 1 |
| [S0031 BACKSPACE](https://attack.mitre.org/software/S0031/) ([local](/mitre/software/S0031.md)) | malware | 14 | 1 |
| [S0229 Orz](https://attack.mitre.org/software/S0229/) ([local](/mitre/software/S0229.md)) | malware | 13 | 1 |
| [S0678 Torisma](https://attack.mitre.org/software/S0678/) ([local](/mitre/software/S0678.md)) | malware | 13 | 0 |
| [S1075 KOPILUWAK](https://attack.mitre.org/software/S1075/) ([local](/mitre/software/S1075.md)) | malware | 13 | 1 |
| [S0230 ZeroT](https://attack.mitre.org/software/S0230/) ([local](/mitre/software/S0230.md)) | malware | 13 | 1 |
| [S0481 Ragnar Locker](https://attack.mitre.org/software/S0481/) ([local](/mitre/software/S0481.md)) | malware | 13 | 1 |
| [S0694 DRATzarus](https://attack.mitre.org/software/S0694/) ([local](/mitre/software/S0694.md)) | malware | 13 | 0 |
| [S0608 Conficker](https://attack.mitre.org/software/S0608/) ([local](/mitre/software/S0608.md)) | malware | 13 | 0 |
| [S0436 TSCookie](https://attack.mitre.org/software/S0436/) ([local](/mitre/software/S0436.md)) | malware | 13 | 1 |
| [S1182 MagicRAT](https://attack.mitre.org/software/S1182/) ([local](/mitre/software/S1182.md)) | malware | 13 | 1 |
| [S0098 T9000](https://attack.mitre.org/software/S0098/) ([local](/mitre/software/S0098.md)) | malware | 13 | 0 |
| [S1161 BPFDoor](https://attack.mitre.org/software/S1161/) ([local](/mitre/software/S1161.md)) | malware | 13 | 0 |
| [S0513 LiteDuke](https://attack.mitre.org/software/S0513/) ([local](/mitre/software/S0513.md)) | malware | 13 | 1 |
| [S1042 SUGARDUMP](https://attack.mitre.org/software/S1042/) ([local](/mitre/software/S1042.md)) | malware | 13 | 0 |
| [S0664 Pandora](https://attack.mitre.org/software/S0664/) ([local](/mitre/software/S0664.md)) | malware | 13 | 2 |
| [S0336 NanoCore](https://attack.mitre.org/software/S0336/) ([local](/mitre/software/S0336.md)) | malware | 13 | 4 |
| [S1169 Mango](https://attack.mitre.org/software/S1169/) ([local](/mitre/software/S1169.md)) | malware | 13 | 1 |
| [S0132 H1N1](https://attack.mitre.org/software/S0132/) ([local](/mitre/software/S0132.md)) | malware | 13 | 0 |
| [S1035 Small Sieve](https://attack.mitre.org/software/S1035/) ([local](/mitre/software/S1035.md)) | malware | 13 | 1 |
| [S1087 AsyncRAT](https://attack.mitre.org/software/S1087/) ([local](/mitre/software/S1087.md)) | tool | 13 | 1 |
| [S0699 Mythic](https://attack.mitre.org/software/S0699/) ([local](/mitre/software/S0699.md)) | tool | 13 | 0 |
| [S0401 Exaramel for Linux](https://attack.mitre.org/software/S0401/) ([local](/mitre/software/S0401.md)) | malware | 12 | 1 |
| [S1164 UPSTYLE](https://attack.mitre.org/software/S1164/) ([local](/mitre/software/S1164.md)) | malware | 12 | 0 |
| [S1028 Action RAT](https://attack.mitre.org/software/S1028/) ([local](/mitre/software/S1028.md)) | malware | 12 | 1 |
| [S0473 Avenger](https://attack.mitre.org/software/S0473/) ([local](/mitre/software/S0473.md)) | malware | 12 | 1 |
| [S1249 HexEval Loader](https://attack.mitre.org/software/S1249/) ([local](/mitre/software/S1249.md)) | malware | 12 | 1 |
| [S0561 GuLoader](https://attack.mitre.org/software/S0561/) ([local](/mitre/software/S0561.md)) | malware | 12 | 0 |
| [S0410 Fysbis](https://attack.mitre.org/software/S0410/) ([local](/mitre/software/S0410.md)) | malware | 12 | 1 |
| [S0398 HyperBro](https://attack.mitre.org/software/S0398/) ([local](/mitre/software/S0398.md)) | malware | 12 | 1 |
| [S0528 Javali](https://attack.mitre.org/software/S0528/) ([local](/mitre/software/S0528.md)) | malware | 12 | 0 |
| [S0569 Explosive](https://attack.mitre.org/software/S0569/) ([local](/mitre/software/S0569.md)) | malware | 12 | 1 |
| [S0228 NanHaiShu](https://attack.mitre.org/software/S0228/) ([local](/mitre/software/S0228.md)) | malware | 12 | 1 |
| [S0680 LitePower](https://attack.mitre.org/software/S0680/) ([local](/mitre/software/S0680.md)) | malware | 12 | 1 |
| [S0651 BoxCaon](https://attack.mitre.org/software/S0651/) ([local](/mitre/software/S0651.md)) | malware | 12 | 1 |
| [S0502 Drovorub](https://attack.mitre.org/software/S0502/) ([local](/mitre/software/S0502.md)) | malware | 12 | 1 |
| [S0337 BadPatch](https://attack.mitre.org/software/S0337/) ([local](/mitre/software/S0337.md)) | malware | 12 | 0 |
| [S1043 ccf32](https://attack.mitre.org/software/S1043/) ([local](/mitre/software/S1043.md)) | malware | 12 | 0 |
| [S0562 SUNSPOT](https://attack.mitre.org/software/S0562/) ([local](/mitre/software/S0562.md)) | malware | 12 | 1 |
| [S1052 DEADEYE](https://attack.mitre.org/software/S1052/) ([local](/mitre/software/S1052.md)) | malware | 12 | 0 |
| [S0530 Melcoz](https://attack.mitre.org/software/S0530/) ([local](/mitre/software/S0530.md)) | malware | 12 | 0 |
| [S0144 ChChes](https://attack.mitre.org/software/S0144/) ([local](/mitre/software/S0144.md)) | malware | 12 | 1 |
| [S1217 VIRTUALPITA](https://attack.mitre.org/software/S1217/) ([local](/mitre/software/S1217.md)) | malware | 12 | 1 |
| [S1248 XORIndex Loader](https://attack.mitre.org/software/S1248/) ([local](/mitre/software/S1248.md)) | malware | 12 | 1 |
| [S0527 CSPY Downloader](https://attack.mitre.org/software/S0527/) ([local](/mitre/software/S0527.md)) | tool | 12 | 1 |
| [S0683 Peirates](https://attack.mitre.org/software/S0683/) ([local](/mitre/software/S0683.md)) | tool | 12 | 1 |
| [S0546 SharpStage](https://attack.mitre.org/software/S0546/) ([local](/mitre/software/S0546.md)) | malware | 11 | 1 |
| [S0271 KEYMARBLE](https://attack.mitre.org/software/S0271/) ([local](/mitre/software/S0271.md)) | malware | 11 | 1 |
| [S0391 HAWKBALL](https://attack.mitre.org/software/S0391/) ([local](/mitre/software/S0391.md)) | malware | 11 | 0 |
| [S0086 ZLib](https://attack.mitre.org/software/S0086/) ([local](/mitre/software/S0086.md)) | malware | 11 | 0 |
| [S1089 SharpDisco](https://attack.mitre.org/software/S1089/) ([local](/mitre/software/S1089.md)) | malware | 11 | 1 |
| [S0653 xCaon](https://attack.mitre.org/software/S0653/) ([local](/mitre/software/S0653.md)) | malware | 11 | 1 |
| [S1048 macOS.OSAMiner](https://attack.mitre.org/software/S1048/) ([local](/mitre/software/S1048.md)) | malware | 11 | 0 |
| [S1032 PyDCrypt](https://attack.mitre.org/software/S1032/) ([local](/mitre/software/S1032.md)) | malware | 11 | 1 |
| [S1181 BlackByte 2.0 Ransomware](https://attack.mitre.org/software/S1181/) ([local](/mitre/software/S1181.md)) | malware | 11 | 1 |
| [S1236 CLAIMLOADER](https://attack.mitre.org/software/S1236/) ([local](/mitre/software/S1236.md)) | malware | 11 | 1 |
| [S0019 Regin](https://attack.mitre.org/software/S0019/) ([local](/mitre/software/S0019.md)) | malware | 11 | 0 |
| [S0691 Neoichor](https://attack.mitre.org/software/S0691/) ([local](/mitre/software/S0691.md)) | malware | 11 | 1 |
| [S1219 REPTILE](https://attack.mitre.org/software/S1219/) ([local](/mitre/software/S1219.md)) | malware | 11 | 1 |
| [S0034 NETEAGLE](https://attack.mitre.org/software/S0034/) ([local](/mitre/software/S0034.md)) | malware | 11 | 1 |
| [S0350 zwShell](https://attack.mitre.org/software/S0350/) ([local](/mitre/software/S0350.md)) | malware | 11 | 0 |
| [S0646 SpicyOmelette](https://attack.mitre.org/software/S0646/) ([local](/mitre/software/S0646.md)) | malware | 11 | 1 |
| [S0137 CORESHELL](https://attack.mitre.org/software/S0137/) ([local](/mitre/software/S0137.md)) | malware | 11 | 1 |
| [S0018 Sykipot](https://attack.mitre.org/software/S0018/) ([local](/mitre/software/S0018.md)) | malware | 11 | 0 |
| [S0452 USBferry](https://attack.mitre.org/software/S0452/) ([local](/mitre/software/S0452.md)) | malware | 11 | 1 |
| [S0574 BendyBear](https://attack.mitre.org/software/S0574/) ([local](/mitre/software/S0574.md)) | malware | 11 | 0 |
| [S0585 Kerrdown](https://attack.mitre.org/software/S0585/) ([local](/mitre/software/S0585.md)) | malware | 11 | 1 |
| [S0627 SodaMaster](https://attack.mitre.org/software/S0627/) ([local](/mitre/software/S0627.md)) | malware | 11 | 1 |
| [S0009 Hikit](https://attack.mitre.org/software/S0009/) ([local](/mitre/software/S0009.md)) | malware | 11 | 1 |
| [S0074 Sakula](https://attack.mitre.org/software/S0074/) ([local](/mitre/software/S0074.md)) | malware | 11 | 1 |
| [S0259 InnaputRAT](https://attack.mitre.org/software/S0259/) ([local](/mitre/software/S0259.md)) | malware | 11 | 0 |
| [S0351 Cannon](https://attack.mitre.org/software/S0351/) ([local](/mitre/software/S0351.md)) | malware | 11 | 1 |
| [S0070 HTTPBrowser](https://attack.mitre.org/software/S0070/) ([local](/mitre/software/S0070.md)) | malware | 11 | 2 |
| [S0281 Dok](https://attack.mitre.org/software/S0281/) ([local](/mitre/software/S0281.md)) | malware | 11 | 0 |
| [S0521 BloodHound](https://attack.mitre.org/software/S0521/) ([local](/mitre/software/S0521.md)) | tool | 11 | 6 |
| [S0357 Impacket](https://attack.mitre.org/software/S0357/) ([local](/mitre/software/S0357.md)) | tool | 11 | 18 |
| [S0543 Spark](https://attack.mitre.org/software/S0543/) ([local](/mitre/software/S0543.md)) | malware | 10 | 1 |
| [S1233 PAKLOG](https://attack.mitre.org/software/S1233/) ([local](/mitre/software/S1233.md)) | malware | 10 | 1 |
| [S1187 reGeorg](https://attack.mitre.org/software/S1187/) ([local](/mitre/software/S1187.md)) | malware | 10 | 3 |
| [S0171 Felismus](https://attack.mitre.org/software/S0171/) ([local](/mitre/software/S0171.md)) | malware | 10 | 1 |
| [S0167 Matryoshka](https://attack.mitre.org/software/S0167/) ([local](/mitre/software/S0167.md)) | malware | 10 | 1 |
| [S0088 Kasidet](https://attack.mitre.org/software/S0088/) ([local](/mitre/software/S0088.md)) | malware | 10 | 0 |
| [S0518 PolyglotDuke](https://attack.mitre.org/software/S0518/) ([local](/mitre/software/S0518.md)) | malware | 10 | 1 |
| [S1029 AuTo Stealer](https://attack.mitre.org/software/S1029/) ([local](/mitre/software/S1029.md)) | malware | 10 | 1 |
| [S1133 Apostle](https://attack.mitre.org/software/S1133/) ([local](/mitre/software/S1133.md)) | malware | 10 | 1 |
| [S0642 BADFLICK](https://attack.mitre.org/software/S0642/) ([local](/mitre/software/S0642.md)) | malware | 10 | 1 |
| [S0161 XAgentOSX](https://attack.mitre.org/software/S0161/) ([local](/mitre/software/S0161.md)) | malware | 10 | 1 |
| [S0020 China Chopper](https://attack.mitre.org/software/S0020/) ([local](/mitre/software/S0020.md)) | malware | 10 | 9 |
| [S0253 RunningRAT](https://attack.mitre.org/software/S0253/) ([local](/mitre/software/S0253.md)) | malware | 10 | 0 |
| [S0090 Rover](https://attack.mitre.org/software/S0090/) ([local](/mitre/software/S0090.md)) | malware | 10 | 0 |
| [S1129 Akira](https://attack.mitre.org/software/S1129/) ([local](/mitre/software/S1129.md)) | malware | 10 | 1 |
| [S0472 down_new](https://attack.mitre.org/software/S0472/) ([local](/mitre/software/S0472.md)) | malware | 10 | 1 |
| [S1168 SampleCheck5000](https://attack.mitre.org/software/S1168/) ([local](/mitre/software/S1168.md)) | malware | 10 | 1 |
| [S0345 Seasalt](https://attack.mitre.org/software/S0345/) ([local](/mitre/software/S0345.md)) | malware | 10 | 1 |
| [S0017 BISCUIT](https://attack.mitre.org/software/S0017/) ([local](/mitre/software/S0017.md)) | malware | 10 | 1 |
| [S1222 RIFLESPINE](https://attack.mitre.org/software/S1222/) ([local](/mitre/software/S1222.md)) | malware | 10 | 1 |
| [S1156 Manjusaka](https://attack.mitre.org/software/S1156/) ([local](/mitre/software/S1156.md)) | malware | 10 | 0 |
| [S1134 DEADWOOD](https://attack.mitre.org/software/S1134/) ([local](/mitre/software/S1134.md)) | malware | 10 | 2 |
| [S0165 OSInfo](https://attack.mitre.org/software/S0165/) ([local](/mitre/software/S0165.md)) | malware | 10 | 1 |
| [S0275 UPPERCUT](https://attack.mitre.org/software/S0275/) ([local](/mitre/software/S0275.md)) | malware | 10 | 1 |
| [S0394 HiddenWasp](https://attack.mitre.org/software/S0394/) ([local](/mitre/software/S0394.md)) | malware | 10 | 0 |
| [S0143 Flame](https://attack.mitre.org/software/S0143/) ([local](/mitre/software/S0143.md)) | malware | 10 | 0 |
| [S1155 Covenant](https://attack.mitre.org/software/S1155/) ([local](/mitre/software/S1155.md)) | tool | 10 | 1 |
| [S1144 FRP](https://attack.mitre.org/software/S1144/) ([local](/mitre/software/S1144.md)) | tool | 10 | 3 |
| [S0500 MCMD](https://attack.mitre.org/software/S0500/) ([local](/mitre/software/S0500.md)) | tool | 10 | 1 |
| [S0349 LaZagne](https://attack.mitre.org/software/S0349/) ([local](/mitre/software/S0349.md)) | tool | 10 | 12 |
| [S0605 EKANS](https://attack.mitre.org/software/S0605/) ([local](/mitre/software/S0605.md)) | malware | 9 | 0 |
| [S0686 QuietSieve](https://attack.mitre.org/software/S0686/) ([local](/mitre/software/S0686.md)) | malware | 9 | 1 |
| [S0233 MURKYTOP](https://attack.mitre.org/software/S0233/) ([local](/mitre/software/S0233.md)) | malware | 9 | 1 |
| [S1193 TAMECAT](https://attack.mitre.org/software/S1193/) ([local](/mitre/software/S1193.md)) | malware | 9 | 1 |
| [S1058 Prestige](https://attack.mitre.org/software/S1058/) ([local](/mitre/software/S1058.md)) | malware | 9 | 1 |
| [S0254 PLAINTEE](https://attack.mitre.org/software/S0254/) ([local](/mitre/software/S0254.md)) | malware | 9 | 1 |
| [S0347 AuditCred](https://attack.mitre.org/software/S0347/) ([local](/mitre/software/S0347.md)) | malware | 9 | 1 |
| [S0058 SslMM](https://attack.mitre.org/software/S0058/) ([local](/mitre/software/S0058.md)) | malware | 9 | 1 |
| [S1152 IMAPLoader](https://attack.mitre.org/software/S1152/) ([local](/mitre/software/S1152.md)) | malware | 9 | 1 |
| [S1012 PowerLess](https://attack.mitre.org/software/S1012/) ([local](/mitre/software/S1012.md)) | malware | 9 | 1 |
| [S0497 Dacls](https://attack.mitre.org/software/S0497/) ([local](/mitre/software/S0497.md)) | malware | 9 | 1 |
| [S0547 DropBook](https://attack.mitre.org/software/S0547/) ([local](/mitre/software/S0547.md)) | malware | 9 | 1 |
| [S1170 ODAgent](https://attack.mitre.org/software/S1170/) ([local](/mitre/software/S1170.md)) | malware | 9 | 1 |
| [S0433 Rifdoor](https://attack.mitre.org/software/S0433/) ([local](/mitre/software/S0433.md)) | malware | 9 | 1 |
| [S0511 RegDuke](https://attack.mitre.org/software/S0511/) ([local](/mitre/software/S0511.md)) | malware | 9 | 1 |
| [S0276 Keydnap](https://attack.mitre.org/software/S0276/) ([local](/mitre/software/S0276.md)) | malware | 9 | 0 |
| [S0486 Bonadan](https://attack.mitre.org/software/S0486/) ([local](/mitre/software/S0486.md)) | malware | 9 | 0 |
| [S1186 Line Dancer](https://attack.mitre.org/software/S1186/) ([local](/mitre/software/S1186.md)) | malware | 9 | 0 |
| [S0247 NavRAT](https://attack.mitre.org/software/S0247/) ([local](/mitre/software/S0247.md)) | malware | 9 | 1 |
| [S0087 Hi-Zor](https://attack.mitre.org/software/S0087/) ([local](/mitre/software/S0087.md)) | malware | 9 | 0 |
| [S0051 MiniDuke](https://attack.mitre.org/software/S0051/) ([local](/mitre/software/S0051.md)) | malware | 9 | 1 |
| [S1179 Exbyte](https://attack.mitre.org/software/S1179/) ([local](/mitre/software/S1179.md)) | malware | 9 | 1 |
| [S0616 DEATHRANSOM](https://attack.mitre.org/software/S0616/) ([local](/mitre/software/S0616.md)) | malware | 9 | 0 |
| [S0679 Ferocious](https://attack.mitre.org/software/S0679/) ([local](/mitre/software/S0679.md)) | malware | 9 | 1 |
| [S1047 Mori](https://attack.mitre.org/software/S1047/) ([local](/mitre/software/S1047.md)) | malware | 9 | 1 |
| [S1140 Spica](https://attack.mitre.org/software/S1140/) ([local](/mitre/software/S1140.md)) | malware | 9 | 1 |
| [S1021 DnsSystem](https://attack.mitre.org/software/S1021/) ([local](/mitre/software/S1021.md)) | malware | 9 | 1 |
| [S0261 Catchamas](https://attack.mitre.org/software/S0261/) ([local](/mitre/software/S0261.md)) | malware | 9 | 1 |
| [S0142 StreamEx](https://attack.mitre.org/software/S0142/) ([local](/mitre/software/S0142.md)) | malware | 9 | 1 |
| [S1076 QUIETCANARY](https://attack.mitre.org/software/S1076/) ([local](/mitre/software/S1076.md)) | malware | 9 | 0 |
| [S0515 WellMail](https://attack.mitre.org/software/S0515/) ([local](/mitre/software/S0515.md)) | malware | 9 | 1 |
| [S0176 Wingbird](https://attack.mitre.org/software/S0176/) ([local](/mitre/software/S0176.md)) | malware | 9 | 1 |
| [S0124 Pisloader](https://attack.mitre.org/software/S0124/) ([local](/mitre/software/S0124.md)) | malware | 9 | 1 |
| [S1110 SLIGHTPULSE](https://attack.mitre.org/software/S1110/) ([local](/mitre/software/S1110.md)) | malware | 9 | 1 |
| [S0369 CoinTicker](https://attack.mitre.org/software/S0369/) ([local](/mitre/software/S0369.md)) | malware | 9 | 0 |
| [S1114 ZIPLINE](https://attack.mitre.org/software/S1114/) ([local](/mitre/software/S1114.md)) | malware | 9 | 0 |
| [S1230 HIUPAN](https://attack.mitre.org/software/S1230/) ([local](/mitre/software/S1230.md)) | malware | 9 | 1 |
| [S1227 StarProxy](https://attack.mitre.org/software/S1227/) ([local](/mitre/software/S1227.md)) | malware | 9 | 1 |
| [S0211 Linfo](https://attack.mitre.org/software/S0211/) ([local](/mitre/software/S0211.md)) | malware | 9 | 1 |
| [S0282 MacSpy](https://attack.mitre.org/software/S0282/) ([local](/mitre/software/S0282.md)) | malware | 9 | 0 |
| [S0672 Zox](https://attack.mitre.org/software/S0672/) ([local](/mitre/software/S0672.md)) | malware | 9 | 1 |
| [S0181 FALLCHILL](https://attack.mitre.org/software/S0181/) ([local](/mitre/software/S0181.md)) | malware | 9 | 1 |
| [S0417 GRIFFON](https://attack.mitre.org/software/S0417/) ([local](/mitre/software/S0417.md)) | malware | 8 | 1 |
| [S0343 Exaramel for Windows](https://attack.mitre.org/software/S0343/) ([local](/mitre/software/S0343.md)) | malware | 8 | 1 |
| [S1154 VersaMem](https://attack.mitre.org/software/S1154/) ([local](/mitre/software/S1154.md)) | malware | 8 | 1 |
| [S1224 CASTLETAP](https://attack.mitre.org/software/S1224/) ([local](/mitre/software/S1224.md)) | malware | 8 | 1 |
| [S0346 OceanSalt](https://attack.mitre.org/software/S0346/) ([local](/mitre/software/S0346.md)) | malware | 8 | 0 |
| [S1203 J-magic](https://attack.mitre.org/software/S1203/) ([local](/mitre/software/S1203.md)) | malware | 8 | 0 |
| [S0671 Tomiris](https://attack.mitre.org/software/S0671/) ([local](/mitre/software/S0671.md)) | malware | 8 | 0 |
| [S0333 UBoatRAT](https://attack.mitre.org/software/S0333/) ([local](/mitre/software/S0333.md)) | malware | 8 | 0 |
| [S1033 DCSrv](https://attack.mitre.org/software/S1033/) ([local](/mitre/software/S1033.md)) | malware | 8 | 1 |
| [S0150 POSHSPY](https://attack.mitre.org/software/S0150/) ([local](/mitre/software/S0150.md)) | malware | 8 | 1 |
| [S1188 Line Runner](https://attack.mitre.org/software/S1188/) ([local](/mitre/software/S1188.md)) | malware | 8 | 0 |
| [S1232 SplatDropper](https://attack.mitre.org/software/S1232/) ([local](/mitre/software/S1232.md)) | malware | 8 | 1 |
| [S1051 KEYPLUG](https://attack.mitre.org/software/S1051/) ([local](/mitre/software/S1051.md)) | malware | 8 | 1 |
| [S0117 XTunnel](https://attack.mitre.org/software/S0117/) ([local](/mitre/software/S0117.md)) | malware | 8 | 1 |
| [S1023 CreepyDrive](https://attack.mitre.org/software/S1023/) ([local](/mitre/software/S1023.md)) | malware | 8 | 1 |
| [S0556 Pay2Key](https://attack.mitre.org/software/S0556/) ([local](/mitre/software/S0556.md)) | malware | 8 | 1 |
| [S0430 Winnti for Linux](https://attack.mitre.org/software/S0430/) ([local](/mitre/software/S0430.md)) | malware | 8 | 3 |
| [S1151 ZeroCleare](https://attack.mitre.org/software/S1151/) ([local](/mitre/software/S1151.md)) | malware | 8 | 1 |
| [S0390 SQLRat](https://attack.mitre.org/software/S0390/) ([local](/mitre/software/S0390.md)) | malware | 8 | 1 |
| [S0443 MESSAGETAP](https://attack.mitre.org/software/S0443/) ([local](/mitre/software/S0443.md)) | malware | 8 | 1 |
| [S0245 BADCALL](https://attack.mitre.org/software/S0245/) ([local](/mitre/software/S0245.md)) | malware | 8 | 1 |
| [S1235 CorKLOG](https://attack.mitre.org/software/S1235/) ([local](/mitre/software/S1235.md)) | malware | 8 | 1 |
| [S0072 OwaAuth](https://attack.mitre.org/software/S0072/) ([local](/mitre/software/S0072.md)) | malware | 8 | 0 |
| [S0454 Cadelspy](https://attack.mitre.org/software/S0454/) ([local](/mitre/software/S0454.md)) | malware | 8 | 1 |
| [S0338 Cobian RAT](https://attack.mitre.org/software/S0338/) ([local](/mitre/software/S0338.md)) | malware | 8 | 0 |
| [S0130 Unknown Logger](https://attack.mitre.org/software/S0130/) ([local](/mitre/software/S0130.md)) | malware | 8 | 1 |
| [S1166 Solar](https://attack.mitre.org/software/S1166/) ([local](/mitre/software/S1166.md)) | malware | 8 | 1 |
| [S1189 Neo-reGeorg](https://attack.mitre.org/software/S1189/) ([local](/mitre/software/S1189.md)) | malware | 8 | 1 |
| [S1107 NKAbuse](https://attack.mitre.org/software/S1107/) ([local](/mitre/software/S1107.md)) | malware | 8 | 0 |
| [S0004 TinyZBot](https://attack.mitre.org/software/S0004/) ([local](/mitre/software/S0004.md)) | malware | 8 | 1 |
| [S1046 PowGoop](https://attack.mitre.org/software/S1046/) ([local](/mitre/software/S1046.md)) | malware | 8 | 1 |
| [S0471 build_downer](https://attack.mitre.org/software/S0471/) ([local](/mitre/software/S0471.md)) | malware | 8 | 1 |
| [S0459 MechaFlounder](https://attack.mitre.org/software/S0459/) ([local](/mitre/software/S0459.md)) | malware | 8 | 1 |
| [S0208 Pasam](https://attack.mitre.org/software/S0208/) ([local](/mitre/software/S0208.md)) | malware | 8 | 1 |
| [S0618 FIVEHANDS](https://attack.mitre.org/software/S0618/) ([local](/mitre/software/S0618.md)) | malware | 8 | 0 |
| [S0581 IronNetInjector](https://attack.mitre.org/software/S0581/) ([local](/mitre/software/S0581.md)) | tool | 8 | 1 |
| [S1121 LITTLELAMB.WOOLTEA](https://attack.mitre.org/software/S1121/) ([local](/mitre/software/S1121.md)) | malware | 7 | 0 |
| [S1211 Hannotog](https://attack.mitre.org/software/S1211/) ([local](/mitre/software/S1211.md)) | malware | 7 | 1 |
| [S0252 Brave Prince](https://attack.mitre.org/software/S0252/) ([local](/mitre/software/S0252.md)) | malware | 7 | 1 |
| [S0278 iKitten](https://attack.mitre.org/software/S0278/) ([local](/mitre/software/S0278.md)) | malware | 7 | 0 |
| [S0037 HAMMERTOSS](https://attack.mitre.org/software/S0037/) ([local](/mitre/software/S0037.md)) | malware | 7 | 1 |
| [S0079 MobileOrder](https://attack.mitre.org/software/S0079/) ([local](/mitre/software/S0079.md)) | malware | 7 | 1 |
| [S0654 ProLock](https://attack.mitre.org/software/S0654/) ([local](/mitre/software/S0654.md)) | malware | 7 | 0 |
| [S0219 WINERACK](https://attack.mitre.org/software/S0219/) ([local](/mitre/software/S0219.md)) | malware | 7 | 1 |
| [S0277 FruitFly](https://attack.mitre.org/software/S0277/) ([local](/mitre/software/S0277.md)) | malware | 7 | 0 |
| [S1167 AcidPour](https://attack.mitre.org/software/S1167/) ([local](/mitre/software/S1167.md)) | malware | 7 | 1 |
| [S0565 Raindrop](https://attack.mitre.org/software/S0565/) ([local](/mitre/software/S0565.md)) | malware | 7 | 1 |
| [S0372 LockerGoga](https://attack.mitre.org/software/S0372/) ([local](/mitre/software/S0372.md)) | malware | 7 | 1 |
| [S0643 Peppy](https://attack.mitre.org/software/S0643/) ([local](/mitre/software/S0643.md)) | malware | 7 | 1 |
| [S0450 SHARPSTATS](https://attack.mitre.org/software/S0450/) ([local](/mitre/software/S0450.md)) | malware | 7 | 1 |
| [S0553 MoleNet](https://attack.mitre.org/software/S0553/) ([local](/mitre/software/S0553.md)) | malware | 7 | 1 |
| [S1011 Tarrask](https://attack.mitre.org/software/S1011/) ([local](/mitre/software/S1011.md)) | malware | 7 | 1 |
| [S0498 Cryptoistic](https://attack.mitre.org/software/S0498/) ([local](/mitre/software/S0498.md)) | malware | 7 | 1 |
| [S0469 ABK](https://attack.mitre.org/software/S0469/) ([local](/mitre/software/S0469.md)) | malware | 7 | 1 |
| [S0389 JCry](https://attack.mitre.org/software/S0389/) ([local](/mitre/software/S0389.md)) | malware | 7 | 0 |
| [S0048 PinchDuke](https://attack.mitre.org/software/S0048/) ([local](/mitre/software/S0048.md)) | malware | 7 | 1 |
| [S0437 Kivars](https://attack.mitre.org/software/S0437/) ([local](/mitre/software/S0437.md)) | malware | 7 | 1 |
| [S0693 CaddyWiper](https://attack.mitre.org/software/S0693/) ([local](/mitre/software/S0693.md)) | malware | 7 | 0 |
| [S0258 RGDoor](https://attack.mitre.org/software/S0258/) ([local](/mitre/software/S0258.md)) | malware | 7 | 1 |
| [S1120 FRAMESTING](https://attack.mitre.org/software/S1120/) ([local](/mitre/software/S1120.md)) | malware | 7 | 0 |
| [S1115 WIREFIRE](https://attack.mitre.org/software/S1115/) ([local](/mitre/software/S1115.md)) | malware | 7 | 0 |
| [S1024 CreepySnail](https://attack.mitre.org/software/S1024/) ([local](/mitre/software/S1024.md)) | malware | 7 | 1 |
| [S0360 BONDUPDATER](https://attack.mitre.org/software/S0360/) ([local](/mitre/software/S0360.md)) | malware | 7 | 1 |
| [S0069 BLACKCOFFEE](https://attack.mitre.org/software/S0069/) ([local](/mitre/software/S0069.md)) | malware | 7 | 3 |
| [S1074 ANDROMEDA](https://attack.mitre.org/software/S1074/) ([local](/mitre/software/S1074.md)) | malware | 7 | 0 |
| [S0200 Dipsind](https://attack.mitre.org/software/S0200/) ([local](/mitre/software/S0200.md)) | malware | 7 | 1 |
| [S0186 DownPaper](https://attack.mitre.org/software/S0186/) ([local](/mitre/software/S0186.md)) | malware | 7 | 1 |
| [S0470 BBK](https://attack.mitre.org/software/S0470/) ([local](/mitre/software/S0470.md)) | malware | 7 | 1 |
| [S0162 Komplex](https://attack.mitre.org/software/S0162/) ([local](/mitre/software/S0162.md)) | malware | 7 | 1 |
| [S0648 JSS Loader](https://attack.mitre.org/software/S0648/) ([local](/mitre/software/S0648.md)) | malware | 7 | 1 |
| [S1131 NPPSPY](https://attack.mitre.org/software/S1131/) ([local](/mitre/software/S1131.md)) | tool | 7 | 0 |
| [S1206 JumbledPath](https://attack.mitre.org/software/S1206/) ([local](/mitre/software/S1206.md)) | malware | 6 | 1 |
| [S0213 DOGCALL](https://attack.mitre.org/software/S0213/) ([local](/mitre/software/S0213.md)) | malware | 6 | 1 |
| [S0460 Get2](https://attack.mitre.org/software/S0460/) ([local](/mitre/software/S0460.md)) | malware | 6 | 1 |
| [S0400 RobbinHood](https://attack.mitre.org/software/S0400/) ([local](/mitre/software/S0400.md)) | malware | 6 | 0 |
| [S0151 HALFBAKED](https://attack.mitre.org/software/S0151/) ([local](/mitre/software/S0151.md)) | malware | 6 | 1 |
| [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362/) ([local](/mitre/software/S0362.md)) | malware | 6 | 0 |
| [S0145 POWERSOURCE](https://attack.mitre.org/software/S0145/) ([local](/mitre/software/S0145.md)) | malware | 6 | 1 |
| [S0049 GeminiDuke](https://attack.mitre.org/software/S0049/) ([local](/mitre/software/S0049.md)) | malware | 6 | 1 |
| [S0462 CARROTBAT](https://attack.mitre.org/software/S0462/) ([local](/mitre/software/S0462.md)) | malware | 6 | 0 |
| [S0059 WinMM](https://attack.mitre.org/software/S0059/) ([local](/mitre/software/S0059.md)) | malware | 6 | 1 |
| [S1118 BUSHWALK](https://attack.mitre.org/software/S1118/) ([local](/mitre/software/S1118.md)) | malware | 6 | 0 |
| [S0537 HyperStack](https://attack.mitre.org/software/S0537/) ([local](/mitre/software/S0537.md)) | malware | 6 | 1 |
| [S0138 OLDBAIT](https://attack.mitre.org/software/S0138/) ([local](/mitre/software/S0138.md)) | malware | 6 | 1 |
| [S0560 TEARDROP](https://attack.mitre.org/software/S0560/) ([local](/mitre/software/S0560.md)) | malware | 6 | 1 |
| [S1158 DUSTPAN](https://attack.mitre.org/software/S1158/) ([local](/mitre/software/S1158.md)) | malware | 6 | 1 |
| [S1237 CANONSTAGER](https://attack.mitre.org/software/S1237/) ([local](/mitre/software/S1237.md)) | malware | 6 | 1 |
| [S0092 Agent.btz](https://attack.mitre.org/software/S0092/) ([local](/mitre/software/S0092.md)) | malware | 6 | 0 |
| [S0036 FLASHFLOOD](https://attack.mitre.org/software/S0036/) ([local](/mitre/software/S0036.md)) | malware | 6 | 1 |
| [S1049 SUGARUSH](https://attack.mitre.org/software/S1049/) ([local](/mitre/software/S1049.md)) | malware | 6 | 0 |
| [S1101 LoFiSe](https://attack.mitre.org/software/S1101/) ([local](/mitre/software/S1101.md)) | malware | 6 | 1 |
| [S1191 Megazord](https://attack.mitre.org/software/S1191/) ([local](/mitre/software/S1191.md)) | malware | 6 | 1 |
| [S0216 POORAIM](https://attack.mitre.org/software/S0216/) ([local](/mitre/software/S0216.md)) | malware | 6 | 1 |
| [S0063 SHOTPUT](https://attack.mitre.org/software/S0063/) ([local](/mitre/software/S0063.md)) | malware | 6 | 1 |
| [S0617 HELLOKITTY](https://attack.mitre.org/software/S0617/) ([local](/mitre/software/S0617.md)) | malware | 6 | 0 |
| [S0614 CostaBricks](https://attack.mitre.org/software/S0614/) ([local](/mitre/software/S0614.md)) | malware | 6 | 0 |
| [S0564 BlackMould](https://attack.mitre.org/software/S0564/) ([local](/mitre/software/S0564.md)) | malware | 6 | 1 |
| [S1109 PACEMAKER](https://attack.mitre.org/software/S1109/) ([local](/mitre/software/S1109.md)) | malware | 6 | 1 |
| [S1218 VIRTUALPIE](https://attack.mitre.org/software/S1218/) ([local](/mitre/software/S1218.md)) | malware | 6 | 1 |
| [S0060 Sys10](https://attack.mitre.org/software/S0060/) ([local](/mitre/software/S0060.md)) | malware | 6 | 1 |
| [S0035 SPACESHIP](https://attack.mitre.org/software/S0035/) ([local](/mitre/software/S0035.md)) | malware | 6 | 1 |
| [S0065 4H RAT](https://attack.mitre.org/software/S0065/) ([local](/mitre/software/S0065.md)) | malware | 6 | 1 |
| [S1194 Akira _v2](https://attack.mitre.org/software/S1194/) ([local](/mitre/software/S1194.md)) | malware | 6 | 1 |
| [S0355 Final1stspy](https://attack.mitre.org/software/S0355/) ([local](/mitre/software/S0355.md)) | malware | 6 | 1 |
| [S0637 NativeZone](https://attack.mitre.org/software/S0637/) ([local](/mitre/software/S0637.md)) | malware | 6 | 1 |
| [S1221 MOPSLED](https://attack.mitre.org/software/S1221/) ([local](/mitre/software/S1221.md)) | malware | 6 | 2 |
| [S0388 YAHOYAH](https://attack.mitre.org/software/S0388/) ([local](/mitre/software/S0388.md)) | malware | 6 | 1 |
| [S0199 TURNEDUP](https://attack.mitre.org/software/S0199/) ([local](/mitre/software/S0199.md)) | malware | 6 | 1 |
| [S0371 POWERTON](https://attack.mitre.org/software/S0371/) ([local](/mitre/software/S0371.md)) | malware | 6 | 1 |
| [S0593 ECCENTRICBANDWAGON](https://attack.mitre.org/software/S0593/) ([local](/mitre/software/S0593.md)) | malware | 6 | 2 |
| [S1234 SplatCloak](https://attack.mitre.org/software/S1234/) ([local](/mitre/software/S1234.md)) | malware | 6 | 1 |
| [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104/) ([local](/mitre/software/S1104.md)) | malware | 6 | 1 |
| [S1040 Rclone](https://attack.mitre.org/software/S1040/) ([local](/mitre/software/S1040.md)) | tool | 6 | 7 |
| [S0684 ROADTools](https://attack.mitre.org/software/S0684/) ([local](/mitre/software/S0684.md)) | tool | 6 | 1 |
| [S0106 cmd](https://attack.mitre.org/software/S0106/) ([local](/mitre/software/S0106.md)) | tool | 6 | 6 |
| [S0404 esentutl](https://attack.mitre.org/software/S0404/) ([local](/mitre/software/S0404.md)) | tool | 6 | 3 |
| [S1192 NICECURL](https://attack.mitre.org/software/S1192/) ([local](/mitre/software/S1192.md)) | malware | 5 | 1 |
| [S0134 Downdelph](https://attack.mitre.org/software/S0134/) ([local](/mitre/software/S0134.md)) | malware | 5 | 1 |
| [S0164 TDTESS](https://attack.mitre.org/software/S0164/) ([local](/mitre/software/S0164.md)) | malware | 5 | 1 |
| [S1041 Chinoxy](https://attack.mitre.org/software/S1041/) ([local](/mitre/software/S1041.md)) | malware | 5 | 0 |
| [S0613 PS1](https://attack.mitre.org/software/S0613/) ([local](/mitre/software/S0613.md)) | malware | 5 | 0 |
| [S0503 FrameworkPOS](https://attack.mitre.org/software/S0503/) ([local](/mitre/software/S0503.md)) | malware | 5 | 1 |
| [S0624 Ecipekac](https://attack.mitre.org/software/S0624/) ([local](/mitre/software/S0624.md)) | malware | 5 | 1 |
| [S1173 PowerExchange](https://attack.mitre.org/software/S1173/) ([local](/mitre/software/S1173.md)) | malware | 5 | 1 |
| [S0152 EvilGrab](https://attack.mitre.org/software/S0152/) ([local](/mitre/software/S0152.md)) | malware | 5 | 1 |
| [S1238 STATICPLUGIN](https://attack.mitre.org/software/S1238/) ([local](/mitre/software/S1238.md)) | malware | 5 | 1 |
| [S1223 THINCRUST](https://attack.mitre.org/software/S1223/) ([local](/mitre/software/S1223.md)) | malware | 5 | 1 |
| [S0221 Umbreon](https://attack.mitre.org/software/S0221/) ([local](/mitre/software/S0221.md)) | malware | 5 | 0 |
| [S1084 QUIETEXIT](https://attack.mitre.org/software/S1084/) ([local](/mitre/software/S1084.md)) | malware | 5 | 1 |
| [S0370 SamSam](https://attack.mitre.org/software/S0370/) ([local](/mitre/software/S0370.md)) | malware | 5 | 0 |
| [S0415 BOOSTWRITE](https://attack.mitre.org/software/S0415/) ([local](/mitre/software/S0415.md)) | malware | 5 | 1 |
| [S1163 SnappyTCP](https://attack.mitre.org/software/S1163/) ([local](/mitre/software/S1163.md)) | malware | 5 | 1 |
| [S0220 Chaos](https://attack.mitre.org/software/S0220/) ([local](/mitre/software/S0220.md)) | malware | 5 | 0 |
| [S1096 Cheerscrypt](https://attack.mitre.org/software/S1096/) ([local](/mitre/software/S1096.md)) | malware | 5 | 1 |
| [S1119 LIGHTWIRE](https://attack.mitre.org/software/S1119/) ([local](/mitre/software/S1119.md)) | malware | 5 | 0 |
| [S1143 LunarLoader](https://attack.mitre.org/software/S1143/) ([local](/mitre/software/S1143.md)) | malware | 5 | 1 |
| [S1106 NGLite](https://attack.mitre.org/software/S1106/) ([local](/mitre/software/S1106.md)) | malware | 5 | 0 |
| [S0626 P8RAT](https://attack.mitre.org/software/S0626/) ([local](/mitre/software/S0626.md)) | malware | 5 | 1 |
| [S0442 VBShower](https://attack.mitre.org/software/S0442/) ([local](/mitre/software/S0442.md)) | malware | 5 | 1 |
| [S0169 RawPOS](https://attack.mitre.org/software/S0169/) ([local](/mitre/software/S0169.md)) | malware | 5 | 1 |
| [S0155 WINDSHIELD](https://attack.mitre.org/software/S0155/) ([local](/mitre/software/S0155.md)) | malware | 5 | 1 |
| [S0157 SOUNDBITE](https://attack.mitre.org/software/S0157/) ([local](/mitre/software/S0157.md)) | malware | 5 | 1 |
| [S1116 WARPWIRE](https://attack.mitre.org/software/S1116/) ([local](/mitre/software/S1116.md)) | malware | 5 | 0 |
| [S0235 CrossRAT](https://attack.mitre.org/software/S0235/) ([local](/mitre/software/S0235.md)) | malware | 5 | 1 |
| [S0052 OnionDuke](https://attack.mitre.org/software/S0052/) ([local](/mitre/software/S0052.md)) | malware | 5 | 1 |
| [S0578 SUPERNOVA](https://attack.mitre.org/software/S0578/) ([local](/mitre/software/S0578.md)) | malware | 5 | 0 |
| [S0397 LoJax](https://attack.mitre.org/software/S0397/) ([local](/mitre/software/S0397.md)) | malware | 5 | 1 |
| [S0246 HARDRAIN](https://attack.mitre.org/software/S0246/) ([local](/mitre/software/S0246.md)) | malware | 5 | 1 |
| [S0682 TrailBlazer](https://attack.mitre.org/software/S0682/) ([local](/mitre/software/S0682.md)) | malware | 5 | 1 |
| [S1112 STEADYPULSE](https://attack.mitre.org/software/S1112/) ([local](/mitre/software/S1112.md)) | malware | 5 | 0 |
| [S0272 NDiskMonitor](https://attack.mitre.org/software/S0272/) ([local](/mitre/software/S0272.md)) | malware | 5 | 1 |
| [S1123 PITSTOP](https://attack.mitre.org/software/S1123/) ([local](/mitre/software/S1123.md)) | malware | 5 | 0 |
| [S0393 PowerStallion](https://attack.mitre.org/software/S0393/) ([local](/mitre/software/S0393.md)) | malware | 5 | 1 |
| [S0078 Psylo](https://attack.mitre.org/software/S0078/) ([local](/mitre/software/S0078.md)) | malware | 5 | 1 |
| [S1088 Disco](https://attack.mitre.org/software/S1088/) ([local](/mitre/software/S1088.md)) | malware | 5 | 1 |
| [S0280 MirageFox](https://attack.mitre.org/software/S0280/) ([local](/mitre/software/S0280.md)) | malware | 5 | 1 |
| [S0273 Socksbot](https://attack.mitre.org/software/S0273/) ([local](/mitre/software/S0273.md)) | malware | 5 | 0 |
| [S0464 SYSCON](https://attack.mitre.org/software/S0464/) ([local](/mitre/software/S0464.md)) | malware | 5 | 0 |
| [S0508 ngrok](https://attack.mitre.org/software/S0508/) ([local](/mitre/software/S0508.md)) | tool | 5 | 5 |
| [S0594 Out1](https://attack.mitre.org/software/S0594/) ([local](/mitre/software/S0594.md)) | tool | 5 | 1 |
| [S0590 NBTscan](https://attack.mitre.org/software/S0590/) ([local](/mitre/software/S0590.md)) | tool | 5 | 10 |
| [S1071 Rubeus](https://attack.mitre.org/software/S1071/) ([local](/mitre/software/S1071.md)) | tool | 5 | 1 |
| [S0552 AdFind](https://attack.mitre.org/software/S0552/) ([local](/mitre/software/S0552.md)) | tool | 5 | 12 |
| [S0029 PsExec](https://attack.mitre.org/software/S0029/) ([local](/mitre/software/S0029.md)) | tool | 5 | 38 |
| [S1204 cd00r](https://attack.mitre.org/software/S1204/) ([local](/mitre/software/S1204.md)) | malware | 4 | 0 |
| [S0206 Wiarp](https://attack.mitre.org/software/S0206/) ([local](/mitre/software/S0206.md)) | malware | 4 | 1 |
| [S1125 AcidRain](https://attack.mitre.org/software/S1125/) ([local](/mitre/software/S1125.md)) | malware | 4 | 1 |
| [S0185 SEASHARPEE](https://attack.mitre.org/software/S0185/) ([local](/mitre/software/S0185.md)) | malware | 4 | 1 |
| [S1220 MEDUSA](https://attack.mitre.org/software/S1220/) ([local](/mitre/software/S1220.md)) | malware | 4 | 1 |
| [S0163 Janicab](https://attack.mitre.org/software/S0163/) ([local](/mitre/software/S0163.md)) | malware | 4 | 0 |
| [S0159 SNUGRIDE](https://attack.mitre.org/software/S0159/) ([local](/mitre/software/S0159.md)) | malware | 4 | 1 |
| [S0215 KARAE](https://attack.mitre.org/software/S0215/) ([local](/mitre/software/S0215.md)) | malware | 4 | 1 |
| [S0628 FYAnti](https://attack.mitre.org/software/S0628/) ([local](/mitre/software/S0628.md)) | malware | 4 | 1 |
| [S0205 Naid](https://attack.mitre.org/software/S0205/) ([local](/mitre/software/S0205.md)) | malware | 4 | 1 |
| [S1117 GLASSTOKEN](https://attack.mitre.org/software/S1117/) ([local](/mitre/software/S1117.md)) | malware | 4 | 0 |
| [S0189 ISMInjector](https://attack.mitre.org/software/S0189/) ([local](/mitre/software/S0189.md)) | malware | 4 | 1 |
| [S0204 Briba](https://attack.mitre.org/software/S0204/) ([local](/mitre/software/S0204.md)) | malware | 4 | 1 |
| [S0066 3PARA RAT](https://attack.mitre.org/software/S0066/) ([local](/mitre/software/S0066.md)) | malware | 4 | 1 |
| [S0131 TINYTYPHON](https://attack.mitre.org/software/S0131/) ([local](/mitre/software/S0131.md)) | malware | 4 | 1 |
| [S1113 RAPIDPULSE](https://attack.mitre.org/software/S1113/) ([local](/mitre/software/S1113.md)) | malware | 4 | 1 |
| [S0055 RARSTONE](https://attack.mitre.org/software/S0055/) ([local](/mitre/software/S0055.md)) | malware | 4 | 1 |
| [S0636 VaporRage](https://attack.mitre.org/software/S0636/) ([local](/mitre/software/S0636.md)) | malware | 4 | 1 |
| [S1108 PULSECHECK](https://attack.mitre.org/software/S1108/) ([local](/mitre/software/S1108.md)) | malware | 4 | 1 |
| [S0076 FakeM](https://attack.mitre.org/software/S0076/) ([local](/mitre/software/S0076.md)) | malware | 4 | 1 |
| [S0210 Nerex](https://attack.mitre.org/software/S0210/) ([local](/mitre/software/S0210.md)) | malware | 4 | 1 |
| [S0077 CallMe](https://attack.mitre.org/software/S0077/) ([local](/mitre/software/S0077.md)) | malware | 4 | 1 |
| [S0255 DDKONG](https://attack.mitre.org/software/S0255/) ([local](/mitre/software/S0255.md)) | malware | 4 | 1 |
| [S0685 PowerPunch](https://attack.mitre.org/software/S0685/) ([local](/mitre/software/S0685.md)) | malware | 4 | 1 |
| [S1136 BFG Agonizer](https://attack.mitre.org/software/S1136/) ([local](/mitre/software/S1136.md)) | malware | 4 | 1 |
| [S1102 Pcexter](https://attack.mitre.org/software/S1102/) ([local](/mitre/software/S1102.md)) | malware | 4 | 1 |
| [S0207 Vasport](https://attack.mitre.org/software/S0207/) ([local](/mitre/software/S0207.md)) | malware | 4 | 1 |
| [S0129 AutoIt backdoor](https://attack.mitre.org/software/S0129/) ([local](/mitre/software/S0129.md)) | malware | 4 | 2 |
| [S0080 Mivast](https://attack.mitre.org/software/S0080/) ([local](/mitre/software/S0080.md)) | malware | 4 | 1 |
| [S0056 Net Crawler](https://attack.mitre.org/software/S0056/) ([local](/mitre/software/S0056.md)) | malware | 4 | 1 |
| [S0592 RemoteUtilities](https://attack.mitre.org/software/S0592/) ([local](/mitre/software/S0592.md)) | tool | 4 | 1 |
| [S0160 certutil](https://attack.mitre.org/software/S0160/) ([local](/mitre/software/S0160.md)) | tool | 4 | 13 |
| [S0105 dsquery](https://attack.mitre.org/software/S0105/) ([local](/mitre/software/S0105.md)) | tool | 4 | 2 |
| [S0108 netsh](https://attack.mitre.org/software/S0108/) ([local](/mitre/software/S0108.md)) | tool | 4 | 7 |
| [S0465 CARROTBALL](https://attack.mitre.org/software/S0465/) ([local](/mitre/software/S0465.md)) | tool | 4 | 0 |
| [S0190 BITSAdmin](https://attack.mitre.org/software/S0190/) ([local](/mitre/software/S0190.md)) | tool | 4 | 8 |
| [S0358 Ruler](https://attack.mitre.org/software/S0358/) ([local](/mitre/software/S0358.md)) | tool | 4 | 1 |
| [S0416 RDFSNIFFER](https://attack.mitre.org/software/S0416/) ([local](/mitre/software/S0416.md)) | malware | 3 | 1 |
| [S0202 adbupd](https://attack.mitre.org/software/S0202/) ([local](/mitre/software/S0202.md)) | malware | 3 | 1 |
| [S0043 BUBBLEWRAP](https://attack.mitre.org/software/S0043/) ([local](/mitre/software/S0043.md)) | malware | 3 | 1 |
| [S0109 WEBC2](https://attack.mitre.org/software/S0109/) ([local](/mitre/software/S0109.md)) | malware | 3 | 1 |
| [S0214 HAPPYWORK](https://attack.mitre.org/software/S0214/) ([local](/mitre/software/S0214.md)) | malware | 3 | 1 |
| [S1162 Playcrypt](https://attack.mitre.org/software/S1162/) ([local](/mitre/software/S1162.md)) | malware | 3 | 1 |
| [S0042 LOWBALL](https://attack.mitre.org/software/S0042/) ([local](/mitre/software/S0042.md)) | malware | 3 | 1 |
| [S0064 ELMER](https://attack.mitre.org/software/S0064/) ([local](/mitre/software/S0064.md)) | malware | 3 | 1 |
| [S0218 SLOWDRIFT](https://attack.mitre.org/software/S0218/) ([local](/mitre/software/S0218.md)) | malware | 3 | 1 |
| [S0217 SHUTTERSPEED](https://attack.mitre.org/software/S0217/) ([local](/mitre/software/S0217.md)) | malware | 3 | 1 |
| [S0166 RemoteCMD](https://attack.mitre.org/software/S0166/) ([local](/mitre/software/S0166.md)) | malware | 3 | 1 |
| [S1097 HUI Loader](https://attack.mitre.org/software/S1097/) ([local](/mitre/software/S1097.md)) | malware | 3 | 2 |
| [S0232 HOMEFRY](https://attack.mitre.org/software/S0232/) ([local](/mitre/software/S0232.md)) | malware | 3 | 1 |
| [S0156 KOMPROGO](https://attack.mitre.org/software/S0156/) ([local](/mitre/software/S0156.md)) | malware | 3 | 1 |
| [S0067 pngdowner](https://attack.mitre.org/software/S0067/) ([local](/mitre/software/S0067.md)) | malware | 3 | 1 |
| [S0519 SYNful Knock](https://attack.mitre.org/software/S0519/) ([local](/mitre/software/S0519.md)) | malware | 3 | 0 |
| [S0212 CORALDECK](https://attack.mitre.org/software/S0212/) ([local](/mitre/software/S0212.md)) | malware | 3 | 1 |
| [S0243 DealersChoice](https://attack.mitre.org/software/S0243/) ([local](/mitre/software/S0243.md)) | malware | 3 | 1 |
| [S1197 GoBear](https://attack.mitre.org/software/S1197/) ([local](/mitre/software/S1197.md)) | malware | 3 | 1 |
| [S0118 Nidiran](https://attack.mitre.org/software/S0118/) ([local](/mitre/software/S0118.md)) | malware | 3 | 1 |
| [S1171 OilCheck](https://attack.mitre.org/software/S1171/) ([local](/mitre/software/S1171.md)) | malware | 3 | 1 |
| [S0028 SHIPSHAPE](https://attack.mitre.org/software/S0028/) ([local](/mitre/software/S0028.md)) | malware | 3 | 1 |
| [S0107 Cherry Picker](https://attack.mitre.org/software/S0107/) ([local](/mitre/software/S0107.md)) | malware | 3 | 0 |
| [S0597 GoldFinder](https://attack.mitre.org/software/S0597/) ([local](/mitre/software/S0597.md)) | malware | 3 | 1 |
| [S0197 PUNCHTRACK](https://attack.mitre.org/software/S0197/) ([local](/mitre/software/S0197.md)) | malware | 3 | 1 |
| [S0054 CloudDuke](https://attack.mitre.org/software/S0054/) ([local](/mitre/software/S0054.md)) | malware | 3 | 1 |
| [S0068 httpclient](https://attack.mitre.org/software/S0068/) ([local](/mitre/software/S0068.md)) | malware | 3 | 1 |
| [S0158 PHOREAL](https://attack.mitre.org/software/S0158/) ([local](/mitre/software/S0158.md)) | malware | 3 | 1 |
| [S0639 Seth-Locker](https://attack.mitre.org/software/S0639/) ([local](/mitre/software/S0639.md)) | malware | 3 | 0 |
| [S0057 Tasklist](https://attack.mitre.org/software/S0057/) ([local](/mitre/software/S0057.md)) | tool | 3 | 12 |
| [S0364 RawDisk](https://attack.mitre.org/software/S0364/) ([local](/mitre/software/S0364.md)) | tool | 3 | 1 |
| [S0591 ConnectWise](https://attack.mitre.org/software/S0591/) ([local](/mitre/software/S0591.md)) | tool | 3 | 3 |
| [S0193 Forfiles](https://attack.mitre.org/software/S0193/) ([local](/mitre/software/S0193.md)) | tool | 3 | 1 |
| [S0359 Nltest](https://attack.mitre.org/software/S0359/) ([local](/mitre/software/S0359.md)) | tool | 3 | 7 |
| [S0413 MailSniper](https://attack.mitre.org/software/S0413/) ([local](/mitre/software/S0413.md)) | tool | 3 | 1 |
| [S0361 Expand](https://attack.mitre.org/software/S0361/) ([local](/mitre/software/S0361.md)) | tool | 3 | 0 |
| [S0075 Reg](https://attack.mitre.org/software/S0075/) ([local](/mitre/software/S0075.md)) | tool | 3 | 8 |
| [S0095 ftp](https://attack.mitre.org/software/S0095/) ([local](/mitre/software/S0095.md)) | tool | 3 | 5 |
| [S0040 HTRAN](https://attack.mitre.org/software/S0040/) ([local](/mitre/software/S0040.md)) | tool | 3 | 2 |
| [S0645 Wevtutil](https://attack.mitre.org/software/S0645/) ([local](/mitre/software/S0645.md)) | tool | 3 | 5 |
| [S1209 Quick Assist](https://attack.mitre.org/software/S1209/) ([local](/mitre/software/S1209.md)) | tool | 3 | 1 |
| [S0061 HDoor](https://attack.mitre.org/software/S0061/) ([local](/mitre/software/S0061.md)) | malware | 2 | 1 |
| [S0010 Lurid](https://attack.mitre.org/software/S0010/) ([local](/mitre/software/S0010.md)) | malware | 2 | 1 |
| [S1137 Moneybird](https://attack.mitre.org/software/S1137/) ([local](/mitre/software/S1137.md)) | malware | 2 | 1 |
| [S0047 Hacking Team UEFI Rootkit](https://attack.mitre.org/software/S0047/) ([local](/mitre/software/S0047.md)) | malware | 2 | 0 |
| [S0146 TEXTMATE](https://attack.mitre.org/software/S0146/) ([local](/mitre/software/S0146.md)) | malware | 2 | 1 |
| [S0027 Zeroaccess](https://attack.mitre.org/software/S0027/) ([local](/mitre/software/S0027.md)) | malware | 2 | 0 |
| [S0025 CALENDAR](https://attack.mitre.org/software/S0025/) ([local](/mitre/software/S0025.md)) | malware | 2 | 1 |
| [S0178 Truvasys](https://attack.mitre.org/software/S0178/) ([local](/mitre/software/S0178.md)) | malware | 2 | 1 |
| [S0188 Starloader](https://attack.mitre.org/software/S0188/) ([local](/mitre/software/S0188.md)) | malware | 2 | 1 |
| [S0071 hcdLoader](https://attack.mitre.org/software/S0071/) ([local](/mitre/software/S0071.md)) | malware | 2 | 1 |
| [S0003 RIPTIDE](https://attack.mitre.org/software/S0003/) ([local](/mitre/software/S0003.md)) | malware | 2 | 1 |
| [S0222 CCBkdr](https://attack.mitre.org/software/S0222/) ([local](/mitre/software/S0222.md)) | malware | 2 | 0 |
| [S0033 NetTraveler](https://attack.mitre.org/software/S0033/) ([local](/mitre/software/S0033.md)) | malware | 2 | 1 |
| [S0114 BOOTRASH](https://attack.mitre.org/software/S0114/) ([local](/mitre/software/S0114.md)) | malware | 2 | 0 |
| [S0135 HIDEDRV](https://attack.mitre.org/software/S0135/) ([local](/mitre/software/S0135.md)) | malware | 2 | 1 |
| [S0026 GLOOXMAIL](https://attack.mitre.org/software/S0026/) ([local](/mitre/software/S0026.md)) | malware | 2 | 1 |
| [S0099 Arp](https://attack.mitre.org/software/S0099/) ([local](/mitre/software/S0099.md)) | tool | 2 | 4 |
| [S0174 Responder](https://attack.mitre.org/software/S0174/) ([local](/mitre/software/S0174.md)) | tool | 2 | 3 |
| [S0008 gsecdump](https://attack.mitre.org/software/S0008/) ([local](/mitre/software/S0008.md)) | tool | 2 | 5 |
| [S0102 nbtstat](https://attack.mitre.org/software/S0102/) ([local](/mitre/software/S0102.md)) | tool | 2 | 1 |
| [S0231 Invoke-PSImage](https://attack.mitre.org/software/S0231/) ([local](/mitre/software/S0231.md)) | tool | 2 | 1 |
| [S0195 SDelete](https://attack.mitre.org/software/S0195/) ([local](/mitre/software/S0195.md)) | tool | 2 | 5 |
| [S0183 Tor](https://attack.mitre.org/software/S0183/) ([local](/mitre/software/S0183.md)) | tool | 2 | 6 |
| [S0177 Power Loader](https://attack.mitre.org/software/S0177/) ([local](/mitre/software/S0177.md)) | malware | 1 | 0 |
| [S0173 FLIPSIDE](https://attack.mitre.org/software/S0173/) ([local](/mitre/software/S0173.md)) | malware | 1 | 1 |
| [S0133 Miner-C](https://attack.mitre.org/software/S0133/) ([local](/mitre/software/S0133.md)) | malware | 1 | 0 |
| [S0383 FlawedGrace](https://attack.mitre.org/software/S0383/) ([local](/mitre/software/S0383.md)) | malware | 1 | 1 |
| [S0073 ASPXSpy](https://attack.mitre.org/software/S0073/) ([local](/mitre/software/S0073.md)) | malware | 1 | 5 |
| [S1010 VPNFilter](https://attack.mitre.org/software/S1010/) ([local](/mitre/software/S1010.md)) | malware | 1 | 1 |
| [S0014 BS2005](https://attack.mitre.org/software/S0014/) ([local](/mitre/software/S0014.md)) | malware | 1 | 0 |
| [S1072 Industroyer2](https://attack.mitre.org/software/S1072/) ([local](/mitre/software/S1072.md)) | malware | 1 | 1 |
| [S0007 Skeleton Key](https://attack.mitre.org/software/S0007/) ([local](/mitre/software/S0007.md)) | malware | 1 | 1 |
| [S0041 Wiper](https://attack.mitre.org/software/S0041/) ([local](/mitre/software/S0041.md)) | malware | 1 | 0 |
| [S0016 P2P ZeuS](https://attack.mitre.org/software/S0016/) ([local](/mitre/software/S0016.md)) | malware | 1 | 0 |
| [S0001 Trojan.Mebromi](https://attack.mitre.org/software/S0001/) ([local](/mitre/software/S0001.md)) | malware | 1 | 0 |
| [S0112 ROCKBOOT](https://attack.mitre.org/software/S0112/) ([local](/mitre/software/S0112.md)) | malware | 1 | 1 |
| [S0110 at](https://attack.mitre.org/software/S0110/) ([local](/mitre/software/S0110.md)) | tool | 1 | 3 |
| [S0116 UACMe](https://attack.mitre.org/software/S0116/) ([local](/mitre/software/S0116.md)) | tool | 1 | 0 |
| [S0005 Windows Credential Editor](https://attack.mitre.org/software/S0005/) ([local](/mitre/software/S0005.md)) | tool | 1 | 7 |
| [S0100 ipconfig](https://attack.mitre.org/software/S0100/) ([local](/mitre/software/S0100.md)) | tool | 1 | 13 |
| [S0121 Lslsass](https://attack.mitre.org/software/S0121/) ([local](/mitre/software/S0121.md)) | tool | 1 | 1 |
| [S0227 spwebmember](https://attack.mitre.org/software/S0227/) ([local](/mitre/software/S0227.md)) | tool | 1 | 1 |
| [S0101 ifconfig](https://attack.mitre.org/software/S0101/) ([local](/mitre/software/S0101.md)) | tool | 1 | 0 |
| [S0104 netstat](https://attack.mitre.org/software/S0104/) ([local](/mitre/software/S0104.md)) | tool | 1 | 11 |
| [S0120 Fgdump](https://attack.mitre.org/software/S0120/) ([local](/mitre/software/S0120.md)) | tool | 1 | 0 |
| [S0123 xCmd](https://attack.mitre.org/software/S0123/) ([local](/mitre/software/S0123.md)) | tool | 1 | 1 |
| [S0179 MimiPenguin](https://attack.mitre.org/software/S0179/) ([local](/mitre/software/S0179.md)) | tool | 1 | 1 |
| [S0175 meek](https://attack.mitre.org/software/S0175/) ([local](/mitre/software/S0175.md)) | tool | 1 | 1 |
| [S0096 Systeminfo](https://attack.mitre.org/software/S0096/) ([local](/mitre/software/S0096.md)) | tool | 1 | 10 |
| [S1176 attrib](https://attack.mitre.org/software/S1176/) ([local](/mitre/software/S1176.md)) | tool | 1 | 0 |
| [S0191 Winexe](https://attack.mitre.org/software/S0191/) ([local](/mitre/software/S0191.md)) | tool | 1 | 3 |
| [S0225 sqlmap](https://attack.mitre.org/software/S0225/) ([local](/mitre/software/S0225.md)) | tool | 1 | 2 |
| [S0006 pwdump](https://attack.mitre.org/software/S0006/) ([local](/mitre/software/S0006.md)) | tool | 1 | 6 |
| [S0122 Pass-The-Hash Toolkit](https://attack.mitre.org/software/S0122/) ([local](/mitre/software/S0122.md)) | tool | 1 | 1 |
| [S0097 Ping](https://attack.mitre.org/software/S0097/) ([local](/mitre/software/S0097.md)) | tool | 1 | 14 |
| [S0103 route](https://attack.mitre.org/software/S0103/) ([local](/mitre/software/S0103.md)) | tool | 1 | 2 |
| [S0111 schtasks](https://attack.mitre.org/software/S0111/) ([local](/mitre/software/S0111.md)) | tool | 1 | 3 |
| [S0119 Cachedump](https://attack.mitre.org/software/S0119/) ([local](/mitre/software/S0119.md)) | tool | 1 | 1 |
| [S1205 cipher.exe](https://attack.mitre.org/software/S1205/) ([local](/mitre/software/S1205.md)) | tool | 1 | 1 |
| [S0224 Havij](https://attack.mitre.org/software/S0224/) ([local](/mitre/software/S0224.md)) | tool | 1 | 1 |

---

## Detailed profiles: most capable software

### S0260: InvisiMole
<a id="s0260"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0260](https://attack.mitre.org/software/S0260) ([local](/mitre/software/S0260.md)), 73 techniques, 0 groups  

InvisiMole is a modular spyware program that has been used by the InvisiMole Group since at least 2013. InvisiMole has two backdoor modules called RC2FM and RC2CL that are used to perform post-exploitation activities. It has been discovered on compromised victims in the Ukraine and Russia.

Techniques: [T1001.003](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) Protocol or Service Impersonation, [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1025](https://attack.mitre.org/techniques/T1025) ([local](/mitre/techniques/T1025.md)) Data from Removable Media, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.005](https://attack.mitre.org/techniques/T1027/005) ([local](/mitre/techniques/T1027-005.md)) Indicator Removal from Tools, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.002](https://attack.mitre.org/techniques/T1055/002) ([local](/mitre/techniques/T1055-002.md)) Portable Executable Injection, [T1055.004](https://attack.mitre.org/techniques/T1055/004) ([local](/mitre/techniques/T1055-004.md)) Asynchronous Procedure Call, [T1055.015](https://attack.mitre.org/techniques/T1055/015) ([local](/mitre/techniques/T1055-015.md)) ListPlanting, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging

---

### S0363: Empire
<a id="s0363"></a>

Aliases: Empire, EmPyre, PowerShell Empire  
Type: tool, Platforms: Linux, macOS, Windows, ATT&CK: [S0363](https://attack.mitre.org/software/S0363) ([local](/mitre/software/S0363.md)), 73 techniques, 17 groups  

Empire is an open-source, cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python, the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS.

Used by: G0010 Turla, G0034 Sandworm Team, G0051 FIN10, G0052 CopyKittens, G0064 APT33, G0065 Leviathan, G0069 MuddyWater, G0073 APT19, G0090 WIRTE, G0091 Silence, G0096 APT41, G0102 Wizard Spider, G0119 Indrik Spider, G0140 LazyScripter, G1001 HEXANE, G1016 FIN13, G1040 Play

Techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1020](https://attack.mitre.org/techniques/T1020) ([local](/mitre/techniques/T1020.md)) Automated Exfiltration, [T1021.003](https://attack.mitre.org/techniques/T1021/003) ([local](/mitre/techniques/T1021-003.md)) Distributed Component Object Model, [T1021.004](https://attack.mitre.org/techniques/T1021/004) ([local](/mitre/techniques/T1021-004.md)) SSH, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1040](https://attack.mitre.org/techniques/T1040) ([local](/mitre/techniques/T1040.md)) Network Sniffing, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1056.004](https://attack.mitre.org/techniques/T1056/004) ([local](/mitre/techniques/T1056-004.md)) Credential API Hooking, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059](https://attack.mitre.org/techniques/T1059) ([local](/mitre/techniques/T1059.md)) Command and Scripting Interpreter, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell

---

### S0154: Cobalt Strike
<a id="s0154"></a>

Type: malware, Platforms: Windows, Linux, macOS, ATT&CK: [S0154](https://attack.mitre.org/software/S0154) ([local](/mitre/software/S0154.md)), 72 techniques, 29 groups  

Cobalt Strike is a commercial, full-featured, remote access tool that bills itself as “adversary simulation software designed to execute targeted attacks and emulate the post-exploitation actions of advanced threat actors”.

Used by: G0016 APT29, G0027 Threat Group-3390, G0034 Sandworm Team, G0037 FIN6, G0045 menuPass, G0046 FIN7, G0050 APT32, G0052 CopyKittens, G0065 Leviathan, G0067 APT37, G0073 APT19, G0079 DarkHydrus, G0080 Cobalt Group, G0092 TA505, G0096 APT41, G0102 Wizard Spider, G0114 Chimera, G0119 Indrik Spider, G0129 Mustang Panda, G0143 Aquatic Panda

Techniques: [T1001.003](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) Protocol or Service Impersonation, [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002) ([local](/mitre/techniques/T1003-002.md)) Security Account Manager, [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) ([local](/mitre/techniques/T1021-001.md)) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) ([local](/mitre/techniques/T1021-002.md)) SMB/Windows Admin Shares, [T1021.003](https://attack.mitre.org/techniques/T1021/003) ([local](/mitre/techniques/T1021-003.md)) Distributed Component Object Model, [T1021.004](https://attack.mitre.org/techniques/T1021/004) ([local](/mitre/techniques/T1021-004.md)) SSH, [T1021.006](https://attack.mitre.org/techniques/T1021/006) ([local](/mitre/techniques/T1021-006.md)) Windows Remote Management, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.005](https://attack.mitre.org/techniques/T1027/005) ([local](/mitre/techniques/T1027-005.md)) Indicator Removal from Tools, [T1029](https://attack.mitre.org/techniques/T1029) ([local](/mitre/techniques/T1029.md)) Scheduled Transfer, [T1030](https://attack.mitre.org/techniques/T1030) ([local](/mitre/techniques/T1030.md)) Data Transfer Size Limits, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery

---

### S0650: QakBot
<a id="s0650"></a>

Aliases: QakBot, Pinkslipbot, QuackBot, QBot  
Type: malware, Platforms: Windows, ATT&CK: [S0650](https://attack.mitre.org/software/S0650) ([local](/mitre/software/S0650.md)), 71 techniques, 3 groups  

QakBot is a modular banking trojan that has been used primarily by financially-motivated actors since at least 2007. QakBot is continuously maintained and developed and has evolved from an information stealer into a delivery agent for ransomware, most notably ProLock and Egregor.

Used by: G0127 TA551, G1037 TA577, G1046 Storm-1811

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1016.001](https://attack.mitre.org/techniques/T1016/001) ([local](/mitre/techniques/T1016-001.md)) Internet Connection Discovery, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.001](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) Binary Padding, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.005](https://attack.mitre.org/techniques/T1027/005) ([local](/mitre/techniques/T1027-005.md)) Indicator Removal from Tools, [T1027.006](https://attack.mitre.org/techniques/T1027/006) ([local](/mitre/techniques/T1027-006.md)) HTML Smuggling, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.008](https://attack.mitre.org/techniques/T1036/008) ([local](/mitre/techniques/T1036-008.md)) Masquerade File Type, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing

---

### S1111: DarkGate
<a id="s1111"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1111](https://attack.mitre.org/software/S1111) ([local](/mitre/software/S1111.md)), 58 techniques, 0 groups  

DarkGate first emerged in 2018 and has evolved into an initial access and data gathering tool associated with various criminal cyber operations. Written in Delphi and named "DarkGate" by its author, DarkGate is associated with credential theft, cryptomining, cryptotheft, and pre-ransomware actions.

Techniques: [T1001](https://attack.mitre.org/techniques/T1001) ([local](/mitre/techniques/T1001.md)) Data Obfuscation, [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1036.003](https://attack.mitre.org/techniques/T1036/003) ([local](/mitre/techniques/T1036-003.md)) Rename Legitimate Utilities, [T1036.007](https://attack.mitre.org/techniques/T1036/007) ([local](/mitre/techniques/T1036-007.md)) Double File Extension, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1059.010](https://attack.mitre.org/techniques/T1059/010) ([local](/mitre/techniques/T1059-010.md)) AutoHotKey & AutoIT, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.004](https://attack.mitre.org/techniques/T1071/004) ([local](/mitre/techniques/T1071-004.md)) DNS, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery

---

### S0266: TrickBot
<a id="s0266"></a>

Aliases: TrickBot, Totbrick, TSPY_TRICKLOAD  
Type: malware, Platforms: Windows, ATT&CK: [S0266](https://attack.mitre.org/software/S0266) ([local](/mitre/software/S0266.md)), 55 techniques, 2 groups  

TrickBot is a Trojan spyware program written in C++ that first emerged in September 2016 as a possible successor to Dyre.

Used by: G0092 TA505, G0102 Wizard Spider

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1021.005](https://attack.mitre.org/techniques/T1021/005) ([local](/mitre/techniques/T1021-005.md)) VNC, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1056.004](https://attack.mitre.org/techniques/T1056/004) ([local](/mitre/techniques/T1056-004.md)) Credential API Hooking, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1069](https://attack.mitre.org/techniques/T1069) ([local](/mitre/techniques/T1069.md)) Permission Groups Discovery

---

### S0692: SILENTTRINITY
<a id="s0692"></a>

Type: tool, Platforms: Windows, ATT&CK: [S0692](https://attack.mitre.org/software/S0692) ([local](/mitre/software/S0692.md)), 53 techniques, 0 groups  

SILENTTRINITY is an open source remote administration and post-exploitation framework primarily written in Python that includes stagers written in Powershell, C, and Boo. SILENTTRINITY was used in a 2019 campaign against Croatian government agencies by unidentified cyber actors.

Techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1021.003](https://attack.mitre.org/techniques/T1021/003) ([local](/mitre/techniques/T1021-003.md)) Distributed Component Object Model, [T1021.006](https://attack.mitre.org/techniques/T1021/006) ([local](/mitre/techniques/T1021-006.md)) Windows Remote Management, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1056.002](https://attack.mitre.org/techniques/T1056/002) ([local](/mitre/techniques/T1056-002.md)) GUI Input Capture, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) ([local](/mitre/techniques/T1059-006.md)) Python, [T1069.001](https://attack.mitre.org/techniques/T1069/001) ([local](/mitre/techniques/T1069-001.md)) Local Groups, [T1069.002](https://attack.mitre.org/techniques/T1069/002) ([local](/mitre/techniques/T1069-002.md)) Domain Groups

---

### S0534: Bazar
<a id="s0534"></a>

Aliases: Bazar, KEGTAP, Team9, Bazaloader  
Type: malware, Platforms: Windows, ATT&CK: [S0534](https://attack.mitre.org/software/S0534) ([local](/mitre/software/S0534.md)), 51 techniques, 2 groups  

Bazar is a downloader and backdoor that has been used since at least April 2020, with infections primarily against professional services, healthcare, manufacturing, IT, logistics and travel companies across the US and Europe.

Used by: G0102 Wizard Spider, G1011 EXOTIC LILY

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.007](https://attack.mitre.org/techniques/T1027/007) ([local](/mitre/techniques/T1027-007.md)) Dynamic API Resolution, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1036.007](https://attack.mitre.org/techniques/T1036/007) ([local](/mitre/techniques/T1036-007.md)) Double File Extension, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1055.013](https://attack.mitre.org/techniques/T1055/013) ([local](/mitre/techniques/T1055-013.md)) Process Doppelgänging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell

---

### S0013: PlugX
<a id="s0013"></a>

Aliases: PlugX, Thoper, TVT, DestroyRAT, Sogu, Kaba, Korplug  
Type: malware, Platforms: Windows, ATT&CK: [S0013](https://attack.mitre.org/software/S0013) ([local](/mitre/software/S0013.md)), 49 techniques, 15 groups  

PlugX is a remote access tool (RAT) with modular plugins that has been used by multiple threat groups.

Used by: G0001 Axiom, G0017 DragonOK, G0022 APT3, G0027 Threat Group-3390, G0044 Winnti Group, G0045 menuPass, G0062 TA459, G0093 GALLIUM, G0096 APT41, G0126 Higaisa, G0129 Mustang Panda, G1014 LuminousMoth, G1021 Cinnamon Tempest, G1034 Daggerfly, G1047 Velvet Ant

Techniques: [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.001](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) Binary Padding, [T1027.007](https://attack.mitre.org/techniques/T1027/007) ([local](/mitre/techniques/T1027-007.md)) Dynamic API Resolution, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1070.009](https://attack.mitre.org/techniques/T1070/009) ([local](/mitre/techniques/T1070-009.md)) Clear Persistence, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.004](https://attack.mitre.org/techniques/T1071/004) ([local](/mitre/techniques/T1071-004.md)) DNS, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging

---

### S0367: Emotet
<a id="s0367"></a>

Aliases: Emotet, Geodo  
Type: malware, Platforms: Windows, ATT&CK: [S0367](https://attack.mitre.org/software/S0367) ([local](/mitre/software/S0367.md)), 47 techniques, 1 groups  

Emotet is a modular malware variant which is primarily used as a downloader for other malware variants such as TrickBot and IcedID. Emotet first emerged in June 2014, initially targeting the financial sector, and has expanded to multiple verticals over time.

Used by: G0102 Wizard Spider

Techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1016.002](https://attack.mitre.org/techniques/T1016/002) ([local](/mitre/techniques/T1016-002.md)) Wi-Fi Discovery, [T1021.002](https://attack.mitre.org/techniques/T1021/002) ([local](/mitre/techniques/T1021-002.md)) SMB/Windows Admin Shares, [T1027.001](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) Binary Padding, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.009](https://attack.mitre.org/techniques/T1027/009) ([local](/mitre/techniques/T1027-009.md)) Embedded Payloads, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1040](https://attack.mitre.org/techniques/T1040) ([local](/mitre/techniques/T1040.md)) Network Sniffing, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic

---

### S0455: Metamorfo
<a id="s0455"></a>

Aliases: Metamorfo, Casbaneiro  
Type: malware, Platforms: Windows, ATT&CK: [S0455](https://attack.mitre.org/software/S0455) ([local](/mitre/software/S0455.md)), 46 techniques, 0 groups  

Metamorfo is a Latin-American banking trojan operated by a Brazilian cybercrime group that has been active since at least April 2018. The group focuses on targeting banks and cryptocurrency services in Brazil and Mexico.

Techniques: [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1056.002](https://attack.mitre.org/techniques/T1056/002) ([local](/mitre/techniques/T1056-002.md)) GUI Input Capture, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1059.007](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) JavaScript, [T1070](https://attack.mitre.org/techniques/T1070) ([local](/mitre/techniques/T1070.md)) Indicator Removal, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1095](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) Non-Application Layer Protocol, [T1102.001](https://attack.mitre.org/techniques/T1102/001) ([local](/mitre/techniques/T1102-001.md)) Dead Drop Resolver

---

### S0198: NETWIRE
<a id="s0198"></a>

Type: malware, Platforms: Windows, Linux, macOS, ATT&CK: [S0198](https://attack.mitre.org/software/S0198) ([local](/mitre/software/S0198.md)), 45 techniques, 4 groups  

NETWIRE is a publicly available, multiplatform remote administration tool (RAT) that has been used by criminal and APT groups since at least 2012.

Used by: G0064 APT33, G0083 SilverTerrier, G0089 The White Company, G1018 TA2541

Techniques: [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1036.001](https://attack.mitre.org/techniques/T1036/001) ([local](/mitre/techniques/T1036-001.md)) Invalid Code Signature, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.003](https://attack.mitre.org/techniques/T1053/003) ([local](/mitre/techniques/T1053-003.md)) Cron, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.004](https://attack.mitre.org/techniques/T1059/004) ([local](/mitre/techniques/T1059-004.md)) Unix Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging

---

### S0603: Stuxnet
<a id="s0603"></a>

Aliases: Stuxnet, W32.Stuxnet  
Type: malware, Platforms: Windows, ATT&CK: [S0603](https://attack.mitre.org/software/S0603) ([local](/mitre/software/S0603.md)), 44 techniques, 0 groups  

Stuxnet was the first publicly reported piece of malware to specifically target industrial control systems devices. Stuxnet is a large and complex piece of malware that utilized multiple different behaviors including multiple zero-day vulnerabilities, a sophisticated Windows rootkit, and network infection routines.

Techniques: [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1014](https://attack.mitre.org/techniques/T1014) ([local](/mitre/techniques/T1014.md)) Rootkit, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1021](https://attack.mitre.org/techniques/T1021) ([local](/mitre/techniques/T1021.md)) Remote Services, [T1021.002](https://attack.mitre.org/techniques/T1021/002) ([local](/mitre/techniques/T1021-002.md)) SMB/Windows Admin Shares, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1068](https://attack.mitre.org/techniques/T1068) ([local](/mitre/techniques/T1068.md)) Exploitation for Privilege Escalation, [T1070](https://attack.mitre.org/techniques/T1070) ([local](/mitre/techniques/T1070.md)) Indicator Removal, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1070.006](https://attack.mitre.org/techniques/T1070/006) ([local](/mitre/techniques/T1070-006.md)) Timestomp, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1078.001](https://attack.mitre.org/techniques/T1078/001) ([local](/mitre/techniques/T1078-001.md)) Default Accounts, [T1078.002](https://attack.mitre.org/techniques/T1078/002) ([local](/mitre/techniques/T1078-002.md)) Domain Accounts, [T1080](https://attack.mitre.org/techniques/T1080) ([local](/mitre/techniques/T1080.md)) Taint Shared Content, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery

---

### S1239: TONESHELL
<a id="s1239"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1239](https://attack.mitre.org/software/S1239) ([local](/mitre/software/S1239.md)), 43 techniques, 1 groups  

TONESHELL is a custom backdoor that has been used since at least Q1 2021. TONESHELL malware has previously been leveraged by Chinese affiliated actors identified as Mustang Panda.

Used by: G0129 Mustang Panda

Techniques: [T1001.003](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) Protocol or Service Impersonation, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1027.001](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) Binary Padding, [T1027.007](https://attack.mitre.org/techniques/T1027/007) ([local](/mitre/techniques/T1027-007.md)) Dynamic API Resolution, [T1027.012](https://attack.mitre.org/techniques/T1027/012) ([local](/mitre/techniques/T1027-012.md)) LNK Icon Smuggling, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1087](https://attack.mitre.org/techniques/T1087) ([local](/mitre/techniques/T1087.md)) Account Discovery, [T1095](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) Non-Application Layer Protocol, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer

---

### S1160: Latrodectus
<a id="s1160"></a>

Aliases: Latrodectus, IceNova, Unidentified 111  
Type: malware, Platforms: Windows, ATT&CK: [S1160](https://attack.mitre.org/software/S1160) ([local](/mitre/software/S1160.md)), 43 techniques, 2 groups  

Latrodectus is a Windows malware downloader that has been used since at least 2023 to download and execute additional payloads and modules. Latrodectus has most often been distributed through email campaigns, primarily by TA577 and TA578, and has infrastructure overlaps with historic IcedID operations.

Used by: G1037 TA577, G1038 TA578

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1021.005](https://attack.mitre.org/techniques/T1021/005) ([local](/mitre/techniques/T1021-005.md)) VNC, [T1027.001](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) Binary Padding, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.007](https://attack.mitre.org/techniques/T1027/007) ([local](/mitre/techniques/T1027-007.md)) Dynamic API Resolution, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.007](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) JavaScript, [T1069.002](https://attack.mitre.org/techniques/T1069/002) ([local](/mitre/techniques/T1069-002.md)) Domain Groups, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery

---

### S0531: Grandoreiro
<a id="s0531"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0531](https://attack.mitre.org/software/S0531) ([local](/mitre/software/S0531.md)), 43 techniques, 0 groups  

Grandoreiro is a banking trojan written in Delphi that was first observed in 2016 and uses a Malware-as-a-Service (MaaS) business model. Grandoreiro has confirmed victims in Brazil, Mexico, Portugal, and Spain.

Techniques: [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.001](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) Binary Padding, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1087.003](https://attack.mitre.org/techniques/T1087/003) ([local](/mitre/techniques/T1087-003.md)) Email Account, [T1102.001](https://attack.mitre.org/techniques/T1102/001) ([local](/mitre/techniques/T1102-001.md)) Dead Drop Resolver, [T1102.002](https://attack.mitre.org/techniques/T1102/002) ([local](/mitre/techniques/T1102-002.md)) Bidirectional Communication, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1106](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) Native API, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry

---

### S0409: Machete
<a id="s0409"></a>

Aliases: Machete, Pyark  
Type: malware, Platforms: Windows, ATT&CK: [S0409](https://attack.mitre.org/software/S0409) ([local](/mitre/software/S0409.md)), 41 techniques, 1 groups  

Machete is a cyber espionage toolset used by Machete. It is a Python-based backdoor targeting Windows machines that was first observed in 2010.

Used by: G0095 Machete

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1016.002](https://attack.mitre.org/techniques/T1016/002) ([local](/mitre/techniques/T1016-002.md)) Wi-Fi Discovery, [T1020](https://attack.mitre.org/techniques/T1020) ([local](/mitre/techniques/T1020.md)) Automated Exfiltration, [T1025](https://attack.mitre.org/techniques/T1025) ([local](/mitre/techniques/T1025.md)) Data from Removable Media, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1029](https://attack.mitre.org/techniques/T1029) ([local](/mitre/techniques/T1029.md)) Scheduled Transfer, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1052.001](https://attack.mitre.org/techniques/T1052/001) ([local](/mitre/techniques/T1052-001.md)) Exfiltration over USB, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.006](https://attack.mitre.org/techniques/T1059/006) ([local](/mitre/techniques/T1059-006.md)) Python, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols

---

### S1130: Raspberry Robin
<a id="s1130"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1130](https://attack.mitre.org/software/S1130) ([local](/mitre/software/S1130.md)), 41 techniques, 0 groups  

Raspberry Robin is initial access malware first identified in September 2021, and active through early 2024. The malware is notable for spreading via infected USB devices containing a malicious LNK object that, on execution, retrieves remote hosted payloads for installation.

Techniques: [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1036.008](https://attack.mitre.org/techniques/T1036/008) ([local](/mitre/techniques/T1036-008.md)) Masquerade File Type, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059](https://attack.mitre.org/techniques/T1059) ([local](/mitre/techniques/T1059.md)) Command and Scripting Interpreter, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1070.009](https://attack.mitre.org/techniques/T1070/009) ([local](/mitre/techniques/T1070-009.md)) Clear Persistence, [T1071](https://attack.mitre.org/techniques/T1071) ([local](/mitre/techniques/T1071.md)) Application Layer Protocol, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1091](https://attack.mitre.org/techniques/T1091) ([local](/mitre/techniques/T1091.md)) Replication Through Removable Media, [T1102](https://attack.mitre.org/techniques/T1102) ([local](/mitre/techniques/T1102.md)) Web Service, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1140](https://attack.mitre.org/techniques/T1140) ([local](/mitre/techniques/T1140.md)) Deobfuscate/Decode Files or Information

---

### S0192: Pupy
<a id="s0192"></a>

Type: tool, Platforms: Linux, Windows, macOS, Android, ATT&CK: [S0192](https://attack.mitre.org/software/S0192) ([local](/mitre/software/S0192.md)), 41 techniques, 2 groups  

Pupy is an open source, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool. It is written in Python and can be generated as a payload in several different ways (Windows exe, Python file, PowerShell oneliner/file, Linux elf, APK, Rubber Ducky, etc.). Pupy is publicly available on GitHub.

Used by: G0059 Magic Hound, G0064 APT33

Techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1003.004](https://attack.mitre.org/techniques/T1003/004) ([local](/mitre/techniques/T1003-004.md)) LSA Secrets, [T1003.005](https://attack.mitre.org/techniques/T1003/005) ([local](/mitre/techniques/T1003-005.md)) Cached Domain Credentials, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) ([local](/mitre/techniques/T1021-001.md)) Remote Desktop Protocol, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) ([local](/mitre/techniques/T1059-006.md)) Python, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001) ([local](/mitre/techniques/T1087-001.md)) Local Account, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1685.005](https://attack.mitre.org/techniques/T1685/005) ([local](/mitre/techniques/T1685-005.md)) Clear Windows Event Logs (replaces revoked T1070.001)

---

### S0356: KONNI
<a id="s0356"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0356](https://attack.mitre.org/software/S0356) ([local](/mitre/software/S0356.md)), 40 techniques, 0 groups  

KONNI is a remote access tool that security researchers assess has been used by North Korean cyber actors since at least 2014.

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1048.003](https://attack.mitre.org/techniques/T1048/003) ([local](/mitre/techniques/T1048-003.md)) Exfiltration Over Unencrypted Non-C2 Protocol, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.007](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) JavaScript, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer

---

### S1242: Qilin
<a id="s1242"></a>

Aliases: Qilin, Agenda  
Type: malware, Platforms: ESXi, Windows, ATT&CK: [S1242](https://attack.mitre.org/software/S1242) ([local](/mitre/software/S1242.md)), 40 techniques, 2 groups  

Qilin ransomware is a Ransomware-as-a-Service (RaaS) that has been active since at least 2022 with versions written in Golang and Rust that are capable of targeting Windows or VMWare ESXi devices.

Used by: G1036 Moonstone Sleet, G1050 Water Galura

Techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1021.002](https://attack.mitre.org/techniques/T1021/002) ([local](/mitre/techniques/T1021-002.md)) SMB/Windows Admin Shares, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001) ([local](/mitre/techniques/T1087-001.md)) Local Account, [T1106](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) Native API, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry, [T1134](https://attack.mitre.org/techniques/T1134) ([local](/mitre/techniques/T1134.md)) Access Token Manipulation, [T1135](https://attack.mitre.org/techniques/T1135) ([local](/mitre/techniques/T1135.md)) Network Share Discovery, [T1190](https://attack.mitre.org/techniques/T1190) ([local](/mitre/techniques/T1190.md)) Exploit Public-Facing Application, [T1685.005](https://attack.mitre.org/techniques/T1685/005) ([local](/mitre/techniques/T1685-005.md)) Clear Windows Event Logs (replaces revoked T1070.001)

---

### S1039: Bumblebee
<a id="s1039"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1039](https://attack.mitre.org/software/S1039) ([local](/mitre/software/S1039.md)), 39 techniques, 2 groups  

Bumblebee is a custom loader written in C++ that has been used by multiple threat actors, including possible initial access brokers, to download and execute additional payloads since at least March 2022.

Used by: G1011 EXOTIC LILY, G1038 TA578

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1055.004](https://attack.mitre.org/techniques/T1055/004) ([local](/mitre/techniques/T1055-004.md)) Asynchronous Procedure Call, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1102](https://attack.mitre.org/techniques/T1102) ([local](/mitre/techniques/T1102.md)) Web Service, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer

---

### S0458: Ramsay
<a id="s0458"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0458](https://attack.mitre.org/software/S0458) ([local](/mitre/software/S0458.md)), 39 techniques, 0 groups  

Ramsay is an information stealing malware framework designed to collect and exfiltrate sensitive documents, including from air-gapped systems. Researchers have identified overlaps between Ramsay and the Darkhotel-associated Retro malware.

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1014](https://attack.mitre.org/techniques/T1014) ([local](/mitre/techniques/T1014.md)) Rootkit, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1025](https://attack.mitre.org/techniques/T1025) ([local](/mitre/techniques/T1025.md)) Data from Removable Media, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.003](https://attack.mitre.org/techniques/T1027/003) ([local](/mitre/techniques/T1027-003.md)) Steganography, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1039](https://attack.mitre.org/techniques/T1039) ([local](/mitre/techniques/T1039.md)) Data from Network Shared Drive, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1080](https://attack.mitre.org/techniques/T1080) ([local](/mitre/techniques/T1080.md)) Taint Shared Content, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1091](https://attack.mitre.org/techniques/T1091) ([local](/mitre/techniques/T1091.md)) Replication Through Removable Media

---

### S0148: RTM
<a id="s0148"></a>

Aliases: RTM, Redaman  
Type: malware, Platforms: Windows, ATT&CK: [S0148](https://attack.mitre.org/software/S0148) ([local](/mitre/software/S0148.md)), 38 techniques, 1 groups  

RTM is custom malware written in Delphi. It is used by the group of the same name (RTM). Newer versions of the malware have been reported publicly as Redaman.

Used by: G0048 RTM

Techniques: [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.015](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) Compression, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1070.009](https://attack.mitre.org/techniques/T1070/009) ([local](/mitre/techniques/T1070-009.md)) Clear Persistence, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1102.001](https://attack.mitre.org/techniques/T1102/001) ([local](/mitre/techniques/T1102-001.md)) Dead Drop Resolver, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1106](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) Native API, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry, [T1113](https://attack.mitre.org/techniques/T1113) ([local](/mitre/techniques/T1113.md)) Screen Capture, [T1115](https://attack.mitre.org/techniques/T1115) ([local](/mitre/techniques/T1115.md)) Clipboard Data

---

### S1018: Saint Bot
<a id="s1018"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1018](https://attack.mitre.org/software/S1018) ([local](/mitre/software/S1018.md)), 37 techniques, 2 groups  

Saint Bot is a .NET downloader that has been used by Saint Bear since at least March 2021.

Used by: G1003 Ember Bear, G1031 Saint Bear

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1055.004](https://attack.mitre.org/techniques/T1055/004) ([local](/mitre/techniques/T1055-004.md)) Asynchronous Procedure Call, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery

---

### S1044: FunnyDream
<a id="s1044"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1044](https://attack.mitre.org/software/S1044) ([local](/mitre/software/S1044.md)), 37 techniques, 0 groups  

FunnyDream is a backdoor with multiple components that was used during the FunnyDream campaign since at least 2019, primarily for execution and exfiltration.

Techniques: [T1001](https://attack.mitre.org/techniques/T1001) ([local](/mitre/techniques/T1001.md)) Data Obfuscation, [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1025](https://attack.mitre.org/techniques/T1025) ([local](/mitre/techniques/T1025.md)) Data from Removable Media, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070](https://attack.mitre.org/techniques/T1070) ([local](/mitre/techniques/T1070.md)) Indicator Removal, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery

---

### S0331: Agent Tesla
<a id="s0331"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0331](https://attack.mitre.org/software/S0331) ([local](/mitre/software/S0331.md)), 37 techniques, 2 groups  

Agent Tesla is a spyware Trojan written for the .NET framework that has been observed since at least 2014.

Used by: G0083 SilverTerrier, G1018 TA2541

Techniques: [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1016.002](https://attack.mitre.org/techniques/T1016/002) ([local](/mitre/techniques/T1016-002.md)) Wi-Fi Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1048.003](https://attack.mitre.org/techniques/T1048/003) ([local](/mitre/techniques/T1048-003.md)) Exfiltration Over Unencrypted Non-C2 Protocol, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.003](https://attack.mitre.org/techniques/T1071/003) ([local](/mitre/techniques/T1071-003.md)) Mail Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001) ([local](/mitre/techniques/T1087-001.md)) Local Account, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry, [T1113](https://attack.mitre.org/techniques/T1113) ([local](/mitre/techniques/T1113.md)) Screen Capture, [T1115](https://attack.mitre.org/techniques/T1115) ([local](/mitre/techniques/T1115.md)) Clipboard Data, [T1124](https://attack.mitre.org/techniques/T1124) ([local](/mitre/techniques/T1124.md)) System Time Discovery

---

### S1060: Mafalda
<a id="s1060"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1060](https://attack.mitre.org/software/S1060) ([local](/mitre/software/S1060.md)), 36 techniques, 1 groups  

Mafalda is a flexible interactive implant that has been used by Metador. Security researchers assess the Mafalda name may be inspired by an Argentinian cartoon character that has been popular as a means of political commentary since the 1960s.

Used by: G1013 Metador

Techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1056](https://attack.mitre.org/techniques/T1056) ([local](/mitre/techniques/T1056.md)) Input Capture, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1090.001](https://attack.mitre.org/techniques/T1090/001) ([local](/mitre/techniques/T1090-001.md)) Internal Proxy, [T1095](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) Non-Application Layer Protocol, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1685.005](https://attack.mitre.org/techniques/T1685/005) ([local](/mitre/techniques/T1685-005.md)) Clear Windows Event Logs (replaces revoked T1070.001)

---

### S0022: Uroburos
<a id="s0022"></a>

Aliases: Uroburos, Snake  
Type: malware, Platforms: Linux, Windows, macOS, ATT&CK: [S0022](https://attack.mitre.org/software/S0022) ([local](/mitre/software/S0022.md)), 36 techniques, 1 groups  

Uroburos is a sophisticated cyber espionage tool written in C that has been used by units within Russia's Federal Security Service (FSB) associated with the Turla toolset to collect intelligence on sensitive targets worldwide.

Used by: G0010 Turla

Techniques: [T1001.001](https://attack.mitre.org/techniques/T1001/001) ([local](/mitre/techniques/T1001-001.md)) Junk Data, [T1001.003](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) Protocol or Service Impersonation, [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1014](https://attack.mitre.org/techniques/T1014) ([local](/mitre/techniques/T1014.md)) Rootkit, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.009](https://attack.mitre.org/techniques/T1027/009) ([local](/mitre/techniques/T1027-009.md)) Embedded Payloads, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.003](https://attack.mitre.org/techniques/T1071/003) ([local](/mitre/techniques/T1071-003.md)) Mail Protocols, [T1071.004](https://attack.mitre.org/techniques/T1071/004) ([local](/mitre/techniques/T1071-004.md)) DNS, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery

---

### S0559: SUNBURST
<a id="s0559"></a>

Aliases: SUNBURST, Solorigate  
Type: malware, Platforms: Windows, ATT&CK: [S0559](https://attack.mitre.org/software/S0559) ([local](/mitre/software/S0559.md)), 36 techniques, 1 groups  

SUNBURST is a trojanized DLL designed to fit within the SolarWinds Orion software update framework. It was used by APT29 since at least February 2020.

Used by: G0016 APT29

Techniques: [T1001.001](https://attack.mitre.org/techniques/T1001/001) ([local](/mitre/techniques/T1001-001.md)) Junk Data, [T1001.002](https://attack.mitre.org/techniques/T1001/002) ([local](/mitre/techniques/T1001-002.md)) Steganography, [T1001.003](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) Protocol or Service Impersonation, [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.005](https://attack.mitre.org/techniques/T1027/005) ([local](/mitre/techniques/T1027-005.md)) Indicator Removal from Tools, [T1027.015](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) Compression, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1070](https://attack.mitre.org/techniques/T1070) ([local](/mitre/techniques/T1070.md)) Indicator Removal, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1070.007](https://attack.mitre.org/techniques/T1070/007) ([local](/mitre/techniques/T1070-007.md)) Clear Network Connection History and Configurations, [T1070.009](https://attack.mitre.org/techniques/T1070/009) ([local](/mitre/techniques/T1070-009.md)) Clear Persistence, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols

---

### S0373: Astaroth
<a id="s0373"></a>

Aliases: Astaroth, Guildma  
Type: malware, Platforms: Windows, ATT&CK: [S0373](https://attack.mitre.org/software/S0373) ([local](/mitre/software/S0373.md)), 36 techniques, 0 groups  

Astaroth is a Trojan and information stealer known to affect companies in Europe, Brazil, and throughout Latin America. It has been known publicly since at least late 2017.

Techniques: [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1059.007](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) JavaScript, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1102.001](https://attack.mitre.org/techniques/T1102/001) ([local](/mitre/techniques/T1102-001.md)) Dead Drop Resolver, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1115](https://attack.mitre.org/techniques/T1115) ([local](/mitre/techniques/T1115.md)) Clipboard Data, [T1124](https://attack.mitre.org/techniques/T1124) ([local](/mitre/techniques/T1124.md)) System Time Discovery, [T1129](https://attack.mitre.org/techniques/T1129) ([local](/mitre/techniques/T1129.md)) Shared Modules, [T1132.001](https://attack.mitre.org/techniques/T1132/001) ([local](/mitre/techniques/T1132-001.md)) Standard Encoding

---

### S0386: Ursnif
<a id="s0386"></a>

Aliases: Ursnif, Gozi-ISFB, PE_URSNIF, Dreambot  
Type: malware, Platforms: Windows, ATT&CK: [S0386](https://attack.mitre.org/software/S0386) ([local](/mitre/software/S0386.md)), 35 techniques, 1 groups  

Ursnif is a banking trojan and variant of the Gozi malware observed being spread through various automated exploit kits, Spearphishing Attachments, and malicious links. Ursnif is associated primarily with data theft, but variants also include components (backdoors, spyware, file injectors, etc.) capable of a wide variety of behaviors.

Used by: G0127 TA551

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1055.005](https://attack.mitre.org/techniques/T1055/005) ([local](/mitre/techniques/T1055-005.md)) Thread Local Storage, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1056.004](https://attack.mitre.org/techniques/T1056/004) ([local](/mitre/techniques/T1056-004.md)) Credential API Hooking, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1080](https://attack.mitre.org/techniques/T1080) ([local](/mitre/techniques/T1080.md)) Taint Shared Content, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1090](https://attack.mitre.org/techniques/T1090) ([local](/mitre/techniques/T1090.md)) Proxy

---

### S1245: InvisibleFerret
<a id="s1245"></a>

Type: malware, Platforms: Linux, macOS, Windows, ATT&CK: [S1245](https://attack.mitre.org/software/S1245) ([local](/mitre/software/S1245.md)), 35 techniques, 1 groups  

InvisibleFerret is a modular python malware that is leveraged for data exfiltration and remote access capabilities. InvisibleFerret consists of four modules: main, payload, browser, and AnyDesk. InvisibleFerret malware has been leveraged by North Korea-affiliated threat actors identified as DeceptiveDevelopment or Contagious Interview since 2023.

Used by: G1052 Contagious Interview

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1048.003](https://attack.mitre.org/techniques/T1048/003) ([local](/mitre/techniques/T1048-003.md)) Exfiltration Over Unencrypted Non-C2 Protocol, [T1056](https://attack.mitre.org/techniques/T1056) ([local](/mitre/techniques/T1056.md)) Input Capture, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) ([local](/mitre/techniques/T1059-006.md)) Python, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001) ([local](/mitre/techniques/T1087-001.md)) Local Account, [T1095](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) Non-Application Layer Protocol, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1115](https://attack.mitre.org/techniques/T1115) ([local](/mitre/techniques/T1115.md)) Clipboard Data, [T1140](https://attack.mitre.org/techniques/T1140) ([local](/mitre/techniques/T1140.md)) Deobfuscate/Decode Files or Information

---

### S1081: BADHATCH
<a id="s1081"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1081](https://attack.mitre.org/software/S1081) ([local](/mitre/software/S1081.md)), 35 techniques, 1 groups  

BADHATCH is a backdoor that has been utilized by FIN8 since at least 2019. BADHATCH has been used to target the insurance, retail, technology, and chemical industries in the United States, Canada, South Africa, Panama, and Italy.

Used by: G0061 FIN8

Techniques: [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1027.009](https://attack.mitre.org/techniques/T1027/009) ([local](/mitre/techniques/T1027-009.md)) Embedded Payloads, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1027.015](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) Compression, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1055.004](https://attack.mitre.org/techniques/T1055/004) ([local](/mitre/techniques/T1055-004.md)) Asynchronous Procedure Call, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1069.002](https://attack.mitre.org/techniques/T1069/002) ([local](/mitre/techniques/T1069-002.md)) Domain Groups, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.002](https://attack.mitre.org/techniques/T1071/002) ([local](/mitre/techniques/T1071-002.md)) File Transfer Protocols

---

### S1228: PUBLOAD
<a id="s1228"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1228](https://attack.mitre.org/software/S1228) ([local](/mitre/software/S1228.md)), 35 techniques, 1 groups  

PUBLOAD is a stager malware that has been observed installing itself in existing directories such as `C:\Users\Public` or creating new directories to stage the malware and its components. PUBLOAD malware collects details of the victim host, establishes persistence, encrypts victim details using RC4 and communicates victim details back to C2.

Used by: G0129 Mustang Panda

Techniques: [T1001.003](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) Protocol or Service Impersonation, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1016.001](https://attack.mitre.org/techniques/T1016/001) ([local](/mitre/techniques/T1016-001.md)) Internet Connection Discovery, [T1016.002](https://attack.mitre.org/techniques/T1016/002) ([local](/mitre/techniques/T1016-002.md)) Wi-Fi Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.015](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) Compression, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1048.003](https://attack.mitre.org/techniques/T1048/003) ([local](/mitre/techniques/T1048-003.md)) Exfiltration Over Unencrypted Non-C2 Protocol, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.002](https://attack.mitre.org/techniques/T1071/002) ([local](/mitre/techniques/T1071-002.md)) File Transfer Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer

---

### S1213: Lumma Stealer
<a id="s1213"></a>

Aliases: Lumma Stealer, LummaStealer  
Type: malware, Platforms: Windows, ATT&CK: [S1213](https://attack.mitre.org/software/S1213) ([local](/mitre/software/S1213.md)), 35 techniques, 0 groups  

Lumma Stealer is an information stealer malware family in use since at least 2022. Lumma Stealer is a Malware as a Service (MaaS) where captured data has been sold in criminal markets to Initial Access Brokers.

Techniques: [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036.008](https://attack.mitre.org/techniques/T1036/008) ([local](/mitre/techniques/T1036-008.md)) Masquerade File Type, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) ([local](/mitre/techniques/T1059-006.md)) Python, [T1059.010](https://attack.mitre.org/techniques/T1059/010) ([local](/mitre/techniques/T1059-010.md)) AutoHotKey & AutoIT, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1113](https://attack.mitre.org/techniques/T1113) ([local](/mitre/techniques/T1113.md)) Screen Capture, [T1119](https://attack.mitre.org/techniques/T1119) ([local](/mitre/techniques/T1119.md)) Automated Collection, [T1140](https://attack.mitre.org/techniques/T1140) ([local](/mitre/techniques/T1140.md)) Deobfuscate/Decode Files or Information, [T1176.001](https://attack.mitre.org/techniques/T1176/001) ([local](/mitre/techniques/T1176-001.md)) Browser Extensions, [T1195](https://attack.mitre.org/techniques/T1195) ([local](/mitre/techniques/T1195.md)) Supply Chain Compromise, [T1204](https://attack.mitre.org/techniques/T1204) ([local](/mitre/techniques/T1204.md)) User Execution, [T1204.002](https://attack.mitre.org/techniques/T1204/002) ([local](/mitre/techniques/T1204-002.md)) Malicious File, [T1217](https://attack.mitre.org/techniques/T1217) ([local](/mitre/techniques/T1217.md)) Browser Information Discovery, [T1218.005](https://attack.mitre.org/techniques/T1218/005) ([local](/mitre/techniques/T1218-005.md)) Mshta

---

### S1240: RedLine Stealer
<a id="s1240"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1240](https://attack.mitre.org/software/S1240) ([local](/mitre/software/S1240.md)), 35 techniques, 0 groups  

RedLine Stealer is an information-stealer malware variant first identified in 2020. RedLine Stealer is a Malware as a Service (MaaS) and was reportedly sold as either a one-time purchase or a monthly subscription service.

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.011](https://attack.mitre.org/techniques/T1059/011) ([local](/mitre/techniques/T1059-011.md)) Lua, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001) ([local](/mitre/techniques/T1087-001.md)) Local Account, [T1102](https://attack.mitre.org/techniques/T1102) ([local](/mitre/techniques/T1102.md)) Web Service, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1113](https://attack.mitre.org/techniques/T1113) ([local](/mitre/techniques/T1113.md)) Screen Capture, [T1132.001](https://attack.mitre.org/techniques/T1132/001) ([local](/mitre/techniques/T1132-001.md)) Standard Encoding, [T1140](https://attack.mitre.org/techniques/T1140) ([local](/mitre/techniques/T1140.md)) Deobfuscate/Decode Files or Information

---

### S0438: Attor
<a id="s0438"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0438](https://attack.mitre.org/software/S0438) ([local](/mitre/software/S0438.md)), 35 techniques, 0 groups  

Attor is a Windows-based espionage platform that has been seen in use since 2013. Attor has a loadable plugin architecture to customize functionality for specific targets.

Techniques: [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1020](https://attack.mitre.org/techniques/T1020) ([local](/mitre/techniques/T1020.md)) Automated Exfiltration, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1037.001](https://attack.mitre.org/techniques/T1037/001) ([local](/mitre/techniques/T1037-001.md)) Logon Script (Windows), [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.004](https://attack.mitre.org/techniques/T1055/004) ([local](/mitre/techniques/T1055-004.md)) Asynchronous Procedure Call, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1070.006](https://attack.mitre.org/techniques/T1070/006) ([local](/mitre/techniques/T1070-006.md)) Timestomp, [T1071.002](https://attack.mitre.org/techniques/T1071/002) ([local](/mitre/techniques/T1071-002.md)) File Transfer Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1090.003](https://attack.mitre.org/techniques/T1090/003) ([local](/mitre/techniques/T1090-003.md)) Multi-hop Proxy, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1106](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) Native API, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry

---

### S0496: REvil
<a id="s0496"></a>

Aliases: REvil, Sodin, Sodinokibi  
Type: malware, Platforms: Windows, ATT&CK: [S0496](https://attack.mitre.org/software/S0496) ([local](/mitre/software/S0496.md)), 35 techniques, 2 groups  

REvil is a ransomware family that has been linked to the GOLD SOUTHFIELD group and operated as ransomware-as-a-service (RaaS) since at least April 2019. REvil, which as been used against organizations in the manufacturing, transportation, and electric sectors, is highly configurable and shares code similarities with the GandCrab RaaS.

Used by: G0046 FIN7, G0115 GOLD SOUTHFIELD

Techniques: [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1069.002](https://attack.mitre.org/techniques/T1069/002) ([local](/mitre/techniques/T1069-002.md)) Domain Groups, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1106](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) Native API, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry, [T1134.001](https://attack.mitre.org/techniques/T1134/001) ([local](/mitre/techniques/T1134-001.md)) Token Impersonation/Theft

---

### S0428: PoetRAT
<a id="s0428"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0428](https://attack.mitre.org/software/S0428) ([local](/mitre/software/S0428.md)), 35 techniques, 0 groups  

PoetRAT is a remote access trojan (RAT) that was first identified in April 2020. PoetRAT has been used in multiple campaigns against the private and public sectors in Azerbaijan, including ICS and SCADA systems in the energy sector. The STIBNITE activity group has been observed using the malware.

Techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1018](https://attack.mitre.org/techniques/T1018) ([local](/mitre/techniques/T1018.md)) Remote System Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1048](https://attack.mitre.org/techniques/T1048) ([local](/mitre/techniques/T1048.md)) Exfiltration Over Alternative Protocol, [T1048.003](https://attack.mitre.org/techniques/T1048/003) ([local](/mitre/techniques/T1048-003.md)) Exfiltration Over Unencrypted Non-C2 Protocol, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1059.006](https://attack.mitre.org/techniques/T1059/006) ([local](/mitre/techniques/T1059-006.md)) Python, [T1059.011](https://attack.mitre.org/techniques/T1059/011) ([local](/mitre/techniques/T1059-011.md)) Lua, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.002](https://attack.mitre.org/techniques/T1071/002) ([local](/mitre/techniques/T1071-002.md)) File Transfer Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer

---

### S0439: Okrum
<a id="s0439"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0439](https://attack.mitre.org/software/S0439) ([local](/mitre/software/S0439.md)), 34 techniques, 1 groups  

Okrum is a Windows backdoor that has been seen in use since December 2016 with strong links to Ke3chang.

Used by: G0004 Ke3chang

Techniques: [T1001](https://attack.mitre.org/techniques/T1001) ([local](/mitre/techniques/T1001.md)) Data Obfuscation, [T1001.003](https://attack.mitre.org/techniques/T1001/003) ([local](/mitre/techniques/T1001-003.md)) Protocol or Service Impersonation, [T1003.001](https://attack.mitre.org/techniques/T1003/001) ([local](/mitre/techniques/T1003-001.md)) LSASS Memory, [T1003.005](https://attack.mitre.org/techniques/T1003/005) ([local](/mitre/techniques/T1003-005.md)) Cached Domain Credentials, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.003](https://attack.mitre.org/techniques/T1027/003) ([local](/mitre/techniques/T1027-003.md)) Steganography, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) ([local](/mitre/techniques/T1036-004.md)) Masquerade Task or Service, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1049](https://attack.mitre.org/techniques/T1049) ([local](/mitre/techniques/T1049.md)) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1090.002](https://attack.mitre.org/techniques/T1090/002) ([local](/mitre/techniques/T1090-002.md)) External Proxy, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1124](https://attack.mitre.org/techniques/T1124) ([local](/mitre/techniques/T1124.md)) System Time Discovery

---

### S0673: DarkWatchman
<a id="s0673"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0673](https://attack.mitre.org/software/S0673) ([local](/mitre/software/S0673.md)), 34 techniques, 0 groups  

DarkWatchman is a lightweight JavaScript-based remote access tool (RAT) that avoids file operations; it was first observed in November 2021.

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1010](https://attack.mitre.org/techniques/T1010) ([local](/mitre/techniques/T1010.md)) Application Window Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1027.004](https://attack.mitre.org/techniques/T1027/004) ([local](/mitre/techniques/T1027-004.md)) Compile After Delivery, [T1027.010](https://attack.mitre.org/techniques/T1027/010) ([local](/mitre/techniques/T1027-010.md)) Command Obfuscation, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1027.015](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) Compression, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.007](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) JavaScript, [T1070](https://attack.mitre.org/techniques/T1070) ([local](/mitre/techniques/T1070.md)) Indicator Removal, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1074.001](https://attack.mitre.org/techniques/T1074/001) ([local](/mitre/techniques/T1074-001.md)) Local Data Staging, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery

---

### S0268: Bisonal
<a id="s0268"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0268](https://attack.mitre.org/software/S0268) ([local](/mitre/software/S0268.md)), 34 techniques, 1 groups  

Bisonal is a remote access tool (RAT) that has been used by Tonto Team against public and private sector organizations in Russia, South Korea, and Japan since at least December 2010.

Used by: G0131 Tonto Team

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027.001](https://attack.mitre.org/techniques/T1027/001) ([local](/mitre/techniques/T1027-001.md)) Binary Padding, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) ([local](/mitre/techniques/T1059-005.md)) Visual Basic, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1090](https://attack.mitre.org/techniques/T1090) ([local](/mitre/techniques/T1090.md)) Proxy, [T1095](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) Non-Application Layer Protocol, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1106](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) Native API

---

### S0660: Clambling
<a id="s0660"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0660](https://attack.mitre.org/software/S0660) ([local](/mitre/software/S0660.md)), 34 techniques, 1 groups  

Clambling is a modular backdoor written in C++ that has been used by Threat Group-3390 since at least 2017.

Used by: G0027 Threat Group-3390

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1055](https://attack.mitre.org/techniques/T1055) ([local](/mitre/techniques/T1055.md)) Process Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) ([local](/mitre/techniques/T1055-012.md)) Process Hollowing, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1071](https://attack.mitre.org/techniques/T1071) ([local](/mitre/techniques/T1071.md)) Application Layer Protocol, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1095](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) Non-Application Layer Protocol, [T1102.002](https://attack.mitre.org/techniques/T1102/002) ([local](/mitre/techniques/T1102-002.md)) Bidirectional Communication, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry, [T1113](https://attack.mitre.org/techniques/T1113) ([local](/mitre/techniques/T1113.md)) Screen Capture, [T1115](https://attack.mitre.org/techniques/T1115) ([local](/mitre/techniques/T1115.md)) Clipboard Data

---

### S1202: LockBit 3.0
<a id="s1202"></a>

Aliases: LockBit 3.0, LockBit Black  
Type: malware, Platforms: Windows, ATT&CK: [S1202](https://attack.mitre.org/software/S1202) ([local](/mitre/software/S1202.md)), 34 techniques, 0 groups  

LockBit 3.0 is an evolution of the LockBit Ransomware-as-a-Service (RaaS) offering with similarities to BlackMatter and BlackCat ransomware.

Techniques: [T1021.002](https://attack.mitre.org/techniques/T1021/002) ([local](/mitre/techniques/T1021-002.md)) SMB/Windows Admin Shares, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1078.003](https://attack.mitre.org/techniques/T1078/003) ([local](/mitre/techniques/T1078-003.md)) Local Accounts, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1106](https://attack.mitre.org/techniques/T1106) ([local](/mitre/techniques/T1106.md)) Native API, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry, [T1120](https://attack.mitre.org/techniques/T1120) ([local](/mitre/techniques/T1120.md)) Peripheral Device Discovery, [T1132.001](https://attack.mitre.org/techniques/T1132/001) ([local](/mitre/techniques/T1132-001.md)) Standard Encoding, [T1135](https://attack.mitre.org/techniques/T1135) ([local](/mitre/techniques/T1135.md)) Network Share Discovery, [T1140](https://attack.mitre.org/techniques/T1140) ([local](/mitre/techniques/T1140.md)) Deobfuscate/Decode Files or Information, [T1218.003](https://attack.mitre.org/techniques/T1218/003) ([local](/mitre/techniques/T1218-003.md)) CMSTP, [T1480](https://attack.mitre.org/techniques/T1480) ([local](/mitre/techniques/T1480.md)) Execution Guardrails, [T1480.002](https://attack.mitre.org/techniques/T1480/002) ([local](/mitre/techniques/T1480-002.md)) Mutual Exclusion, [T1685.005](https://attack.mitre.org/techniques/T1685/005) ([local](/mitre/techniques/T1685-005.md)) Clear Windows Event Logs (replaces revoked T1070.001)

---

### S1183: StrelaStealer
<a id="s1183"></a>

Type: malware, Platforms: Windows, ATT&CK: [S1183](https://attack.mitre.org/software/S1183) ([local](/mitre/software/S1183.md)), 34 techniques, 0 groups  

StrelaStealer is an information stealer malware variant first identified in November 2022 and active through late 2024. StrelaStealer focuses on the automated identification, collection, and exfiltration of email credentials from email clients such as Outlook and Thunderbird.

Techniques: [T1001](https://attack.mitre.org/techniques/T1001) ([local](/mitre/techniques/T1001.md)) Data Obfuscation, [T1020](https://attack.mitre.org/techniques/T1020) ([local](/mitre/techniques/T1020.md)) Automated Exfiltration, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1027.015](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) Compression, [T1027.016](https://attack.mitre.org/techniques/T1027/016) ([local](/mitre/techniques/T1027-016.md)) Junk Code Insertion, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1036.003](https://attack.mitre.org/techniques/T1036/003) ([local](/mitre/techniques/T1036-003.md)) Rename Legitimate Utilities, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1036.008](https://attack.mitre.org/techniques/T1036/008) ([local](/mitre/techniques/T1036-008.md)) Masquerade File Type, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1059.007](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) JavaScript, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1119](https://attack.mitre.org/techniques/T1119) ([local](/mitre/techniques/T1119.md)) Automated Collection, [T1132.001](https://attack.mitre.org/techniques/T1132/001) ([local](/mitre/techniques/T1132-001.md)) Standard Encoding

---

### S0476: Valak
<a id="s0476"></a>

Type: malware, Platforms: Windows, ATT&CK: [S0476](https://attack.mitre.org/software/S0476) ([local](/mitre/software/S0476.md)), 34 techniques, 1 groups  

Valak is a multi-stage modular malware that can function as a standalone information stealer or downloader, first observed in 2019 targeting enterprises in the US and Germany.

Used by: G0127 TA551

Techniques: [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) ([local](/mitre/techniques/T1016.md)) System Network Configuration Discovery, [T1027](https://attack.mitre.org/techniques/T1027) ([local](/mitre/techniques/T1027.md)) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) ([local](/mitre/techniques/T1027-002.md)) Software Packing, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) ([local](/mitre/techniques/T1047.md)) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) ([local](/mitre/techniques/T1053-005.md)) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) ([local](/mitre/techniques/T1059-001.md)) PowerShell, [T1059.007](https://attack.mitre.org/techniques/T1059/007) ([local](/mitre/techniques/T1059-007.md)) JavaScript, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1087.001](https://attack.mitre.org/techniques/T1087/001) ([local](/mitre/techniques/T1087-001.md)) Local Account, [T1087.002](https://attack.mitre.org/techniques/T1087/002) ([local](/mitre/techniques/T1087-002.md)) Domain Account, [T1104](https://attack.mitre.org/techniques/T1104) ([local](/mitre/techniques/T1104.md)) Multi-Stage Channels, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1112](https://attack.mitre.org/techniques/T1112) ([local](/mitre/techniques/T1112.md)) Modify Registry

---

### S0412: ZxShell
<a id="s0412"></a>

Aliases: ZxShell, Sensocode  
Type: malware, Platforms: Windows, ATT&CK: [S0412](https://attack.mitre.org/software/S0412) ([local](/mitre/software/S0412.md)), 34 techniques, 3 groups  

ZxShell is a remote administration tool and backdoor that can be downloaded from the Internet, particularly from Chinese hacker websites. It has been used since at least 2004.

Used by: G0001 Axiom, G0027 Threat Group-3390, G0096 APT41

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) ([local](/mitre/techniques/T1007.md)) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1021.001](https://attack.mitre.org/techniques/T1021/001) ([local](/mitre/techniques/T1021-001.md)) Remote Desktop Protocol, [T1021.005](https://attack.mitre.org/techniques/T1021/005) ([local](/mitre/techniques/T1021-005.md)) VNC, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1046](https://attack.mitre.org/techniques/T1046) ([local](/mitre/techniques/T1046.md)) Network Service Discovery, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1056.001](https://attack.mitre.org/techniques/T1056/001) ([local](/mitre/techniques/T1056-001.md)) Keylogging, [T1056.004](https://attack.mitre.org/techniques/T1056/004) ([local](/mitre/techniques/T1056-004.md)) Credential API Hooking, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.002](https://attack.mitre.org/techniques/T1071/002) ([local](/mitre/techniques/T1071-002.md)) File Transfer Protocols, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1090](https://attack.mitre.org/techniques/T1090) ([local](/mitre/techniques/T1090.md)) Proxy, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1685.005](https://attack.mitre.org/techniques/T1685/005) ([local](/mitre/techniques/T1685-005.md)) Clear Windows Event Logs (replaces revoked T1070.001)

---

### S0658: XCSSET
<a id="s0658"></a>

Aliases: XCSSET, OSX.DubRobber  
Type: malware, Platforms: macOS, ATT&CK: [S0658](https://attack.mitre.org/software/S0658) ([local](/mitre/software/S0658.md)), 33 techniques, 0 groups  

XCSSET is a modular macOS malware family delivered through infected Xcode projects and executed when the project is compiled. Active since August 2020, it has been observed installing backdoors, spoofed browsers, collecting data, and encrypting user files.

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1027.013](https://attack.mitre.org/techniques/T1027/013) ([local](/mitre/techniques/T1027-013.md)) Encrypted/Encoded File, [T1036](https://attack.mitre.org/techniques/T1036) ([local](/mitre/techniques/T1036.md)) Masquerading, [T1041](https://attack.mitre.org/techniques/T1041) ([local](/mitre/techniques/T1041.md)) Exfiltration Over C2 Channel, [T1056.002](https://attack.mitre.org/techniques/T1056/002) ([local](/mitre/techniques/T1056-002.md)) GUI Input Capture, [T1059.004](https://attack.mitre.org/techniques/T1059/004) ([local](/mitre/techniques/T1059-004.md)) Unix Shell, [T1068](https://attack.mitre.org/techniques/T1068) ([local](/mitre/techniques/T1068.md)) Exploitation for Privilege Escalation, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1087](https://attack.mitre.org/techniques/T1087) ([local](/mitre/techniques/T1087.md)) Account Discovery, [T1098.004](https://attack.mitre.org/techniques/T1098/004) ([local](/mitre/techniques/T1098-004.md)) SSH Authorized Keys, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer, [T1113](https://attack.mitre.org/techniques/T1113) ([local](/mitre/techniques/T1113.md)) Screen Capture, [T1195.001](https://attack.mitre.org/techniques/T1195/001) ([local](/mitre/techniques/T1195-001.md)) Compromise Software Dependencies and Development Tools, [T1222.002](https://attack.mitre.org/techniques/T1222/002) ([local](/mitre/techniques/T1222-002.md)) Linux and Mac File and Directory Permissions Modification, [T1486](https://attack.mitre.org/techniques/T1486) ([local](/mitre/techniques/T1486.md)) Data Encrypted for Impact, [T1497.003](https://attack.mitre.org/techniques/T1497/003) ([local](/mitre/techniques/T1497-003.md)) Time Based Checks, [T1518](https://attack.mitre.org/techniques/T1518) ([local](/mitre/techniques/T1518.md)) Software Discovery, [T1518.001](https://attack.mitre.org/techniques/T1518/001) ([local](/mitre/techniques/T1518-001.md)) Security Software Discovery, [T1539](https://attack.mitre.org/techniques/T1539) ([local](/mitre/techniques/T1539.md)) Steal Web Session Cookie

---

### S0666: Gelsemium
<a id="s0666"></a>

Aliases: Gelsemium, Gelsevirine, Gelsenicine, Gelsemine  
Type: malware, Platforms: Windows, ATT&CK: [S0666](https://attack.mitre.org/software/S0666) ([local](/mitre/software/S0666.md)), 33 techniques, 0 groups  

Gelsemium is a modular malware comprised of a dropper (Gelsemine), a loader (Gelsenicine), and main (Gelsevirine) plug-ins written using the Microsoft Foundation Class (MFC) framework. Gelsemium has been used by the Gelsemium group since at least 2014.

Techniques: [T1005](https://attack.mitre.org/techniques/T1005) ([local](/mitre/techniques/T1005.md)) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) ([local](/mitre/techniques/T1008.md)) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) ([local](/mitre/techniques/T1012.md)) Query Registry, [T1027.011](https://attack.mitre.org/techniques/T1027/011) ([local](/mitre/techniques/T1027-011.md)) Fileless Storage, [T1027.015](https://attack.mitre.org/techniques/T1027/015) ([local](/mitre/techniques/T1027-015.md)) Compression, [T1027.016](https://attack.mitre.org/techniques/T1027/016) ([local](/mitre/techniques/T1027-016.md)) Junk Code Insertion, [T1033](https://attack.mitre.org/techniques/T1033) ([local](/mitre/techniques/T1033.md)) System Owner/User Discovery, [T1036.001](https://attack.mitre.org/techniques/T1036/001) ([local](/mitre/techniques/T1036-001.md)) Invalid Code Signature, [T1036.005](https://attack.mitre.org/techniques/T1036/005) ([local](/mitre/techniques/T1036-005.md)) Match Legitimate Resource Name or Location, [T1055.001](https://attack.mitre.org/techniques/T1055/001) ([local](/mitre/techniques/T1055-001.md)) Dynamic-link Library Injection, [T1057](https://attack.mitre.org/techniques/T1057) ([local](/mitre/techniques/T1057.md)) Process Discovery, [T1059.003](https://attack.mitre.org/techniques/T1059/003) ([local](/mitre/techniques/T1059-003.md)) Windows Command Shell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) ([local](/mitre/techniques/T1070-004.md)) File Deletion, [T1070.006](https://attack.mitre.org/techniques/T1070/006) ([local](/mitre/techniques/T1070-006.md)) Timestomp, [T1071.001](https://attack.mitre.org/techniques/T1071/001) ([local](/mitre/techniques/T1071-001.md)) Web Protocols, [T1071.004](https://attack.mitre.org/techniques/T1071/004) ([local](/mitre/techniques/T1071-004.md)) DNS, [T1082](https://attack.mitre.org/techniques/T1082) ([local](/mitre/techniques/T1082.md)) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) ([local](/mitre/techniques/T1083.md)) File and Directory Discovery, [T1095](https://attack.mitre.org/techniques/T1095) ([local](/mitre/techniques/T1095.md)) Non-Application Layer Protocol, [T1105](https://attack.mitre.org/techniques/T1105) ([local](/mitre/techniques/T1105.md)) Ingress Tool Transfer

---

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Threat-informed defense and ATT&CK](/hubs/threat-informed-defense.md)
- [Threat Group Profiles](/THREAT_GROUP_PROFILES.md)
- [ATT&CK Technique Atlas](/ATTACK_TECHNIQUE_ATLAS.md)
- [Malware Families](/MALWARE_FAMILIES.md)

<!-- related:end -->

---

*© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*
