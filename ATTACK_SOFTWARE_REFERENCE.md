# ATT&CK Software Reference

> The **784 software entries** in MITRE ATT&CK Enterprise (v18.1) — **693 malware** families and **91 tools** — that adversaries use to carry out techniques. Each entry lists the number of ATT&CK techniques it implements and the threat groups known to use it. Pair with [Threat Group Profiles](THREAT_GROUP_PROFILES.md), the [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md), and [Malware Families](MALWARE_FAMILIES.md).

Machine-readable: [`data/attack/software.jsonl`](data/attack/software.jsonl) · [`data/attack/software_to_technique.jsonl`](data/attack/software_to_technique.jsonl)

## All software by technique breadth

| Software | Type | Techniques | Groups |
|---|---|--:|--:|
| [S0260 InvisiMole](#s0260) | malware | 73 | 0 |
| [S0363 Empire](#s0363) | tool | 73 | 17 |
| [S0154 Cobalt Strike](#s0154) | malware | 72 | 29 |
| [S0650 QakBot](#s0650) | malware | 71 | 3 |
| [S1111 DarkGate](#s1111) | malware | 58 | 0 |
| [S0266 TrickBot](#s0266) | malware | 55 | 2 |
| [S0692 SILENTTRINITY](#s0692) | tool | 53 | 0 |
| [S0534 Bazar](#s0534) | malware | 51 | 2 |
| [S0013 PlugX](#s0013) | malware | 49 | 15 |
| [S0367 Emotet](#s0367) | malware | 47 | 1 |
| [S0455 Metamorfo](#s0455) | malware | 46 | 0 |
| [S0198 NETWIRE](#s0198) | malware | 45 | 4 |
| [S0603 Stuxnet](#s0603) | malware | 44 | 0 |
| [S1239 TONESHELL](#s1239) | malware | 43 | 1 |
| [S1160 Latrodectus](#s1160) | malware | 43 | 2 |
| [S0531 Grandoreiro](#s0531) | malware | 43 | 0 |
| [S0409 Machete](#s0409) | malware | 41 | 1 |
| [S1130 Raspberry Robin](#s1130) | malware | 41 | 0 |
| [S0192 Pupy](#s0192) | tool | 41 | 2 |
| [S0356 KONNI](#s0356) | malware | 40 | 0 |
| [S1242 Qilin](#s1242) | malware | 40 | 2 |
| [S1039 Bumblebee](#s1039) | malware | 39 | 2 |
| [S0458 Ramsay](#s0458) | malware | 39 | 0 |
| [S0148 RTM](#s0148) | malware | 38 | 1 |
| [S1018 Saint Bot](#s1018) | malware | 37 | 2 |
| [S1044 FunnyDream](#s1044) | malware | 37 | 0 |
| [S0331 Agent Tesla](#s0331) | malware | 37 | 2 |
| [S1060 Mafalda](#s1060) | malware | 36 | 1 |
| [S0022 Uroburos](#s0022) | malware | 36 | 1 |
| [S0559 SUNBURST](#s0559) | malware | 36 | 1 |
| [S0373 Astaroth](#s0373) | malware | 36 | 0 |
| [S0386 Ursnif](#s0386) | malware | 35 | 1 |
| [S1245 InvisibleFerret](#s1245) | malware | 35 | 1 |
| [S1081 BADHATCH](#s1081) | malware | 35 | 1 |
| [S1228 PUBLOAD](#s1228) | malware | 35 | 1 |
| [S1213 Lumma Stealer](#s1213) | malware | 35 | 0 |
| [S1240 RedLine Stealer](#s1240) | malware | 35 | 0 |
| [S0438 Attor](#s0438) | malware | 35 | 0 |
| [S0496 REvil](#s0496) | malware | 35 | 2 |
| [S0428 PoetRAT](#s0428) | malware | 35 | 0 |
| [S0439 Okrum](#s0439) | malware | 34 | 1 |
| [S0673 DarkWatchman](#s0673) | malware | 34 | 0 |
| [S0268 Bisonal](#s0268) | malware | 34 | 1 |
| [S0660 Clambling](#s0660) | malware | 34 | 1 |
| [S1202 LockBit 3.0](#s1202) | malware | 34 | 0 |
| [S1183 StrelaStealer](#s1183) | malware | 34 | 0 |
| [S0476 Valak](#s0476) | malware | 34 | 1 |
| [S0412 ZxShell](#s0412) | malware | 34 | 3 |
| [S0658 XCSSET](#s0658) | malware | 33 | 0 |
| [S0666 Gelsemium](#s0666) | malware | 33 | 0 |
| [S1063 Brute Ratel C4](#s1063) | tool | 33 | 0 |
| [S0622 AppleSeed](#s0622) | malware | 32 | 1 |
| [S0378 PoshC2](#s0378) | tool | 32 | 3 |
| [S0483 IcedID](#s0483) | malware | 31 | 2 |
| [S0265 Kazuar](#s0265) | malware | 31 | 1 |
| [S1149 CHIMNEYSWEEP](#s1149) | malware | 31 | 0 |
| [S0251 Zebrocy](#s0251) | malware | 31 | 1 |
| [S0663 SysUpdate](#s0663) | malware | 31 | 1 |
| [S0385 njRAT](#s0385) | malware | 31 | 7 |
| [S0115 Crimson](#s0115) | malware | 30 | 1 |
| [S1065 Woody RAT](#s1065) | malware | 30 | 0 |
| [S0240 ROKRAT](#s0240) | malware | 30 | 1 |
| [S0125 Remsec](#s0125) | malware | 30 | 1 |
| [S1141 LunarWeb](#s1141) | malware | 30 | 1 |
| [S0670 WarzoneRAT](#s0670) | malware | 30 | 3 |
| [S1159 DUSTTRAP](#s1159) | malware | 29 | 1 |
| [S1100 Ninja](#s1100) | malware | 28 | 1 |
| [S0689 WhisperGate](#s0689) | malware | 28 | 1 |
| [S1066 DarkTortilla](#s1066) | malware | 28 | 0 |
| [S0631 Chaes](#s0631) | malware | 28 | 0 |
| [S1207 XLoader](#s1207) | malware | 28 | 0 |
| [S0352 OSX_OCEANLOTUS.D](#s0352) | malware | 28 | 1 |
| [S0447 Lokibot](#s0447) | malware | 28 | 1 |
| [S1059 metaMain](#s1059) | malware | 28 | 1 |
| [S0283 jRAT](#s0283) | malware | 28 | 1 |
| [S0681 Lizar](#s0681) | malware | 28 | 1 |
| [S0194 PowerSploit](#s0194) | tool | 28 | 9 |
| [S0601 Hildegard](#s0601) | malware | 27 | 1 |
| [S1016 MacMa](#s1016) | malware | 27 | 1 |
| [S0223 POWERSTATS](#s0223) | malware | 27 | 1 |
| [S0250 Koadic](#s0250) | tool | 27 | 4 |
| [S1229 Havoc](#s1229) | malware | 26 | 0 |
| [S0491 StrongPity](#s0491) | malware | 26 | 1 |
| [S1153 Cuckoo Stealer](#s1153) | malware | 26 | 0 |
| [S1122 Mispadu](#s1122) | malware | 26 | 1 |
| [S0234 Bandook](#s0234) | malware | 26 | 1 |
| [S1070 Black Basta](#s1070) | malware | 26 | 1 |
| [S0697 HermeticWiper](#s0697) | malware | 26 | 0 |
| [S1199 LockBit 2.0](#s1199) | malware | 26 | 0 |
| [S1085 Sardonic](#s1085) | malware | 25 | 1 |
| [S0239 Bankshot](#s0239) | malware | 25 | 1 |
| [S0629 RainyDay](#s0629) | malware | 25 | 1 |
| [S0089 BlackEnergy](#s0089) | malware | 25 | 1 |
| [S0484 Carberp](#s0484) | malware | 25 | 0 |
| [S0632 GrimAgent](#s0632) | malware | 25 | 2 |
| [S0554 Egregor](#s0554) | malware | 25 | 0 |
| [S0456 Aria-body](#s0456) | malware | 24 | 1 |
| [S0615 SombRAT](#s0615) | malware | 24 | 0 |
| [S0532 Lucifer](#s0532) | malware | 24 | 0 |
| [S0696 Flagpro](#s0696) | malware | 24 | 1 |
| [S1064 SVCReady](#s1064) | malware | 24 | 0 |
| [S0674 CharmPower](#s0674) | malware | 24 | 1 |
| [S0032 gh0st RAT](#s0032) | malware | 24 | 11 |
| [S0140 Shamoon](#s0140) | malware | 24 | 0 |
| [S0461 SDBbot](#s0461) | malware | 24 | 1 |
| [S0467 TajMahal](#s0467) | malware | 24 | 0 |
| [S1148 Raccoon Stealer](#s1148) | malware | 24 | 1 |
| [S0128 BADNEWS](#s0128) | malware | 24 | 1 |
| [S0533 SLOTHFULMEDIA](#s0533) | malware | 24 | 0 |
| [S0677 AADInternals](#s0677) | tool | 24 | 2 |
| [S0262 QuasarRAT](#s0262) | tool | 24 | 6 |
| [S0330 Zeus Panda](#s0330) | malware | 23 | 0 |
| [S1246 BeaverTail](#s1246) | malware | 23 | 1 |
| [S0625 Cuba](#s0625) | malware | 23 | 0 |
| [S0482 Bundlore](#s0482) | malware | 23 | 0 |
| [S0501 PipeMon](#s0501) | malware | 23 | 1 |
| [S0449 Maze](#s0449) | malware | 23 | 2 |
| [S0567 Dtrack](#s0567) | malware | 23 | 1 |
| [S0045 ADVSTORESHELL](#s0045) | malware | 23 | 1 |
| [S0633 Sliver](#s0633) | tool | 23 | 3 |
| [S0520 BLINDINGCAN](#s0520) | malware | 22 | 1 |
| [S0662 RCSession](#s0662) | malware | 22 | 2 |
| [S1244 Medusa Ransomware](#s1244) | malware | 22 | 1 |
| [S0381 FlawedAmmyy](#s0381) | malware | 22 | 2 |
| [S0652 MarkiRAT](#s0652) | malware | 22 | 1 |
| [S0091 Epic](#s0091) | malware | 22 | 1 |
| [S0395 LightNeuron](#s0395) | malware | 22 | 1 |
| [S1247 Embargo](#s1247) | malware | 22 | 1 |
| [S0094 Trojan.Karagany](#s0094) | malware | 22 | 1 |
| [S0446 Ryuk](#s0446) | malware | 22 | 2 |
| [S0182 FinFisher](#s0182) | malware | 22 | 1 |
| [S0348 Cardinal RAT](#s0348) | malware | 22 | 0 |
| [S0236 Kwampirs](#s0236) | malware | 22 | 1 |
| [S0141 Winnti for Windows](#s0141) | malware | 22 | 2 |
| [S1196 Troll Stealer](#s1196) | malware | 22 | 1 |
| [S0377 Ebury](#s0377) | malware | 22 | 1 |
| [S0126 ComRAT](#s0126) | malware | 22 | 1 |
| [S1145 Pikabot](#s1145) | malware | 21 | 1 |
| [S1212 RansomHub](#s1212) | malware | 21 | 0 |
| [S1030 Squirrelwaffle](#s1030) | malware | 21 | 0 |
| [S0376 HOPLIGHT](#s0376) | malware | 21 | 2 |
| [S1068 BlackCat](#s1068) | malware | 21 | 1 |
| [S0512 FatDuke](#s0512) | malware | 21 | 1 |
| [S0444 ShimRat](#s0444) | malware | 21 | 1 |
| [S0038 Duqu](#s0038) | malware | 21 | 0 |
| [S0661 FoggyWeb](#s0661) | malware | 21 | 1 |
| [S0649 SMOKEDHAM](#s0649) | malware | 21 | 0 |
| [S1090 NightClub](#s1090) | malware | 21 | 1 |
| [S1180 BlackByte Ransomware](#s1180) | malware | 21 | 1 |
| [S0687 Cyclops Blink](#s0687) | malware | 21 | 1 |
| [S1020 Kevin](#s1020) | malware | 21 | 1 |
| [S0596 ShadowPad](#s0596) | malware | 21 | 8 |
| [S0170 Helminth](#s0170) | malware | 21 | 1 |
| [S1091 Pacu](#s1091) | tool | 21 | 0 |
| [S1050 PcShare](#s1050) | tool | 21 | 1 |
| [S0184 POWRUNER](#s0184) | malware | 20 | 1 |
| [S0113 Prikormka](#s0113) | malware | 20 | 0 |
| [S1178 ShrinkLocker](#s1178) | malware | 20 | 0 |
| [S1086 Snip3](#s1086) | malware | 20 | 1 |
| [S0612 WastedLocker](#s0612) | malware | 20 | 1 |
| [S0495 RDAT](#s0495) | malware | 20 | 1 |
| [S0448 Rising Sun](#s0448) | malware | 20 | 0 |
| [S0504 Anchor](#s0504) | malware | 20 | 1 |
| [S0085 S-Type](#s0085) | malware | 20 | 0 |
| [S0044 JHUHUGIT](#s0044) | malware | 20 | 1 |
| [S0526 KGH_SPY](#s0526) | malware | 20 | 1 |
| [S0431 HotCroissant](#s0431) | malware | 20 | 1 |
| [S1015 Milan](#s1015) | malware | 20 | 1 |
| [S0011 Taidoor](#s0011) | malware | 20 | 0 |
| [S0688 Meteor](#s0688) | malware | 20 | 0 |
| [S0201 JPIN](#s0201) | malware | 20 | 1 |
| [S0669 KOCTOPUS](#s0669) | malware | 20 | 1 |
| [S0584 AppleJeus](#s0584) | malware | 20 | 1 |
| [S0354 Denis](#s0354) | malware | 20 | 1 |
| [S0488 CrackMapExec](#s0488) | tool | 20 | 5 |
| [S0237 GravityRAT](#s0237) | malware | 19 | 0 |
| [S0050 CosmicDuke](#s0050) | malware | 19 | 1 |
| [S0180 Volgmer](#s0180) | malware | 19 | 1 |
| [S0659 Diavol](#s0659) | malware | 19 | 1 |
| [S1124 SocGholish](#s1124) | malware | 19 | 1 |
| [S0062 DustySky](#s0062) | malware | 19 | 1 |
| [S0203 Hydraq](#s0203) | malware | 19 | 2 |
| [S0081 Elise](#s0081) | malware | 19 | 1 |
| [S0657 BLUELIGHT](#s0657) | malware | 19 | 1 |
| [S0264 OopsIE](#s0264) | malware | 19 | 1 |
| [S1099 Samurai](#s1099) | malware | 19 | 1 |
| [S0023 CHOPSTICK](#s0023) | malware | 19 | 1 |
| [S0267 FELIXROOT](#s0267) | malware | 19 | 0 |
| [S1022 IceApple](#s1022) | malware | 19 | 0 |
| [S0340 Octopus](#s0340) | malware | 19 | 1 |
| [S0604 Industroyer](#s0604) | malware | 19 | 1 |
| [S0244 Comnie](#s0244) | malware | 19 | 0 |
| [S1105 COATHANGER](#s1105) | malware | 18 | 0 |
| [S0647 Turian](#s0647) | malware | 18 | 1 |
| [S1138 Gootloader](#s1138) | malware | 18 | 0 |
| [S0334 DarkComet](#s0334) | malware | 18 | 3 |
| [S0690 Green Lambert](#s0690) | malware | 18 | 0 |
| [S0588 GoldMax](#s0588) | malware | 18 | 1 |
| [S0387 KeyBoy](#s0387) | malware | 18 | 1 |
| [S0595 ThiefQuest](#s0595) | malware | 18 | 0 |
| [S0030 Carbanak](#s0030) | malware | 18 | 2 |
| [S0457 Netwalker](#s0457) | malware | 18 | 0 |
| [S0168 Gazer](#s0168) | malware | 18 | 1 |
| [S1210 Sagerunex](#s1210) | malware | 18 | 1 |
| [S0270 RogueRobin](#s0270) | malware | 18 | 1 |
| [S0021 Derusbi](#s0021) | malware | 18 | 4 |
| [S0589 Sibot](#s0589) | malware | 18 | 1 |
| [S0335 Carbon](#s0335) | malware | 18 | 1 |
| [S0379 Revenge RAT](#s0379) | malware | 18 | 2 |
| [S0587 Penquin](#s0587) | malware | 18 | 1 |
| [S0084 Mis-Type](#s0084) | malware | 18 | 0 |
| [S0477 Goopy](#s0477) | malware | 18 | 1 |
| [S0451 LoudMiner](#s0451) | malware | 18 | 0 |
| [S0570 BitPaymer](#s0570) | malware | 18 | 1 |
| [S1025 Amadey](#s1025) | malware | 17 | 2 |
| [S1078 RotaJakiro](#s1078) | malware | 17 | 1 |
| [S0153 RedLeaves](#s0153) | malware | 17 | 1 |
| [S1226 BOOKWORM](#s1226) | malware | 17 | 1 |
| [S0342 GreyEnergy](#s0342) | malware | 17 | 1 |
| [S0257 VERMIN](#s0257) | malware | 17 | 0 |
| [S0640 Avaddon](#s0640) | malware | 17 | 0 |
| [S0196 PUNCHBUGGY](#s0196) | malware | 17 | 1 |
| [S0147 Pteranodon](#s0147) | malware | 17 | 1 |
| [S0269 QUADAGENT](#s0269) | malware | 17 | 1 |
| [S0256 Mosquito](#s0256) | malware | 17 | 1 |
| [S1019 Shark](#s1019) | malware | 17 | 1 |
| [S1146 MgBot](#s1146) | malware | 17 | 1 |
| [S1142 LunarMail](#s1142) | malware | 17 | 1 |
| [S1017 OutSteel](#s1017) | malware | 17 | 1 |
| [S0611 Clop](#s0611) | malware | 17 | 1 |
| [S0599 Kinsing](#s0599) | malware | 17 | 0 |
| [S0002 Mimikatz](#s0002) | tool | 17 | 51 |
| [S0353 NOKKI](#s0353) | malware | 16 | 1 |
| [S0093 Backdoor.Oldrea](#s0093) | malware | 16 | 1 |
| [S0083 Misdat](#s0083) | malware | 16 | 0 |
| [S0453 Pony](#s0453) | malware | 16 | 0 |
| [S0468 Skidmap](#s0468) | malware | 16 | 0 |
| [S0575 Conti](#s0575) | malware | 16 | 1 |
| [S1185 LightSpy](#s1185) | malware | 16 | 1 |
| [S0024 Dyre](#s0024) | malware | 16 | 1 |
| [S0341 Xbash](#s0341) | malware | 16 | 0 |
| [S0366 WannaCry](#s0366) | malware | 16 | 1 |
| [S0586 TAINTEDSCRIBE](#s0586) | malware | 16 | 1 |
| [S0339 Micropsia](#s0339) | malware | 16 | 1 |
| [S0576 MegaCortex](#s0576) | malware | 16 | 0 |
| [S0583 Pysa](#s0583) | malware | 16 | 0 |
| [S0187 Daserf](#s0187) | malware | 16 | 1 |
| [S0475 BackConfig](#s0475) | malware | 16 | 1 |
| [S0635 BoomBox](#s0635) | malware | 16 | 1 |
| [S0582 LookBack](#s0582) | malware | 16 | 0 |
| [S0414 BabyShark](#s0414) | malware | 16 | 1 |
| [S0375 Remexi](#s0375) | malware | 16 | 1 |
| [S0344 Azorult](#s0344) | malware | 16 | 1 |
| [S0698 HermeticWizard](#s0698) | malware | 16 | 0 |
| [S0039 Net](#s0039) | tool | 16 | 32 |
| [S0445 ShimRatReporter](#s0445) | tool | 16 | 1 |
| [S0332 Remcos](#s0332) | tool | 16 | 3 |
| [S0434 Imminent Monitor](#s0434) | tool | 16 | 2 |
| [S0695 Donut](#s0695) | tool | 16 | 1 |
| [S0139 PowerDuke](#s0139) | malware | 15 | 1 |
| [S0238 Proxysvc](#s0238) | malware | 15 | 1 |
| [S0248 yty](#s0248) | malware | 15 | 0 |
| [S1053 AvosLocker](#s1053) | malware | 15 | 0 |
| [S0466 WindTail](#s0466) | malware | 15 | 1 |
| [S0082 Emissary](#s0082) | malware | 15 | 1 |
| [S0630 Nebulae](#s0630) | malware | 15 | 1 |
| [S0606 Bad Rabbit](#s0606) | malware | 15 | 1 |
| [S1184 BOLDMOVE](#s1184) | malware | 15 | 0 |
| [S1031 PingPull](#s1031) | malware | 15 | 1 |
| [S0514 WellMess](#s0514) | malware | 15 | 1 |
| [S0598 P.A.S. Webshell](#s0598) | malware | 15 | 2 |
| [S1201 TRANSLATEXT](#s1201) | malware | 15 | 1 |
| [S0053 SeaDuke](#s0053) | malware | 15 | 1 |
| [S1026 Mongall](#s1026) | malware | 15 | 1 |
| [S0572 Caterpillar WebShell](#s0572) | malware | 15 | 1 |
| [S0263 TYPEFRAME](#s0263) | malware | 15 | 1 |
| [S1073 Royal](#s1073) | malware | 15 | 0 |
| [S0015 Ixeshe](#s0015) | malware | 15 | 1 |
| [S0380 StoneDrill](#s0380) | malware | 15 | 1 |
| [S0538 Crutch](#s0538) | malware | 15 | 1 |
| [S0641 Kobalos](#s0641) | malware | 15 | 0 |
| [S0241 RATANKBA](#s0241) | malware | 15 | 1 |
| [S0149 MoonWind](#s0149) | malware | 15 | 0 |
| [S0374 SpeakUp](#s0374) | malware | 15 | 0 |
| [S0396 EvilBunny](#s0396) | malware | 15 | 0 |
| [S0382 ServHelper](#s0382) | malware | 15 | 1 |
| [S1172 OilBooster](#s1172) | malware | 15 | 1 |
| [S0012 PoisonIvy](#s0012) | malware | 15 | 14 |
| [S0435 PLEAD](#s0435) | malware | 15 | 1 |
| [S1132 IPsec Helper](#s1132) | malware | 15 | 1 |
| [S0274 Calisto](#s0274) | malware | 15 | 0 |
| [S0493 GoldenSpy](#s0493) | malware | 15 | 0 |
| [S0517 Pillowmint](#s0517) | malware | 15 | 1 |
| [S1150 ROADSWEEP](#s1150) | malware | 15 | 0 |
| [S0284 More_eggs](#s0284) | malware | 15 | 3 |
| [S0279 Proton](#s0279) | malware | 15 | 0 |
| [S1200 StealBit](#s1200) | malware | 15 | 0 |
| [S0610 SideTwist](#s0610) | malware | 15 | 1 |
| [S1027 Heyoka Backdoor](#s1027) | malware | 15 | 1 |
| [S0607 KillDisk](#s0607) | malware | 15 | 2 |
| [S0384 Dridex](#s0384) | malware | 15 | 2 |
| [S0402 OSX/Shlayer](#s0402) | malware | 15 | 0 |
| [S1139 INC Ransomware](#s1139) | malware | 15 | 1 |
| [S1034 StrifeWater](#s1034) | malware | 15 | 1 |
| [S0242 SynAck](#s0242) | malware | 14 | 0 |
| [S0226 Smoke Loader](#s0226) | malware | 14 | 0 |
| [S0665 ThreatNeedle](#s0665) | malware | 14 | 1 |
| [S0668 TinyTurla](#s0668) | malware | 14 | 1 |
| [S0634 EnvyScout](#s0634) | malware | 14 | 1 |
| [S1198 Gomir](#s1198) | malware | 14 | 1 |
| [S0365 Olympic Destroyer](#s0365) | malware | 14 | 1 |
| [S0600 Doki](#s0600) | malware | 14 | 0 |
| [S0623 Siloscape](#s0623) | malware | 14 | 0 |
| [S1147 Nightdoor](#s1147) | malware | 14 | 1 |
| [S0441 PowerShower](#s0441) | malware | 14 | 1 |
| [S0368 NotPetya](#s0368) | malware | 14 | 1 |
| [S0667 Chrommme](#s0667) | malware | 14 | 0 |
| [S0644 ObliqueRAT](#s0644) | malware | 14 | 1 |
| [S0638 Babuk](#s0638) | malware | 14 | 0 |
| [S0127 BBSRAT](#s0127) | malware | 14 | 0 |
| [S0172 Reaver](#s0172) | malware | 14 | 0 |
| [S1135 MultiLayer Wiper](#s1135) | malware | 14 | 1 |
| [S0568 EVILNUM](#s0568) | malware | 14 | 1 |
| [S1013 ZxxZ](#s1013) | malware | 14 | 1 |
| [S1190 Kapeka](#s1190) | malware | 14 | 1 |
| [S0136 USBStealer](#s0136) | malware | 14 | 1 |
| [S1014 DanBot](#s1014) | malware | 14 | 1 |
| [S0249 Gold Dragon](#s0249) | malware | 14 | 1 |
| [S0487 Kessel](#s0487) | malware | 14 | 0 |
| [S0516 SoreFang](#s0516) | malware | 14 | 1 |
| [S1037 STARWHALE](#s1037) | malware | 14 | 1 |
| [S0046 CozyCar](#s0046) | malware | 14 | 1 |
| [S0492 CookieMiner](#s0492) | malware | 14 | 0 |
| [S0499 Hancitor](#s0499) | malware | 14 | 0 |
| [S0579 Waterbear](#s0579) | malware | 14 | 1 |
| [S0031 BACKSPACE](#s0031) | malware | 14 | 1 |
| [S0229 Orz](#s0229) | malware | 13 | 1 |
| [S0678 Torisma](#s0678) | malware | 13 | 0 |
| [S1075 KOPILUWAK](#s1075) | malware | 13 | 1 |
| [S0230 ZeroT](#s0230) | malware | 13 | 1 |
| [S0481 Ragnar Locker](#s0481) | malware | 13 | 1 |
| [S0694 DRATzarus](#s0694) | malware | 13 | 0 |
| [S0608 Conficker](#s0608) | malware | 13 | 0 |
| [S0436 TSCookie](#s0436) | malware | 13 | 1 |
| [S1182 MagicRAT](#s1182) | malware | 13 | 1 |
| [S0098 T9000](#s0098) | malware | 13 | 0 |
| [S1161 BPFDoor](#s1161) | malware | 13 | 0 |
| [S0513 LiteDuke](#s0513) | malware | 13 | 1 |
| [S1042 SUGARDUMP](#s1042) | malware | 13 | 0 |
| [S0664 Pandora](#s0664) | malware | 13 | 2 |
| [S0336 NanoCore](#s0336) | malware | 13 | 4 |
| [S1169 Mango](#s1169) | malware | 13 | 1 |
| [S0132 H1N1](#s0132) | malware | 13 | 0 |
| [S1035 Small Sieve](#s1035) | malware | 13 | 1 |
| [S1087 AsyncRAT](#s1087) | tool | 13 | 1 |
| [S0699 Mythic](#s0699) | tool | 13 | 0 |
| [S0401 Exaramel for Linux](#s0401) | malware | 12 | 1 |
| [S1164 UPSTYLE](#s1164) | malware | 12 | 0 |
| [S1028 Action RAT](#s1028) | malware | 12 | 1 |
| [S0473 Avenger](#s0473) | malware | 12 | 1 |
| [S1249 HexEval Loader](#s1249) | malware | 12 | 1 |
| [S0561 GuLoader](#s0561) | malware | 12 | 0 |
| [S0410 Fysbis](#s0410) | malware | 12 | 1 |
| [S0398 HyperBro](#s0398) | malware | 12 | 1 |
| [S0528 Javali](#s0528) | malware | 12 | 0 |
| [S0569 Explosive](#s0569) | malware | 12 | 1 |
| [S0228 NanHaiShu](#s0228) | malware | 12 | 1 |
| [S0680 LitePower](#s0680) | malware | 12 | 1 |
| [S0651 BoxCaon](#s0651) | malware | 12 | 1 |
| [S0502 Drovorub](#s0502) | malware | 12 | 1 |
| [S0337 BadPatch](#s0337) | malware | 12 | 0 |
| [S1043 ccf32](#s1043) | malware | 12 | 0 |
| [S0562 SUNSPOT](#s0562) | malware | 12 | 1 |
| [S1052 DEADEYE](#s1052) | malware | 12 | 0 |
| [S0530 Melcoz](#s0530) | malware | 12 | 0 |
| [S0144 ChChes](#s0144) | malware | 12 | 1 |
| [S1217 VIRTUALPITA](#s1217) | malware | 12 | 1 |
| [S1248 XORIndex Loader](#s1248) | malware | 12 | 1 |
| [S0527 CSPY Downloader](#s0527) | tool | 12 | 1 |
| [S0683 Peirates](#s0683) | tool | 12 | 1 |
| [S0546 SharpStage](#s0546) | malware | 11 | 1 |
| [S0271 KEYMARBLE](#s0271) | malware | 11 | 1 |
| [S0391 HAWKBALL](#s0391) | malware | 11 | 0 |
| [S0086 ZLib](#s0086) | malware | 11 | 0 |
| [S1089 SharpDisco](#s1089) | malware | 11 | 1 |
| [S0653 xCaon](#s0653) | malware | 11 | 1 |
| [S1048 macOS.OSAMiner](#s1048) | malware | 11 | 0 |
| [S1032 PyDCrypt](#s1032) | malware | 11 | 1 |
| [S1181 BlackByte 2.0 Ransomware](#s1181) | malware | 11 | 1 |
| [S1236 CLAIMLOADER](#s1236) | malware | 11 | 1 |
| [S0019 Regin](#s0019) | malware | 11 | 0 |
| [S0691 Neoichor](#s0691) | malware | 11 | 1 |
| [S1219 REPTILE](#s1219) | malware | 11 | 1 |
| [S0034 NETEAGLE](#s0034) | malware | 11 | 1 |
| [S0350 zwShell](#s0350) | malware | 11 | 0 |
| [S0646 SpicyOmelette](#s0646) | malware | 11 | 1 |
| [S0137 CORESHELL](#s0137) | malware | 11 | 1 |
| [S0018 Sykipot](#s0018) | malware | 11 | 0 |
| [S0452 USBferry](#s0452) | malware | 11 | 1 |
| [S0574 BendyBear](#s0574) | malware | 11 | 0 |
| [S0585 Kerrdown](#s0585) | malware | 11 | 1 |
| [S0627 SodaMaster](#s0627) | malware | 11 | 1 |
| [S0009 Hikit](#s0009) | malware | 11 | 1 |
| [S0074 Sakula](#s0074) | malware | 11 | 1 |
| [S0259 InnaputRAT](#s0259) | malware | 11 | 0 |
| [S0351 Cannon](#s0351) | malware | 11 | 1 |
| [S0070 HTTPBrowser](#s0070) | malware | 11 | 2 |
| [S0281 Dok](#s0281) | malware | 11 | 0 |
| [S0521 BloodHound](#s0521) | tool | 11 | 6 |
| [S0357 Impacket](#s0357) | tool | 11 | 18 |
| [S0543 Spark](#s0543) | malware | 10 | 1 |
| [S1233 PAKLOG](#s1233) | malware | 10 | 1 |
| [S1187 reGeorg](#s1187) | malware | 10 | 3 |
| [S0171 Felismus](#s0171) | malware | 10 | 1 |
| [S0167 Matryoshka](#s0167) | malware | 10 | 1 |
| [S0088 Kasidet](#s0088) | malware | 10 | 0 |
| [S0518 PolyglotDuke](#s0518) | malware | 10 | 1 |
| [S1029 AuTo Stealer](#s1029) | malware | 10 | 1 |
| [S1133 Apostle](#s1133) | malware | 10 | 1 |
| [S0642 BADFLICK](#s0642) | malware | 10 | 1 |
| [S0161 XAgentOSX](#s0161) | malware | 10 | 1 |
| [S0020 China Chopper](#s0020) | malware | 10 | 9 |
| [S0253 RunningRAT](#s0253) | malware | 10 | 0 |
| [S0090 Rover](#s0090) | malware | 10 | 0 |
| [S1129 Akira](#s1129) | malware | 10 | 1 |
| [S0472 down_new](#s0472) | malware | 10 | 1 |
| [S1168 SampleCheck5000](#s1168) | malware | 10 | 1 |
| [S0345 Seasalt](#s0345) | malware | 10 | 1 |
| [S0017 BISCUIT](#s0017) | malware | 10 | 1 |
| [S1222 RIFLESPINE](#s1222) | malware | 10 | 1 |
| [S1156 Manjusaka](#s1156) | malware | 10 | 0 |
| [S1134 DEADWOOD](#s1134) | malware | 10 | 2 |
| [S0165 OSInfo](#s0165) | malware | 10 | 1 |
| [S0275 UPPERCUT](#s0275) | malware | 10 | 1 |
| [S0394 HiddenWasp](#s0394) | malware | 10 | 0 |
| [S0143 Flame](#s0143) | malware | 10 | 0 |
| [S1155 Covenant](#s1155) | tool | 10 | 1 |
| [S1144 FRP](#s1144) | tool | 10 | 3 |
| [S0500 MCMD](#s0500) | tool | 10 | 1 |
| [S0349 LaZagne](#s0349) | tool | 10 | 12 |
| [S0605 EKANS](#s0605) | malware | 9 | 0 |
| [S0686 QuietSieve](#s0686) | malware | 9 | 1 |
| [S0233 MURKYTOP](#s0233) | malware | 9 | 1 |
| [S1193 TAMECAT](#s1193) | malware | 9 | 1 |
| [S1058 Prestige](#s1058) | malware | 9 | 1 |
| [S0254 PLAINTEE](#s0254) | malware | 9 | 1 |
| [S0347 AuditCred](#s0347) | malware | 9 | 1 |
| [S0058 SslMM](#s0058) | malware | 9 | 1 |
| [S1152 IMAPLoader](#s1152) | malware | 9 | 1 |
| [S1012 PowerLess](#s1012) | malware | 9 | 1 |
| [S0497 Dacls](#s0497) | malware | 9 | 1 |
| [S0547 DropBook](#s0547) | malware | 9 | 1 |
| [S1170 ODAgent](#s1170) | malware | 9 | 1 |
| [S0433 Rifdoor](#s0433) | malware | 9 | 1 |
| [S0511 RegDuke](#s0511) | malware | 9 | 1 |
| [S0276 Keydnap](#s0276) | malware | 9 | 0 |
| [S0486 Bonadan](#s0486) | malware | 9 | 0 |
| [S1186 Line Dancer](#s1186) | malware | 9 | 0 |
| [S0247 NavRAT](#s0247) | malware | 9 | 1 |
| [S0087 Hi-Zor](#s0087) | malware | 9 | 0 |
| [S0051 MiniDuke](#s0051) | malware | 9 | 1 |
| [S1179 Exbyte](#s1179) | malware | 9 | 1 |
| [S0616 DEATHRANSOM](#s0616) | malware | 9 | 0 |
| [S0679 Ferocious](#s0679) | malware | 9 | 1 |
| [S1047 Mori](#s1047) | malware | 9 | 1 |
| [S1140 Spica](#s1140) | malware | 9 | 1 |
| [S1021 DnsSystem](#s1021) | malware | 9 | 1 |
| [S0261 Catchamas](#s0261) | malware | 9 | 1 |
| [S0142 StreamEx](#s0142) | malware | 9 | 1 |
| [S1076 QUIETCANARY](#s1076) | malware | 9 | 0 |
| [S0515 WellMail](#s0515) | malware | 9 | 1 |
| [S0176 Wingbird](#s0176) | malware | 9 | 1 |
| [S0124 Pisloader](#s0124) | malware | 9 | 1 |
| [S1110 SLIGHTPULSE](#s1110) | malware | 9 | 1 |
| [S0369 CoinTicker](#s0369) | malware | 9 | 0 |
| [S1114 ZIPLINE](#s1114) | malware | 9 | 0 |
| [S1230 HIUPAN](#s1230) | malware | 9 | 1 |
| [S1227 StarProxy](#s1227) | malware | 9 | 1 |
| [S0211 Linfo](#s0211) | malware | 9 | 1 |
| [S0282 MacSpy](#s0282) | malware | 9 | 0 |
| [S0672 Zox](#s0672) | malware | 9 | 1 |
| [S0181 FALLCHILL](#s0181) | malware | 9 | 1 |
| [S0417 GRIFFON](#s0417) | malware | 8 | 1 |
| [S0343 Exaramel for Windows](#s0343) | malware | 8 | 1 |
| [S1154 VersaMem](#s1154) | malware | 8 | 1 |
| [S1224 CASTLETAP](#s1224) | malware | 8 | 1 |
| [S0346 OceanSalt](#s0346) | malware | 8 | 0 |
| [S1203 J-magic](#s1203) | malware | 8 | 0 |
| [S0671 Tomiris](#s0671) | malware | 8 | 0 |
| [S0333 UBoatRAT](#s0333) | malware | 8 | 0 |
| [S1033 DCSrv](#s1033) | malware | 8 | 1 |
| [S0150 POSHSPY](#s0150) | malware | 8 | 1 |
| [S1188 Line Runner](#s1188) | malware | 8 | 0 |
| [S1232 SplatDropper](#s1232) | malware | 8 | 1 |
| [S1051 KEYPLUG](#s1051) | malware | 8 | 1 |
| [S0117 XTunnel](#s0117) | malware | 8 | 1 |
| [S1023 CreepyDrive](#s1023) | malware | 8 | 1 |
| [S0556 Pay2Key](#s0556) | malware | 8 | 1 |
| [S0430 Winnti for Linux](#s0430) | malware | 8 | 3 |
| [S1151 ZeroCleare](#s1151) | malware | 8 | 1 |
| [S0390 SQLRat](#s0390) | malware | 8 | 1 |
| [S0443 MESSAGETAP](#s0443) | malware | 8 | 1 |
| [S0245 BADCALL](#s0245) | malware | 8 | 1 |
| [S1235 CorKLOG](#s1235) | malware | 8 | 1 |
| [S0072 OwaAuth](#s0072) | malware | 8 | 0 |
| [S0454 Cadelspy](#s0454) | malware | 8 | 1 |
| [S0338 Cobian RAT](#s0338) | malware | 8 | 0 |
| [S0130 Unknown Logger](#s0130) | malware | 8 | 1 |
| [S1166 Solar](#s1166) | malware | 8 | 1 |
| [S1189 Neo-reGeorg](#s1189) | malware | 8 | 1 |
| [S1107 NKAbuse](#s1107) | malware | 8 | 0 |
| [S0004 TinyZBot](#s0004) | malware | 8 | 1 |
| [S1046 PowGoop](#s1046) | malware | 8 | 1 |
| [S0471 build_downer](#s0471) | malware | 8 | 1 |
| [S0459 MechaFlounder](#s0459) | malware | 8 | 1 |
| [S0208 Pasam](#s0208) | malware | 8 | 1 |
| [S0618 FIVEHANDS](#s0618) | malware | 8 | 0 |
| [S0581 IronNetInjector](#s0581) | tool | 8 | 1 |
| [S1121 LITTLELAMB.WOOLTEA](#s1121) | malware | 7 | 0 |
| [S1211 Hannotog](#s1211) | malware | 7 | 1 |
| [S0252 Brave Prince](#s0252) | malware | 7 | 1 |
| [S0278 iKitten](#s0278) | malware | 7 | 0 |
| [S0037 HAMMERTOSS](#s0037) | malware | 7 | 1 |
| [S0079 MobileOrder](#s0079) | malware | 7 | 1 |
| [S0654 ProLock](#s0654) | malware | 7 | 0 |
| [S0219 WINERACK](#s0219) | malware | 7 | 1 |
| [S0277 FruitFly](#s0277) | malware | 7 | 0 |
| [S1167 AcidPour](#s1167) | malware | 7 | 1 |
| [S0565 Raindrop](#s0565) | malware | 7 | 1 |
| [S0372 LockerGoga](#s0372) | malware | 7 | 1 |
| [S0643 Peppy](#s0643) | malware | 7 | 1 |
| [S0450 SHARPSTATS](#s0450) | malware | 7 | 1 |
| [S0553 MoleNet](#s0553) | malware | 7 | 1 |
| [S1011 Tarrask](#s1011) | malware | 7 | 1 |
| [S0498 Cryptoistic](#s0498) | malware | 7 | 1 |
| [S0469 ABK](#s0469) | malware | 7 | 1 |
| [S0389 JCry](#s0389) | malware | 7 | 0 |
| [S0048 PinchDuke](#s0048) | malware | 7 | 1 |
| [S0437 Kivars](#s0437) | malware | 7 | 1 |
| [S0693 CaddyWiper](#s0693) | malware | 7 | 0 |
| [S0258 RGDoor](#s0258) | malware | 7 | 1 |
| [S1120 FRAMESTING](#s1120) | malware | 7 | 0 |
| [S1115 WIREFIRE](#s1115) | malware | 7 | 0 |
| [S1024 CreepySnail](#s1024) | malware | 7 | 1 |
| [S0360 BONDUPDATER](#s0360) | malware | 7 | 1 |
| [S0069 BLACKCOFFEE](#s0069) | malware | 7 | 3 |
| [S1074 ANDROMEDA](#s1074) | malware | 7 | 0 |
| [S0200 Dipsind](#s0200) | malware | 7 | 1 |
| [S0186 DownPaper](#s0186) | malware | 7 | 1 |
| [S0470 BBK](#s0470) | malware | 7 | 1 |
| [S0162 Komplex](#s0162) | malware | 7 | 1 |
| [S0648 JSS Loader](#s0648) | malware | 7 | 1 |
| [S1131 NPPSPY](#s1131) | tool | 7 | 0 |
| [S1206 JumbledPath](#s1206) | malware | 6 | 1 |
| [S0213 DOGCALL](#s0213) | malware | 6 | 1 |
| [S0460 Get2](#s0460) | malware | 6 | 1 |
| [S0400 RobbinHood](#s0400) | malware | 6 | 0 |
| [S0151 HALFBAKED](#s0151) | malware | 6 | 1 |
| [S0362 Linux Rabbit](#s0362) | malware | 6 | 0 |
| [S0145 POWERSOURCE](#s0145) | malware | 6 | 1 |
| [S0049 GeminiDuke](#s0049) | malware | 6 | 1 |
| [S0462 CARROTBAT](#s0462) | malware | 6 | 0 |
| [S0059 WinMM](#s0059) | malware | 6 | 1 |
| [S1118 BUSHWALK](#s1118) | malware | 6 | 0 |
| [S0537 HyperStack](#s0537) | malware | 6 | 1 |
| [S0138 OLDBAIT](#s0138) | malware | 6 | 1 |
| [S0560 TEARDROP](#s0560) | malware | 6 | 1 |
| [S1158 DUSTPAN](#s1158) | malware | 6 | 1 |
| [S1237 CANONSTAGER](#s1237) | malware | 6 | 1 |
| [S0092 Agent.btz](#s0092) | malware | 6 | 0 |
| [S0036 FLASHFLOOD](#s0036) | malware | 6 | 1 |
| [S1049 SUGARUSH](#s1049) | malware | 6 | 0 |
| [S1101 LoFiSe](#s1101) | malware | 6 | 1 |
| [S1191 Megazord](#s1191) | malware | 6 | 1 |
| [S0216 POORAIM](#s0216) | malware | 6 | 1 |
| [S0063 SHOTPUT](#s0063) | malware | 6 | 1 |
| [S0617 HELLOKITTY](#s0617) | malware | 6 | 0 |
| [S0614 CostaBricks](#s0614) | malware | 6 | 0 |
| [S0564 BlackMould](#s0564) | malware | 6 | 1 |
| [S1109 PACEMAKER](#s1109) | malware | 6 | 1 |
| [S1218 VIRTUALPIE](#s1218) | malware | 6 | 1 |
| [S0060 Sys10](#s0060) | malware | 6 | 1 |
| [S0035 SPACESHIP](#s0035) | malware | 6 | 1 |
| [S0065 4H RAT](#s0065) | malware | 6 | 1 |
| [S1194 Akira _v2](#s1194) | malware | 6 | 1 |
| [S0355 Final1stspy](#s0355) | malware | 6 | 1 |
| [S0637 NativeZone](#s0637) | malware | 6 | 1 |
| [S1221 MOPSLED](#s1221) | malware | 6 | 2 |
| [S0388 YAHOYAH](#s0388) | malware | 6 | 1 |
| [S0199 TURNEDUP](#s0199) | malware | 6 | 1 |
| [S0371 POWERTON](#s0371) | malware | 6 | 1 |
| [S0593 ECCENTRICBANDWAGON](#s0593) | malware | 6 | 2 |
| [S1234 SplatCloak](#s1234) | malware | 6 | 1 |
| [S1104 SLOWPULSE](#s1104) | malware | 6 | 1 |
| [S1040 Rclone](#s1040) | tool | 6 | 7 |
| [S0684 ROADTools](#s0684) | tool | 6 | 1 |
| [S0106 cmd](#s0106) | tool | 6 | 6 |
| [S0404 esentutl](#s0404) | tool | 6 | 3 |
| [S1192 NICECURL](#s1192) | malware | 5 | 1 |
| [S0134 Downdelph](#s0134) | malware | 5 | 1 |
| [S0164 TDTESS](#s0164) | malware | 5 | 1 |
| [S1041 Chinoxy](#s1041) | malware | 5 | 0 |
| [S0613 PS1](#s0613) | malware | 5 | 0 |
| [S0503 FrameworkPOS](#s0503) | malware | 5 | 1 |
| [S0624 Ecipekac](#s0624) | malware | 5 | 1 |
| [S1173 PowerExchange](#s1173) | malware | 5 | 1 |
| [S0152 EvilGrab](#s0152) | malware | 5 | 1 |
| [S1238 STATICPLUGIN](#s1238) | malware | 5 | 1 |
| [S1223 THINCRUST](#s1223) | malware | 5 | 1 |
| [S0221 Umbreon](#s0221) | malware | 5 | 0 |
| [S1084 QUIETEXIT](#s1084) | malware | 5 | 1 |
| [S0370 SamSam](#s0370) | malware | 5 | 0 |
| [S0415 BOOSTWRITE](#s0415) | malware | 5 | 1 |
| [S1163 SnappyTCP](#s1163) | malware | 5 | 1 |
| [S0220 Chaos](#s0220) | malware | 5 | 0 |
| [S1096 Cheerscrypt](#s1096) | malware | 5 | 1 |
| [S1119 LIGHTWIRE](#s1119) | malware | 5 | 0 |
| [S1143 LunarLoader](#s1143) | malware | 5 | 1 |
| [S1106 NGLite](#s1106) | malware | 5 | 0 |
| [S0626 P8RAT](#s0626) | malware | 5 | 1 |
| [S0442 VBShower](#s0442) | malware | 5 | 1 |
| [S0169 RawPOS](#s0169) | malware | 5 | 1 |
| [S0155 WINDSHIELD](#s0155) | malware | 5 | 1 |
| [S0157 SOUNDBITE](#s0157) | malware | 5 | 1 |
| [S1116 WARPWIRE](#s1116) | malware | 5 | 0 |
| [S0235 CrossRAT](#s0235) | malware | 5 | 1 |
| [S0052 OnionDuke](#s0052) | malware | 5 | 1 |
| [S0578 SUPERNOVA](#s0578) | malware | 5 | 0 |
| [S0397 LoJax](#s0397) | malware | 5 | 1 |
| [S0246 HARDRAIN](#s0246) | malware | 5 | 1 |
| [S0682 TrailBlazer](#s0682) | malware | 5 | 1 |
| [S1112 STEADYPULSE](#s1112) | malware | 5 | 0 |
| [S0272 NDiskMonitor](#s0272) | malware | 5 | 1 |
| [S1123 PITSTOP](#s1123) | malware | 5 | 0 |
| [S0393 PowerStallion](#s0393) | malware | 5 | 1 |
| [S0078 Psylo](#s0078) | malware | 5 | 1 |
| [S1088 Disco](#s1088) | malware | 5 | 1 |
| [S0280 MirageFox](#s0280) | malware | 5 | 1 |
| [S0273 Socksbot](#s0273) | malware | 5 | 0 |
| [S0464 SYSCON](#s0464) | malware | 5 | 0 |
| [S0508 ngrok](#s0508) | tool | 5 | 5 |
| [S0594 Out1](#s0594) | tool | 5 | 1 |
| [S0590 NBTscan](#s0590) | tool | 5 | 10 |
| [S1071 Rubeus](#s1071) | tool | 5 | 1 |
| [S0552 AdFind](#s0552) | tool | 5 | 12 |
| [S0029 PsExec](#s0029) | tool | 5 | 38 |
| [S1204 cd00r](#s1204) | malware | 4 | 0 |
| [S0206 Wiarp](#s0206) | malware | 4 | 1 |
| [S1125 AcidRain](#s1125) | malware | 4 | 1 |
| [S0185 SEASHARPEE](#s0185) | malware | 4 | 1 |
| [S1220 MEDUSA](#s1220) | malware | 4 | 1 |
| [S0163 Janicab](#s0163) | malware | 4 | 0 |
| [S0159 SNUGRIDE](#s0159) | malware | 4 | 1 |
| [S0215 KARAE](#s0215) | malware | 4 | 1 |
| [S0628 FYAnti](#s0628) | malware | 4 | 1 |
| [S0205 Naid](#s0205) | malware | 4 | 1 |
| [S1117 GLASSTOKEN](#s1117) | malware | 4 | 0 |
| [S0189 ISMInjector](#s0189) | malware | 4 | 1 |
| [S0204 Briba](#s0204) | malware | 4 | 1 |
| [S0066 3PARA RAT](#s0066) | malware | 4 | 1 |
| [S0131 TINYTYPHON](#s0131) | malware | 4 | 1 |
| [S1113 RAPIDPULSE](#s1113) | malware | 4 | 1 |
| [S0055 RARSTONE](#s0055) | malware | 4 | 1 |
| [S0636 VaporRage](#s0636) | malware | 4 | 1 |
| [S1108 PULSECHECK](#s1108) | malware | 4 | 1 |
| [S0076 FakeM](#s0076) | malware | 4 | 1 |
| [S0210 Nerex](#s0210) | malware | 4 | 1 |
| [S0077 CallMe](#s0077) | malware | 4 | 1 |
| [S0255 DDKONG](#s0255) | malware | 4 | 1 |
| [S0685 PowerPunch](#s0685) | malware | 4 | 1 |
| [S1136 BFG Agonizer](#s1136) | malware | 4 | 1 |
| [S1102 Pcexter](#s1102) | malware | 4 | 1 |
| [S0207 Vasport](#s0207) | malware | 4 | 1 |
| [S0129 AutoIt backdoor](#s0129) | malware | 4 | 2 |
| [S0080 Mivast](#s0080) | malware | 4 | 1 |
| [S0056 Net Crawler](#s0056) | malware | 4 | 1 |
| [S0592 RemoteUtilities](#s0592) | tool | 4 | 1 |
| [S0160 certutil](#s0160) | tool | 4 | 13 |
| [S0105 dsquery](#s0105) | tool | 4 | 2 |
| [S0108 netsh](#s0108) | tool | 4 | 7 |
| [S0465 CARROTBALL](#s0465) | tool | 4 | 0 |
| [S0190 BITSAdmin](#s0190) | tool | 4 | 8 |
| [S0358 Ruler](#s0358) | tool | 4 | 1 |
| [S0416 RDFSNIFFER](#s0416) | malware | 3 | 1 |
| [S0202 adbupd](#s0202) | malware | 3 | 1 |
| [S0043 BUBBLEWRAP](#s0043) | malware | 3 | 1 |
| [S0109 WEBC2](#s0109) | malware | 3 | 1 |
| [S0214 HAPPYWORK](#s0214) | malware | 3 | 1 |
| [S1162 Playcrypt](#s1162) | malware | 3 | 1 |
| [S0042 LOWBALL](#s0042) | malware | 3 | 1 |
| [S0064 ELMER](#s0064) | malware | 3 | 1 |
| [S0218 SLOWDRIFT](#s0218) | malware | 3 | 1 |
| [S0217 SHUTTERSPEED](#s0217) | malware | 3 | 1 |
| [S0166 RemoteCMD](#s0166) | malware | 3 | 1 |
| [S1097 HUI Loader](#s1097) | malware | 3 | 2 |
| [S0232 HOMEFRY](#s0232) | malware | 3 | 1 |
| [S0156 KOMPROGO](#s0156) | malware | 3 | 1 |
| [S0067 pngdowner](#s0067) | malware | 3 | 1 |
| [S0519 SYNful Knock](#s0519) | malware | 3 | 0 |
| [S0212 CORALDECK](#s0212) | malware | 3 | 1 |
| [S0243 DealersChoice](#s0243) | malware | 3 | 1 |
| [S1197 GoBear](#s1197) | malware | 3 | 1 |
| [S0118 Nidiran](#s0118) | malware | 3 | 1 |
| [S1171 OilCheck](#s1171) | malware | 3 | 1 |
| [S0028 SHIPSHAPE](#s0028) | malware | 3 | 1 |
| [S0107 Cherry Picker](#s0107) | malware | 3 | 0 |
| [S0597 GoldFinder](#s0597) | malware | 3 | 1 |
| [S0197 PUNCHTRACK](#s0197) | malware | 3 | 1 |
| [S0054 CloudDuke](#s0054) | malware | 3 | 1 |
| [S0068 httpclient](#s0068) | malware | 3 | 1 |
| [S0158 PHOREAL](#s0158) | malware | 3 | 1 |
| [S0639 Seth-Locker](#s0639) | malware | 3 | 0 |
| [S0057 Tasklist](#s0057) | tool | 3 | 12 |
| [S0364 RawDisk](#s0364) | tool | 3 | 1 |
| [S0591 ConnectWise](#s0591) | tool | 3 | 3 |
| [S0193 Forfiles](#s0193) | tool | 3 | 1 |
| [S0359 Nltest](#s0359) | tool | 3 | 7 |
| [S0413 MailSniper](#s0413) | tool | 3 | 1 |
| [S0361 Expand](#s0361) | tool | 3 | 0 |
| [S0075 Reg](#s0075) | tool | 3 | 8 |
| [S0095 ftp](#s0095) | tool | 3 | 5 |
| [S0040 HTRAN](#s0040) | tool | 3 | 2 |
| [S0645 Wevtutil](#s0645) | tool | 3 | 5 |
| [S1209 Quick Assist](#s1209) | tool | 3 | 1 |
| [S0061 HDoor](#s0061) | malware | 2 | 1 |
| [S0010 Lurid](#s0010) | malware | 2 | 1 |
| [S1137 Moneybird](#s1137) | malware | 2 | 1 |
| [S0047 Hacking Team UEFI Rootkit](#s0047) | malware | 2 | 0 |
| [S0146 TEXTMATE](#s0146) | malware | 2 | 1 |
| [S0027 Zeroaccess](#s0027) | malware | 2 | 0 |
| [S0025 CALENDAR](#s0025) | malware | 2 | 1 |
| [S0178 Truvasys](#s0178) | malware | 2 | 1 |
| [S0188 Starloader](#s0188) | malware | 2 | 1 |
| [S0071 hcdLoader](#s0071) | malware | 2 | 1 |
| [S0003 RIPTIDE](#s0003) | malware | 2 | 1 |
| [S0222 CCBkdr](#s0222) | malware | 2 | 0 |
| [S0033 NetTraveler](#s0033) | malware | 2 | 1 |
| [S0114 BOOTRASH](#s0114) | malware | 2 | 0 |
| [S0135 HIDEDRV](#s0135) | malware | 2 | 1 |
| [S0026 GLOOXMAIL](#s0026) | malware | 2 | 1 |
| [S0099 Arp](#s0099) | tool | 2 | 4 |
| [S0174 Responder](#s0174) | tool | 2 | 3 |
| [S0008 gsecdump](#s0008) | tool | 2 | 5 |
| [S0102 nbtstat](#s0102) | tool | 2 | 1 |
| [S0231 Invoke-PSImage](#s0231) | tool | 2 | 1 |
| [S0195 SDelete](#s0195) | tool | 2 | 5 |
| [S0183 Tor](#s0183) | tool | 2 | 6 |
| [S0177 Power Loader](#s0177) | malware | 1 | 0 |
| [S0173 FLIPSIDE](#s0173) | malware | 1 | 1 |
| [S0133 Miner-C](#s0133) | malware | 1 | 0 |
| [S0383 FlawedGrace](#s0383) | malware | 1 | 1 |
| [S0073 ASPXSpy](#s0073) | malware | 1 | 5 |
| [S1010 VPNFilter](#s1010) | malware | 1 | 1 |
| [S0014 BS2005](#s0014) | malware | 1 | 0 |
| [S1072 Industroyer2](#s1072) | malware | 1 | 1 |
| [S0007 Skeleton Key](#s0007) | malware | 1 | 1 |
| [S0041 Wiper](#s0041) | malware | 1 | 0 |
| [S0016 P2P ZeuS](#s0016) | malware | 1 | 0 |
| [S0001 Trojan.Mebromi](#s0001) | malware | 1 | 0 |
| [S0112 ROCKBOOT](#s0112) | malware | 1 | 1 |
| [S0110 at](#s0110) | tool | 1 | 3 |
| [S0116 UACMe](#s0116) | tool | 1 | 0 |
| [S0005 Windows Credential Editor](#s0005) | tool | 1 | 7 |
| [S0100 ipconfig](#s0100) | tool | 1 | 13 |
| [S0121 Lslsass](#s0121) | tool | 1 | 1 |
| [S0227 spwebmember](#s0227) | tool | 1 | 1 |
| [S0101 ifconfig](#s0101) | tool | 1 | 0 |
| [S0104 netstat](#s0104) | tool | 1 | 11 |
| [S0120 Fgdump](#s0120) | tool | 1 | 0 |
| [S0123 xCmd](#s0123) | tool | 1 | 1 |
| [S0179 MimiPenguin](#s0179) | tool | 1 | 1 |
| [S0175 meek](#s0175) | tool | 1 | 1 |
| [S0096 Systeminfo](#s0096) | tool | 1 | 10 |
| [S1176 attrib](#s1176) | tool | 1 | 0 |
| [S0191 Winexe](#s0191) | tool | 1 | 3 |
| [S0225 sqlmap](#s0225) | tool | 1 | 2 |
| [S0006 pwdump](#s0006) | tool | 1 | 6 |
| [S0122 Pass-The-Hash Toolkit](#s0122) | tool | 1 | 1 |
| [S0097 Ping](#s0097) | tool | 1 | 14 |
| [S0103 route](#s0103) | tool | 1 | 2 |
| [S0111 schtasks](#s0111) | tool | 1 | 3 |
| [S0119 Cachedump](#s0119) | tool | 1 | 1 |
| [S1205 cipher.exe](#s1205) | tool | 1 | 1 |
| [S0224 Havij](#s0224) | tool | 1 | 1 |

---

## Detailed profiles — most capable software

### S0260 — InvisiMole
<a id="s0260"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0260](https://attack.mitre.org/software/S0260) · **73** techniques · **0** groups  

InvisiMole is a modular spyware program that has been used by the InvisiMole Group since at least 2013. InvisiMole has two backdoor modules called RC2FM and RC2CL that are used to perform post-exploitation activities. It has been discovered on compromised victims in the Ukraine and Russia.

**Techniques:** [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.002](https://attack.mitre.org/techniques/T1055/002) Portable Executable Injection · [T1055.004](https://attack.mitre.org/techniques/T1055/004) Asynchronous Procedure Call · [T1055.015](https://attack.mitre.org/techniques/T1055/015) ListPlanting · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging

---

### S0363 — Empire
<a id="s0363"></a>

**Aliases:** Empire, EmPyre, PowerShell Empire  
**Type:** tool · **Platforms:** Linux, macOS, Windows · **ATT&CK:** [S0363](https://attack.mitre.org/software/S0363) · **73** techniques · **17** groups  

Empire is an open-source, cross-platform remote administration and post-exploitation framework that is publicly available on GitHub. While the tool itself is primarily written in Python, the post-exploitation agents are written in pure PowerShell for Windows and Python for Linux/macOS.

**Used by:** G0010 Turla, G0034 Sandworm Team, G0051 FIN10, G0052 CopyKittens, G0064 APT33, G0065 Leviathan, G0069 MuddyWater, G0073 APT19, G0090 WIRTE, G0091 Silence, G0096 APT41, G0102 Wizard Spider, G0119 Indrik Spider, G0140 LazyScripter, G1001 HEXANE, G1016 FIN13, G1040 Play

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration · [T1021.003](https://attack.mitre.org/techniques/T1021/003) Distributed Component Object Model · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1056.004](https://attack.mitre.org/techniques/T1056/004) Credential API Hooking · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell

---

### S0154 — Cobalt Strike
<a id="s0154"></a>

**Type:** malware · **Platforms:** Windows, Linux, macOS · **ATT&CK:** [S0154](https://attack.mitre.org/software/S0154) · **72** techniques · **29** groups  

Cobalt Strike is a commercial, full-featured, remote access tool that bills itself as “adversary simulation software designed to execute targeted attacks and emulate the post-exploitation actions of advanced threat actors”.

**Used by:** G0016 APT29, G0027 Threat Group-3390, G0034 Sandworm Team, G0037 FIN6, G0045 menuPass, G0046 FIN7, G0050 APT32, G0052 CopyKittens, G0065 Leviathan, G0067 APT37, G0073 APT19, G0079 DarkHydrus, G0080 Cobalt Group, G0092 TA505, G0096 APT41, G0102 Wizard Spider, G0114 Chimera, G0119 Indrik Spider, G0129 Mustang Panda, G0143 Aquatic Panda

**Techniques:** [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1021.003](https://attack.mitre.org/techniques/T1021/003) Distributed Component Object Model · [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH · [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools · [T1029](https://attack.mitre.org/techniques/T1029) Scheduled Transfer · [T1030](https://attack.mitre.org/techniques/T1030) Data Transfer Size Limits · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery

---

### S0650 — QakBot
<a id="s0650"></a>

**Aliases:** QakBot, Pinkslipbot, QuackBot, QBot  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0650](https://attack.mitre.org/software/S0650) · **71** techniques · **3** groups  

QakBot is a modular banking trojan that has been used primarily by financially-motivated actors since at least 2007. QakBot is continuously maintained and developed and has evolved from an information stealer into a delivery agent for ransomware, most notably ProLock and Egregor.

**Used by:** G0127 TA551, G1037 TA577, G1046 Storm-1811

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools · [T1027.006](https://attack.mitre.org/techniques/T1027/006) HTML Smuggling · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing

---

### S1111 — DarkGate
<a id="s1111"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1111](https://attack.mitre.org/software/S1111) · **58** techniques · **0** groups  

DarkGate first emerged in 2018 and has evolved into an initial access and data gathering tool associated with various criminal cyber operations. Written in Delphi and named "DarkGate" by its author, DarkGate is associated with credential theft, cryptomining, cryptotheft, and pre-ransomware actions.

**Techniques:** [T1001](https://attack.mitre.org/techniques/T1001) Data Obfuscation · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.003](https://attack.mitre.org/techniques/T1036/003) Rename Legitimate Utilities · [T1036.007](https://attack.mitre.org/techniques/T1036/007) Double File Extension · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.010](https://attack.mitre.org/techniques/T1059/010) AutoHotKey & AutoIT · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery

---

### S0266 — TrickBot
<a id="s0266"></a>

**Aliases:** TrickBot, Totbrick, TSPY_TRICKLOAD  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0266](https://attack.mitre.org/software/S0266) · **55** techniques · **2** groups  

TrickBot is a Trojan spyware program written in C++ that first emerged in September 2016 as a possible successor to Dyre.

**Used by:** G0092 TA505, G0102 Wizard Spider

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1056.004](https://attack.mitre.org/techniques/T1056/004) Credential API Hooking · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1069](https://attack.mitre.org/techniques/T1069) Permission Groups Discovery

---

### S0692 — SILENTTRINITY
<a id="s0692"></a>

**Type:** tool · **Platforms:** Windows · **ATT&CK:** [S0692](https://attack.mitre.org/software/S0692) · **53** techniques · **0** groups  

SILENTTRINITY is an open source remote administration and post-exploitation framework primarily written in Python that includes stagers written in Powershell, C, and Boo. SILENTTRINITY was used in a 2019 campaign against Croatian government agencies by unidentified cyber actors.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.003](https://attack.mitre.org/techniques/T1021/003) Distributed Component Object Model · [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1056.002](https://attack.mitre.org/techniques/T1056/002) GUI Input Capture · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1069.001](https://attack.mitre.org/techniques/T1069/001) Local Groups · [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups

---

### S0534 — Bazar
<a id="s0534"></a>

**Aliases:** Bazar, KEGTAP, Team9, Bazaloader  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0534](https://attack.mitre.org/software/S0534) · **51** techniques · **2** groups  

Bazar is a downloader and backdoor that has been used since at least April 2020, with infections primarily against professional services, healthcare, manufacturing, IT, logistics and travel companies across the US and Europe.

**Used by:** G0102 Wizard Spider, G1011 EXOTIC LILY

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.007](https://attack.mitre.org/techniques/T1027/007) Dynamic API Resolution · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1036.007](https://attack.mitre.org/techniques/T1036/007) Double File Extension · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1055.013](https://attack.mitre.org/techniques/T1055/013) Process Doppelgänging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell

---

### S0013 — PlugX
<a id="s0013"></a>

**Aliases:** PlugX, Thoper, TVT, DestroyRAT, Sogu, Kaba, Korplug  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0013](https://attack.mitre.org/software/S0013) · **49** techniques · **15** groups  

PlugX is a remote access tool (RAT) with modular plugins that has been used by multiple threat groups.

**Used by:** G0001 Axiom, G0017 DragonOK, G0022 APT3, G0027 Threat Group-3390, G0044 Winnti Group, G0045 menuPass, G0062 TA459, G0093 GALLIUM, G0096 APT41, G0126 Higaisa, G0129 Mustang Panda, G1014 LuminousMoth, G1021 Cinnamon Tempest, G1034 Daggerfly, G1047 Velvet Ant

**Techniques:** [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding · [T1027.007](https://attack.mitre.org/techniques/T1027/007) Dynamic API Resolution · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.009](https://attack.mitre.org/techniques/T1070/009) Clear Persistence · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging

---

### S0367 — Emotet
<a id="s0367"></a>

**Aliases:** Emotet, Geodo  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0367](https://attack.mitre.org/software/S0367) · **47** techniques · **1** groups  

Emotet is a modular malware variant which is primarily used as a downloader for other malware variants such as TrickBot and IcedID. Emotet first emerged in June 2014, initially targeting the financial sector, and has expanded to multiple verticals over time.

**Used by:** G0102 Wizard Spider

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1016.002](https://attack.mitre.org/techniques/T1016/002) Wi-Fi Discovery · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic

---

### S0455 — Metamorfo
<a id="s0455"></a>

**Aliases:** Metamorfo, Casbaneiro  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0455](https://attack.mitre.org/software/S0455) · **46** techniques · **0** groups  

Metamorfo is a Latin-American banking trojan operated by a Brazilian cybercrime group that has been active since at least April 2018. The group focuses on targeting banks and cryptocurrency services in Brazil and Mexico.

**Techniques:** [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1056.002](https://attack.mitre.org/techniques/T1056/002) GUI Input Capture · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1102.001](https://attack.mitre.org/techniques/T1102/001) Dead Drop Resolver

---

### S0198 — NETWIRE
<a id="s0198"></a>

**Type:** malware · **Platforms:** Windows, Linux, macOS · **ATT&CK:** [S0198](https://attack.mitre.org/software/S0198) · **45** techniques · **4** groups  

NETWIRE is a publicly available, multiplatform remote administration tool (RAT) that has been used by criminal and APT groups since at least 2012.

**Used by:** G0064 APT33, G0083 SilverTerrier, G0089 The White Company, G1018 TA2541

**Techniques:** [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1036.001](https://attack.mitre.org/techniques/T1036/001) Invalid Code Signature · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.003](https://attack.mitre.org/techniques/T1053/003) Cron · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging

---

### S0603 — Stuxnet
<a id="s0603"></a>

**Aliases:** Stuxnet, W32.Stuxnet  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0603](https://attack.mitre.org/software/S0603) · **44** techniques · **0** groups  

Stuxnet was the first publicly reported piece of malware to specifically target industrial control systems devices. Stuxnet is a large and complex piece of malware that utilized multiple different behaviors including multiple zero-day vulnerabilities, a sophisticated Windows rootkit, and network infection routines.

**Techniques:** [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1014](https://attack.mitre.org/techniques/T1014) Rootkit · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1021](https://attack.mitre.org/techniques/T1021) Remote Services · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.006](https://attack.mitre.org/techniques/T1070/006) Timestomp · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1078.001](https://attack.mitre.org/techniques/T1078/001) Default Accounts · [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts · [T1080](https://attack.mitre.org/techniques/T1080) Taint Shared Content · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery

---

### S1239 — TONESHELL
<a id="s1239"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1239](https://attack.mitre.org/software/S1239) · **43** techniques · **1** groups  

TONESHELL is a custom backdoor that has been used since at least Q1 2021. TONESHELL malware has previously been leveraged by Chinese affiliated actors identified as Mustang Panda.

**Used by:** G0129 Mustang Panda

**Techniques:** [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding · [T1027.007](https://attack.mitre.org/techniques/T1027/007) Dynamic API Resolution · [T1027.012](https://attack.mitre.org/techniques/T1027/012) LNK Icon Smuggling · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1087](https://attack.mitre.org/techniques/T1087) Account Discovery · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S1160 — Latrodectus
<a id="s1160"></a>

**Aliases:** Latrodectus, IceNova, Unidentified 111  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1160](https://attack.mitre.org/software/S1160) · **43** techniques · **2** groups  

Latrodectus is a Windows malware downloader that has been used since at least 2023 to download and execute additional payloads and modules. Latrodectus has most often been distributed through email campaigns, primarily by TA577 and TA578, and has infrastructure overlaps with historic IcedID operations.

**Used by:** G1037 TA577, G1038 TA578

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC · [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.007](https://attack.mitre.org/techniques/T1027/007) Dynamic API Resolution · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery

---

### S0531 — Grandoreiro
<a id="s0531"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0531](https://attack.mitre.org/software/S0531) · **43** techniques · **0** groups  

Grandoreiro is a banking trojan written in Delphi that was first observed in 2016 and uses a Malware-as-a-Service (MaaS) business model. Grandoreiro has confirmed victims in Brazil, Mexico, Portugal, and Spain.

**Techniques:** [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1087.003](https://attack.mitre.org/techniques/T1087/003) Email Account · [T1102.001](https://attack.mitre.org/techniques/T1102/001) Dead Drop Resolver · [T1102.002](https://attack.mitre.org/techniques/T1102/002) Bidirectional Communication · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry

---

### S0409 — Machete
<a id="s0409"></a>

**Aliases:** Machete, Pyark  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0409](https://attack.mitre.org/software/S0409) · **41** techniques · **1** groups  

Machete is a cyber espionage toolset used by Machete. It is a Python-based backdoor targeting Windows machines that was first observed in 2010.

**Used by:** G0095 Machete

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1016.002](https://attack.mitre.org/techniques/T1016/002) Wi-Fi Discovery · [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration · [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1029](https://attack.mitre.org/techniques/T1029) Scheduled Transfer · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1052.001](https://attack.mitre.org/techniques/T1052/001) Exfiltration over USB · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols

---

### S1130 — Raspberry Robin
<a id="s1130"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1130](https://attack.mitre.org/software/S1130) · **41** techniques · **0** groups  

Raspberry Robin is initial access malware first identified in September 2021, and active through early 2024. The malware is notable for spreading via infected USB devices containing a malicious LNK object that, on execution, retrieves remote hosted payloads for installation.

**Techniques:** [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.009](https://attack.mitre.org/techniques/T1070/009) Clear Persistence · [T1071](https://attack.mitre.org/techniques/T1071) Application Layer Protocol · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1091](https://attack.mitre.org/techniques/T1091) Replication Through Removable Media · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information

---

### S0192 — Pupy
<a id="s0192"></a>

**Type:** tool · **Platforms:** Linux, Windows, macOS, Android · **ATT&CK:** [S0192](https://attack.mitre.org/software/S0192) · **41** techniques · **2** groups  

Pupy is an open source, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool. It is written in Python and can be generated as a payload in several different ways (Windows exe, Python file, PowerShell oneliner/file, Linux elf, APK, Rubber Ducky, etc.). Pupy is publicly available on GitHub.

**Used by:** G0059 Magic Hound, G0064 APT33

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets · [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S0356 — KONNI
<a id="s0356"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0356](https://attack.mitre.org/software/S0356) · **40** techniques · **0** groups  

KONNI is a remote access tool that security researchers assess has been used by North Korean cyber actors since at least 2014.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S1242 — Qilin
<a id="s1242"></a>

**Aliases:** Qilin, Agenda  
**Type:** malware · **Platforms:** ESXi, Windows · **ATT&CK:** [S1242](https://attack.mitre.org/software/S1242) · **40** techniques · **2** groups  

Qilin ransomware is a Ransomware-as-a-Service (RaaS) that has been active since at least 2022 with versions written in Golang and Rust that are capable of targeting Windows or VMWare ESXi devices.

**Used by:** G1036 Moonstone Sleet, G1050 Water Galura

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1134](https://attack.mitre.org/techniques/T1134) Access Token Manipulation · [T1135](https://attack.mitre.org/techniques/T1135) Network Share Discovery · [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application

---

### S1039 — Bumblebee
<a id="s1039"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1039](https://attack.mitre.org/software/S1039) · **39** techniques · **2** groups  

Bumblebee is a custom loader written in C++ that has been used by multiple threat actors, including possible initial access brokers, to download and execute additional payloads since at least March 2022.

**Used by:** G1011 EXOTIC LILY, G1038 TA578

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1055.004](https://attack.mitre.org/techniques/T1055/004) Asynchronous Procedure Call · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S0458 — Ramsay
<a id="s0458"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0458](https://attack.mitre.org/software/S0458) · **39** techniques · **0** groups  

Ramsay is an information stealing malware framework designed to collect and exfiltrate sensitive documents, including from air-gapped systems. Researchers have identified overlaps between Ramsay and the Darkhotel-associated Retro malware.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1014](https://attack.mitre.org/techniques/T1014) Rootkit · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.003](https://attack.mitre.org/techniques/T1027/003) Steganography · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1039](https://attack.mitre.org/techniques/T1039) Data from Network Shared Drive · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1080](https://attack.mitre.org/techniques/T1080) Taint Shared Content · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1091](https://attack.mitre.org/techniques/T1091) Replication Through Removable Media

---

### S0148 — RTM
<a id="s0148"></a>

**Aliases:** RTM, Redaman  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0148](https://attack.mitre.org/software/S0148) · **38** techniques · **1** groups  

RTM is custom malware written in Delphi. It is used by the group of the same name (RTM). Newer versions of the malware have been reported publicly as Redaman.

**Used by:** G0048 RTM

**Techniques:** [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.009](https://attack.mitre.org/techniques/T1070/009) Clear Persistence · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1102.001](https://attack.mitre.org/techniques/T1102/001) Dead Drop Resolver · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1113](https://attack.mitre.org/techniques/T1113) Screen Capture · [T1115](https://attack.mitre.org/techniques/T1115) Clipboard Data

---

### S1018 — Saint Bot
<a id="s1018"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1018](https://attack.mitre.org/software/S1018) · **37** techniques · **2** groups  

Saint Bot is a .NET downloader that has been used by Saint Bear since at least March 2021.

**Used by:** G1003 Ember Bear, G1031 Saint Bear

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1055.004](https://attack.mitre.org/techniques/T1055/004) Asynchronous Procedure Call · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery

---

### S1044 — FunnyDream
<a id="s1044"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1044](https://attack.mitre.org/software/S1044) · **37** techniques · **0** groups  

FunnyDream is a backdoor with multiple components that was used during the FunnyDream campaign since at least 2019, primarily for execution and exfiltration.

**Techniques:** [T1001](https://attack.mitre.org/techniques/T1001) Data Obfuscation · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery

---

### S0331 — Agent Tesla
<a id="s0331"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0331](https://attack.mitre.org/software/S0331) · **37** techniques · **2** groups  

Agent Tesla is a spyware Trojan written for the .NET framework that has been observed since at least 2014.

**Used by:** G0083 SilverTerrier, G1018 TA2541

**Techniques:** [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1016.002](https://attack.mitre.org/techniques/T1016/002) Wi-Fi Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.003](https://attack.mitre.org/techniques/T1071/003) Mail Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1113](https://attack.mitre.org/techniques/T1113) Screen Capture · [T1115](https://attack.mitre.org/techniques/T1115) Clipboard Data · [T1124](https://attack.mitre.org/techniques/T1124) System Time Discovery

---

### S1060 — Mafalda
<a id="s1060"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1060](https://attack.mitre.org/software/S1060) · **36** techniques · **1** groups  

Mafalda is a flexible interactive implant that has been used by Metador. Security researchers assess the Mafalda name may be inspired by an Argentinian cartoon character that has been popular as a means of political commentary since the 1960s.

**Used by:** G1013 Metador

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1056](https://attack.mitre.org/techniques/T1056) Input Capture · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1090.001](https://attack.mitre.org/techniques/T1090/001) Internal Proxy · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S0022 — Uroburos
<a id="s0022"></a>

**Aliases:** Uroburos, Snake  
**Type:** malware · **Platforms:** Linux, Windows, macOS · **ATT&CK:** [S0022](https://attack.mitre.org/software/S0022) · **36** techniques · **1** groups  

Uroburos is a sophisticated cyber espionage tool written in C that has been used by units within Russia's Federal Security Service (FSB) associated with the Turla toolset to collect intelligence on sensitive targets worldwide.

**Used by:** G0010 Turla

**Techniques:** [T1001.001](https://attack.mitre.org/techniques/T1001/001) Junk Data · [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1014](https://attack.mitre.org/techniques/T1014) Rootkit · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.003](https://attack.mitre.org/techniques/T1071/003) Mail Protocols · [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery

---

### S0559 — SUNBURST
<a id="s0559"></a>

**Aliases:** SUNBURST, Solorigate  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0559](https://attack.mitre.org/software/S0559) · **36** techniques · **1** groups  

SUNBURST is a trojanized DLL designed to fit within the SolarWinds Orion software update framework. It was used by APT29 since at least February 2020.

**Used by:** G0016 APT29

**Techniques:** [T1001.001](https://attack.mitre.org/techniques/T1001/001) Junk Data · [T1001.002](https://attack.mitre.org/techniques/T1001/002) Steganography · [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.007](https://attack.mitre.org/techniques/T1070/007) Clear Network Connection History and Configurations · [T1070.009](https://attack.mitre.org/techniques/T1070/009) Clear Persistence · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols

---

### S0373 — Astaroth
<a id="s0373"></a>

**Aliases:** Astaroth, Guildma  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0373](https://attack.mitre.org/software/S0373) · **36** techniques · **0** groups  

Astaroth is a Trojan and information stealer known to affect companies in Europe, Brazil, and throughout Latin America. It has been known publicly since at least late 2017.

**Techniques:** [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1102.001](https://attack.mitre.org/techniques/T1102/001) Dead Drop Resolver · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1115](https://attack.mitre.org/techniques/T1115) Clipboard Data · [T1124](https://attack.mitre.org/techniques/T1124) System Time Discovery · [T1129](https://attack.mitre.org/techniques/T1129) Shared Modules · [T1132.001](https://attack.mitre.org/techniques/T1132/001) Standard Encoding

---

### S0386 — Ursnif
<a id="s0386"></a>

**Aliases:** Ursnif, Gozi-ISFB, PE_URSNIF, Dreambot  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0386](https://attack.mitre.org/software/S0386) · **35** techniques · **1** groups  

Ursnif is a banking trojan and variant of the Gozi malware observed being spread through various automated exploit kits, Spearphishing Attachments, and malicious links. Ursnif is associated primarily with data theft, but variants also include components (backdoors, spyware, file injectors, etc.) capable of a wide variety of behaviors.

**Used by:** G0127 TA551

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055.005](https://attack.mitre.org/techniques/T1055/005) Thread Local Storage · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1056.004](https://attack.mitre.org/techniques/T1056/004) Credential API Hooking · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1080](https://attack.mitre.org/techniques/T1080) Taint Shared Content · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1090](https://attack.mitre.org/techniques/T1090) Proxy

---

### S1245 — InvisibleFerret
<a id="s1245"></a>

**Type:** malware · **Platforms:** Linux, macOS, Windows · **ATT&CK:** [S1245](https://attack.mitre.org/software/S1245) · **35** techniques · **1** groups  

InvisibleFerret is a modular python malware that is leveraged for data exfiltration and remote access capabilities. InvisibleFerret consists of four modules: main, payload, browser, and AnyDesk. InvisibleFerret malware has been leveraged by North Korea-affiliated threat actors identified as DeceptiveDevelopment or Contagious Interview since 2023.

**Used by:** G1052 Contagious Interview

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1056](https://attack.mitre.org/techniques/T1056) Input Capture · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1115](https://attack.mitre.org/techniques/T1115) Clipboard Data · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information

---

### S1081 — BADHATCH
<a id="s1081"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1081](https://attack.mitre.org/software/S1081) · **35** techniques · **1** groups  

BADHATCH is a backdoor that has been utilized by FIN8 since at least 2019. BADHATCH has been used to target the insurance, retail, technology, and chemical industries in the United States, Canada, South Africa, Panama, and Italy.

**Used by:** G0061 FIN8

**Techniques:** [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1055.004](https://attack.mitre.org/techniques/T1055/004) Asynchronous Procedure Call · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols

---

### S1228 — PUBLOAD
<a id="s1228"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1228](https://attack.mitre.org/software/S1228) · **35** techniques · **1** groups  

PUBLOAD is a stager malware that has been observed installing itself in existing directories such as `C:\Users\Public` or creating new directories to stage the malware and its components. PUBLOAD malware collects details of the victim host, establishes persistence, encrypts victim details using RC4 and communicates victim details back to C2.

**Used by:** G0129 Mustang Panda

**Techniques:** [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery · [T1016.002](https://attack.mitre.org/techniques/T1016/002) Wi-Fi Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S1213 — Lumma Stealer
<a id="s1213"></a>

**Aliases:** Lumma Stealer, LummaStealer  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1213](https://attack.mitre.org/software/S1213) · **35** techniques · **0** groups  

Lumma Stealer is an information stealer malware family in use since at least 2022. Lumma Stealer is a Malware as a Service (MaaS) where captured data has been sold in criminal markets to Initial Access Brokers.

**Techniques:** [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1059.010](https://attack.mitre.org/techniques/T1059/010) AutoHotKey & AutoIT · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1113](https://attack.mitre.org/techniques/T1113) Screen Capture · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1176.001](https://attack.mitre.org/techniques/T1176/001) Browser Extensions · [T1195](https://attack.mitre.org/techniques/T1195) Supply Chain Compromise · [T1204](https://attack.mitre.org/techniques/T1204) User Execution · [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File · [T1217](https://attack.mitre.org/techniques/T1217) Browser Information Discovery · [T1218.005](https://attack.mitre.org/techniques/T1218/005) Mshta

---

### S1240 — RedLine Stealer
<a id="s1240"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1240](https://attack.mitre.org/software/S1240) · **35** techniques · **0** groups  

RedLine Stealer is an information-stealer malware variant first identified in 2020. RedLine Stealer is a Malware as a Service (MaaS) and was reportedly sold as either a one-time purchase or a monthly subscription service.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.011](https://attack.mitre.org/techniques/T1059/011) Lua · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account · [T1102](https://attack.mitre.org/techniques/T1102) Web Service · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1113](https://attack.mitre.org/techniques/T1113) Screen Capture · [T1132.001](https://attack.mitre.org/techniques/T1132/001) Standard Encoding · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information

---

### S0438 — Attor
<a id="s0438"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0438](https://attack.mitre.org/software/S0438) · **35** techniques · **0** groups  

Attor is a Windows-based espionage platform that has been seen in use since 2013. Attor has a loadable plugin architecture to customize functionality for specific targets.

**Techniques:** [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1037.001](https://attack.mitre.org/techniques/T1037/001) Logon Script (Windows) · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.004](https://attack.mitre.org/techniques/T1055/004) Asynchronous Procedure Call · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.006](https://attack.mitre.org/techniques/T1070/006) Timestomp · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry

---

### S0496 — REvil
<a id="s0496"></a>

**Aliases:** REvil, Sodin, Sodinokibi  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0496](https://attack.mitre.org/software/S0496) · **35** techniques · **2** groups  

REvil is a ransomware family that has been linked to the GOLD SOUTHFIELD group and operated as ransomware-as-a-service (RaaS) since at least April 2019. REvil, which as been used against organizations in the manufacturing, transportation, and electric sectors, is highly configurable and shares code similarities with the GandCrab RaaS.

**Used by:** G0046 FIN7, G0115 GOLD SOUTHFIELD

**Techniques:** [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1134.001](https://attack.mitre.org/techniques/T1134/001) Token Impersonation/Theft

---

### S0428 — PoetRAT
<a id="s0428"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0428](https://attack.mitre.org/software/S0428) · **35** techniques · **0** groups  

PoetRAT is a remote access trojan (RAT) that was first identified in April 2020. PoetRAT has been used in multiple campaigns against the private and public sectors in Azerbaijan, including ICS and SCADA systems in the energy sector. The STIBNITE activity group has been observed using the malware.

**Techniques:** [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol · [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python · [T1059.011](https://attack.mitre.org/techniques/T1059/011) Lua · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S0439 — Okrum
<a id="s0439"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0439](https://attack.mitre.org/software/S0439) · **34** techniques · **1** groups  

Okrum is a Windows backdoor that has been seen in use since December 2016 with strong links to Ke3chang.

**Used by:** G0004 Ke3chang

**Techniques:** [T1001](https://attack.mitre.org/techniques/T1001) Data Obfuscation · [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation · [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory · [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.003](https://attack.mitre.org/techniques/T1027/003) Steganography · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1090.002](https://attack.mitre.org/techniques/T1090/002) External Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1124](https://attack.mitre.org/techniques/T1124) System Time Discovery

---

### S0673 — DarkWatchman
<a id="s0673"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0673](https://attack.mitre.org/software/S0673) · **34** techniques · **0** groups  

DarkWatchman is a lightweight JavaScript-based remote access tool (RAT) that avoids file operations; it was first observed in November 2021.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1027.004](https://attack.mitre.org/techniques/T1027/004) Compile After Delivery · [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1070](https://attack.mitre.org/techniques/T1070) Indicator Removal · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery

---

### S0268 — Bisonal
<a id="s0268"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0268](https://attack.mitre.org/software/S0268) · **34** techniques · **1** groups  

Bisonal is a remote access tool (RAT) that has been used by Tonto Team against public and private sector organizations in Russia, South Korea, and Japan since at least December 2010.

**Used by:** G0131 Tonto Team

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1106](https://attack.mitre.org/techniques/T1106) Native API

---

### S0660 — Clambling
<a id="s0660"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0660](https://attack.mitre.org/software/S0660) · **34** techniques · **1** groups  

Clambling is a modular backdoor written in C++ that has been used by Threat Group-3390 since at least 2017.

**Used by:** G0027 Threat Group-3390

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1055](https://attack.mitre.org/techniques/T1055) Process Injection · [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1071](https://attack.mitre.org/techniques/T1071) Application Layer Protocol · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1102.002](https://attack.mitre.org/techniques/T1102/002) Bidirectional Communication · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1113](https://attack.mitre.org/techniques/T1113) Screen Capture · [T1115](https://attack.mitre.org/techniques/T1115) Clipboard Data

---

### S1202 — LockBit 3.0
<a id="s1202"></a>

**Aliases:** LockBit 3.0, LockBit Black  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1202](https://attack.mitre.org/software/S1202) · **34** techniques · **0** groups  

LockBit 3.0 is an evolution of the LockBit Ransomware-as-a-Service (RaaS) offering with similarities to BlackMatter and BlackCat ransomware.

**Techniques:** [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1078.003](https://attack.mitre.org/techniques/T1078/003) Local Accounts · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1106](https://attack.mitre.org/techniques/T1106) Native API · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry · [T1120](https://attack.mitre.org/techniques/T1120) Peripheral Device Discovery · [T1132.001](https://attack.mitre.org/techniques/T1132/001) Standard Encoding · [T1135](https://attack.mitre.org/techniques/T1135) Network Share Discovery · [T1140](https://attack.mitre.org/techniques/T1140) Deobfuscate/Decode Files or Information · [T1218.003](https://attack.mitre.org/techniques/T1218/003) CMSTP · [T1480](https://attack.mitre.org/techniques/T1480) Execution Guardrails · [T1480.002](https://attack.mitre.org/techniques/T1480/002) Mutual Exclusion

---

### S1183 — StrelaStealer
<a id="s1183"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S1183](https://attack.mitre.org/software/S1183) · **34** techniques · **0** groups  

StrelaStealer is an information stealer malware variant first identified in November 2022 and active through late 2024. StrelaStealer focuses on the automated identification, collection, and exfiltration of email credentials from email clients such as Outlook and Thunderbird.

**Techniques:** [T1001](https://attack.mitre.org/techniques/T1001) Data Obfuscation · [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1036.003](https://attack.mitre.org/techniques/T1036/003) Rename Legitimate Utilities · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1119](https://attack.mitre.org/techniques/T1119) Automated Collection · [T1132.001](https://attack.mitre.org/techniques/T1132/001) Standard Encoding

---

### S0476 — Valak
<a id="s0476"></a>

**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0476](https://attack.mitre.org/software/S0476) · **34** techniques · **1** groups  

Valak is a multi-stage modular malware that can function as a standalone information stealer or downloader, first observed in 2019 targeting enterprises in the US and Germany.

**Used by:** G0127 TA551

**Techniques:** [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery · [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information · [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation · [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell · [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1087.001](https://attack.mitre.org/techniques/T1087/001) Local Account · [T1087.002](https://attack.mitre.org/techniques/T1087/002) Domain Account · [T1104](https://attack.mitre.org/techniques/T1104) Multi-Stage Channels · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1112](https://attack.mitre.org/techniques/T1112) Modify Registry

---

### S0412 — ZxShell
<a id="s0412"></a>

**Aliases:** ZxShell, Sensocode  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0412](https://attack.mitre.org/software/S0412) · **34** techniques · **3** groups  

ZxShell is a remote administration tool and backdoor that can be downloaded from the Internet, particularly from Chinese hacker websites. It has been used since at least 2004.

**Used by:** G0001 Axiom, G0027 Threat Group-3390, G0096 APT41

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol · [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging · [T1056.004](https://attack.mitre.org/techniques/T1056/004) Credential API Hooking · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.001](https://attack.mitre.org/techniques/T1070/001) Clear Windows Event Logs · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1090](https://attack.mitre.org/techniques/T1090) Proxy · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

### S0658 — XCSSET
<a id="s0658"></a>

**Aliases:** XCSSET, OSX.DubRobber  
**Type:** malware · **Platforms:** macOS · **ATT&CK:** [S0658](https://attack.mitre.org/software/S0658) · **33** techniques · **0** groups  

XCSSET is a modular macOS malware family delivered through infected Xcode projects and executed when the project is compiled. Active since August 2020, it has been observed installing backdoors, spoofed browsers, collecting data, and encrypting user files.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File · [T1036](https://attack.mitre.org/techniques/T1036) Masquerading · [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel · [T1056.002](https://attack.mitre.org/techniques/T1056/002) GUI Input Capture · [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell · [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1087](https://attack.mitre.org/techniques/T1087) Account Discovery · [T1098.004](https://attack.mitre.org/techniques/T1098/004) SSH Authorized Keys · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer · [T1113](https://attack.mitre.org/techniques/T1113) Screen Capture · [T1195.001](https://attack.mitre.org/techniques/T1195/001) Compromise Software Dependencies and Development Tools · [T1222.002](https://attack.mitre.org/techniques/T1222/002) Linux and Mac File and Directory Permissions Modification · [T1486](https://attack.mitre.org/techniques/T1486) Data Encrypted for Impact · [T1497.003](https://attack.mitre.org/techniques/T1497/003) Time Based Checks · [T1518](https://attack.mitre.org/techniques/T1518) Software Discovery · [T1518.001](https://attack.mitre.org/techniques/T1518/001) Security Software Discovery · [T1539](https://attack.mitre.org/techniques/T1539) Steal Web Session Cookie

---

### S0666 — Gelsemium
<a id="s0666"></a>

**Aliases:** Gelsemium, Gelsevirine, Gelsenicine, Gelsemine  
**Type:** malware · **Platforms:** Windows · **ATT&CK:** [S0666](https://attack.mitre.org/software/S0666) · **33** techniques · **0** groups  

Gelsemium is a modular malware comprised of a dropper (Gelsemine), a loader (Gelsenicine), and main (Gelsevirine) plug-ins written using the Microsoft Foundation Class (MFC) framework. Gelsemium has been used by the Gelsemium group since at least 2014.

**Techniques:** [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System · [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels · [T1012](https://attack.mitre.org/techniques/T1012) Query Registry · [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage · [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression · [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion · [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery · [T1036.001](https://attack.mitre.org/techniques/T1036/001) Invalid Code Signature · [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location · [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection · [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery · [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell · [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion · [T1070.006](https://attack.mitre.org/techniques/T1070/006) Timestomp · [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols · [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS · [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery · [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery · [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol · [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer

---

