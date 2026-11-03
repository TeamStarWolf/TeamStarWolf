# Threat Group Profiles

<!-- generated: written by scripts/build_attack_atlases.py from data/attack (ATT&CK v20.0); edit the script, not this page. The header card and the related-pages footer belong to build_doc_meta.py and build_crosslinks.py. -->

> Authoritative profiles for the 174 tracked adversary groups in MITRE ATT&CK Enterprise (v20.0) that have observed technique usage (nation-state APTs, eCrime crews, and intrusion sets; 174 of the 178 groups ATT&CK lists), each with its aliases, the count of techniques and software attributed to it, and (for the most active) its signature ATT&CK techniques. Pair this with [Threat Actors](THREAT_ACTORS.md) for narrative context and the [Technique Atlas](ATTACK_TECHNIQUE_ATLAS.md) for the behaviors.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Threat intelligence analysts and threat-informed defense practitioners

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 31 min (7,042 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need a group's aliases resolved to one ATT&CK ID, you are scoping which adversaries have the broadest technique coverage, or you want a group's signature techniques for threat-informed defense

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[All tracked groups](#all-tracked-groups) for the alias-and-counts table, [Detailed profiles](#detailed-profiles-most-active-groups) for the most active groups' signature techniques

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (last corrected, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Last corrected</th><td>

2026-10-13, revoked IDs re-keyed: T1070.001 to T1685.005, T1070.002 to T1685.006 ([#118](https://github.com/TeamStarWolf/TeamStarWolf/pull/118), ATT&CK v19.2)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<details class="tsw-meta-which"><summary>Which page should I read? This page is one of 2 on threat actors.</summary>

| Page | Read it for |
|---|---|
| Threat Group Profiles (this page) | Profiles built from ATT&CK group data: aliases, technique and software counts, and signature techniques. |
| [Threat Actors](/THREAT_ACTORS.md) | A narrative quick reference to notable groups by nation and type, with aliases, targets, and signature TTPs. |

</details>

<!-- meta:end -->

Machine-readable: [`data/attack/groups.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/groups.jsonl), [`data/attack/group_to_technique.jsonl`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/data/attack/group_to_technique.jsonl)

## All tracked groups

Sorted by breadth of attributed ATT&CK techniques. The 40 most active link to their profile below; the rest link to their ATT&CK entry.

| Group | Also known as | Techniques | Software |
|---|---|--:|--:|
| [G0094 Kimsuky](#g0094) | Black Banshee, Velvet Chollima, Emerald Sleet, THALLIUM, APT43, TA427 (+3 more) | 130 | 19 |
| [G0082 APT38](#g0082) | NICKEL GLADSTONE, BeagleBoyz, Bluenoroff, Stardust Chollima, Sapphire Sleet (+1 more) | 115 | 6 |
| [G0007 APT28](#g0007) | IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm (+8 more) | 93 | 29 |
| [G0032 Lazarus Group](#g0032) | Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY (+1 more) | 93 | 26 |
| [G0129 Mustang Panda](#g0129) | TA416, RedDelta, BRONZE PRESIDENT, STATELY TAURUS, FIREANT, CAMARO DRAGON (+9 more) | 85 | 23 |
| [G0096 APT41](#g0096) | Wicked Panda, Brass Typhoon, BARIUM | 82 | 32 |
| [G1017 Volt Typhoon](#g1017) | BRONZE SILHOUETTE, Vanguard Panda, DEV-0391, UNC3236, Voltzite, Insidious Taurus (+1 more) | 81 | 17 |
| [G0034 Sandworm Team](#g0034) | ELECTRUM, Telebots, IRON VIKING, BlackEnergy (Group), Quedagh, Voodoo Bear (+4 more) | 79 | 27 |
| [G0050 APT32](#g0050) | SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone, BISMUTH | 78 | 15 |
| [G0059 Magic Hound](#g0059) | TA453, COBALT ILLUSION, Charming Kitten, ITG18, Phosphorus, Newscaster, APT35 (+1 more) | 78 | 13 |
| [G0049 OilRig](#g0049) | COBALT GYPSY, IRN2, APT34, Helix Kitten, Evasive Serpens, Hazel Sandstorm (+5 more) | 76 | 30 |
| [G0047 Gamaredon Group](#g0047) | IRON TILDEN, Primitive Bear, ACTINIUM, Armageddon, Shuckworm, DEV-0157 (+2 more) | 70 | 6 |
| [G0010 Turla](#g0010) | IRON HUNTER, Group 88, Waterbug, WhiteBear, Snake, Krypton, Venomous Bear (+2 more) | 68 | 30 |
| [G0069 MuddyWater](#g0069) | Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm (+2 more) | 68 | 21 |
| [G0046 FIN7](#g0046) | GOLD NIAGARA, ITG14, Carbon Spider, ELBRUS, Sangria Tempest | 67 | 19 |
| [G0016 APT29](#g0016) | IRON RITUAL, IRON HEMLOCK, NobleBaron, Dark Halo, NOBELIUM, UNC2452, YTTRIUM (+7 more) | 66 | 49 |
| [G1059 NIMBUS MANTICORE](#g1059) | UNC1549, TA455, COBALT SMOKEY | 65 | 13 |
| [G0102 Wizard Spider](#g0102) | UNC1878, TEMP.MixMaster, Grim Spider, FIN12, GOLD BLACKBURN, ITG23 (+4 more) | 64 | 22 |
| [G1015 Scattered Spider](#g1015) | Roasted 0ktapus, Octo Tempest, Storm-0875, UNC3944 | 64 | 10 |
| [G1055 VOID MANTICORE](#g1055) | COBALT MYSTIQUE, Handala Hack, Homeland Justice, Karma, Karmabelow80 (+2 more) | 63 | 0 |
| [G0114 Chimera](#g0114) | None | 59 | 6 |
| [G1045 Salt Typhoon](#g1045) | None | 58 | 1 |
| [G0027 Threat Group-3390](#g0027) | Earth Smilodon, TG-3390, Emissary Panda, BRONZE UNION, APT27, Iron Tiger (+2 more) | 57 | 24 |
| [G1051 Medusa Group](#g1051) | None | 57 | 5 |
| [G0035 Dragonfly](#g0035) | TEMP.Isotope, DYMALLOY, Berserk Bear, TG-4192, Crouching Yeti, IRON LIBERTY (+3 more) | 56 | 10 |
| [G0139 TeamTNT](#g0139) | None | 56 | 4 |
| [G1052 Contagious Interview](#g1052) | DeceptiveDevelopment, Gwisin Gang, Tenacious Pungsan, DEV#POPPER, PurpleBravo (+1 more) | 54 | 4 |
| [G0087 APT39](#g0087) | ITG07, Chafer, Remix Kitten | 53 | 11 |
| [G1016 FIN13](#g1016) | Elephant Beetle | 53 | 4 |
| [G0065 Leviathan](#g0065) | MUDCARP, Kryptonite Panda, Gadolinium, BRONZE MOHAWK, TEMP.Jumper, APT40 (+2 more) | 50 | 17 |
| [G1048 UNC3886](#g1048) | None | 49 | 8 |
| [G1043 BlackByte](#g1043) | Hecamede | 48 | 8 |
| [G1003 Ember Bear](#g1003) | UNC2589, Bleeding Bear, DEV-0586, Cadet Blizzard, Frozenvista, UAC-0056 | 47 | 11 |
| [G0004 Ke3chang](#g0004) | APT15, Mirage, Vixen Panda, GREF, Playful Dragon, RoyalAPT, NICKEL (+1 more) | 46 | 11 |
| [G0045 menuPass](#g0045) | Cicada, POTASSIUM, Stone Panda, APT10, Red Apollo, CVNX, HOGFISH (+1 more) | 46 | 25 |
| [G1057 ShinyHunters](#g1057) | UNC6240, Bling Libra | 46 | 1 |
| [G0022 APT3](#g0022) | Gothic Panda, Pirpi, UPS Team, Buckeye, Threat Group-0110, TG-0110 | 44 | 6 |
| [G0125 HAFNIUM](#g0125) | Operation Exchange Marauder, Silk Typhoon | 44 | 6 |
| [G1006 Earth Lusca](#g1006) | TAG-22, Charcoal Typhoon, CHROMIUM, ControlX | 44 | 9 |
| [G1004 LAPSUS$](#g1004) | DEV-0537, Strawberry Tempest | 43 | 1 |
| [G1054 MirrorFace](https://attack.mitre.org/groups/G1054/) | Earth Kasha | 43 | 16 |
| [G1053 Storm-0501](https://attack.mitre.org/groups/G1053/) | None | 42 | 8 |
| [G0040 Patchwork](https://attack.mitre.org/groups/G0040/) | Hangover Group, Dropping Elephant, Chinastrats, MONSOON, Operation Hangover | 41 | 8 |
| [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117/) | UNC757, Parisite, Pioneer Kitten, RUBIDIUM, Lemon Sandstorm | 41 | 5 |
| [G1039 RedCurl](https://attack.mitre.org/groups/G1039/) | None | 41 | 0 |
| [G0037 FIN6](https://attack.mitre.org/groups/G0037/) | Magecart Group 6, ITG08, Skeleton Spider, TAAL, Camouflage Tempest | 40 | 12 |
| [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060/) | REDBALDKNIGHT, Tick | 40 | 14 |
| [G0081 Tropic Trooper](https://attack.mitre.org/groups/G0081/) | Pirate Panda, KeyBoy | 40 | 6 |
| [G0099 APT-C-36](https://attack.mitre.org/groups/G0099/) | Blind Eagle, TAG-144, AguilaCiega, APT-Q-98 | 38 | 9 |
| [G1056 TeamPCP](https://attack.mitre.org/groups/G1056/) | PCPCat, ShellForce, DeadCatx3, SHADOW-WATER-058, UNC6780 | 37 | 3 |
| [G0061 FIN8](https://attack.mitre.org/groups/G0061/) | Syssphinx | 36 | 11 |
| [G0106 Rocke](https://attack.mitre.org/groups/G0106/) | None | 36 | 0 |
| [G1001 HEXANE](https://attack.mitre.org/groups/G1001/) | Lyceum, Siamesekitten, Spirlin | 36 | 12 |
| [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143/) | None | 35 | 6 |
| [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080/) | GOLD KINGSWOOD, Cobalt Gang, Cobalt Spider | 34 | 6 |
| [G0092 TA505](https://attack.mitre.org/groups/G0092/) | Hive0065, Spandex Tempest, CHIMBORAZO | 34 | 16 |
| [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119/) | Evil Corp, Manatee Tempest, DEV-0243, UNC2165 | 33 | 8 |
| [G1044 APT42](https://attack.mitre.org/groups/G1044/) | None | 33 | 2 |
| [G0064 APT33](https://attack.mitre.org/groups/G0064/) | HOLMIUM, Elfin, Peach Sandstorm | 31 | 16 |
| [G0093 GALLIUM](https://attack.mitre.org/groups/G0093/) | Granite Typhoon | 31 | 16 |
| [G1046 Storm-1811](https://attack.mitre.org/groups/G1046/) | None | 31 | 7 |
| [G0121 Sidewinder](https://attack.mitre.org/groups/G0121/) | T-APT-04, Rattlesnake | 30 | 1 |
| [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036/) | Storm-1789 | 30 | 1 |
| [G0067 APT37](https://attack.mitre.org/groups/G0067/) | InkySquid, ScarCruft, Reaper, Group123, TEMP.Reaper, Ricochet Chollima | 29 | 13 |
| [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128/) | APT31, Violet Typhoon | 29 | 0 |
| [G1023 APT5](https://attack.mitre.org/groups/G1023/) | Mulberry Typhoon, MANGANESE, BRONZE FLEETWOOD, Keyhole Panda, UNC2630 | 29 | 13 |
| [G0091 Silence](https://attack.mitre.org/groups/G0091/) | Whisper Spider | 28 | 3 |
| [G0126 Higaisa](https://attack.mitre.org/groups/G0126/) | None | 28 | 3 |
| [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014/) | None | 28 | 2 |
| [G1018 TA2541](https://attack.mitre.org/groups/G1018/) | None | 28 | 9 |
| [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035/) | TA473, UAC-0114 | 27 | 0 |
| [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041/) | Teal Kurma, Marbled Dust, Cosmic Wolf, SILICON | 27 | 1 |
| [G0090 WIRTE](https://attack.mitre.org/groups/G0090/) | Ashen Lepus | 26 | 8 |
| [G1040 Play](https://attack.mitre.org/groups/G1040/) | None | 26 | 9 |
| [G1022 ToddyCat](https://attack.mitre.org/groups/G1022/) | None | 25 | 9 |
| [G1032 INC Ransom](https://attack.mitre.org/groups/G1032/) | GOLD IONIC | 25 | 8 |
| [G0012 Darkhotel](https://attack.mitre.org/groups/G0012/) | DUBNIUM, Zigzag Hail | 24 | 0 |
| [G0006 APT1](https://attack.mitre.org/groups/G0006/) | Comment Crew, Comment Group, Comment Panda | 23 | 17 |
| [G0100 Inception](https://attack.mitre.org/groups/G0100/) | Inception Framework, Cloud Atlas | 22 | 3 |
| [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108/) | None | 22 | 2 |
| [G1030 Agrius](https://attack.mitre.org/groups/G1030/) | Pink Sandstorm, AMERICIUM, Agonizing Serpens, BlackShadow | 22 | 9 |
| [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047/) | None | 22 | 2 |
| [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030/) | DRAGONFISH, Spring Dragon, RADIUM, Raspberry Typhoon, Bilbug, Thrip | 21 | 9 |
| [G0073 APT19](https://attack.mitre.org/groups/G0073/) | Codoso, C0d0so0, Codoso Team, Sunshop Group | 21 | 2 |
| [G0140 LazyScripter](https://attack.mitre.org/groups/G0140/) | None | 20 | 7 |
| [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033/) | SEABORGIUM, Callisto Group, TA446, COLDRIVER | 20 | 1 |
| [G0112 Windshift](https://attack.mitre.org/groups/G0112/) | Bahamut | 19 | 1 |
| [G0142 Confucius](https://attack.mitre.org/groups/G0142/) | Confucius APT | 19 | 1 |
| [G1012 CURIUM](https://attack.mitre.org/groups/G1012/) | Crimson Sandstorm, TA456, Tortoise Shell, Yellow Liderc | 19 | 1 |
| [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021/) | DEV-0401, Emperor Dragonfly, BRONZE STARLIGHT | 19 | 8 |
| [G1031 Saint Bear](https://attack.mitre.org/groups/G1031/) | Storm-0587, TA471, UAC-0056, Lorec53 | 18 | 2 |
| [G0077 Leafminer](https://attack.mitre.org/groups/G0077/) | Raspite | 17 | 4 |
| [G1024 Akira](https://attack.mitre.org/groups/G1024/) | GOLD SAHARA, PUNK SPIDER, Howling Scorpius | 17 | 8 |
| [G1034 Daggerfly](https://attack.mitre.org/groups/G1034/) | Evasive Panda, BRONZE HIGHLAND | 17 | 6 |
| [G1058 The Gentlemen](https://attack.mitre.org/groups/G1058/) | Storm-2697, GOLD SHERWOOD | 17 | 3 |
| [G0001 Axiom](https://attack.mitre.org/groups/G0001/) | Group 72 | 16 | 8 |
| [G0021 Molerats](https://attack.mitre.org/groups/G0021/) | Operation Molerats, Gaza Cybergang | 16 | 6 |
| [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038/) | None | 16 | 0 |
| [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078/) | None | 16 | 4 |
| [G1002 BITTER](https://attack.mitre.org/groups/G1002/) | T-APT-17 | 16 | 1 |
| [G1008 SideCopy](https://attack.mitre.org/groups/G1008/) | None | 16 | 2 |
| [G0131 Tonto Team](https://attack.mitre.org/groups/G0131/) | Earth Akhlut, BRONZE HUNTLEY, CactusPete, Karma Panda | 15 | 6 |
| [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135/) | None | 15 | 5 |
| [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011/) | None | 15 | 2 |
| [G0019 Naikon](https://attack.mitre.org/groups/G0019/) | None | 14 | 15 |
| [G0098 BlackTech](https://attack.mitre.org/groups/G0098/) | Palmerworm | 14 | 6 |
| [G0127 TA551](https://attack.mitre.org/groups/G0127/) | GOLD CABIN, Shathak | 14 | 5 |
| [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134/) | COPPER FIELDSTONE, APT36, Mythic Leopard, ProjectM | 14 | 5 |
| [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122/) | TA407, COBALT DICKENS | 13 | 0 |
| [G0018 admin@338](https://attack.mitre.org/groups/G0018/) | None | 12 | 7 |
| [G0026 APT18](https://attack.mitre.org/groups/G0026/) | TG-0416, Dynamite Panda, Threat Group-0416 | 12 | 5 |
| [G0070 Dark Caracal](https://attack.mitre.org/groups/G0070/) | None | 12 | 3 |
| [G0085 FIN4](https://attack.mitre.org/groups/G0085/) | None | 12 | 0 |
| [G0138 Andariel](https://attack.mitre.org/groups/G0138/) | Silent Chollima, PLUTONIUM, Onyx Sleet | 12 | 2 |
| [G1009 Moses Staff](https://attack.mitre.org/groups/G1009/) | DEV-0500, Marigold Sandstorm | 12 | 4 |
| [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020/) | DEV-0206, TA569, GOLD PRELUDE, UNC1543 | 12 | 2 |
| [G1026 Malteiro](https://attack.mitre.org/groups/G1026/) | None | 12 | 1 |
| [G0051 FIN10](https://attack.mitre.org/groups/G0051/) | None | 11 | 1 |
| [G0053 FIN5](https://attack.mitre.org/groups/G0053/) | None | 11 | 6 |
| [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056/) | StrongPity | 11 | 2 |
| [G0068 PLATINUM](https://attack.mitre.org/groups/G0068/) | None | 11 | 3 |
| [G0095 Machete](https://attack.mitre.org/groups/G0095/) | APT-C-43, El Machete | 11 | 1 |
| [G0120 Evilnum](https://attack.mitre.org/groups/G0120/) | None | 11 | 3 |
| [G0009 Deep Panda](https://attack.mitre.org/groups/G0009/) | Shell Crew, WebMasters, KungFu Kittens, PinkPanther, Black Vine | 10 | 7 |
| [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105/) | None | 10 | 2 |
| [G0008 Carbanak](https://attack.mitre.org/groups/G0008/) | Anunak | 9 | 4 |
| [G0054 Sowbug](https://attack.mitre.org/groups/G0054/) | None | 9 | 2 |
| [G0066 Elderwood](https://attack.mitre.org/groups/G0066/) | Elderwood Gang, Beijing Group, Sneaky Panda | 9 | 9 |
| [G0075 Rancor](https://attack.mitre.org/groups/G0075/) | None | 9 | 4 |
| [G0107 Whitefly](https://attack.mitre.org/groups/G0107/) | None | 9 | 1 |
| [G0115 GOLD SOUTHFIELD](https://attack.mitre.org/groups/G0115/) | Pinchy Spider | 9 | 2 |
| [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007/) | None | 9 | 2 |
| [G1013 Metador](https://attack.mitre.org/groups/G1013/) | None | 9 | 2 |
| [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033/) | None | 8 | 0 |
| [G0052 CopyKittens](https://attack.mitre.org/groups/G0052/) | None | 8 | 4 |
| [G1019 MoustachedBouncer](https://attack.mitre.org/groups/G1019/) | None | 8 | 3 |
| [G0048 RTM](https://attack.mitre.org/groups/G0048/) | None | 7 | 1 |
| [G0079 DarkHydrus](https://attack.mitre.org/groups/G0079/) | None | 7 | 3 |
| [G0089 The White Company](https://attack.mitre.org/groups/G0089/) | None | 7 | 2 |
| [G0124 Windigo](https://attack.mitre.org/groups/G0124/) | None | 7 | 1 |
| [G0133 Nomadic Octopus](https://attack.mitre.org/groups/G0133/) | DustSquad | 7 | 1 |
| [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136/) | None | 7 | 3 |
| [G1005 POLONIUM](https://attack.mitre.org/groups/G1005/) | Plaid Rain | 7 | 2 |
| [G0044 Winnti Group](https://attack.mitre.org/groups/G0044/) | Blackfly | 6 | 3 |
| [G0084 Gallmaker](https://attack.mitre.org/groups/G0084/) | None | 6 | 0 |
| [G0103 Mofang](https://attack.mitre.org/groups/G0103/) | None | 6 | 2 |
| [G0130 Ajax Security Team](https://attack.mitre.org/groups/G0130/) | Operation Woolen-Goldfish, AjaxTM, Rocket Kitten, Flying Kitten (+1 more) | 6 | 2 |
| [G0137 Ferocious Kitten](https://attack.mitre.org/groups/G0137/) | None | 6 | 2 |
| [G1037 TA577](https://attack.mitre.org/groups/G1037/) | None | 6 | 3 |
| [G0003 Cleaver](https://attack.mitre.org/groups/G0003/) | Threat Group 2889, TG-2889 | 5 | 4 |
| [G0005 APT12](https://attack.mitre.org/groups/G0005/) | IXESHE, DynCalc, Numbered Panda, DNSCALC | 5 | 3 |
| [G0039 Suckfly](https://attack.mitre.org/groups/G0039/) | None | 5 | 1 |
| [G0062 TA459](https://attack.mitre.org/groups/G0062/) | None | 5 | 4 |
| [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123/) | Lebanese Cedar | 5 | 2 |
| [G1042 RedEcho](https://attack.mitre.org/groups/G1042/) | None | 5 | 1 |
| [G0020 Equation](https://attack.mitre.org/groups/G0020/) | None | 4 | 0 |
| [G0024 Putter Panda](https://attack.mitre.org/groups/G0024/) | APT2, MSUpdater | 4 | 4 |
| [G0028 Threat Group-1314](https://attack.mitre.org/groups/G0028/) | TG-1314 | 4 | 2 |
| [G0043 Group5](https://attack.mitre.org/groups/G0043/) | None | 4 | 2 |
| [G0076 Thrip](https://attack.mitre.org/groups/G0076/) | None | 4 | 3 |
| [G0083 SilverTerrier](https://attack.mitre.org/groups/G0083/) | None | 4 | 5 |
| [G1038 TA578](https://attack.mitre.org/groups/G1038/) | None | 4 | 3 |
| [G0041 Strider](https://attack.mitre.org/groups/G0041/) | ProjectSauron | 3 | 1 |
| [G1050 Water Galura](https://attack.mitre.org/groups/G1050/) | GOLD FEATHER | 3 | 2 |
| [G0011 PittyTiger](https://attack.mitre.org/groups/G0011/) | None | 2 | 5 |
| [G0013 APT30](https://attack.mitre.org/groups/G0013/) | None | 2 | 5 |
| [G0025 APT17](https://attack.mitre.org/groups/G0025/) | Deputy Dog | 2 | 1 |
| [G0036 GCMAN](https://attack.mitre.org/groups/G0036/) | None | 2 | 0 |
| [G0071 Orangeworm](https://attack.mitre.org/groups/G0071/) | None | 2 | 8 |
| [G1049 AppleJeus](https://attack.mitre.org/groups/G1049/) | Gleaming Pisces, Citrine Sleet, UNC1720, UNC4736 | 2 | 0 |
| [G0002 Moafee](https://attack.mitre.org/groups/G0002/) | None | 1 | 1 |
| [G0023 APT16](https://attack.mitre.org/groups/G0023/) | None | 1 | 1 |
| [G0029 Scarlet Mimic](https://attack.mitre.org/groups/G0029/) | None | 1 | 4 |
| [G0063 BlackOasis](https://attack.mitre.org/groups/G0063/) | None | 1 | 0 |

---

## Detailed profiles: most active groups

### G0094: Kimsuky
<a id="g0094"></a>

Aliases: Black Banshee, Velvet Chollima, Emerald Sleet, THALLIUM, APT43, TA427, Springtail, Earth Kumiho, PatheticSlug  
ATT&CK: [G0094](https://attack.mitre.org/groups/G0094), 130 techniques, 19 software  

Kimsuky is a Democratic People's Republic of Korea (DPRK)-based cyber espionage group that has been active since at least 2012. The group initially targeted South Korean government agencies, think tanks, and subject-matter experts in various fields.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.007](https://attack.mitre.org/techniques/T1027/007) Dynamic API Resolution, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.012](https://attack.mitre.org/techniques/T1027/012) LNK Icon Smuggling, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression, [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service _(+112 more)_

---

### G0082: APT38
<a id="g0082"></a>

Aliases: NICKEL GLADSTONE, BeagleBoyz, Bluenoroff, Stardust Chollima, Sapphire Sleet, COPERNICIUM  
ATT&CK: [G0082](https://attack.mitre.org/groups/G0082), 115 techniques, 6 software  

APT38 is a North Korean state-sponsored threat group that specializes in financial cyber operations; it has been attributed to the Reconnaissance General Bureau. Active since at least 2014, APT38 has targeted banks, financial institutions, casinos, cryptocurrency exchanges, SWIFT system endpoints, and ATMs in at least 38 countries worldwide.

Notable techniques: [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression, [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.003](https://attack.mitre.org/techniques/T1036/003) Rename Legitimate Utilities, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1036.006](https://attack.mitre.org/techniques/T1036/006) Space after Filename, [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1048.002](https://attack.mitre.org/techniques/T1048/002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.003](https://attack.mitre.org/techniques/T1053/003) Cron, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1053.006](https://attack.mitre.org/techniques/T1053/006) Systemd Timers, [T1055](https://attack.mitre.org/techniques/T1055) Process Injection _(+97 more)_

---

### G0007: APT28
<a id="g0007"></a>

Aliases: IRON TWILIGHT, SNAKEMACKEREL, Swallowtail, Group 74, Sednit, Sofacy, Pawn Storm, Fancy Bear, STRONTIUM, Tsar Team, Threat Group-4127, TG-4127, Forest Blizzard, FROZENLAKE, GruesomeLarch  
ATT&CK: [G0007](https://attack.mitre.org/groups/G0007), 93 techniques, 29 software  

APT28 is a threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) 85th Main Special Service Center (GTsSS) military unit 26165. This group has been active since at least 2004.

Notable techniques: [T1001.001](https://attack.mitre.org/techniques/T1001/001) Junk Data, [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping, [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1014](https://attack.mitre.org/techniques/T1014) Rootkit, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1030](https://attack.mitre.org/techniques/T1030) Data Transfer Size Limits, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1037.001](https://attack.mitre.org/techniques/T1037/001) Logon Script (Windows), [T1039](https://attack.mitre.org/techniques/T1039) Data from Network Shared Drive, [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing, [T1048.002](https://attack.mitre.org/techniques/T1048/002) Exfiltration Over Asymmetric Encrypted Non-C2 Protocol, [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery _(+75 more)_

---

### G0032: Lazarus Group
<a id="g0032"></a>

Aliases: Labyrinth Chollima, HIDDEN COBRA, Guardians of Peace, ZINC, NICKEL ACADEMY, Diamond Sleet  
ATT&CK: [G0032](https://attack.mitre.org/groups/G0032), 93 techniques, 26 software  

Lazarus Group is a North Korean state-sponsored cyber threat group attributed to the Reconnaissance General Bureau (RGB). Lazarus Group has been active since at least 2009 and is reportedly responsible for the November 2014 destructive wiper attack on Sony Pictures Entertainment, identified by Novetta as part of Operation Blockbuster.

Notable techniques: [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels, [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1027.007](https://attack.mitre.org/techniques/T1027/007) Dynamic API Resolution, [T1027.009](https://attack.mitre.org/techniques/T1027/009) Embedded Payloads, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.003](https://attack.mitre.org/techniques/T1036/003) Rename Legitimate Utilities, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery _(+75 more)_

---

### G0129: Mustang Panda
<a id="g0129"></a>

Aliases: TA416, RedDelta, BRONZE PRESIDENT, STATELY TAURUS, FIREANT, CAMARO DRAGON, EARTH PRETA, HIVE0154, TWILL TYPHOON, TANTALUM, LUMINOUS MOTH, UNC6384, TEMP.Hex, Red Lich, ClumsyToad  
ATT&CK: [G0129](https://attack.mitre.org/groups/G0129), 85 techniques, 23 software  

Mustang Panda is a China-based cyber espionage threat actor that has been conducting operations since at least 2012. Mustang Panda has been known to use tailored phishing lures and decoy documents to deliver malicious payloads.

Notable techniques: [T1001.003](https://attack.mitre.org/techniques/T1001/003) Protocol or Service Impersonation, [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping, [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.007](https://attack.mitre.org/techniques/T1027/007) Dynamic API Resolution, [T1027.012](https://attack.mitre.org/techniques/T1027/012) LNK Icon Smuggling, [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1036.007](https://attack.mitre.org/techniques/T1036/007) Double File Extension, [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol _(+67 more)_

---

### G0096: APT41
<a id="g0096"></a>

Aliases: Wicked Panda, Brass Typhoon, BARIUM  
ATT&CK: [G0096](https://attack.mitre.org/groups/G0096), 82 techniques, 32 software  

APT41 is a threat group that researchers have assessed as Chinese state-sponsored espionage group that also conducts financially-motivated operations. Active since at least 2012, APT41 has been observed targeting various industries, including but not limited to healthcare, telecom, technology, finance, education, retail and video game industries in 14 countries.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1014](https://attack.mitre.org/techniques/T1014) Rootkit, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1030](https://attack.mitre.org/techniques/T1030) Data Transfer Size Limits, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1037](https://attack.mitre.org/techniques/T1037) Boot or Logon Initialization Scripts _(+64 more)_

---

### G1017: Volt Typhoon
<a id="g1017"></a>

Aliases: BRONZE SILHOUETTE, Vanguard Panda, DEV-0391, UNC3236, Voltzite, Insidious Taurus, DazedToad  
ATT&CK: [G1017](https://attack.mitre.org/groups/G1017), 81 techniques, 17 software  

Volt Typhoon is a People's Republic of China (PRC) state-sponsored actor that has been active since at least 2021, primarily targeting critical infrastructure organizations in the US and its territories including Guam. Volt Typhoon's targeting and pattern of behavior have been assessed as pre-positioning to enable lateral movement to operational technology (OT) assets for potential destructive or disruptive attacks.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1006](https://attack.mitre.org/techniques/T1006) Direct Volume Access, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1010](https://attack.mitre.org/techniques/T1010) Application Window Discovery, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery _(+63 more)_

---

### G0034: Sandworm Team
<a id="g0034"></a>

Aliases: ELECTRUM, Telebots, IRON VIKING, BlackEnergy (Group), Quedagh, Voodoo Bear, IRIDIUM, Seashell Blizzard, FROZENBARENTS, APT44  
ATT&CK: [G0034](https://attack.mitre.org/groups/G0034), 79 techniques, 27 software  

Sandworm Team is a destructive threat group that has been attributed to Russia's General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455. This group has been active since at least 2009.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic _(+61 more)_

---

### G0050: APT32
<a id="g0050"></a>

Aliases: SeaLotus, OceanLotus, APT-C-00, Canvas Cyclone, BISMUTH  
ATT&CK: [G0050](https://attack.mitre.org/groups/G0050), 78 techniques, 15 software  

APT32 is a suspected Vietnam-based threat group that has been active since at least 2014. The group has targeted multiple private sector industries as well as foreign governments, dissidents, and journalists with a strong focus on Southeast Asian countries like Vietnam, the Philippines, Laos, and Cambodia.

Notable techniques: [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping, [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.003](https://attack.mitre.org/techniques/T1036/003) Rename Legitimate Utilities, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation _(+60 more)_

---

### G0059: Magic Hound
<a id="g0059"></a>

Aliases: TA453, COBALT ILLUSION, Charming Kitten, ITG18, Phosphorus, Newscaster, APT35, Mint Sandstorm  
ATT&CK: [G0059](https://attack.mitre.org/groups/G0059), 78 techniques, 13 software  

Magic Hound is an Iranian-sponsored threat group that conducts long term, resource-intensive cyber espionage operations, likely on behalf of the Islamic Revolutionary Guard Corps. They have targeted European, U.S., and Middle Eastern government and military personnel, academics, journalists, and organizations such as the World Health Organization (WHO), via complex social engineering campaigns since at least 2014.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery, [T1016.002](https://attack.mitre.org/techniques/T1016/002) Wi-Fi Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1036.010](https://attack.mitre.org/techniques/T1036/010) Masquerade Account Name, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging _(+60 more)_

---

### G0049: OilRig
<a id="g0049"></a>

Aliases: COBALT GYPSY, IRN2, APT34, Helix Kitten, Evasive Serpens, Hazel Sandstorm, EUROPIUM, ITG13, Earth Simnavaz, Crambus, TA452  
ATT&CK: [G0049](https://attack.mitre.org/groups/G0049), 76 techniques, 30 software  

OilRig is a suspected Iranian threat group that has targeted Middle Eastern and international victims since at least 2014. The group has targeted a variety of sectors, including financial, government, energy, chemical, and telecommunications.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media, [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation _(+58 more)_

---

### G0047: Gamaredon Group
<a id="g0047"></a>

Aliases: IRON TILDEN, Primitive Bear, ACTINIUM, Armageddon, Shuckworm, DEV-0157, Aqua Blizzard, NastyShrew  
ATT&CK: [G0047](https://attack.mitre.org/groups/G0047), 70 techniques, 6 software  

Gamaredon Group is a suspected Russian cyber espionage group that has targeted military, law enforcement, judiciary, non-profit, and non-governmental organizations in Ukraine since at least 2013. The name Gamaredon Group derives from a misspelling of the word "Armageddon," found in early campaigns.

Notable techniques: [T1001](https://attack.mitre.org/techniques/T1001) Data Obfuscation, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery, [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration, [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC, [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.004](https://attack.mitre.org/techniques/T1027/004) Compile After Delivery, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.012](https://attack.mitre.org/techniques/T1027/012) LNK Icon Smuggling, [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression, [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1039](https://attack.mitre.org/techniques/T1039) Data from Network Shared Drive, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation _(+52 more)_

---

### G0010: Turla
<a id="g0010"></a>

Aliases: IRON HUNTER, Group 88, Waterbug, WhiteBear, Snake, Krypton, Venomous Bear, Secret Blizzard, BELUGASTURGEON  
ATT&CK: [G0010](https://attack.mitre.org/groups/G0010), 68 techniques, 30 software  

Turla is a cyber espionage threat group that has been attributed to Russia's Federal Security Service (FSB). They have compromised victims in over 50 countries since at least 2004, spanning a range of industries including government, embassies, military, education, research and pharmaceutical companies.

Notable techniques: [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1025](https://attack.mitre.org/techniques/T1025) Data from Removable Media, [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.011](https://attack.mitre.org/techniques/T1027/011) Fileless Storage, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1055](https://attack.mitre.org/techniques/T1055) Process Injection, [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell _(+50 more)_

---

### G0069: MuddyWater
<a id="g0069"></a>

Aliases: Earth Vetala, MERCURY, Static Kitten, Seedworm, TEMP.Zagros, Mango Sandstorm, TA450, MuddyKrill  
ATT&CK: [G0069](https://attack.mitre.org/groups/G0069), 68 techniques, 21 software  

MuddyWater is a cyber espionage group assessed to be a subordinate element within Iran's Ministry of Intelligence and Security (MOIS). Since at least 2017, MuddyWater has targeted a range of government and private organizations across sectors, including telecommunications, local government, finance, defense, and oil and natural gas organizations, in the Middle East (specifically the UAE and Saudi Arabia), Asia, Africa, Europe, and North America.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1003.005](https://attack.mitre.org/techniques/T1003/005) Cached Domain Credentials, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1027.003](https://attack.mitre.org/techniques/T1027/003) Steganography, [T1027.004](https://attack.mitre.org/techniques/T1027/004) Compile After Delivery, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python _(+50 more)_

---

### G0046: FIN7
<a id="g0046"></a>

Aliases: GOLD NIAGARA, ITG14, Carbon Spider, ELBRUS, Sangria Tempest  
ATT&CK: [G0046](https://attack.mitre.org/groups/G0046), 67 techniques, 19 software  

FIN7 is a financially-motivated threat group that has been active since 2013. FIN7 has targeted the retail, restaurant, hospitality, software, consulting, financial services, medical equipment, cloud services, media, food and beverage, transportation, pharmaceutical, and utilities industries in the United States.

Notable techniques: [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1021.005](https://attack.mitre.org/techniques/T1021/005) VNC, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.016](https://attack.mitre.org/techniques/T1027/016) Junk Code Insertion, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic, [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript _(+49 more)_

---

### G0016: APT29
<a id="g0016"></a>

Aliases: IRON RITUAL, IRON HEMLOCK, NobleBaron, Dark Halo, NOBELIUM, UNC2452, YTTRIUM, The Dukes, Cozy Bear, CozyDuke, SolarStorm, Blue Kitsune, UNC3524, Midnight Blizzard  
ATT&CK: [G0016](https://attack.mitre.org/groups/G0016), 66 techniques, 49 software  

APT29 is threat group that has been attributed to Russia's Foreign Intelligence Service (SVR). They have operated since at least 2008, often targeting government networks in Europe and NATO member countries, research institutes, and think tanks.

Notable techniques: [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery, [T1021.007](https://attack.mitre.org/techniques/T1021/007) Cloud Services, [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.006](https://attack.mitre.org/techniques/T1027/006) HTML Smuggling, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1037](https://attack.mitre.org/techniques/T1037) Boot or Logon Initialization Scripts, [T1037.004](https://attack.mitre.org/techniques/T1037/004) RC Scripts, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python, [T1059.009](https://attack.mitre.org/techniques/T1059/009) Cloud API, [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion _(+48 more)_

---

### G1059: NIMBUS MANTICORE
<a id="g1059"></a>

Aliases: UNC1549, TA455, COBALT SMOKEY  
ATT&CK: [G1059](https://attack.mitre.org/groups/G1059), 65 techniques, 13 software  

NIMBUS MANTICORE is a State Sponsored cyber espionage group associated with the Iranian Regime specifically the Iranian Revolutionary Guard Corps (IRGC). NIMBUS MANTICORE has employed social engineering attacks to include HR related themes and has leveraged custom malware against its victims.

Notable techniques: [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1039](https://attack.mitre.org/techniques/T1039) Data from Network Shared Drive, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion, [T1070.007](https://attack.mitre.org/techniques/T1070/007) Clear Network Connection History and Configurations _(+47 more)_

---

### G0102: Wizard Spider
<a id="g0102"></a>

Aliases: UNC1878, TEMP.MixMaster, Grim Spider, FIN12, GOLD BLACKBURN, ITG23, Periwinkle Tempest, DEV-0193, Pistachio Tempest, DEV-0237  
ATT&CK: [G0102](https://attack.mitre.org/groups/G0102), 64 techniques, 22 software  

Wizard Spider is a Russia-based financially motivated threat group originally known for the creation and deployment of TrickBot since at least 2016. Wizard Spider possesses a diverse arsenal of tools and has conducted ransomware campaigns against a variety of organizations, ranging from major corporations to hospitals.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021](https://attack.mitre.org/techniques/T1021) Remote Services, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) Process Injection _(+46 more)_

---

### G1015: Scattered Spider
<a id="g1015"></a>

Aliases: Roasted 0ktapus, Octo Tempest, Storm-0875, UNC3944  
ATT&CK: [G1015](https://attack.mitre.org/groups/G1015), 64 techniques, 10 software  

Scattered Spider is a native English-speaking cybercriminal group active since at least 2022. The group initially targeted customer relationship management (CRM) providers, business process outsourcing (BPO) firms, and telecommunications and technology companies before expanding in 2023 to gaming, hospitality, retail, managed service provider (MSP), manufacturing, and financial sectors.

Notable techniques: [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1006](https://attack.mitre.org/techniques/T1006) Direct Volume Access, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1021.007](https://attack.mitre.org/techniques/T1021/007) Cloud Services, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell, [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation, [T1069](https://attack.mitre.org/techniques/T1069) Permission Groups Discovery, [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups, [T1070.008](https://attack.mitre.org/techniques/T1070/008) Clear Mailbox Data, [T1074](https://attack.mitre.org/techniques/T1074) Data Staged, [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts, [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts, [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery _(+46 more)_

---

### G1055: VOID MANTICORE
<a id="g1055"></a>

Aliases: COBALT MYSTIQUE, Handala Hack, Homeland Justice, Karma, Karmabelow80, BANISHED KITTEN, Red Sandstorm  
ATT&CK: [G1055](https://attack.mitre.org/groups/G1055), 63 techniques, 0 software  

VOID MANTICORE is a threat group assessed to operate on behalf of Iran’s Ministry of Intelligence and Security (MOIS). Active since at least mid-2022, VOID MANTICORE has targeted government entities, critical infrastructure, and private sector organizations across Albania, Israel, and the United States.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python, [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols, [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools, [T1074](https://attack.mitre.org/techniques/T1074) Data Staged, [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts, [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts, [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts, [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery, [T1087.002](https://attack.mitre.org/techniques/T1087/002) Domain Account _(+45 more)_

---

### G0114: Chimera
<a id="g0114"></a>

ATT&CK: [G0114](https://attack.mitre.org/groups/G0114), 59 techniques, 6 software  

Chimera is a suspected China-based threat group that has been active since at least 2018 targeting the semiconductor industry in Taiwan as well as data from the airline industry.

Notable techniques: [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1039](https://attack.mitre.org/techniques/T1039) Data from Network Shared Drive, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery _(+41 more)_

---

### G1045: Salt Typhoon
<a id="g1045"></a>

ATT&CK: [G1045](https://attack.mitre.org/groups/G1045), 58 techniques, 1 software  

Salt Typhoon is a People's Republic of China (PRC) state-backed actor that has been active since at least 2019 and responsible for numerous compromises of network infrastructure at major U.S. telecommunication and internet service providers (ISP). Salt Typhoon has targeted and leveraged public facing network edge devices to gain access to victim environments.

Notable techniques: [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1020.001](https://attack.mitre.org/techniques/T1020/001) Traffic Duplication, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol, [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python, [T1059.008](https://attack.mitre.org/techniques/T1059/008) Network Device CLI, [T1059.013](https://attack.mitre.org/techniques/T1059/013) Container CLI/API, [T1070.003](https://attack.mitre.org/techniques/T1070/003) Clear Command History, [T1070.007](https://attack.mitre.org/techniques/T1070/007) Clear Network Connection History and Configurations, [T1070.009](https://attack.mitre.org/techniques/T1070/009) Clear Persistence, [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols _(+40 more)_

---

### G0027: Threat Group-3390
<a id="g0027"></a>

Aliases: Earth Smilodon, TG-3390, Emissary Panda, BRONZE UNION, APT27, Iron Tiger, LuckyMouse, Linen Typhoon  
ATT&CK: [G0027](https://attack.mitre.org/groups/G0027), 57 techniques, 24 software  

Threat Group-3390 is a Chinese threat group that has extensively used strategic Web compromises to target victims. The group has been active since at least 2010 and has targeted organizations in the aerospace, government, defense, technology, energy, manufacturing and gambling/betting sectors.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression, [T1030](https://attack.mitre.org/techniques/T1030) Data Transfer Size Limits, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.002](https://attack.mitre.org/techniques/T1053/002) At, [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing _(+39 more)_

---

### G1051: Medusa Group
<a id="g1051"></a>

ATT&CK: [G1051](https://attack.mitre.org/groups/G1051), 57 techniques, 5 software  

Medusa Group has been active since at least 2021 and was initially operated as a closed ransomware group before evolving into a Ransomware-as-a-Service (RaaS) operation. Some reporting indicates that certain attacks may still be conducted directly by the ransomware’s core developers.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups, [T1070.003](https://attack.mitre.org/techniques/T1070/003) Clear Command History, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols, [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools _(+39 more)_

---

### G0035: Dragonfly
<a id="g0035"></a>

Aliases: TEMP.Isotope, DYMALLOY, Berserk Bear, TG-4192, Crouching Yeti, IRON LIBERTY, Energetic Bear, Ghost Blizzard, BROMINE  
ATT&CK: [G0035](https://attack.mitre.org/groups/G0035), 56 techniques, 10 software  

Dragonfly is a cyber espionage group that has been attributed to Russia's Federal Security Service (FSB) Center 16. Active since at least 2010, Dragonfly has targeted defense and aviation companies, government entities, companies related to industrial control systems, and critical infrastructure sectors worldwide through supply chain, spearphishing, and drive-by compromise attacks.

Notable techniques: [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.010](https://attack.mitre.org/techniques/T1036/010) Masquerade Account Name, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python, [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion, [T1071.002](https://attack.mitre.org/techniques/T1071/002) File Transfer Protocols _(+38 more)_

---

### G0139: TeamTNT
<a id="g0139"></a>

ATT&CK: [G0139](https://attack.mitre.org/groups/G0139), 56 techniques, 4 software  

TeamTNT is a threat group that has primarily targeted cloud and containerized environments. The group as been active since at least October 2019 and has mainly focused its efforts on leveraging cloud and container resources to deploy cryptocurrency miners in victim environments.

Notable techniques: [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1014](https://attack.mitre.org/techniques/T1014) Rootkit, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1048](https://attack.mitre.org/techniques/T1048) Exfiltration Over Alternative Protocol, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell, [T1059.009](https://attack.mitre.org/techniques/T1059/009) Cloud API, [T1059.013](https://attack.mitre.org/techniques/T1059/013) Container CLI/API, [T1070.003](https://attack.mitre.org/techniques/T1070/003) Clear Command History _(+38 more)_

---

### G1052: Contagious Interview
<a id="g1052"></a>

Aliases: DeceptiveDevelopment, Gwisin Gang, Tenacious Pungsan, DEV#POPPER, PurpleBravo, TAG-121  
ATT&CK: [G1052](https://attack.mitre.org/groups/G1052), 54 techniques, 4 software  

Contagious Interview is a North Korea-aligned threat group active since 2023. The group conducts both cyberespionage and financially motivated operations, including the theft of cryptocurrency and user credentials.

Notable techniques: [T1027.010](https://attack.mitre.org/techniques/T1027/010) Command Obfuscation, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1048.003](https://attack.mitre.org/techniques/T1048/003) Exfiltration Over Unencrypted Non-C2 Protocol, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python, [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion, [T1071.003](https://attack.mitre.org/techniques/T1071/003) Mail Protocols, [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery, [T1090](https://attack.mitre.org/techniques/T1090) Proxy, [T1204.001](https://attack.mitre.org/techniques/T1204/001) Malicious Link, [T1204.002](https://attack.mitre.org/techniques/T1204/002) Malicious File, [T1204.004](https://attack.mitre.org/techniques/T1204/004) Malicious Copy and Paste _(+36 more)_

---

### G0087: APT39
<a id="g0087"></a>

Aliases: ITG07, Chafer, Remix Kitten  
ATT&CK: [G0087](https://attack.mitre.org/groups/G0087), 53 techniques, 11 software  

APT39 is one of several names for cyber espionage activity conducted by the Iranian Ministry of Intelligence and Security (MOIS) through the front company Rana Intelligence Computing since at least 2014. APT39 has primarily targeted the travel, hospitality, academic, and telecommunications industries in Iran and across Asia, Africa, Europe, and North America to track individuals and entities considered to be a threat by the MOIS.

Notable techniques: [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping, [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1056](https://attack.mitre.org/techniques/T1056) Input Capture, [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging, [T1059](https://attack.mitre.org/techniques/T1059) Command and Scripting Interpreter _(+35 more)_

---

### G1016: FIN13
<a id="g1016"></a>

Aliases: Elephant Beetle  
ATT&CK: [G1016](https://attack.mitre.org/groups/G1016), 53 techniques, 4 software  

FIN13 is a financially motivated cyber threat group that has targeted the financial, retail, and hospitality industries in Mexico and Latin America, as early as 2016. FIN13 achieves its objectives by stealing intellectual property, financial data, mergers and acquisition information, or PII.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1021.006](https://attack.mitre.org/techniques/T1021/006) Windows Remote Management, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging _(+35 more)_

---

### G0065: Leviathan
<a id="g0065"></a>

Aliases: MUDCARP, Kryptonite Panda, Gadolinium, BRONZE MOHAWK, TEMP.Jumper, APT40, TEMP.Periscope, Gingham Typhoon  
ATT&CK: [G0065](https://attack.mitre.org/groups/G0065), 50 techniques, 17 software  

Leviathan is a Chinese state-sponsored cyber espionage group that has been attributed to the Ministry of State Security's (MSS) Hainan State Security Department and an affiliated front company. Active since at least 2009, Leviathan has targeted the following sectors: academia, aerospace/aviation, biomedical, defense industrial base, government, healthcare, manufacturing, maritime, and transportation across the US, Canada, Australia, Europe, the Middle East, and Southeast Asia.

Notable techniques: [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping, [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1027.001](https://attack.mitre.org/techniques/T1027/001) Binary Padding, [T1027.003](https://attack.mitre.org/techniques/T1027/003) Steganography, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1027.015](https://attack.mitre.org/techniques/T1027/015) Compression, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1055.001](https://attack.mitre.org/techniques/T1055/001) Dynamic-link Library Injection, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic, [T1074.001](https://attack.mitre.org/techniques/T1074/001) Local Data Staging, [T1074.002](https://attack.mitre.org/techniques/T1074/002) Remote Data Staging, [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts, [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy, [T1102.003](https://attack.mitre.org/techniques/T1102/003) One-Way Communication _(+32 more)_

---

### G1048: UNC3886
<a id="g1048"></a>

ATT&CK: [G1048](https://attack.mitre.org/groups/G1048), 49 techniques, 8 software  

UNC3886 is a China-nexus cyberespionage group that has been active since at least 2022, targeting defense, technology, and telecommunication organizations located in the United States and the Asia-Pacific-Japan (APJ) regions. UNC3886 has displayed a deep understanding of edge devices and virtualization technologies through the exploitation of zero-day vulnerabilities and the use of novel malware families and utilities.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1008](https://attack.mitre.org/techniques/T1008) Fallback Channels, [T1014](https://attack.mitre.org/techniques/T1014) Rootkit, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools, [T1036.004](https://attack.mitre.org/techniques/T1036/004) Masquerade Task or Service, [T1037](https://attack.mitre.org/techniques/T1037) Boot or Logon Initialization Scripts, [T1037.004](https://attack.mitre.org/techniques/T1037/004) RC Scripts, [T1040](https://attack.mitre.org/techniques/T1040) Network Sniffing, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1059.004](https://attack.mitre.org/techniques/T1059/004) Unix Shell, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python, [T1059.012](https://attack.mitre.org/techniques/T1059/012) Hypervisor CLI, [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion, [T1070.006](https://attack.mitre.org/techniques/T1070/006) Timestomp _(+31 more)_

---

### G1043: BlackByte
<a id="g1043"></a>

Aliases: Hecamede  
ATT&CK: [G1043](https://attack.mitre.org/groups/G1043), 48 techniques, 8 software  

BlackByte is a ransomware threat actor operating since at least 2021. BlackByte is associated with several versions of ransomware also labeled BlackByte Ransomware.

Notable techniques: [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping, [T1012](https://attack.mitre.org/techniques/T1012) Query Registry, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1036.008](https://attack.mitre.org/techniques/T1036/008) Masquerade File Type, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1055](https://attack.mitre.org/techniques/T1055) Process Injection, [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion, [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols _(+30 more)_

---

### G1003: Ember Bear
<a id="g1003"></a>

Aliases: UNC2589, Bleeding Bear, DEV-0586, Cadet Blizzard, Frozenvista, UAC-0056  
ATT&CK: [G1003](https://attack.mitre.org/groups/G1003), 47 techniques, 11 software  

Ember Bear is a Russian state-sponsored cyber espionage group that has been active since at least 2020, linked to Russia's General Staff Main Intelligence Directorate (GRU) 161st Specialist Training Center (Unit 29155). Ember Bear has primarily focused operations against Ukrainian government and telecommunication entities, but has also operated against critical infrastructure entities in Europe and the Americas.

Notable techniques: [T1003](https://attack.mitre.org/techniques/T1003) OS Credential Dumping, [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021](https://attack.mitre.org/techniques/T1021) Remote Services, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1070.004](https://attack.mitre.org/techniques/T1070/004) File Deletion, [T1071.004](https://attack.mitre.org/techniques/T1071/004) DNS, [T1078.001](https://attack.mitre.org/techniques/T1078/001) Default Accounts, [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy, [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol _(+29 more)_

---

### G0004: Ke3chang
<a id="g0004"></a>

Aliases: APT15, Mirage, Vixen Panda, GREF, Playful Dragon, RoyalAPT, NICKEL, Nylon Typhoon  
ATT&CK: [G0004](https://attack.mitre.org/groups/G0004), 46 techniques, 11 software  

Ke3chang is a threat group attributed to actors operating out of China. Ke3chang has targeted oil, government, diplomatic, military, and NGOs in Central and South America, the Caribbean, Europe, and North America since at least 2010.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1020](https://attack.mitre.org/techniques/T1020) Automated Exfiltration, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.002](https://attack.mitre.org/techniques/T1036/002) Right-to-Left Override, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery _(+28 more)_

---

### G0045: menuPass
<a id="g0045"></a>

Aliases: Cicada, POTASSIUM, Stone Panda, APT10, Red Apollo, CVNX, HOGFISH, BRONZE RIVERSIDE  
ATT&CK: [G0045](https://attack.mitre.org/groups/G0045), 46 techniques, 25 software  

menuPass is a threat group that has been active since at least 2006. Individual members of menuPass are known to have acted in association with the Chinese Ministry of State Security's (MSS) Tianjin State Security Bureau and worked for the Huaying Haitai Science and Technology Development Company.

Notable techniques: [T1003.002](https://attack.mitre.org/techniques/T1003/002) Security Account Manager, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1003.004](https://attack.mitre.org/techniques/T1003/004) LSA Secrets, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.004](https://attack.mitre.org/techniques/T1021/004) SSH, [T1027.013](https://attack.mitre.org/techniques/T1027/013) Encrypted/Encoded File, [T1036](https://attack.mitre.org/techniques/T1036) Masquerading, [T1036.003](https://attack.mitre.org/techniques/T1036/003) Rename Legitimate Utilities, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1039](https://attack.mitre.org/techniques/T1039) Data from Network Shared Drive, [T1046](https://attack.mitre.org/techniques/T1046) Network Service Discovery, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1055.012](https://attack.mitre.org/techniques/T1055/012) Process Hollowing _(+28 more)_

---

### G1057: ShinyHunters
<a id="g1057"></a>

Aliases: UNC6240, Bling Libra  
ATT&CK: [G1057](https://attack.mitre.org/groups/G1057), 46 techniques, 1 software  

ShinyHunters is a cyber criminal collective that has been active since at least 2019 operating under the ShinyCorp persona. ShinyHunters has targeted multiple industries and geographic regions gathering legitimate credentials and personally identifiable information (PII) for resale or extortion of victims.

Notable techniques: [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript, [T1059.009](https://attack.mitre.org/techniques/T1059/009) Cloud API, [T1069.003](https://attack.mitre.org/techniques/T1069/003) Cloud Groups, [T1072](https://attack.mitre.org/techniques/T1072) Software Deployment Tools, [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts, [T1078.002](https://attack.mitre.org/techniques/T1078/002) Domain Accounts, [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts, [T1082](https://attack.mitre.org/techniques/T1082) System Information Discovery, [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery, [T1090.003](https://attack.mitre.org/techniques/T1090/003) Multi-hop Proxy, [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer, [T1110](https://attack.mitre.org/techniques/T1110) Brute Force, [T1190](https://attack.mitre.org/techniques/T1190) Exploit Public-Facing Application, [T1195.001](https://attack.mitre.org/techniques/T1195/001) Compromise Software Dependencies and Development Tools, [T1203](https://attack.mitre.org/techniques/T1203) Exploitation for Client Execution _(+28 more)_

---

### G0022: APT3
<a id="g0022"></a>

Aliases: Gothic Panda, Pirpi, UPS Team, Buckeye, Threat Group-0110, TG-0110  
ATT&CK: [G0022](https://attack.mitre.org/groups/G0022), 44 techniques, 6 software  

APT3 is a China-based threat group that researchers have attributed to China's Ministry of State Security. This group is responsible for the campaigns known as Operation Clandestine Fox, Operation Clandestine Wolf, and Operation Double Tap.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1021.001](https://attack.mitre.org/techniques/T1021/001) Remote Desktop Protocol, [T1021.002](https://attack.mitre.org/techniques/T1021/002) SMB/Windows Admin Shares, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.002](https://attack.mitre.org/techniques/T1027/002) Software Packing, [T1027.005](https://attack.mitre.org/techniques/T1027/005) Indicator Removal from Tools, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.010](https://attack.mitre.org/techniques/T1036/010) Masquerade Account Name, [T1041](https://attack.mitre.org/techniques/T1041) Exfiltration Over C2 Channel, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1056.001](https://attack.mitre.org/techniques/T1056/001) Keylogging, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell _(+26 more)_

---

### G0125: HAFNIUM
<a id="g0125"></a>

Aliases: Operation Exchange Marauder, Silk Typhoon  
ATT&CK: [G0125](https://attack.mitre.org/groups/G0125), 44 techniques, 6 software  

HAFNIUM is a likely state-sponsored cyber espionage group operating out of China that has been active since at least January 2021. HAFNIUM primarily targets entities in the US across a number of industry sectors, including infectious disease researchers, law firms, higher education institutions, defense contractors, policy think tanks, and NGOs.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1016.001](https://attack.mitre.org/techniques/T1016/001) Internet Connection Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.003](https://attack.mitre.org/techniques/T1059/003) Windows Command Shell, [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation, [T1071.001](https://attack.mitre.org/techniques/T1071/001) Web Protocols, [T1078.003](https://attack.mitre.org/techniques/T1078/003) Local Accounts, [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts, [T1083](https://attack.mitre.org/techniques/T1083) File and Directory Discovery, [T1095](https://attack.mitre.org/techniques/T1095) Non-Application Layer Protocol, [T1098](https://attack.mitre.org/techniques/T1098) Account Manipulation, [T1105](https://attack.mitre.org/techniques/T1105) Ingress Tool Transfer _(+26 more)_

---

### G1006: Earth Lusca
<a id="g1006"></a>

Aliases: TAG-22, Charcoal Typhoon, CHROMIUM, ControlX  
ATT&CK: [G1006](https://attack.mitre.org/groups/G1006), 44 techniques, 9 software  

Earth Lusca is a suspected China-based cyber espionage group that has been active since at least April 2019. Earth Lusca has targeted organizations in Australia, China, Hong Kong, Mongolia, Nepal, the Philippines, Taiwan, Thailand, Vietnam, the United Arab Emirates, Nigeria, Germany, France, and the United States.

Notable techniques: [T1003.001](https://attack.mitre.org/techniques/T1003/001) LSASS Memory, [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync, [T1007](https://attack.mitre.org/techniques/T1007) System Service Discovery, [T1016](https://attack.mitre.org/techniques/T1016) System Network Configuration Discovery, [T1018](https://attack.mitre.org/techniques/T1018) Remote System Discovery, [T1027](https://attack.mitre.org/techniques/T1027) Obfuscated Files or Information, [T1027.003](https://attack.mitre.org/techniques/T1027/003) Steganography, [T1033](https://attack.mitre.org/techniques/T1033) System Owner/User Discovery, [T1036.005](https://attack.mitre.org/techniques/T1036/005) Match Legitimate Resource Name or Location, [T1047](https://attack.mitre.org/techniques/T1047) Windows Management Instrumentation, [T1049](https://attack.mitre.org/techniques/T1049) System Network Connections Discovery, [T1053.005](https://attack.mitre.org/techniques/T1053/005) Scheduled Task, [T1057](https://attack.mitre.org/techniques/T1057) Process Discovery, [T1059.001](https://attack.mitre.org/techniques/T1059/001) PowerShell, [T1059.005](https://attack.mitre.org/techniques/T1059/005) Visual Basic, [T1059.006](https://attack.mitre.org/techniques/T1059/006) Python, [T1059.007](https://attack.mitre.org/techniques/T1059/007) JavaScript, [T1090](https://attack.mitre.org/techniques/T1090) Proxy _(+26 more)_

---

### G1004: LAPSUS$
<a id="g1004"></a>

Aliases: DEV-0537, Strawberry Tempest  
ATT&CK: [G1004](https://attack.mitre.org/groups/G1004), 43 techniques, 1 software  

LAPSUS$ is cyber criminal threat group that has been active since at least mid-2021. LAPSUS$ specializes in large-scale social engineering and extortion operations, including destructive attacks without the use of ransomware.

Notable techniques: [T1003.003](https://attack.mitre.org/techniques/T1003/003) NTDS, [T1003.006](https://attack.mitre.org/techniques/T1003/006) DCSync, [T1005](https://attack.mitre.org/techniques/T1005) Data from Local System, [T1068](https://attack.mitre.org/techniques/T1068) Exploitation for Privilege Escalation, [T1069.002](https://attack.mitre.org/techniques/T1069/002) Domain Groups, [T1078](https://attack.mitre.org/techniques/T1078) Valid Accounts, [T1078.004](https://attack.mitre.org/techniques/T1078/004) Cloud Accounts, [T1087.002](https://attack.mitre.org/techniques/T1087/002) Domain Account, [T1090](https://attack.mitre.org/techniques/T1090) Proxy, [T1098.003](https://attack.mitre.org/techniques/T1098/003) Additional Cloud Roles, [T1111](https://attack.mitre.org/techniques/T1111) Multi-Factor Authentication Interception, [T1114.003](https://attack.mitre.org/techniques/T1114/003) Email Forwarding Rule, [T1133](https://attack.mitre.org/techniques/T1133) External Remote Services, [T1136.003](https://attack.mitre.org/techniques/T1136/003) Cloud Account, [T1199](https://attack.mitre.org/techniques/T1199) Trusted Relationship, [T1204](https://attack.mitre.org/techniques/T1204) User Execution, [T1213.001](https://attack.mitre.org/techniques/T1213/001) Confluence, [T1213.002](https://attack.mitre.org/techniques/T1213/002) Sharepoint _(+25 more)_

<!-- related:start (written by scripts/build_crosslinks.py; do not edit) -->

## Related pages

- Domain: [Threat intelligence and adversaries](/hubs/threat-intelligence.md)
- [Threat Intelligence Reference](/THREAT_INTELLIGENCE_REFERENCE.md)
- [Threat Actors](/THREAT_ACTORS.md)

<!-- related:end -->

---

*Source: MITRE ATT&CK Enterprise v20.0, through data/attack/groups.jsonl and data/attack/group_profiles.jsonl. Full technique lists for every group are in the machine-readable edge table. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.*
