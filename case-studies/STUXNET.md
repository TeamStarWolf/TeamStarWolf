# Stuxnet: The Case Study

*A TeamStarWolf case study. Published 3 November 2026; every source checked as of that date.*

[All case studies](/case-studies/README.md) · Related: [Notable Incidents](/NOTABLE_INCIDENTS.md), [Malware Families](/MALWARE_FAMILIES.md), [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md), [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md), [CVE Reference](/CVE_REFERENCE.md)

## Executive summary

Stuxnet is the incident that taught the industrial-control community its hardest lesson: a plant that is not connected to the internet can still be reached, and a controller that looks healthy on the engineering screen can be running someone else's code. It was a Windows worm with a second payload written for Siemens programmable logic controllers (PLCs). It crossed air gaps on USB drives, used four zero-day exploits (two to spread, two to raise its privileges) plus the older MS08-067 bug, signed its drivers with compromised code-signing certificates, and rewrote the logic on a narrowly defined set of PLCs that drive frequency converters. While the sabotage ran, it played recorded "normal" process values back to the operators. Symantec, whose W32.Stuxnet Dossier remains the reference analysis, described its goal as reprogramming industrial control systems and hiding those changes from the people running them [1] (**Confirmed**).

The record is unusually rich on the technical side and unusually thin on the official side. Vendor primaries (Symantec, ESET, Kaspersky, CrySyS) and government advisories (ICS-CERT, Microsoft, NVD, CISA's Known Exploited Vulnerabilities catalog) document how it worked in detail. The IAEA's reports document what happened to the centrifuge cascades at Natanz in 2009 and 2010, but never name a cause. No government has acknowledged building Stuxnet in any source this study opened. The widely repeated account of a joint US and Israeli program called "Olympic Games" rests on journalism citing anonymous officials, and this study grades it accordingly.

Evidence grade: the malware's design, spread, sabotage logic and the vulnerabilities it used are **Confirmed** from vendor and government primaries. The effect on Natanz is **Confirmed** as IAEA-observed cascade changes and **Reported** as a causal link. Attribution to specific governments is **Reported** (journalism) and never **Confirmed**.

### Key facts at a glance

| Field | Value |
|---|---|
| Name | Stuxnet (W32.Stuxnet); ATT&CK software `S0603` (v1.5, last modified 24 April 2026) [30] |
| What it is | A Windows worm carrying a PLC payload for Siemens Step 7 environments, with a Windows rootkit and the first PLC rootkit [1] |
| Earliest known version | Stuxnet 0.5, submitted to a public scanning service on 15 November 2007; its C&C domains were registered from 3 November 2005 [2] |
| Earliest 1.x sample | June 2009; first variant to exploit the LNK flaw (MS10-046) in March 2010 [1] |
| Public discovery | VirusBlokAda found samples on 17 June 2010 [1] [52]; CERT/CC published VU#940193 on 15 July 2010 [19] |
| Exploits | Four zero-days plus MS08-067, which Conficker also used [15] |
| Scale | About 100,000 infected hosts by 29 September 2010, roughly 60 percent of them in Iran [1] |
| PLC targets | S7-315 CPUs driving at least 33 Vacon NX or Fararo Paya KFC750V3 frequency converters; S7-417 cascade protection controllers [1] [2] [14] |
| Effect at Natanz | IAEA recorded disconnected centrifuges in Unit A26 by 31 January 2010 with no cause given [36]; ISIS estimated about 1,000 IR-1 centrifuges replaced and called Stuxnet a reasonable but unproven explanation [39] |
| Official attribution | None found. Press reports, citing anonymous officials, describe a US and Israeli program [44] [49] (**Reported**) |
| Coded stop date | Infection stops after 24 June 2012 in the 1.x configuration [1] [2] |
| KEV status | CVE-2010-2568 (LNK) added 15 September 2022; CVE-2008-4250 (MS08-067) added 20 May 2026 [29] |
| ATT&CK record | 44 Enterprise and 25 ICS technique rows in ATT&CK v20.0; no group or campaign is linked [30] |

### Key findings

- **The air gap was crossed by design, not by accident.** Symantec's attack scenario (labelled by the authors as speculation) says PLCs are often programmed from Windows machines with no internet or even internal network connection, and that removable drives likely carried the final hop [1] (**Confirmed** that Symantec says so). Stuxnet 0.5 spread only through infected Step 7 project archives and used no Microsoft vulnerability at all [2] (**Confirmed**).
- **Every Windows layer was abused in turn.** The LNK flaw ran code when a folder was merely viewed; the MS10-061 Print Spooler zero-day, the older MS08-067 bug and network shares carried it sideways; MS10-073 and a Task Scheduler flaw raised its privileges; and a hard-coded WinCC database password let it infect the control software itself [1] [15] [28] (**Confirmed**).
- **Signed meant nothing.** Its drivers carried valid signatures from a compromised Realtek certificate, signed on 25 January 2010 and revoked in July 2010, and a second variant used a JMicron certificate [1] [16] (**Confirmed**). The sources disagree by one day on the Realtek revocation (16 July per Symantec, 17 July per ESET) [1] [3].
- **The sabotage was precise and patient.** On S7-315 controllers it waited about 12.8 days, then pushed drive frequencies to 1410 Hz, down to 2 Hz and back to 1064 Hz while replaying recorded values to WinCC [1] (**Confirmed**). Langner reads the earlier S7-417 routine as an overpressure attack that closed cascade valves and the later one as a rotor-speed attack [14] (**Confirmed** as his analysis).
- **The controller's own readback lied.** The PLC rootkit lived in the replaced Step 7 communication library and returned clean copies of infected blocks on read, so checking logic through the infected workstation could not reveal the change [1] (**Confirmed** for the mechanism; the defensive reading is **Inferred**).
- **Attribution stays at Reported.** The governments most often named have not acknowledged it in any source opened here. A US general pleaded guilty in 2016 to false statements in a leak investigation and was pardoned in 2017, but the Justice Department documents do not mention Stuxnet or Iran [47] [48] (**Confirmed** for the documents; the Stuxnet link is press reporting).
- **The library needs three corrections.** `MALWARE_FAMILIES.md` attributes Stuxnet to Equation Group, `NOTABLE_INCIDENTS.md` dates official confirmation to "2011 leaks", and the Stuxnet section of `ICS_OT_SECURITY_REFERENCE.md` lists ICS techniques that ATT&CK does not map to S0603 (Part 4.9).

### Top recommendations

1. **Treat isolation as one control, not the defence.** NIST SP 800-82r3 states that relying on air gaps alone is not enough once OT connects to IT [54]. Monitor inside the control network and plan for a worm that arrives on a laptop or a USB drive.
2. **Control removable media at every OT node.** Permit no unauthorized removable media on any OT node, and scan laptops and USB storage before they connect [54]. Map this to D3FEND IO Port Restriction and Hardware Component Inventory (Part 5).
3. **Do not equate a valid signature with trust.** Watch for unusual driver loads, and enable driver integrity protections where the platform supports them, as the 2022 joint advisory on OT tooling recommends [57].
4. **Verify controller logic out of band.** Keep known-good offline backups of PLC programs and configurations and check them with hashes [57]; put PLC key switches in run or remote mode with the key removed [54]; do not trust a readback through a workstation that may be compromised.
5. **Remove hard-coded and default credentials from control software.** CVE-2010-2772 (CWE-798) gave Stuxnet the WinCC database [28]. Inventory vendor default passwords and change them (D3FEND Change Default Password).
6. **Patch the Windows estate around the plant.** MS08-067, MS10-046, MS10-061, MS10-073 and MS10-092 were all available by December 2010 [20] [22] [23] [24] [25], and two of these flaws are now in CISA's KEV catalog [29]. Old engineering workstations are where these bugs live longest.

## Scope and method

This study covers Stuxnet from the earliest dated infrastructure (2005) through its discovery (2010), the analyses that followed (2010 to 2015), the official and legal record (2010 to 2017), and the ICS malware that defenders now compare it to (2016 to 2022). It follows the method in the [case studies README](/case-studies/README.md): primary sources first, every claim graded, numbers given as the source states them. Every source in the Sources table was opened on 3 November 2026. Where a primary could not be opened (for example the New York Times originals, or Langner's 2013 paper "To Kill a Centrifuge"), the study says so and grades the claim on what was opened. Direct quotations are kept under 15 words.

| Grade | Meaning in this study |
|---|---|
| Confirmed | Stated in a primary opened for this study: the vendor or lab that did the analysis, a government agency or court record, the IAEA, or the MITRE page itself |
| Reported | Stated only in journalism or in a secondary source relaying another party; the original was not opened or does not exist publicly |
| Demonstrated | A public reproduction exists that others can check (no claim in this study needed this grade) |
| Inferred | The study's own reasoning from Confirmed facts, labelled as such |

## Part 1: the technical record

### 1.1 What it was built to do

Symantec's W32.Stuxnet Dossier v1.4 (February 2011) says the final goal was to reprogram industrial control systems by modifying code on Siemens PLCs and to hide those changes from the equipment operator [1] (**Confirmed**). To get there it combined zero-day exploits, a Windows rootkit, the first known PLC rootkit, peer-to-peer updates and a command-and-control interface [1]. Symantec's summary calls it the first threat to exploit four zero-days, compromise two digital certificates and hide injected industrial code from the operator, and adds that few attackers could build something similar [1] (**Confirmed**). The dossier gives the target only as likely in Iran, and labels its own attack scenario as speculation [1].

### 1.2 Versions and lineage

| Version | Dates | How it spread | Platform | Source |
|---|---|---|---|---|
| 0.5 | C&C domains registered from 3 November 2005; submitted to a public scanning service 15 November 2007; programmed to stop C&C contact after 11 January 2009 and to stop spreading on 4 July 2009 | Only through infected Step 7 project archives; no Microsoft vulnerability (it did use the Siemens flaw CVE-2012-3015 to load its DLL) | Partly based on the Flamer platform | [2] (**Confirmed**) |
| 1.x, June 2009 variant | Earliest 1.x sample June 2009 | autorun.inf on removable drives; no LNK exploit, no signed drivers | Mainly the Tilded platform | [1] [2] (**Confirmed**) |
| 1.x, March and April 2010 variants | First LNK (MS10-046) variant March 2010 | LNK flaw, network routines, signed drivers | Tilded | [1] (**Confirmed**) |
| 1.x stop date | Infection stops after 24 June 2012 | | | [1] [2] (**Confirmed**) |

The "0.5" and "1.x" labels come from Symantec's 2013 paper "Stuxnet 0.5: The Missing Link" [2]; the 2011 dossier simply calls the June 2009 sample the earliest seen [1]. Stuxnet 0.5 used C&C domains dressed as advertising sites: smartclick.org, best-advertising.net, internetadvertising4u.com and ad-marketing.net [2] (**Confirmed**).

Kaspersky found the bridge to Flame. Resource 207 (520,192 bytes) in the 2009 version of Stuxnet contains a 351,768-byte file that Kaspersky identified as a proto-Flame plugin [4] (**Confirmed**). Its conclusions point to two independent developer teams, which it called Team F (Flame) and Team D (Tilded), and to Flame source code being used in Stuxnet in 2009 [4] (**Confirmed** as Kaspersky's assessment).

### 1.3 Getting in: removable drives

In the 2010 variants a removable drive carried four crafted `.lnk` shortcut files, `~WTR4141.tmp` (a loader) and `~WTR4132.tmp` (the main DLL). Through the LNK flaw, the loader ran as soon as a user viewed the folder, with no click needed [1] (**Confirmed**). The drive could delete its own copies once it had infected three computers, which the dossier gives as one example of a configurable removal rule [1]. The June 2009 variant used a single file instead: an executable with autorun.inf data appended, which added a second "Open" entry to the drive's context menu [1] (**Confirmed**).

ICS-CERT's advisory said the malware appears to launch when a USB drive is viewed in a file manager and can run without AutoRun [16] (**Confirmed**). The LNK flaw is CVE-2010-2568, fixed by MS10-046 [20]. Microsoft's advisory 2286198 was published on 16 July 2010 [21], and the bulletin on 2 August 2010, when the flaw was already used by a number of malware families [20] (**Confirmed**). It was not unique to Stuxnet even earlier: Symantec's timeline records a Trojan.Zlob variant using the same LNK vulnerability on 20 November 2008 [1] (**Confirmed**).

### 1.4 Spreading inside the network

Inside a network, Symantec documents five propagation routines [1] (**Confirmed**):

| Routine | Detail | Source |
|---|---|---|
| Peer-to-peer updates | RPC server on each infected host; versions update one another | [1] [15] |
| WinCC database | Logs in to the WinCC SQL database with a hard-coded password (CVE-2010-2772, CWE-798) and plants code in it | [1] [28] |
| Network shares | Copies itself as `DEFRAG*.tmp` and runs it through a scheduled job or WMI two minutes after infection | [1] |
| MS10-061 Print Spooler | Copies itself as `%System%\winsta.exe`; tried only before 1 June 2011 | [1] [22] |
| MS08-067 Server service | The same bug Conficker used | [1] [15] [25] |

ICS-CERT's primary advisory ICSA-10-272-01 lists the same picture: infected USB devices, network shares, STEP 7 project files, WinCC database files and the MS10-061 print spooler flaw, with updates through C2 and peer-to-peer RPC [15] (**Confirmed**). NVD's record for CVE-2010-2772 says the hard-coded password was demonstrated in the wild in July 2010 by Stuxnet [28], and ICS-CERT's later advisory ICSA-12-205-01 says the issue was first found alongside Stuxnet and fixed by Siemens in 2010 [18] (**Confirmed**).

Step 7 projects were also a carrier. Stuxnet hooked `CreateFileA` in the Simatic manager process `s7tgtopx.exe` and `StgOpenStorage` in `ccprojectmgr.exe`, wrote `xutils\listen\xr000000.mdx` (an encrypted copy of the main DLL) and dropped a DLL into the `hOmSave7` subfolders, so the manager loaded it when the project was opened. Manager versions 5.3 and 5.4 SP4 were affected [1] (**Confirmed**).

### 1.5 Hiding on Windows: drivers, certificates and the rootkit

Installation dropped `Oem7a.pnf` (the payload) plus `mdmeric3.PNF`, `mdmcpq3.PNF` (the configuration) and `oem6C.PNF` (a log). The boot-start driver `MrxCls.sys` injected the payload into `services.exe`, `s7tgtopx.exe` and `CCProjectMgr.exe` (and a second file into `explorer.exe`). The rootkit driver `MrxNet.sys` hid 4,171-byte `.LNK` files and `~WTR` temporary files on drives. Driver file times were set to match other files in the system directory [1] (**Confirmed**).

Both drivers were signed with a compromised Realtek Semiconductor certificate; a driver was signed with it on 25 January 2010 [1] (**Confirmed**). Symantec says the drivers needed signatures to avoid suspicion and that the attackers compromised two certificates; the idea that someone physically entered the two companies' premises is the authors' own speculation [1]. ICS-CERT noted that Windows showed no warning on install even though the certificate had expired in June 2010, and that VeriSign revoked it [16] (**Confirmed**). On 17 July 2010 ESET found a new driver signed with a JMicron certificate, which VeriSign revoked on 22 July [1] [16] (**Confirmed**).

Discrepancy: Symantec dates the Realtek revocation to 16 July 2010 [1]; ESET gives 17 July [3]. Both are vendor primaries; the study shows both.

### 1.6 Guardrails

Stuxnet carried rules that limited where it ran [1] (**Confirmed**): it exited on 64-bit hosts; it skipped a machine whose registry value `NTVDM TRACE` under `MS-DOS Emulation` equals `19790509`, which Symantec reads as a likely "do not infect" marker; and it stopped infecting after the configured date of 24 June 2012.

### 1.7 Command and control

C2 ran over HTTP on port 80 to `www[.]mypremierfutbol[.]com` and `www[.]todaysfutbol[.]com`, names that had pointed to servers in Malaysia and Denmark. Outbound data was XORed with 0xFF, then with a 31-byte static key, hex-encoded and sent as `index.php?data=`. Replies, encrypted with a different key, could deliver a module that Stuxnet loaded and ran [1] (**Confirmed**). Symantec began monitoring this traffic on 20 July 2010 [1].

### 1.8 Finding the target

The S7-315 payload (sequences A and B) ran only on a very specific plant [1] (**Confirmed**):

- the CPU had to be a 6ES7-315-2;
- a system data block had to hold `0100CB2Ch` at offset `50h`, which marks a CP 342-5 Profibus module;
- at least 33 frequency converter drives had to be counted with the values `7050h` or `9500h`, which the dossier says appear to be Profibus identifiers for the Fararo Paya KFC750V3 (Tehran) and the Vacon NX.

Sequence A ran if Vacon drives outnumbered Fararo Paya drives, and sequence B otherwise. Stuxnet moved the standard `DP_RECV` block to `FC1869`, replaced it with its own monitor, and infected `OB1` and `OB35` [1].

### 1.9 The sabotage: rotor speed

For sequence A, Symantec documents the timing [1] (**Confirmed**). The attackers expected the drives to run between 807 Hz and 1210 Hz. After about 12.8 days of monitoring, the maximum frequency was set to 1410 Hz, then to 2 Hz, then to 1064 Hz. Later cycles waited about 26.6 days. One state transition took 15 minutes in the first sub-sequence and 50 minutes in the second, and a flag in data block `DB890` synchronized the attack across every S7-315 on the bus.

Langner's 2013 retrospective reads the same routine as a rotor-speed attack on the IR-1 centrifuge: from a normal 63,000 rpm to 84,600 rpm for 15 minutes, then the next run down to 120 rpm and back over a total of 50 minutes, about once a month [14] (**Confirmed** as Langner's analysis). He judges from the close monitoring of pressures that the intent was to stress rotors and shorten their life rather than to destroy them at once [14] (**Confirmed** as Langner's own reading; it is his inference about intent, not an observed fact).

While the sabotage ran, Stuxnet halted the original `OB1` and `OB35` code and played recorded frequencies back to WinCC, so monitoring showed a normal plant. Because `OB35` normally acts as a watchdog, suppressing it could prevent a safe shutdown if that original code was meant to trigger one [1] (**Confirmed**, with the source's own condition).

### 1.10 The PLC rootkit

The PLC rootkit lived entirely in a fake `s7otbxdx.dll`, the library Step 7 uses to talk to PLCs; Stuxnet renamed the original to `s7otbxsx.dll` [1] [15] (**Confirmed**). Its hooks on `s7blk_read`, `s7blk_findfirst` and `s7blk_findnext` hid its own blocks and returned clean copies of the infected `OB1` and `OB35`; hooks on `s7blk_write` and `s7blk_delete` protected the infection from being overwritten [1] (**Confirmed**). Symantec's summary describes victims trying to verify their logic and seeing no rogue code [1].

### 1.11 The valve attack: S7-417

In the 1.x code the S7-417 routine (sequence C) is incomplete: one DLL function is missing, so data block `DB8061` is never created and `OB1` is never modified. The code expects six groups of 164 peripherals, which Symantec says could be six cascades of 164 centrifuges, and makes a 21-second recording of the input area [1] (**Confirmed**).

Stuxnet 0.5 carries a fully implemented version. It fingerprints the target through `s7aaapix.dll`, builds `DB8061`, replays fake input signals and closes valves in the six top-rated cascades out of a possible 18. Symantec ties it directly to the uranium enrichment facility at Natanz and says whether it succeeded is unknown [2] (**Confirmed**). Langner describes the same overpressure attack on the cascade protection system: 21 seconds of sensor values recorded and replayed in a loop, then the isolation valves closed in the first two and last two enrichment stages [14] (**Confirmed** as his analysis). He calls this earlier routine about an order of magnitude more complex and stealthy, and says the attackers switched to the rotor-speed variant in 2009 [14].

### 1.12 The vulnerabilities

| CVE | Fix | Published | Stuxnet use | NVD CWE | KEV | Source |
|---|---|---|---|---|---|---|
| CVE-2010-2568 (Windows Shell LNK) | MS10-046 | 2 Aug 2010 (advisory 2286198 on 16 Jul 2010) | Removable-drive spread, from March 2010 | NVD-CWE-noinfo (KEV lists CWE-20) | Added 15 Sep 2022 | [20] [21] [28] [29] (**Confirmed**) |
| CVE-2010-2729 (Print Spooler) | MS10-061 | 14 Sep 2010 | Network spread; exploited on a limited scale at release | CWE-20 | Not listed | [1] [22] [28] [29] (**Confirmed**) |
| CVE-2008-4250 (Server service RPC) | MS08-067 | 23 Oct 2008 | Network spread; the Conficker bug | CWE-94 (NVD); CWE-119 (CISA ADP enrichment); KEV lists CWE-94 | Added 20 May 2026 | [1] [15] [25] [28] [29] (**Confirmed**) |
| CVE-2010-2743 (Win32k keyboard layout) | MS10-073 | 12 Oct 2010 | Local privilege escalation; NVD names Stuxnet | NVD-CWE-Other | Not listed | [23] [28] [29] (**Confirmed**) |
| CVE-2010-3338 (Task Scheduler) | MS10-092 | 14 Dec 2010 | Privilege escalation on Vista, 7 and 2008; forged CRC32 on task XML | CWE-20 | Not listed | [3] [24] [28] [29] (**Confirmed**) |
| CVE-2010-2772 (Siemens WinCC/PCS 7 hard-coded password) | Siemens update, 2010 | NVD 22 Jul 2010 | WinCC database infection | CWE-798 | Not listed | [18] [28] (**Confirmed**) |

ESET explains the Task Scheduler bug: task files were checked with CRC32, whose linear properties make it easy to append data that keeps the same checksum, and MS10-092 added a SHA-256 check [3] (**Confirmed**). Microsoft credited Kaspersky, Symantec and ESET researchers for MS10-092, Kaspersky and Symantec for MS10-061 and MS10-073, and VirusBlokAda's Sergey Ulasen and Oleg Kupreev for the LNK flaw [20] [22] [23] [24] (**Confirmed**).

Discrepancy: the exploit table in Symantec's 0.5 paper lists CVE-2010-3888 against the Task Scheduler privilege escalation (for the 1.x versions), while MS10-092 assigns CVE-2010-3338 [2] [24]. NVD's CVE-2010-3338 record notes it might overlap CVE-2010-3888, and NVD's CVE-2010-3888 record says Stuxnet exploited it in July 2010 [28] (**Confirmed**). This study uses CVE-2010-3338, the identifier on Microsoft's bulletin, and treats CVE-2010-3888 as the overlapping record.

## Part 2: the timeline

| Date | Event | Grade | Source |
|---|---|---|---|
| 3 Nov 2005 | Stuxnet 0.5 C&C server registration | Confirmed | [2] |
| May 2006 | Compile timestamp of the Stuxshop C&C module found by Chronicle researchers | Reported | [50] |
| 15 Nov 2007 | Stuxnet 0.5 submitted to a public scanning service (Langner says VirusTotal) | Confirmed | [2] [14] |
| 5 Dec 2007 | Flame component WAVESUP3.DRV first seen in Europe; UAE 28 Apr 2008; Iran 1 Mar 2010 | Confirmed | [11] |
| Jul 2008 | Equation's Fanny worm presumably compiled; first blocked by Kaspersky in Dec 2008; it used the LNK exploit and the MS09-025 flaw before Stuxnet did | Confirmed | [6] [7] |
| 23 Oct 2008 | MS08-067 published | Confirmed | [25] |
| Nov 2008 | Some Stuxnet components in use, per ATT&CK | Confirmed | [30] |
| 20 Nov 2008 | Trojan.Zlob variant found using the LNK vulnerability | Confirmed | [1] |
| 11 Jan 2009 | Stuxnet 0.5 programmed to stop contacting its C&C after this date | Confirmed | [2] |
| Apr 2009 | Hakin9 publishes the Print Spooler remote code execution later fixed by MS10-061 | Confirmed | [1] |
| Jun 2009 | Earliest 1.x sample: no LNK exploit, no signed drivers | Confirmed | [1] |
| 23 Jun 2009 | First initial infection (Domain A), 12 hours after compile | Confirmed | [1] |
| 4 Jul 2009 | Stuxnet 0.5 programmed to stop spreading | Confirmed | [2] |
| 7 or 19 Jul 2009 | Fourth initial infection, Domain D: 19 July per Symantec; 7 July per Kaspersky, which identifies the victim with high confidence as Control-Gostar Jahed | Confirmed (discrepancy) | [1] [5] |
| 2 Nov 2009 | IAEA: UF6 fed into all 18 cascades of Unit A24 and 6 cascades of Unit A26; 3,936 centrifuges fed and 4,756 more installed | Confirmed | [35] |
| 25 Jan 2010 | Stuxnet driver signed with a valid Realtek certificate | Confirmed | [1] |
| 29 and 31 Jan 2010 | IAEA: 8,610 centrifuges installed at FEP, 3,772 fed; centrifuges from the remaining 11 cascades of Unit A26 disconnected; no cause given | Confirmed | [36] |
| Mar 2010 | First variant exploiting MS10-046; Kaspersky says the March 2010 Behpajooh infection led to the global spread | Confirmed | [1] [5] |
| 13 May 2010 | Last of the 10 initial infections | Confirmed | [1] |
| Jun 2010 | Realtek signing certificate expires | Confirmed | [16] |
| 17 Jun 2010 | VirusBlokAda reports the threat (as RootkitTmphider) [1]; its specialists found two new samples with Realtek-signed drivers that day, as Krebs reported on 15 July [52] | Confirmed / Reported | [1] [52] |
| 10 Jul 2010 | CERT/CC "Date Public" for the LNK flaw | Confirmed | [19] |
| 13 Jul 2010 | Symantec adds detection W32.Temphid | Confirmed | [1] |
| 15 Jul 2010 | CERT/CC publishes VU#940193: the LNK flaw is used to spread malware targeting control systems; Krebs reports the drivers and the WinCC focus | Confirmed / Reported | [19] [52] |
| 16 Jul 2010 | Microsoft Security Advisory 2286198; VeriSign revokes the Realtek certificate (17 July per ESET) | Confirmed | [21] [1] [3] |
| 17 Jul 2010 | ESET finds a driver signed with a JMicron certificate | Confirmed | [1] |
| 18 Jul 2010 | Proof-of-concept code for the LNK zero-day released publicly | Confirmed | [16] |
| 19 Jul 2010 | Symantec renames detection to W32.Stuxnet | Confirmed | [1] |
| 20 Jul 2010 | Symantec begins monitoring Stuxnet C&C traffic | Confirmed | [1] |
| 22 Jul 2010 | VeriSign revokes the JMicron certificate; NVD publishes CVE-2010-2772 | Confirmed | [1] [28] |
| 2 Aug 2010 | MS10-046 published; advisory 2286198 updated to v2.0 | Confirmed | [20] [21] |
| 6 Aug 2010 | Symantec reports that Stuxnet injects and hides code on a PLC | Confirmed | [1] |
| 22 Aug 2010 | Iran stops reporting new infections to the sinkhole, most likely because outbound C&C was blocked | Confirmed | [1] |
| 7 Sep 2010 | Siemens reports 15 infections worldwide, none with an adverse impact on the automation system | Confirmed | [17] |
| 14 Sep 2010 | MS10-061 published | Confirmed | [22] |
| 22 Sep 2010 | Siemens update: 15 plant cases since mid-July, about one third in Germany, no production impact known | Reported | [53] |
| 27 Sep 2010 | Bushehr: Iranian officials say staff computers were infected; plant head Mahmoud Jafari says major systems were not damaged | Reported | [40] |
| 29 Sep 2010 | About 100,000 infected hosts, more than 40,000 external IPs in over 155 countries, about 60 percent of hosts in Iran | Confirmed | [1] |
| Sep 2010 | ICS-CERT primary Stuxnet advisory ICSA-10-272-01 (the alert code points to day 272 of 2010) | Confirmed | [15] |
| 12 Oct 2010 | MS10-073 published | Confirmed | [23] |
| 5 to 22 Nov 2010 | IAEA: 29 cascades fed on 5 Nov; none fed on 16 Nov; 28 fed on 22 Nov; no reason given | Confirmed | [38] |
| Mid-Nov 2010 | Iran's nuclear chief Ali Akbar Salehi says the virus "has faced a dead end" | Reported | [41] |
| 14 Dec 2010 | MS10-092 published | Confirmed | [24] |
| 22 Dec 2010 | ISIS calls Stuxnet a reasonable explanation for damage to about 1,000 IR-1 centrifuges, with questions remaining | Confirmed (as ISIS analysis) | [39] |
| 15 to 17 Jan 2011 | New York Times report, relayed by CSM, of testing at Dimona in a joint Israeli-American effort | Reported | [42] |
| Feb 2011 | Symantec W32.Stuxnet Dossier v1.4; farewell video for IDF chief Gabi Ashkenazi reportedly refers to Stuxnet | Confirmed / Reported | [1] [46] |
| 2011 | US Deputy Defense Secretary William Lynn declines to say whether the US was involved | Reported | [44] |
| 16 Apr 2011 | Iran's Passive Defense chief Gholam-Reza Jalali blames Siemens, the US and Israel | Reported | [43] |
| 14 Oct 2011 | CrySyS Duqu report v0.93: Stuxnet code massively reused | Confirmed | [12] |
| 18 Oct 2011 | Symantec W32.Duqu v1.0: same authors as Stuxnet or people with its source | Confirmed | [13] |
| 3 Nov 2011 | Microsoft Security Advisory 2639658 (TrueType, CVE-2011-3402, used by Duqu); fixed by MS11-087 on 13 Dec 2011 | Confirmed | [26] [28] |
| 4 Mar 2012 | 60 Minutes: Michael Hayden calls Stuxnet a good idea and declines to speculate on authorship | Confirmed (as interview record) | [45] |
| 28 May 2012 | Kaspersky's first Flame Q&A: no major similarity with Stuxnet/Duqu | Confirmed | [8] |
| 31 May 2012 | CrySyS sKyWIper report: plausibly a different developer team from Duqu/Stuxnet | Confirmed | [11] |
| 1 Jun 2012 | New York Times "Olympic Games" account, relayed by the Guardian | Reported | [44] |
| 3 Jun 2012 | Microsoft advisory 2718704 revokes Enforced Licensing intermediate CAs used in active attacks (the advisory does not name Flame) | Confirmed; Flame link Inferred | [27] |
| 11 Jun 2012 | Kaspersky: resource 207 is the missing link between Flame and Stuxnet | Confirmed | [4] |
| 24 Jun 2012 | Coded infection stop date for Stuxnet 1.x | Confirmed | [1] [2] |
| 9 Aug 2012 | Kaspersky Gauss report: built on the Flame platform | Confirmed | [9] |
| 26 Feb 2013 | Symantec "Stuxnet 0.5: The Missing Link" | Confirmed | [2] |
| Mar 2013 | Tallinn Manual experts treat Stuxnet as an act of force, without agreement on armed attack | Reported | [51] |
| 19 Nov 2013 | Langner's "Stuxnet's Secret Twin" | Confirmed | [14] |
| 11 Nov 2014 | Kaspersky "Stuxnet: Zero victims" names the first Iranian victims | Confirmed | [5] |
| 16 Feb 2015 | Kaspersky Equation report | Confirmed | [6] |
| 10 Jun 2015 | Kaspersky Duqu 2.0 report | Confirmed | [10] |
| 17 Oct 2016 | Retired Gen. James Cartwright pleads guilty to false statements in a leak investigation | Confirmed | [47] |
| 17 Jan 2017 | Cartwright pardoned | Confirmed | [48] |
| 9 Apr 2019 | Chronicle's Stuxshop and GOSSIPGIRL research, as reported by SecurityWeek | Reported | [50] |
| 2 Sep 2019 | Yahoo News reports a Dutch intelligence mole delivered Stuxnet by USB in 2007 | Reported | [49] |
| 15 Sep 2022 | CVE-2010-2568 added to CISA KEV | Confirmed | [29] |
| 6 Oct 2025 | CVE-2011-3402 (Duqu) added to CISA KEV | Confirmed | [28] [29] |
| 24 Apr 2026 | ATT&CK S0603 last modified (v1.5) | Confirmed | [30] |
| 20 May 2026 | CVE-2008-4250 (MS08-067) added to CISA KEV | Confirmed | [29] |

Symantec cautions that its timing data could be off because of time zones or wrongly set system clocks [1].

## Part 3: attribution and policy

### 3.1 What the analysts said

Symantec traced about 12,000 infections back to 10 initial infections at five organizations, all with a presence in Iran, in waves of June 2009, July 2009, March 2010, April 2010 and May 2010 [1] (**Confirmed**). It said the concentration in Iran likely made Iran the initial target [1]. It discussed the `b:\myrtus\src\objfre_w2k_x86\i386\guava.pdb` build path and the `19790509` marker, and twice cautioned against "drawing any attribution conclusions" from them [1] (**Confirmed**). Kaspersky later named the first victims as Iranian industrial automation firms, including Foolad Technic Engineering Co in Isfahan and Behpajooh [5] (**Confirmed**).

Kaspersky's Equation research found that the Fanny worm used two exploits before Stuxnet did, and judged that Equation and the Stuxnet developers are "either the same or working closely together", adding that Equation malware may have delivered the Stuxnet payload [7] (**Confirmed** as a vendor assessment, not a government attribution). Its Securelist report says Equation interacted with the Stuxnet and Flame groups from a position of superiority [6]. ATT&CK records no relationship between the Equation group (`G0020`) and Stuxnet in either direction [30] [31] (**Confirmed**). Chronicle researchers proposed a "supra threat actor", GOSSIPGIRL, grouping Equation, Flame, Duqu and a Flowershop-linked fourth team [50] (**Reported**).

### 3.2 What the press reported

All of the following are **Reported**: they rest on journalism citing anonymous officials, and the New York Times originals were not opened for this study.

- As relayed by the Christian Science Monitor in January 2011, the New York Times reported that a Stuxnet worm tested at Israel's Dimona complex, in a joint Israeli-American effort, wiped out about a fifth of Iran's centrifuges [42].
- As relayed by the Guardian on 1 June 2012, David Sanger's New York Times account said President Bush launched a program called Olympic Games and President Obama accelerated it; after the 2010 escape Obama chose to continue, Natanz was hit twice more and up to 1,000 centrifuges were damaged, and US sources blamed an Israeli modification for the escape [44].
- Yahoo News (Kim Zetter and Huib Modderkolk, 2 September 2019), citing four intelligence sources, reported that the CIA and Mossad asked the Dutch AIVD for help in 2004 and that an Iranian engineer recruited by AIVD supplied Natanz data and delivered Stuxnet by USB in 2007; it describes Olympic Games as primarily a joint US-Israel mission with Dutch and German participation, France believed to be the third partner, and a role for U.K. intelligence [49].
- The Jewish Chronicle reported in February 2011 that a farewell video for IDF chief Gabi Ashkenazi included a scene referring to Stuxnet, with no further detail [46].

### 3.3 The official record

No official acknowledgement of Stuxnet by the US or Israeli government appeared in any source opened for this study (**Inferred**, an absence of evidence from a search that was not exhaustive).

- In 2011 US Deputy Defense Secretary William Lynn said the question was "not something that we're going to be able to answer" [44] (**Reported**).
- On 60 Minutes in March 2012, former NSA and CIA director Michael Hayden called Stuxnet "a good idea" and said a cyberweapon had been used to cause physical destruction. When the interviewer said the capability and motive left the United States and Israel, Hayden said "Well, yes" and then declined to speculate [45] (**Confirmed** as the interview record; not an attribution by Hayden).
- Retired General James Cartwright, Vice Chairman of the Joint Chiefs from 2007 to 2011, pleaded guilty on 17 October 2016 to making false statements to FBI agents in a leak investigation; the Justice Department release says he gave classified information to two reporters between January and June 2012, some of which appeared in a book [47] (**Confirmed**). President Obama pardoned him on 17 January 2017 [48] (**Confirmed**). Neither document names Stuxnet or Iran; the Stuxnet connection comes from press coverage only.

Iranian officials did speak on the record, as relayed by the press. Iranian authorities blamed foreign enemies and cited about 30,000 infected IP addresses, while the Bushehr plant head said "major systems of the plant have not been damaged" [40] (**Reported**). Ali Akbar Salehi said in November 2010 that the virus had "faced a dead end" [41] (**Reported**). In April 2011 Gholam-Reza Jalali said Siemens should explain how it gave the enemy SCADA code information and that the worm "had been disseminated from sources in the U.S. and Israel" [43] (**Reported**).

### 3.4 What happened at Natanz

The IAEA's Board reports record cascade states, not causes [35] [36] [37] [38] (**Confirmed**):

| Report | Date in report | What it records |
|---|---|---|
| GOV/2009/74 | 2 Nov 2009 | UF6 fed into all 18 cascades of Unit A24 and 6 cascades of Unit A26; 3,936 centrifuges fed and 4,756 more installed (8,692 in all, the study's own sum) |
| GOV/2010/10 | 29 and 31 Jan 2010 | 8,610 centrifuges installed and 3,772 fed; centrifuges from the remaining 11 cascades of Unit A26 disconnected |
| GOV/2010/62 | 5 to 22 Nov 2010 | 54 cascades (8,426 centrifuges) installed in Production Hall A and 29 (4,816) fed; six cascades modified to 174 centrifuges; none fed on 16 Nov; Iran reported 28 fed on 22 Nov |

A full-text search of GOV/2009/74, GOV/2010/10, GOV/2010/46 and GOV/2010/62 found no use of the words Stuxnet, cyber or malware, and none of them assigns a cause to the centrifuge changes [35] [36] [37] [38] (**Confirmed**, a negative finding). ISIS (Albright, Brannan and Walrond) read the series as Iran decommissioning and replacing about 1,000 IR-1 centrifuges in late 2009 or early 2010, and concluded that Stuxnet is a reasonable explanation but that questions remain [39]. The 1,000 figure is ISIS's inference from the cascade data, not an IAEA statement (**Reported** as a causal claim).

### 3.5 Law and norms

As reported by SecurityWeek, the experts behind the Tallinn Manual treated Stuxnet as an act of force but could not agree whether it was an armed attack [51] (**Reported**; the manual itself was not opened).

### 3.6 The family: Duqu, Flame, Gauss and Duqu 2.0

- **Duqu (2011).** CrySyS called it Stuxnet-like and found Stuxnet code massively reused, with a driver signed by another Taiwanese hardware maker [12]. Symantec said it was written by the Stuxnet authors or by people with the source code, first recorded attacking in early April 2011 with compile times from November 2010 [13]. Duqu used CVE-2011-3402 in the wild in November 2011 [28] (**Confirmed**).
- **Flame (2012).** Kaspersky first saw no major similarities and called it a parallel project in the wild by February to March 2010, found while searching for Wiper at the ITU's request [8]. CrySyS judged it plausibly the work of a different team, without excluding separate teams working to the same requirements [11]. On 11 June 2012 Kaspersky revised its view after finding the Flame module inside Stuxnet's resource 207 [4] (**Confirmed**). Microsoft's advisory 2718704 of 3 June 2012 revoked Enforced Licensing intermediate CAs whose certificates were used in active attacks; the advisory does not name Flame, so linking it to Flame is **Inferred** [27].
- **Gauss (2012).** Kaspersky says Gauss came from the same "factory" as Flame and was built on the Flame platform, with first infections in September to October 2011, most of them in Lebanon, and C&C offline from mid-July 2012. It places Gauss in the same pool of projects as Stuxnet, Flame and Duqu, without claiming a shared team with Stuxnet [9] (**Confirmed**).
- **Duqu 2.0 (2015).** Kaspersky describes an updated version of the 2011 Duqu, sometimes called the stepbrother of Stuxnet, found in Kaspersky's own network, with some infections linked to P5+1 negotiation venues [10] (**Confirmed**).

## Part 4: the defender view and legacy

### 4.1 The air gap is a control, not a guarantee

Symantec's own attack scenario assumes the final hop to an isolated Field PG was covered by removable drives, because operators commonly program control systems from non-networked Windows machines and exchange data on removable drives [1] (**Confirmed** as Symantec's reasoning, labelled speculation). NIST SP 800-82r3 now says, as OT connects to IT, relying on traditional measures such as air gaps "is not enough", and lists Stuxnet among its OT incident examples [54] (**Confirmed**). Dragos's 2017 CRASHOVERRIDE analysis warns against treating a strong perimeter or air-gapped network as a silver bullet and says "Human defenders are required" [55] (**Confirmed**).

The guidance moved from disabling USB drives and patching in 2010 [17] to treating isolation as insufficient on its own by 2017 to 2023 [54] [55]. No single source states that arc; it is the study's synthesis (**Inferred**).

### 4.2 Removable media

In 2010 ICS-CERT told owners to apply the Microsoft LNK workarounds, disable AutoRun, be careful with USB drives, run with least privilege, keep antivirus current, and apply Siemens' SIMATIC security update after consulting the vendor and testing [16] (**Confirmed**). A later update told owners to review policies and put technical measures in place to disable USB drives, apply MS10-046 under Siemens guidance, consider MS08-067 and review MS10-061 [17] (**Confirmed**). Today NIST says no unauthorized removable media should be permitted on any OT node, and that laptops and USB storage should be scanned before they connect [54] (**Confirmed**). In the library's data, ICS `T0847` maps to the ATT&CK mitigations `M0928`, `M0934` and `M0942`, and the D3FEND pages for IO Port Restriction and Hardware Component Inventory list both `T0847` and `T1091` as countered [61] (**Confirmed**).

### 4.3 Signed is not safe

Stuxnet's drivers carried signatures from two compromised certificates (Realtek, then JMicron) [1] [16]. Twelve years later, the joint DOE, CISA, NSA and FBI advisory AA22-103A described APT actors who can compromise Windows engineering workstations through a known-vulnerable but legitimately signed ASRock driver (`AsrDrv103.sys`, CVE-2020-15368), and recommended Device Guard, Credential Guard and Hypervisor Code Integrity on management systems and monitoring for unusual driver loads [57] (**Confirmed**). The advisory does not use the name PIPEDREAM itself; that name appears in the Dragos blog it lists under resources. One case used stolen keys and the other a signed but vulnerable driver; both defeat the assumption that signed means safe (**Inferred**).

### 4.4 Do not trust the readback

Because the PLC rootkit sat in the engineering workstation's PLC communication library, reading logic back through that workstation could not be trusted to reveal tampering [1] (**Inferred** from Confirmed mechanism; Symantec states the facts, not the guidance). ICS-CERT's indicators make the same point concretely: a malicious `s7otbxdx.dll` with the original renamed `s7otbxsx.dll`, plus `mrxcls.sys`, `mrxnet.sys` and `.sav` files in `GraCS` project folders [15] (**Confirmed**). The controls that answer this are out-of-band: NIST says PLCs with key switches should sit in run or remote mode with the key removed and managed, so programming changes need physical access [54], and AA22-103A recommends known-good offline backups with hashing and integrity checks on firmware and controller configuration files [57] (**Confirmed**).

### 4.5 Hard-coded credentials

The WinCC database password (CVE-2010-2772, CWE-798) was both a propagation route and a foothold in the control software [1] [28]. ATT&CK maps it to Enterprise `T1078.001` Default Accounts and ICS `T1694.002` Hardcoded Credentials, and the library's CAPEC-70 page relates to CWE-798 [30] [61] (**Confirmed**). The first question to ask of any control-system product is still which credentials ship in it.

### 4.6 Patch the Windows layer

Every Windows exploit Stuxnet used had a Microsoft fix by 14 December 2010 [20] [22] [23] [24] [25]. CVE-2010-2568 entered CISA KEV on 15 September 2022 and CVE-2008-4250 on 20 May 2026 [29] (**Confirmed**), which is a reminder that old bugs on old engineering workstations stay exploitable for as long as the machines run.

### 4.7 The lineage: CRASHOVERRIDE, TRITON and PIPEDREAM

| Year | Malware | What the primary says about Stuxnet's legacy | Source |
|---|---|---|---|
| 2016 | Industroyer / CRASHOVERRIDE | NIST calls Industroyer (17 December 2016, about one hour of outage at one substation) the first known malware specifically designed to attack the power grid [54]. Dragos says Stuxnet's tradecraft was detailed process knowledge but was Siemens-specific and unique to Natanz, so not reasonable to repurpose; CRASHOVERRIDE codified process knowledge in a reusable framework [55]. US-CERT TA17-163A recommended application allowlisting, command authentication on field devices, separate credentials, gold-image backups, ICS isolation, data diodes, time-limited remote access and monitoring inside the control LAN, without mentioning Stuxnet [56]. | [54] [55] [56] (**Confirmed**) |
| 2017 | TRITON / HatMan | Mandiant says TRITON follows Stuxnet and Industroyer in being able to stop safety mechanisms, and recommends segregating safety networks, keeping Triconex keys out of PROGRAM mode, auditing key state, unidirectional gateways, allowlisting and ICS traffic monitoring [58]. DHS says HatMan surpasses both forerunners by compromising a safety system, that its implant accepts commands regardless of key switch position, and that defence in depth is the best mitigation [60]. NIST records that the 2017 Saudi petrochemical SIS shut down safely when its triple-redundant processors found mismatched code [54]. | [54] [58] [60] (**Confirmed**) |
| 2022 | INCONTROLLER / PIPEDREAM | Mandiant calls INCONTROLLER comparable to TRITON, INDUSTROYER and STUXNET and very likely state sponsored, and recommends behavior-based hunting, IT/OT segmentation, allowlisting, ICS-aware intrusion prevention and OPC UA audit logging [59]. AA22-103A recommends ICS isolation, MFA for remote access, OPC UA authentication and trust lists, limiting ICS connections to approved management and engineering workstations, and continuous OT monitoring, without mentioning Stuxnet [57]. | [57] [59] (**Confirmed**) |

### 4.8 Detection lessons as the sources state them

- ICS-CERT found the malware checks for antivirus and may disable it, so owners should verify that antivirus is still active on suspected systems, and should consult their antivirus and control-system vendors before scanning control systems [16] (**Confirmed**).
- Dragos recommends baselining IEC 104, IEC 61850 and DNP3 use, watching OPC scanning, keeping offline tested backups of project logic and IED configurations, and running table-top exercises with manual operations; it says behavioral network analytics give the highest capability to detect such threats [55] (**Confirmed**).
- The HatMan report says its YARA rule is not reliable on its own, because the files may be absent and it cannot run on the controller, and that passive network anomaly vendors added HatMan traffic detection as an early warning [60] (**Confirmed**).

### 4.9 Library corrections

| Page | What it says now | What the record supports | Grade |
|---|---|---|---|
| `MALWARE_FAMILIES.md` | Stuxnet row: "Equation Group (attributed US NSA / Israel Unit 8200)" | Kaspersky says Equation worked with or was the same as the Stuxnet developers, as a vendor assessment [6] [7]; ATT&CK links no group to S0603 [30] [31]; no source opened here names Unit 8200 | Inferred (correction needed) |
| `NOTABLE_INCIDENTS.md` | Attribution "not officially confirmed until 2011 leaks" | No official confirmation at any date in the sources opened here; press reports citing unnamed sources began with the New York Times in January 2011 [42], and the fullest 'Olympic Games' account came in June 2012 [44] | Inferred (correction needed) |
| `ICS_OT_SECURITY_REFERENCE.md`, Stuxnet section | Lists `T0862` Supply Chain Compromise and `T1693.001` System Firmware, and describes `T0849` Masquerading as sensor-reading replay | Neither `T0862` nor `T1693.001` is on S0603; ATT&CK maps the replay to `T0832` Manipulation of View, the DLL rename to `T0849`, and the PLC rootkit to `T0851` [30] | Confirmed |

## Part 5: MITRE mappings

This Part binds the verified record to MITRE ATT&CK v20.0, ATT&CK for ICS, CAPEC, CWE and D3FEND. Every identifier below was checked against the live ATT&CK page for S0603 [30] or the library's own data files [61]; identifiers that could not be checked are left out.

### 5.1 Objects

| Object | ATT&CK id | Library page | Relationship to Stuxnet |
|---|---|---|---|
| Stuxnet | `S0603` | [/mitre/software/S0603.md](/mitre/software/S0603.md) | The software object itself: v1.5, 44 Enterprise and 25 ICS technique rows, no associated group, no campaign [30] |
| Group | none | none | ATT&CK links no group to S0603, so no `G####` id applies [30] |
| Campaign | none | none | ATT&CK lists no Stuxnet campaign, so no `C####` id applies [30] [61] |
| Equation | `G0020` | [/mitre/groups/G0020.md](/mitre/groups/G0020.md) | Not an ATT&CK relationship: the G0020 page does not mention Stuxnet and lists no software [31]. Listed here only because the vendor record discusses it (Part 3.1) |
| Flame | `S0143` | [/mitre/software/S0143.md](/mitre/software/S0143.md) | Related family per Kaspersky and CrySyS [4] [11]; not an ATT&CK relationship |
| Duqu | `S0038` | [/mitre/software/S0038.md](/mitre/software/S0038.md) | Related family per CrySyS and Symantec [12] [13]; not an ATT&CK relationship |
| Industroyer | `S0604` | [/mitre/software/S0604.md](/mitre/software/S0604.md) | Later ICS malware compared to Stuxnet (Part 4.7) |
| 2016 Ukraine Electric Power Attack | `C0025` | [/mitre/campaigns/C0025.md](/mitre/campaigns/C0025.md) | The Industroyer campaign (Part 4.7) |
| Triton Safety Instrumented System Attack | `C0030` | [/mitre/campaigns/C0030.md](/mitre/campaigns/C0030.md) | The TRITON campaign (Part 4.7); the Triton software `S1009` and INCONTROLLER `S1045` are in the library's ICS data but have no library page [61] |

### 5.2 ATT&CK Enterprise techniques (44)

Every row is a technique ATT&CK v20.0 lists on S0603, citing the Symantec W32.Stuxnet Dossier v1.4 [30] [1]. The library's `data/attack/software_to_technique.jsonl` holds the same 44 ids [61]. Tactics come from `data/attack/technique_profiles.jsonl`. The event column dates the behavior from the verified record; where no finer date is supported it gives the variants Symantec analysed (June 2009 to April 2010).

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1134.001`](/mitre/techniques/T1134-001.md) | Access Token Manipulation: Token Impersonation/Theft | Stealth, Privilege Escalation | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1087.001`](/mitre/techniques/T1087-001.md) | Account Discovery: Local Account | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1087.002`](/mitre/techniques/T1087-002.md) | Account Discovery: Domain Account | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1071.001`](/mitre/techniques/T1071-001.md) | Application Layer Protocol: Web Protocols | Command and Control | HTTP C2 on port 80; traffic monitored by Symantec from 2010-07-20 | [30] [1] |
| [`T1560.003`](/mitre/techniques/T1560-003.md) | Archive Collected Data: Archive via Custom Method | Collection | C2 payload encryption; traffic monitored from 2010-07-20 | [30] [1] |
| [`T1543.003`](/mitre/techniques/T1543-003.md) | Create or Modify System Process: Windows Service | Persistence, Privilege Escalation | Installation: MrxCls.sys boot-start service, 2010 variants | [30] [1] |
| [`T1132.001`](/mitre/techniques/T1132-001.md) | Data Encoding: Standard Encoding | Command and Control | Hex-encoded index.php?data= parameter; traffic monitored from 2010-07-20 | [30] [1] |
| [`T1140`](/mitre/techniques/T1140.md) | Deobfuscate/Decode Files or Information | Stealth | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1685`](/mitre/techniques/T1685.md) | Disable or Modify Tools | Defense Impairment | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1573.001`](/mitre/techniques/T1573-001.md) | Encrypted Channel: Symmetric Cryptography | Command and Control | XOR-encrypted C2; traffic monitored from 2010-07-20 | [30] [1] |
| [`T1480`](/mitre/techniques/T1480.md) | Execution Guardrails | Stealth | Configured guardrails, including the 2012-06-24 stop date | [30] [1] |
| [`T1041`](/mitre/techniques/T1041.md) | Exfiltration Over C2 Channel | Exfiltration | Victim data sent over the HTTP C2; traffic monitored from 2010-07-20 | [30] [1] |
| [`T1068`](/mitre/techniques/T1068.md) | Exploitation for Privilege Escalation | Privilege Escalation | 2010 variants: MS10-073 (fixed 2010-10-12) and the Task Scheduler flaw (fixed 2010-12-14) | [30] [1] [3] [23] [24] |
| [`T1210`](/mitre/techniques/T1210.md) | Exploitation of Remote Services | Lateral Movement | 2010 variants: MS10-061 (fixed 2010-09-14) and MS08-067 (fixed 2008-10-23) | [30] [1] [15] [22] [25] |
| [`T1008`](/mitre/techniques/T1008.md) | Fallback Channels | Command and Control | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1083`](/mitre/techniques/T1083.md) | File and Directory Discovery | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1070`](/mitre/techniques/T1070.md) | Indicator Removal | Stealth | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1070.004`](/mitre/techniques/T1070-004.md) | Indicator Removal: File Deletion | Stealth | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1070.006`](/mitre/techniques/T1070-006.md) | Indicator Removal: Timestomp | Stealth | Installation: driver times matched to system files, 2010 variants | [30] [1] |
| [`T1570`](/mitre/techniques/T1570.md) | Lateral Tool Transfer | Lateral Movement | P2P updates over RPC, 2010 variants | [30] [1] [15] |
| [`T1112`](/mitre/techniques/T1112.md) | Modify Registry | Defense Impairment, Persistence | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1106`](/mitre/techniques/T1106.md) | Native API | Execution | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1135`](/mitre/techniques/T1135.md) | Network Share Discovery | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1027.013`](/mitre/techniques/T1027-013.md) | Obfuscated Files or Information: Encrypted/Encoded File | Stealth | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1120`](/mitre/techniques/T1120.md) | Peripheral Device Discovery | Discovery | Removable-drive enumeration for infection, 2009 and 2010 variants | [30] [1] |
| [`T1055.001`](/mitre/techniques/T1055-001.md) | Process Injection: Dynamic-link Library Injection | Stealth, Privilege Escalation | Installation: payload injected into services.exe and Step 7 processes | [30] [1] |
| [`T1090.001`](/mitre/techniques/T1090-001.md) | Proxy: Internal Proxy | Command and Control | P2P updates over RPC, 2010 variants | [30] [1] [15] |
| [`T1012`](/mitre/techniques/T1012.md) | Query Registry | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1021`](/mitre/techniques/T1021.md) | Remote Services | Lateral Movement | P2P updates over RPC, 2010 variants | [30] [1] [15] |
| [`T1021.002`](/mitre/techniques/T1021-002.md) | Remote Services: SMB/Windows Admin Shares | Lateral Movement | Network-share spread, 2010 variants | [30] [1] [15] |
| [`T1091`](/mitre/techniques/T1091.md) | Replication Through Removable Media | Lateral Movement, Initial Access | autorun.inf in the June 2009 variant; LNK flaw CVE-2010-2568 from March 2010 | [30] [1] [20] |
| [`T1014`](/mitre/techniques/T1014.md) | Rootkit | Stealth | Installation: MrxNet.sys hides .LNK and ~WTR files, 2010 variants | [30] [1] |
| [`T1053.005`](/mitre/techniques/T1053-005.md) | Scheduled Task/Job: Scheduled Task | Execution, Persistence, Privilege Escalation | Network-share spread: job runs two minutes after infection, 2010 variants | [30] [1] |
| [`T1505.001`](/mitre/techniques/T1505-001.md) | Server Software Component: SQL Stored Procedures | Persistence | WinCC database infection, 2010 variants | [30] [1] |
| [`T1129`](/mitre/techniques/T1129.md) | Shared Modules | Execution | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1518.001`](/mitre/techniques/T1518-001.md) | Software Discovery: Security Software Discovery | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1553.002`](/mitre/techniques/T1553-002.md) | Subvert Trust Controls: Code Signing | Defense Impairment | Driver signed 2010-01-25 with a compromised Realtek certificate; revoked July 2010 | [30] [1] [3] [16] |
| [`T1082`](/mitre/techniques/T1082.md) | System Information Discovery | Discovery | Host profile sent to C2, including S7P project paths | [30] [1] |
| [`T1016`](/mitre/techniques/T1016.md) | System Network Configuration Discovery | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1124`](/mitre/techniques/T1124.md) | System Time Discovery | Discovery | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1080`](/mitre/techniques/T1080.md) | Taint Shared Content | Lateral Movement | Network shares and WinCC database views, 2010 variants | [30] [1] [15] |
| [`T1078.001`](/mitre/techniques/T1078-001.md) | Valid Accounts: Default Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | WinCC database password, used in the wild by July 2010 (CVE-2010-2772) | [30] [1] [28] |
| [`T1078.002`](/mitre/techniques/T1078-002.md) | Valid Accounts: Domain Accounts | Stealth, Persistence, Privilege Escalation, Initial Access | Variants of June 2009 to April 2010, analysed in the Symantec dossier (Feb 2011) | [30] [1] |
| [`T1047`](/mitre/techniques/T1047.md) | Windows Management Instrumentation | Execution | Network-share spread through WMI, 2010 variants | [30] [1] |

### 5.3 ATT&CK for ICS techniques (25)

Every row is an ATT&CK for ICS technique ATT&CK v20.0 lists on S0603 [30]; all 25 ids are in the library's `data/attack/ics/technique_profiles.jsonl`, which supplies the tactics [61]. The library has no generated per-technique ICS pages, so ids link to attack.mitre.org; the library's [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md) groups them by tactic. Two ids postdate older write-ups: `T1694.002` (added in ATT&CK v19) replaces the revoked `T0891` (per `data/attack/superseded_by.jsonl` and `technique_releases.jsonl`), so write-ups that use `T0891` are stale; and `T1701.002`, the ICS Windows Command Shell sub-technique, was added in v20. ATT&CK cites Ralph Langner's 2013 paper "To Kill a Centrifuge" for `T0832` and `T0847`, and only that paper for `T0851`; its cited URL no longer serves the paper, so this study sources the `T0851` behavior from the Symantec dossier, which describes the same rootkit [1].

| ID | Name | Tactic(s) | Dated event or report | Sources |
|---|---|---|---|---|
| [`T1701.002`](https://attack.mitre.org/techniques/T1701/002/) | Command and Scripting Interpreter: Windows Command Shell | Execution | WinCC database spread: xp_cmdshell and extrac32 | [30] [1] |
| [`T0885`](https://attack.mitre.org/techniques/T0885/) | Commonly Used Port | Command and Control | C2 on port 80; traffic monitored from 2010-07-20 | [30] [1] |
| [`T0866`](https://attack.mitre.org/techniques/T0866/) | Exploitation of Remote Services | Initial Access, Lateral Movement | WinCC database spread, in the wild by July 2010 | [30] [1] [28] |
| [`T0874`](https://attack.mitre.org/techniques/T0874/) | Hooking | Execution, Privilege Escalation | Step 7 project infection: hooks in s7tgtopx.exe and ccprojectmgr.exe | [30] [1] |
| [`T0877`](https://attack.mitre.org/techniques/T0877/) | I/O Image | Collection | 21-second recording of the input area (S7-417 sequence C) | [30] [1] [14] |
| [`T1694.002`](https://attack.mitre.org/techniques/T1694/002/) | Insecure Credentials: Hardcoded Credentials | Persistence, Lateral Movement | WinCC hard-coded database password (CVE-2010-2772), July 2010 | [30] [1] [28] |
| [`T0867`](https://attack.mitre.org/techniques/T0867/) | Lateral Tool Transfer | Lateral Movement | WinCC database spread: DLL inserted as a hex string | [30] [1] |
| [`T0835`](https://attack.mitre.org/techniques/T0835/) | Manipulate I/O Image | Inhibit Response Function | S7-417 sequence C intercepts peripheral output | [30] [1] |
| [`T0831`](https://attack.mitre.org/techniques/T0831/) | Manipulation of Control | Impact | S7-315 rotor-speed sabotage; S7-417 valve closing in 0.5 | [30] [1] [2] [14] |
| [`T0832`](https://attack.mitre.org/techniques/T0832/) | Manipulation of View | Impact | Recorded values replayed to operators during sabotage | [30] [1] [14] |
| [`T0849`](https://attack.mitre.org/techniques/T0849/) | Masquerading | Evasion | Original s7otbxdx.dll renamed s7otbxsx.dll and replaced | [30] [1] [15] |
| [`T0821`](https://attack.mitre.org/techniques/T0821/) | Modify Controller Tasking | Execution | OB1 and OB35 infected on the S7-315 | [30] [1] |
| [`T0836`](https://attack.mitre.org/techniques/T0836/) | Modify Parameter | Impair Process Control | S7-315 drive frequencies set to 1410 Hz, 2 Hz and 1064 Hz | [30] [1] [14] |
| [`T0889`](https://attack.mitre.org/techniques/T0889/) | Modify Program | Persistence | Target-specific PLC code for sequences A, B and C | [30] [1] |
| [`T0801`](https://attack.mitre.org/techniques/T0801/) | Monitor Process State | Collection | S7-315 DP_RECV monitor judges the process state | [30] [1] |
| [`T0834`](https://attack.mitre.org/techniques/T0834/) | Native API | Execution | PLC system function blocks such as SFC1 | [30] [1] |
| [`T0842`](https://attack.mitre.org/techniques/T0842/) | Network Sniffing | Discovery | S7-315 DP_RECV monitor moved to FC1869 | [30] [1] |
| [`T0843`](https://attack.mitre.org/techniques/T0843/) | Program Download | Lateral Movement | Code and data blocks downloaded to the PLC | [30] [1] |
| [`T0873.001`](https://attack.mitre.org/techniques/T0873/001/) | Project File Infection: Siemens Project File Format | Persistence | Step 7 project infection (Simatic manager 5.3 and 5.4 SP4) | [30] [1] [15] |
| [`T0886`](https://attack.mitre.org/techniques/T0886/) | Remote Services | Initial Access, Lateral Movement | WinCC database spread, in the wild by July 2010 | [30] [1] [15] |
| [`T0888`](https://attack.mitre.org/techniques/T0888/) | Remote System Information Discovery | Discovery | S7-315 target checks (sequences A and B) | [30] [1] |
| [`T0847`](https://attack.mitre.org/techniques/T0847/) | Replication Through Removable Media | Initial Access | Removable drives from the June 2009 variant onward; 0.5 spread only through Step 7 archives | [30] [1] [2] [15] |
| [`T0851`](https://attack.mitre.org/techniques/T0851/) | Rootkit | Evasion, Inhibit Response Function | PLC rootkit in the fake s7otbxdx.dll (ATT&CK cites Langner 2013 only) | [30] [1] |
| [`T0869`](https://attack.mitre.org/techniques/T0869/) | Standard Application Layer Protocol | Command and Control | DB890 synchronization across S7-315 controllers | [30] [1] |
| [`T0863`](https://attack.mitre.org/techniques/T0863/) | User Execution | Execution | Step 7 project infection: the manager loads the dropped DLL | [30] [1] |

### 5.4 Vulnerabilities, CWE and CAPEC

| CVE | NVD CWE | CAPEC the library maps | ATT&CK technique on S0603 | Source |
|---|---|---|---|---|
| CVE-2010-2772 | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) Use of Hard-coded Credentials (CWE-798 lists CVE-2010-2772 as an observed example) | [CAPEC-70](/mitre/capec/CAPEC-70.md) Try Common or Default Usernames and Passwords; [CAPEC-191](/mitre/capec/CAPEC-191.md) (related to CWE-798 in `cwe.jsonl` [61]) | `T1078.001`; ICS `T1694.002` | [28] [30] [32] [33] [61] |
| CVE-2010-2568 | NVD-CWE-noinfo (KEV lists CWE-20) | [CAPEC-457](/mitre/capec/CAPEC-457.md) USB Memory Attacks (maps `T1091` and `T1092`) | `T1091`; ICS `T0847` | [28] [29] [30] [32] [61] |
| CVE-2010-2729 | CWE-20 | none mapped | `T1210` | [28] [30] |
| CVE-2008-4250 | CWE-94 (NVD); CWE-119 (CISA ADP enrichment) | none mapped | `T1210` | [28] [30] |
| CVE-2010-2743 | NVD-CWE-Other | none mapped | `T1068` | [28] [30] |
| CVE-2010-3338 | CWE-20 | none mapped | `T1068` | [28] [30] |

Patterns tied to techniques rather than to a CVE: [CAPEC-206](/mitre/capec/CAPEC-206.md) Signing Malicious Code [32] [61] and [CAPEC-68](/mitre/capec/CAPEC-68.md) Subvert Code-signing Facilities [61] both map `T1553.002` (the compromised Realtek and JMicron certificates), and [CAPEC-552](/mitre/capec/CAPEC-552.md) Install Rootkit maps `T1014` in the library's data [61] (**Confirmed**). The pairing of CVE-2010-2743 and CVE-2010-3338 to Stuxnet's MS10-073 and Task Scheduler exploits rests on the NVD descriptions and the Microsoft bulletins, because S0603 names bulletins rather than CVE ids for those two [28] [30]. No library CAPEC maps an ICS technique. See also the [CWE Reference](/CWE_REFERENCE.md) and [CAPEC Reference](/CAPEC_REFERENCE.md).

### 5.5 D3FEND countermeasures

The library's `data/attack/technique_to_d3fend.jsonl` maps these countermeasures to Stuxnet techniques; each has a library page [61] (**Confirmed**). The list is a selection of the closest fits, not every mapped countermeasure.

| D3FEND countermeasure | Stuxnet techniques it counters | Where it meets the record |
|---|---|---|
| [IO Port Restriction](/mitre/d3fend/io-port-restriction.md) | `T1091`, ICS `T0847` | Removable-drive spread (Part 1.3); D3FEND's own page maps it to both [34] |
| [Hardware Component Inventory](/mitre/d3fend/hardware-component-inventory.md) | `T1091`, ICS `T0847` | Knowing which removable devices exist |
| [Change Default Password](/mitre/d3fend/change-default-password.md) | `T1078.001` | The WinCC database password (Part 4.5) |
| [Service Binary Verification](/mitre/d3fend/service-binary-verification.md) | ICS `T0889`, `T0843` | Detecting changed PLC programs |
| [Restore Software](/mitre/d3fend/restore-software.md) | ICS `T0889`, `T0843` | Known-good offline program backups (Part 4.4) |
| [Message Authentication](/mitre/d3fend/message-authentication.md) | ICS `T0821`, `T0836`, `T0843`, `T0889` | Authenticated program downloads and parameter writes |
| [OT Variable Access Restriction](/mitre/d3fend/ot-variable-access-restriction.md) | ICS `T0836`, `T0877`, `T0835`, `T0801` | Limiting who can write drive parameters and read the I/O image |
| [Executable Allowlisting](/mitre/d3fend/executable-allowlisting.md) | ICS `T0863` | Blocking the infected Simatic manager DLLs |
| [System Call Filtering](/mitre/d3fend/system-call-filtering.md) | ICS `T0834`, `T0863`, Enterprise `T1106` | Restricting native calls |

The library has no D3FEND mapping for `T1553.002`, ICS `T0831`, `T0832`, `T0849`, `T0873.001`, `T1701.002` or `T1694.002`, and this study does not invent one. See the [D3FEND Reference](/D3FEND_REFERENCE.md).

### 5.6 ATLAS

MITRE ATLAS does not apply: Stuxnet involves no AI or machine-learning system, and the library's `data/ai/atlas_techniques.jsonl` has no Stuxnet entry [61] (**Inferred** for the first part; the data check is **Confirmed**). Nothing is mapped to ATLAS.

### 5.7 Navigator layers

- Enterprise: [`navigator/library-layers/stuxnet-s0603.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/library-layers/stuxnet-s0603.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/library-layers/stuxnet-s0603.json)), domain `enterprise-attack`, ATT&CK version 20, the 44 techniques of Part 5.2, each shown under its tactics with a comment naming the behavior and the source numbers of this study.
- ICS: [`navigator/case-studies/stuxnet-s0603-ics.json`](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/navigator/case-studies/stuxnet-s0603-ics.json) ([open in Navigator](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/TeamStarWolf/TeamStarWolf/main/navigator/case-studies/stuxnet-s0603-ics.json)), domain `ics-attack`, the 25 techniques of Part 5.3. Curated layers under `navigator/library-layers/` must be `enterprise-attack`, so the ICS layer lives in its own folder and is listed in the CATALOG of `scripts/build_navigator_layers.py`, which generates the [Navigator layer index](/navigator/index.md).

Scores in both layers mean only that ATT&CK lists the technique on S0603, not severity or prevalence.

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.
>
> © The MITRE Corporation. Includes material from MITRE D3FEND™, used under the D3FEND Terms of Use. https://d3fend.mitre.org/
>
> © The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/
>
> © The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/

## Cross-cutting themes

- **Precision is a design choice, and so is spread.** The PLC payload checked a CPU model, a Profibus module and at least 33 specific drives before doing anything [1]; the Windows worm around it infected about 100,000 hosts in over 155 countries [1]. The narrowness of the payload did not limit the reach of the carrier, which is how Stuxnet became public at all.
- **The view is part of the attack surface.** Stuxnet attacked what operators saw as deliberately as what the process did: replayed frequencies on S7-315 [1], replayed sensor values on S7-417 [14], and a rootkit that answered readbacks with clean code [1]. Defences that depend on the same screen and the same workstation inherit the deception.
- **Trust anchors were borrowed, not broken.** Valid driver signatures [1], a vendor's own hard-coded password [28] and the normal Step 7 project workflow [1] all carried the malware. None of these needed a cryptographic break.
- **Old bugs outlive their headlines.** MS08-067 was two years old when Stuxnet used it [25] and entered CISA KEV in 2026 [29]; the LNK flaw was used by other malware before and after [1] [20]. Engineering workstations are where unpatched Windows survives longest.
- **Overstated and understated.** Overstated: claims that Stuxnet destroyed 1,000 to 2,000 centrifuges, or that its effect is a confirmed fact. The IAEA never named a cause [35] [36] [37] [38], and the 1,000 figure is ISIS's inference [39]. Also overstated: statements of attribution as fact [44] [49]. Understated: how ordinary most of the carrier was, with an old MS08-067 bug, a vendor's hard-coded password and normal Step 7 project sharing [1] [25] [28] (**Inferred**, this study's reading of the sources cited).
- **The record is lopsided.** Technical facts are Confirmed many times over by independent vendors and agencies, while authorship remains Reported. A defender does not need the attribution to act on the lessons, and a study should not upgrade it.

## Sources

| # | Source | URL | Opened | Grade |
|---|---|---|---|---|
| 1 | Falliere, O Murchu and Chien, Symantec, "W32.Stuxnet Dossier" v1.4 (February 2011) | https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier-11-en | 3 Nov 2026 | Confirmed |
| 2 | McDonald, O Murchu, Doherty and Chien, Symantec, "Stuxnet 0.5: The Missing Link" v1.0 (26 February 2013) | https://docs.broadcom.com/doc/stuxnet-missing-link-13-en | 3 Nov 2026 | Confirmed |
| 3 | ESET, "Stuxnet Under the Microscope" rev. 1.31 | https://www.welivesecurity.com/media_files/white-papers/Stuxnet_Under_the_Microscope.pdf | 3 Nov 2026 | Confirmed |
| 4 | Kaspersky (Alexander Gostev), "Back to Stuxnet: the missing link" (11 June 2012); also served at /33302/ and /33174/ | https://securelist.com/back-to-stuxnet-the-missing-link/33219/ | 3 Nov 2026 | Confirmed |
| 5 | Kaspersky GReAT, "Stuxnet: Zero victims" (11 November 2014) | https://securelist.com/stuxnet-zero-victims/67483/ | 3 Nov 2026 | Confirmed |
| 6 | Kaspersky GReAT, "Equation: The Death Star of Malware Galaxy" (16 February 2015) | https://securelist.com/equation-the-death-star-of-malware-galaxy/68750/ | 3 Nov 2026 | Confirmed |
| 7 | Kaspersky, "Equation Group: Questions and Answers" v1.5 (February 2015) | https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064459/Equation_group_questions_and_answers.pdf | 3 Nov 2026 | Confirmed |
| 8 | Kaspersky, "The Flame: Questions and Answers" (28 May 2012) | https://securelist.com/the-flame-questions-and-answers/34344/ | 3 Nov 2026 | Confirmed |
| 9 | Kaspersky, "Gauss: Abnormal Distribution" (9 August 2012) | https://securelist.com/gauss-abnormal-distribution/36620/ | 3 Nov 2026 | Confirmed |
| 10 | Kaspersky GReAT, "The Mystery of Duqu 2.0" (10 June 2015) | https://securelist.com/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/70504/ | 3 Nov 2026 | Confirmed |
| 11 | CrySyS Lab, "sKyWIper" v1.05 (31 May 2012) | https://static.crysys.hu/publications/files/skywiper.pdf | 3 Nov 2026 | Confirmed |
| 12 | CrySyS Lab, "Duqu: A Stuxnet-like malware found in the wild" v0.93 (14 October 2011) | https://static.crysys.hu/publications/files/bencsathPBF11duqu.pdf | 3 Nov 2026 | Confirmed |
| 13 | Symantec, "W32.Duqu" v1.4 (23 November 2011; v1.0 18 October 2011) | https://docs.broadcom.com/doc/w32-duqu-11-en | 3 Nov 2026 | Confirmed |
| 14 | Ralph Langner, "Stuxnet's Secret Twin", Foreign Policy (19 November 2013) | https://foreignpolicy.com/2013/11/19/stuxnets-secret-twin/ | 3 Nov 2026 | Confirmed (author's own analysis) |
| 15 | ICS-CERT, ICSA-10-272-01 "Primary Stuxnet Advisory" (last revised 6 September 2018) | https://www.cisa.gov/news-events/ics-advisories/icsa-10-272-01 | 3 Nov 2026 | Confirmed |
| 16 | ICS-CERT, ICSA-10-201-01C (last revised 8 January 2014) | https://www.cisa.gov/news-events/ics-advisories/icsa-10-201-01c | 3 Nov 2026 | Confirmed |
| 17 | ICS-CERT, ICSA-10-238-01B "Stuxnet Malware Mitigation (Update B)" | https://www.cisa.gov/news-events/ics-advisories/icsa-10-238-01b | 3 Nov 2026 | Confirmed |
| 18 | ICS-CERT, ICSA-12-205-01 "Siemens WinCC Insecure SQL Server Authentication" | https://www.cisa.gov/news-events/ics-advisories/icsa-12-205-01 | 3 Nov 2026 | Confirmed |
| 19 | CERT/CC, VU#940193 | https://www.kb.cert.org/vuls/id/940193 | 3 Nov 2026 | Confirmed |
| 20 | Microsoft Security Bulletin MS10-046 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-046 | 3 Nov 2026 | Confirmed |
| 21 | Microsoft Security Advisory 2286198 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2286198 | 3 Nov 2026 | Confirmed |
| 22 | Microsoft Security Bulletin MS10-061 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-061 | 3 Nov 2026 | Confirmed |
| 23 | Microsoft Security Bulletin MS10-073 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-073 | 3 Nov 2026 | Confirmed |
| 24 | Microsoft Security Bulletin MS10-092 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-092 | 3 Nov 2026 | Confirmed |
| 25 | Microsoft Security Bulletin MS08-067 | https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067 | 3 Nov 2026 | Confirmed |
| 26 | Microsoft Security Advisory 2639658 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2011/2639658 | 3 Nov 2026 | Confirmed |
| 27 | Microsoft Security Advisory 2718704 | https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2718704 | 3 Nov 2026 | Confirmed |
| 28 | NVD CVE API 2.0 records for CVE-2010-2568, CVE-2010-2772, CVE-2010-2729, CVE-2010-2743, CVE-2010-3338, CVE-2010-3888, CVE-2008-4250 and CVE-2011-3402 (same endpoint, one `cveId` each) | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2010-2772 | 3 Nov 2026 | Confirmed |
| 29 | CISA Known Exploited Vulnerabilities catalog, catalogVersion 2026.11.03 | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 3 Nov 2026 | Confirmed |
| 30 | MITRE ATT&CK, software S0603 Stuxnet (v1.5, ATT&CK v20.0) | https://attack.mitre.org/software/S0603/ | 3 Nov 2026 | Confirmed |
| 31 | MITRE ATT&CK, group G0020 Equation (v1.2) | https://attack.mitre.org/groups/G0020/ | 3 Nov 2026 | Confirmed |
| 32 | MITRE CAPEC-70, CAPEC-457 and CAPEC-206 | https://capec.mitre.org/data/definitions/70.html | 3 Nov 2026 | Confirmed |
| 33 | MITRE CWE-798 Use of Hard-coded Credentials | https://cwe.mitre.org/data/definitions/798.html | 3 Nov 2026 | Confirmed |
| 34 | MITRE D3FEND, IO Port Restriction (D3-IOPR) | https://d3fend.mitre.org/technique/d3f:IOPortRestriction/ | 3 Nov 2026 | Confirmed |
| 35 | IAEA Board report GOV/2009/74 (16 November 2009) | https://www.iaea.org/sites/default/files/gov2009-74.pdf | 3 Nov 2026 | Confirmed |
| 36 | IAEA Board report GOV/2010/10 (18 February 2010) | https://www.iaea.org/sites/default/files/gov2010-10.pdf | 3 Nov 2026 | Confirmed |
| 37 | IAEA Board report GOV/2010/46 (6 September 2010) | https://www.iaea.org/sites/default/files/gov2010-46.pdf | 3 Nov 2026 | Confirmed |
| 38 | IAEA Board report GOV/2010/62 (23 November 2010) | https://www.iaea.org/sites/default/files/gov2010-62.pdf | 3 Nov 2026 | Confirmed |
| 39 | Albright, Brannan and Walrond, ISIS, "Did Stuxnet Take Out 1,000 Centrifuges at the Natanz Enrichment Plant?" (22 December 2010) | https://isis-online.org/isis-reports/detail/did-stuxnet-take-out-1000-centrifuges-at-the-natanz-enrichment-plant/ | 3 Nov 2026 | Confirmed (as ISIS analysis); Reported (as cause) |
| 40 | World Nuclear News, "Bushehr unaffected by computer virus" (27 September 2010) | https://world-nuclear-news.org/Articles/Bushehr-unaffected-by-computer-virus | 3 Nov 2026 | Reported |
| 41 | Christian Science Monitor, "Stuxnet: Ahmadinejad admits cyberweapon hit Iran nuclear program" (30 November 2010) | https://www.csmonitor.com/USA/2010/1130/Stuxnet-Ahmadinejad-admits-cyberweapon-hit-Iran-nuclear-program | 3 Nov 2026 | Reported |
| 42 | Christian Science Monitor, "Israel tested Stuxnet worm in joint effort with US to thwart Iran, says report" (17 January 2011) | https://www.csmonitor.com/World/terrorism-security/2011/0117/Israel-tested-Stuxnet-worm-in-joint-effort-with-US-to-thwart-Iran-says-report | 3 Nov 2026 | Reported |
| 43 | Tehran Times, "Iran says Siemens behind Stuxnet cyber attack" (17 April 2011) | tehrantimes.com news item 238788, opened in a browser (kept as plain text: the host resets automated link checkers) | 3 Nov 2026 | Reported |
| 44 | The Guardian, "Obama sped up cyberattack on Iran" (1 June 2012) | https://www.theguardian.com/world/2012/jun/01/obama-sped-up-cyberattack-iran | 3 Nov 2026 | Reported |
| 45 | CBS News, 60 Minutes, "Stuxnet: Computer worm opens new era of warfare" (aired 4 March 2012) | https://www.cbsnews.com/news/stuxnet-computer-worm-opens-new-era-of-warfare-01-07-2012/ | 3 Nov 2026 | Confirmed (interview record) |
| 46 | The Jewish Chronicle, "Ashkenazi video triggers Stuxnet rumours" (16 February 2011) | https://thejc.com/news/israel/ashkenazi-video-triggers-stuxnet-rumours-ccscuxeq | 3 Nov 2026 | Reported |
| 47 | US Department of Justice release 16-1213 on James Cartwright's plea (17 October 2016), via the FAS mirror (a copy of the DOJ release; the justice.gov original was not opened: it served an automated-client challenge page) | https://irp.fas.org/news/2016/10/cartwright-rel.html | 3 Nov 2026 | Confirmed |
| 48 | US Department of Justice, Executive Grant of Clemency for James Edward Cartwright (17 January 2017) | https://www.justice.gov/pardon/file/993661/dl | 3 Nov 2026 | Confirmed |
| 49 | Kim Zetter and Huib Modderkolk, Yahoo News, "Revealed: How a secret Dutch mole aided the U.S.-Israeli Stuxnet cyberattack on Iran" (2 September 2019) | https://www.yahoo.com/news/revealed-how-a-secret-dutch-mole-aided-the-us-israeli-stuxnet-cyber-attack-on-iran-160026018.html | 3 Nov 2026 | Reported |
| 50 | SecurityWeek, "New Module Suggests Fourth Team Involved in Stuxnet Development" (9 April 2019) | https://www.securityweek.com/new-module-suggests-fourth-team-involved-stuxnet-development/ | 3 Nov 2026 | Reported |
| 51 | SecurityWeek, "Stuxnet Likely Constituted Illegal Act of Force, Study Says" (27 March 2013) | https://www.securityweek.com/stuxnet-likely-constituted-illegal-act-force-study-says | 3 Nov 2026 | Reported |
| 52 | Krebs on Security, "Experts Warn of New Windows Shortcut Flaw" (15 July 2010) | https://krebsonsecurity.com/2010/07/experts-warn-of-new-windows-shortcut-flaw/ | 3 Nov 2026 | Reported |
| 53 | Automation World, "Siemens Provides Stuxnet Update" (22 September 2010) | https://www.automationworld.com/home/news/13298031/siemens-provides-stuxnet-update | 3 Nov 2026 | Reported |
| 54 | NIST SP 800-82r3, "Guide to Operational Technology (OT) Security" (September 2023) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf | 3 Nov 2026 | Confirmed |
| 55 | Dragos, "CRASHOVERRIDE: Analyzing the Threat to Electric Grid Operations" (June 2017), National Security Archive copy | https://nsarchive.gwu.edu/sites/default/files/documents/3869008/Dragos-CRASHOVERRIDE-Analyzing-the-Threat-to.pdf | 3 Nov 2026 | Confirmed |
| 56 | US-CERT TA17-163A, "CrashOverride Malware" (12 June 2017) | https://www.cisa.gov/news-events/alerts/2017/06/12/crashoverride-malware | 3 Nov 2026 | Confirmed |
| 57 | DOE, CISA, NSA and FBI, AA22-103A (13 April 2022) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-103a | 3 Nov 2026 | Confirmed |
| 58 | Mandiant, "Attackers Deploy New ICS Attack Framework TRITON" (14 December 2017) | https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton | 3 Nov 2026 | Confirmed |
| 59 | Mandiant, INCONTROLLER state-sponsored ICS tooling report (13 April 2022) | https://cloud.google.com/blog/topics/threat-intelligence/incontroller-state-sponsored-ics-tool | 3 Nov 2026 | Confirmed |
| 60 | DHS, MAR-17-352-01 "HatMan: Safety System Targeted Malware (Update B)" (27 February 2019) | https://www.cisa.gov/sites/default/files/documents/MAR-17-352-01%20HatMan%20-%20Safety%20System%20Targeted%20Malware%20%28Update%20B%29.pdf | 3 Nov 2026 | Confirmed |
| 61 | TeamStarWolf library data and pages on main: `data/attack/software_to_technique.jsonl`, `data/attack/technique_profiles.jsonl`, `data/attack/ics/technique_profiles.jsonl`, `data/attack/ics/software.jsonl`, `data/attack/superseded_by.jsonl`, `data/attack/technique_releases.jsonl`, `data/attack/technique_to_d3fend.jsonl`, `data/weaknesses/capec.jsonl`, `data/weaknesses/cwe.jsonl`, `data/ai/atlas_techniques.jsonl`, the `mitre/` tree, `MALWARE_FAMILIES.md`, `NOTABLE_INCIDENTS.md`, `ICS_OT_SECURITY_REFERENCE.md` | https://github.com/TeamStarWolf/TeamStarWolf | 3 Nov 2026 | Confirmed |

Not opened: Ralph Langner, "To Kill a Centrifuge" (November 2013), cited only as ATT&CK cites it; the New York Times originals, cited only as relayed by [42] and [44]; the Tallinn Manual, relayed by [51]; Chronicle's own Stuxshop report, relayed by [50].

## Related references

- [Notable Incidents](/NOTABLE_INCIDENTS.md)
- [Malware Families](/MALWARE_FAMILIES.md)
- [Threat Actors](/THREAT_ACTORS.md)
- [CVE Reference](/CVE_REFERENCE.md)
- [ICS/OT Security Reference](/ICS_OT_SECURITY_REFERENCE.md) and the [ICS ATT&CK Technique Atlas](/ICS_ATTACK_ATLAS.md)
- [ATT&CK Software Reference](/ATTACK_SOFTWARE_REFERENCE.md)
- MITRE pages: [S0603 Stuxnet](/mitre/software/S0603.md), [S0143 Flame](/mitre/software/S0143.md), [S0038 Duqu](/mitre/software/S0038.md), [S0604 Industroyer](/mitre/software/S0604.md), [G0020 Equation](/mitre/groups/G0020.md), [C0025](/mitre/campaigns/C0025.md), [C0030](/mitre/campaigns/C0030.md), and the technique pages linked in Part 5.2
- [CWE Reference](/CWE_REFERENCE.md), [CAPEC Reference](/CAPEC_REFERENCE.md), [D3FEND Reference](/D3FEND_REFERENCE.md)
- [All case studies](/case-studies/README.md)
