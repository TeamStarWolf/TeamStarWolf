# Slide plan: Water and Wastewater Networks: The Control Systems, the Chemistry and the Attacks on Them

- Study: case-studies/WATER_TREATMENT_NETWORKS.md
- Cover title: Water and Wastewater Networks / The Control Systems, the Chemistry / and the Attacks on Them
- Subtitle: Zones, protocols, devices, the dated record, the actors and the MITRE view
- Published: 13 November 2026
- Notes: Slide plan for the deck of the study case-studies/WATER_TREATMENT_NETWORKS.md. Bracketed numbers in the notes are the study's source numbers.

## EXECUTIVE SUMMARY | Exposure, not exploitation, is how attackers reach the water

- **Target-rich and resource-poor:** most systems are small, run by a few staff and an integrator on call.
- **The way in is the internet edge:** exposed PLCs and HMIs with default or weak passwords.
- **The air gap is a belief:** undocumented cellular modems and vendor paths reach "isolated" plants.
- **Devices outlive their fixes:** OT lifetimes of 10 to 15 years; some advisories cover all versions.
- **Engineered limits work:** an operator reversed the 2021 dosing change; pump sizing caps the harm.
Caption: Grades: regulators, advisories, standards and filings Confirmed; press and vendor claims Reported; patterns Inferred.
Notes: Incident response guide [19]; AA21-287A [20]. Top Cyber Actions [15][16]; access paths [56][63][64][109][112], the pattern Inferred. EPA on air gaps [5]; WaterISAC modems [7]; CISA July 2026 [113]. NIST lifetimes [33]; Unitronics legacy [73]. Florida dosing [57].

## KEY FACTS | A huge sector of small systems with a thin federal floor

Stat: ~152,000 | public drinking water systems (CISA)
Stat: >97% | of public water systems serve 10,000 or fewer
Stat: 3,300 | people: the floor for AWIA Section 1433
Stat: >70% | of systems EPA inspected violated Section 1433
- CISA also counts more than 16,000 wastewater systems; EPA and GAO give other totals.
- Section 1433 asks for a risk assessment and an emergency plan; wastewater need not certify.
- EPA's 2023 cybersecurity interpretation was withdrawn after legal challenges.
Notes: CISA sector page [1]; EPA counts [2][3]; GAO [4]. AWIA and Section 1433 [17]. Enforcement alert, May 2024 [18]. Withdrawn interpretation [4].

## PART 1 | EPA defines a water system's OT by the process it runs

| Process area | What runs it |
|---|---|
| Intake and treatment | PLCs, chemical dosing, analyzers, DCS |
| Storage and distribution | Tank level and pressure, remote valves |
| Collection and lift stations | Pump stations, flow meters, RTUs |
| Wastewater treatment | Aeration, biological treatment, solids |
| Supervisory | SCADA servers, HMIs, workstations |
| Communications | Fiber, radio, microwave and cellular |
Caption: The 2025 OT asset inventory guide's water taxonomy, which it calls conceptual and not authoritative.
Notes: EPA OT definition [5]. Inventory guide Appendix D, process areas and criticality [6]. SCADA for distribution and DCS for treatment per NIST [33].

## PART 1 | The Purdue model on paper; remote vendor access in practice

Left: The reference design
- Purdue levels 0 to 3 for industrial devices.
- ICS-DMZ, firewalls, VLANs, data diodes.
- Deny OT connections by default.
- MFA for any remote path to OT.
Right: What the record shows
- Integrators and vendors on call remotely.
- Exposed HMIs found through search platforms.
- An "air gap" with a permanent VPN tunnel.
- Rules start at 3,300 people.
Notes: EPA guidance [8]; WaterISAC zones and remote access [7]. Exposed HMIs fact sheet [9][10]. EPA case studies, small, medium and large [24][25][26]. Section 1433 [17].

## PART 2 | The protocols can be secured; deployment is unmeasured

| Protocol | Security position |
|---|---|
| Modbus (spec 2012) | No authentication or integrity defined |
| Modbus Security | TLS with X.509 certificates, port 802 |
| DNP3 (IEEE 1815) | Base protocol carries no security |
| DNP3-SL | Implements IEC 62351-5 authentication |
| OPC UA, MQTT | Named for polling and data in water |
Caption: The Modbus point is a text search of the specification (Demonstrated); no source opened measures deployment.
Notes: Modbus specification [35], text search Demonstrated; Modbus Security [36]. DNP3 history and primer [37][38]; IEEE 1815 [39]; DNP3-SL [40][41]. Inventory guide [6]. Deployment gap Inferred.

## PART 2 | Controller logic is IEC 61131-3, edited from Windows hosts

- **IEC 61131-3:2025:** Structured Text, Ladder Diagram, Function Block Diagram and SFC elements.
- **Vendor tools:** Unitronics VisiLogic, Siemens STEP 7 (TIA Portal) edit logic and HMI screens.
- **SCADA scripting:** Ignition scripts run on Jython 2.7 with the Java library.
- **Windows hosts:** the 2021 dosing advisory names an end-of-life Windows 7 machine.
- **Remote tools:** TeamViewer, VNC and RDP all appear in the advisories.
Caption: Ladder logic and project files are what the 2023 and 2026 actors replaced or modified.
Notes: IEC 61131-3 editions [42][43]. VisiLogic [44]; STEP 7 [45]; Ignition [46]. Windows 7 [57][58]. TeamViewer [57][60]; VNC [63][64]; RDP [20]. Logic and project files [56][109][112].

## PART 3 | PLCs, HMIs and cellular gateways carry the advisories

| Device class | What the advisory records |
|---|---|
| PLC with HMI | Unitronics Vision: a default password, 9.8 |
| PLC | Rockwell Logix: key exposure, KEV 2026 |
| PLC | Siemens S7-1200 and S7-1500 key weakness |
| SCADA | VTScada flaws, water listed, one in KEV |
| Cellular gateway | Sierra Wireless ALEOS, KEV Dec 2025 |
| Generator controller | DSE855: no patch at publication |
Caption: Sector lists in advisories are not a census: a missing water listing does not mean absence from plants.
Notes: Unitronics [54][55][72]. Rockwell Logix [59][79]. Siemens [80][81]. VTScada [83][48][49]. ALEOS [88][62][84]. DSE855 [94][95], water deployment not established. Sector-list reading Inferred.

## PART 3 | Devices outlive their fixes, and fixes are engineering work

- **Long life:** NIST puts OT lifetimes at 10 to 15 years or longer.
- **No patch for some:** a Unitronics legacy advisory covers all versions.
- **Late KEV entries:** a 2019 gateway flaw entered KEV in 2025 with advice to discontinue.
- **Fixes take projects:** Siemens' key fix needs firmware, project migration and secure links.
- **Rebranded units:** several hacked HMIs were legacy foreign-made devices sold as US ones.
Notes: NIST SP 800-82r3 [33]. Unitronics legacy [73]. KEV catalog [84]. Siemens SSA-568427 [81], engineering-work reading Inferred. Hacktivist fact sheet [63].

## PART 4 | From Maroochy to the 2026 PLC wave, as a dated record

| Date | Event |
|---|---|
| Feb to Apr 2000 | Maroochy: about 800,000 litres of sewage |
| 5 Feb 2021 | US plant: sodium hydroxide dosing raised |
| 22 Nov 2023 | Unitronics PLCs defaced; 34+ in US water |
| Jan 2024 | Texas tanks overflow; CARR claims it |
| 7 Feb 2024 | Volt Typhoon in a water utility's IT |
| 3 Oct 2024 | American Water disconnects systems |
| 9 Dec 2025 | AA25-343A: hacktivists in water HMIs |
| 27 Jul 2026 | MicroLogix wave in at least 7 states |
Caption: Events with a home study (the ICS attacks study, the 2021 chronicle) are summarized there in full.
Notes: Maroochy C0020 [97]. AA21-042A [57]. AA23-335A [56][71]. Treasury on Texas [101]. AA24-038A [96]. 8-K [104]. AA25-343A [64]. FBI and EPA PSA and CISA alert [112][113].

## PART 4 | Four access patterns cover the record

Stat: 4 | access patterns in the US record
Stat: 75+ | Unitronics devices compromised from Nov 2023
Stat: ~9 months | Volt Typhoon in one water utility's IT
- **Exposed controllers and HMIs** with default or weak passwords.
- **Remote-access software and remote desktop:** VNC, RDP, desktop sharing.
- **Ransomware that started in IT** and reached SCADA hosts in 2021.
- **Insiders** and credentials that outlived employment.
Notes: Patterns Inferred from Confirmed rows in Part 4.1. Exposed devices [56][63][108][112][103]. Remote access [57][20][64][96]. Ransomware [20]. Insiders [20][18].

## PART 5 | Iranian and pro-Russia personas tamper; China pre-positions

Left: Personas that claim effects
- CyberAv3ngers (G1027), IRGC-CEC.
- CARR, with GRU links in the record.
- NoName057(16), Z-Pentest, Sector16.
- Iranian-affiliated APT actors, 2026.
Right: Actors that stay quiet
- Volt Typhoon (G1017), PRC state.
- Ransomware crews on SCADA hosts.
- Insiders with retained access.
- The unnamed 2026 MicroLogix actors.
Caption: Claims run ahead of the facts: CISA says the pro-Russia groups regularly exaggerate.
Notes: CyberAv3ngers [56][98][115][117]; AA26-097A [109]. CARR [64][101][119][100]. AA25-343A groups [64]. Volt Typhoon [96]. Ransomware and insiders [20][18]. MicroLogix wave [112]. Claims [63][64][100].

## MITRE MAPPINGS | 32 ICS and 21 Enterprise techniques, led by exposed devices

| Id | Technique | Bound to |
|---|---|---|
| T0883 | Internet Accessible Device | C0031, G1027, AA25-343A, AA26-097A |
| T0836 | Modify Parameter | C0020, AA25-343A |
| T0878 | Alarm Suppression | C0020, AA25-343A |
| T0889 | Modify Program | G1027, AA26-097A |
| T1694.001 | Default Credentials | C0031, G1027, AA25-343A |
| T1078.001 | Default Accounts | AA23-335A |
| T1021.005 | VNC | AA25-343A |
Caption: ATT&CK v20.0; revoked T0812 and T0855 read through superseded_by.jsonl; two Navigator layers.
Notes: Part 6.2 and 6.3 [97][99][117][64][109][56]. Revoked ids [66]. © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

## DEFENDER VIEW | Take controllers off the internet and change every default first

Left: What to do first
- Remove PLCs and HMIs from the internet.
- Change defaults; one login per person.
- Find undocumented modems and vendor paths.
- Back up PLC logic and HMI projects offline.
Right: What the record warns
- Rehearse running the plant by hand.
- Engineer limits the network cannot override.
- Patch by KEV in planned OT downtime.
- Use the free EPA, CISA and WaterISAC help.
Notes: Top recommendations 1 to 8 [9][16][28][18][72][7][113][56][112][15][20][71][102][24][57][8][13][19][29][32][33][84]. D3FEND pairings in Part 6.6 [124].

## CROSS-CUTTING THEMES | Small systems carry the risk; manual operation is the resilience

- **Small systems carry the risk,** large systems carry the rules.
- **The controller program is the target,** from Maroochy to 2026's modified project files.
- **Default credentials are a design choice** made long ago and still in the field.
- **Security exists in the standards** and lags in the plant.
- **Overstated:** the 2021 Florida intrusion and hacktivist claims; **understated:** quiet pre-positioning.
Notes: Themes [3][17][113][97][56][109][112][72][18][36][40][33]. Overstated and understated, Scope and method [57][63][64][100][96].
