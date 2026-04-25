# ICS/OT Security Reference

A comprehensive reference for ICS/OT/SCADA security professionals — covering architecture, threat actors, malware analysis, attack methodology, network security, standards, vulnerability management, detection, incident response, and physical security.

---

## Table of Contents

- [ICS/OT Fundamentals](#icsot-fundamentals)
  - [Terminology](#terminology)
  - [Purdue Model / ISA-95](#purdue-model--isa-95)
  - [Industrial Protocols](#industrial-protocols)
- [ICS Threat Landscape](#ics-threat-landscape)
  - [Nation-State Actors](#nation-state-actors)
  - [Attack Categories](#attack-categories)
- [Stuxnet Technical Deep Dive](#stuxnet-technical-deep-dive)
- [TRITON/TRISIS Analysis](#tritontrisis-analysis)
- [Industroyer/CrashOverride and Industroyer2](#industryovercrashoverride-and-industroyer2)
- [ICS Attack Methodology](#ics-attack-methodology-mitre-attck-for-ics)
- [ICS Network Reconnaissance and Tools](#ics-network-reconnaissance--tools)
- [OT Network Security Architecture](#ot-network-security-architecture)
- [ICS Security Standards and Frameworks](#ics-security-standards--frameworks)
- [ICS Vulnerability Management](#ics-vulnerability-management)
- [ICS Detection and Monitoring](#ics-detection--monitoring)
- [ICS Incident Response](#ics-incident-response)
- [Physical Security for ICS](#physical-security-for-ics)

---

## ICS/OT Fundamentals

### Terminology

| Term | Full Name | Description |
|---|---|---|
| ICS | Industrial Control Systems | Broad category of systems used to monitor and control industrial processes |
| OT | Operational Technology | Hardware and software that detects/causes changes through direct monitoring/control of physical devices |
| SCADA | Supervisory Control and Data Acquisition | Centralized system collecting data from remote sensors and controlling field devices |
| DCS | Distributed Control System | Control system where elements are distributed across the plant/process, typically closed-loop |
| PLC | Programmable Logic Controller | Ruggedized digital computer controlling manufacturing processes; executes ladder logic |
| RTU | Remote Terminal Unit | Field device converting physical signals to digital data; often precursor to modern PLCs |
| HMI | Human-Machine Interface | Graphical interface allowing operators to monitor and interact with control systems |
| EWS | Engineering Workstation | Computer used to program, configure, and maintain PLCs and controllers |
| Historian | Process Data Historian | Time-series database recording process variable data from the OT network (e.g., OSIsoft PI) |
| SIS | Safety Instrumented System | Independent system that takes a process to a safe state if predefined conditions are violated |
| DCS | Distributed Control System | Controller architecture distributed across a facility, often used in continuous processes |

### Purdue Model / ISA-95

The Purdue Enterprise Reference Architecture (PERA) and ISA-95 standard define a hierarchical model for segmenting industrial networks. Each level has distinct security requirements.

| Level | Name | Components | Security Focus |
|---|---|---|---|
| Level 0 | Physical Process | Sensors, actuators, valves, motors | Physical access control, tamper-evident seals |
| Level 1 | Basic Control | PLCs, RTUs, field devices, safety controllers | Network isolation, firmware integrity |
| Level 2 | Supervisory Control | HMIs, DCS consoles, SCADA servers | Application hardening, patch management |
| Level 3 | Site Operations | MES, historians, data aggregation servers | Controlled access, logging, monitoring |
| Level 3.5 | DMZ | Data diode, jump server, historian replication | Strict firewall rules, one-way data transfer |
| Level 4 | Business Logistics | ERP systems, IT network | Standard IT security controls |
| Level 5 | Enterprise | Corporate IT, internet-facing systems | All enterprise security controls |

**Key principle:** Traffic should never flow directly from Level 4/5 into Level 2/1/0 without explicit authorization through the DMZ. Unidirectional gateways (data diodes) enforce one-way data flow from OT to IT.

**Common segmentation failures that lead to breaches:**
- Direct VPN termination into OT network (Oldsmar water treatment, Colonial Pipeline pivot)
- IT/OT firewall rules permitting RDP/SMB across the boundary
- Shared credentials between IT and OT domains
- Historian servers dual-homed to both IT and OT networks
- IT Active Directory used for OT authentication

### Industrial Protocols

| Protocol | Layer | Use Case | Default Port | Security Risk |
|---|---|---|---|---|
| Modbus TCP | Application | PLC/RTU communication | 502/TCP | No authentication, no encryption; any device on network can issue commands |
| DNP3 | Application | Electric/water utilities | 20000/TCP | Weak/optional authentication (Secure Auth v5); replay attack risk |
| IEC 61850 | Application | Power substation automation | 102/TCP (MMS) | Authentication available but rarely enforced |
| EtherNet/IP (CIP) | Application | Rockwell/Allen-Bradley PLCs | 44818/TCP | Limited authentication; CIP Safety extensions exist |
| PROFINET | Application | Siemens automation | Dynamic | No native security; relies on network segmentation |
| OPC-UA | Application | Interoperability/data exchange | 4840/TCP | Certificate-based security available and increasingly used |
| BACnet | Application | Building automation/HVAC | 47808/UDP | No authentication in base standard; BACnet/SC adds TLS |
| IEC 60870-5-104 | Application | SCADA for power/water | 2404/TCP | No authentication; easy to spoof commands |
| S7comm | Application | Siemens S7 PLCs (S7-300/400) | 102/TCP | No authentication or encryption; widely exploited |
| S7comm-Plus | Application | Siemens S7-1200/1500 PLCs | 102/TCP | Challenge-response auth; partially reversed by researchers |
| ICCP (IEC 60870-6) | Application | Control center-to-control center | Various | Authentication optional; historically weak |
| Modbus RTU | Data Link | Serial PLC/RTU | RS-485/232 | No security; physical access to serial bus = full access |

**Protocol security assessment checklist:**
- Are Modbus write function codes (FC05, FC06, FC15, FC16) restricted to authorized engineering stations?
- Is DNP3 Secure Authentication v5 (SAv5) enabled?
- Are OPC-UA certificates validated (not using NoSecurity endpoint)?
- Is S7comm access restricted by IP allowlist at the firewall level?
- Are BACnet broadcast messages filtered at network boundaries?

---

## ICS Threat Landscape

### Nation-State Actors

**XENOTIME / TRITON Group (attributed: Russian CNIIHM)**
- Most dangerous ICS threat actor; specifically targeted safety systems
- 2017: TRISIS/TRITON malware against Schneider Electric Triconex SIS at Saudi Aramco facility
- Objective: disable safety systems to enable physical destruction during concurrent cyber attack
- An accidental safety system trip revealed the intrusion before physical impact occurred
- Expanded targeting observed beyond Middle East to global energy and critical infrastructure

**Sandworm (Russia / GRU Unit 74455)**
- Ukraine power grid 2015 (BlackEnergy3): 225,000 customers lost power; operators locked out of HMIs
- Ukraine power grid 2016 (Industroyer/CrashOverride): automated ICS-protocol attack, first-of-its-kind
- 2022 (Industroyer2 + CaddyWiper): targeted Ukrenergo during ongoing conflict; partially thwarted by CERT-UA
- NotPetya 2017: collateral ICS/OT damage at Maersk, Merck, Mondelez — $10B+ total damages
- Also responsible for VPNFilter (500K+ routers compromised, including ICS-adjacent devices)

**ELECTRUM / Dragonfly 2.0 (attributed: Russia FSB)**
- Targeted US and European energy sector 2014-2017
- Phase 1: watering hole attacks and spear-phishing for initial access
- Phase 2: supply chain compromise of ICS vendor software updates (Havex RAT trojanized)
- Phase 3: direct OT network access; screenshot collection from HMI screens
- Goal: reconnaissance and pre-positioning for potential sabotage

**Volt Typhoon (China / MSS)**
- US critical infrastructure pre-positioning discovered 2023
- Living-off-the-land (LOTL) techniques; minimal malware footprint
- Targeted: water/wastewater, power, communications, transportation sectors
- Goal: disruption capability in event of armed conflict over Taiwan
- Key TTPs: SOHO router compromise for proxy infrastructure, Mimikatz-free credential harvesting

**Lazarus / HIDDEN COBRA (North Korea)**
- Energy sector targeting for revenue generation and geopolitical leverage
- Electric utility intrusions in India, Bangladesh
- Cryptocurrency theft from energy company contractors

**COSMICENERGY (Russia, discovered 2023)**
- Kaspersky-discovered tool targeting IEC 60870-5-104 RTUNET devices
- Capable of controlling electrical substation switches and circuit breakers
- Likely used for testing or red team exercises; no confirmed deployment

### Attack Categories

**Espionage**
- Stealing operational data: process diagrams (P&IDs), network diagrams, vendor lists
- Understanding production capacity and schedules for economic intelligence
- Identifying safety system configurations for future sabotage planning
- Example: Havex RAT collecting OPC server data and sending to C2

**Sabotage**
- Direct manipulation of process setpoints (temperature, pressure, flow)
- Disabling safety instrumented systems (SIS) to allow runaway processes
- Opening/closing circuit breakers to cause power outages
- Example: Stuxnet centrifuge speed manipulation; Industroyer substation control

**Ransomware (IT → OT Impact)**
- Colonial Pipeline (DarkSide, May 2021): IT ransomware, OT proactively shut down; $4.4M ransom
- Oldsmar Water Treatment (2021): attacker attempted to raise NaOH to 111x normal via TeamViewer
- JBS Foods: ransomware forced shutdown of beef processing plants
- Critical distinction: ransomware typically hits IT, but OT shutdown as precaution causes physical/economic impact

**Physical Destruction**
- Stuxnet: first confirmed cyber attack causing physical destruction of centrifuges
- TRISIS/TRITON: attempted to cause physical destruction via SIS bypass
- Aurora Generator Test (NERC/INL 2007): demonstrated that cyber commands can physically destroy a generator

---

## Stuxnet Technical Deep Dive

Stuxnet remains the most technically sophisticated ICS malware ever discovered. Its analysis fundamentally changed how the security community understands cyber-physical attacks.

### Discovery and Attribution

- Discovered: June 2010 by VirusBlokAda; subsequently analyzed by Kaspersky, ESET, Symantec
- Attributed: Joint US-Israeli intelligence operation (Operation Olympic Games)
- Target: Iranian uranium enrichment facility at Natanz
- Goal: Sabotage IR-1 centrifuges to delay Iranian nuclear weapons program

### Delivery and Propagation

Stuxnet used four zero-day vulnerabilities — an unprecedented number for a single piece of malware:

| CVE | Vulnerability | Description |
|---|---|---|
| MS10-046 / CVE-2010-2568 | Windows Shell LNK | Malicious shortcut file executes code when folder is viewed |
| MS10-061 / CVE-2010-2729 | Print Spooler | Remote code execution via SMB print spooler |
| MS08-067 / CVE-2008-4250 | Server Service | Remote code execution (also used by Conficker) |
| MS10-073 / CVE-2010-2743 | Win32k.sys | Privilege escalation via keyboard layout file |

**Propagation methods:**
1. USB drive infection (primary initial vector targeting air-gapped Natanz)
2. Network shares (WNet enumeration)
3. Print spooler vulnerability (MS10-061)
4. Step 7 project file infection (targets engineers who move projects between machines)
5. WinCC database infection
6. Peer-to-peer update mechanism between infected machines

**Rootkit components:**
- `MrxCls.sys` and `MrxNet.sys`: Kernel-mode rootkit signed with stolen Realtek/JMicron certificates
- Concealed Stuxnet files, registry keys, and PLC modifications from OS
- Blocked antivirus enumeration of infected files

### Payload: PLC Attack

The PLC attack component was the most sophisticated aspect. It targeted a very specific configuration:

**Targeting criteria (all must match to activate payload):**
1. Siemens WinCC/Step 7 software installed
2. Siemens S7-315-2 or S7-417 PLCs connected
3. Specific frequency converters from Fararo Paya (Iran) or Vacon (Finland) connected
4. Frequency converters operating in 807-1210 Hz range (indicating uranium centrifuges)

**Attack sequence:**
1. Inject malicious code blocks (OB35, FC1, FC2) into Step 7 project
2. Monitor centrifuge speed; record normal operating data
3. Phase 1 (Speed Attack): Increase rotor speed from 1064 Hz to 1410 Hz for 15 minutes, then reduce to 2 Hz
4. Repeat attack cycle every ~27 days over period of months
5. Replay recorded normal readings to HMI so operators see no anomalies (rootkit function)
6. Physical damage accumulates: rotor stress fractures, bearing wear, process contamination

**MITRE ATT&CK for ICS techniques used:**
- T0862 (Supply Chain Compromise): Siemens software update delivery
- T0843 (Program Download to Controller): Malicious PLC code injection
- T0836 (Modify Parameter): Frequency setpoint manipulation
- T0849 (Masquerading): Replay of normal sensor readings to conceal attack
- T0857 (System Firmware): Rootkit on Siemens S7 PLCs

### Impact and Lessons

- Estimated 1,000-2,000 centrifuges destroyed or damaged at Natanz
- Delayed Iranian enrichment program by 1-2 years (estimated)
- First confirmed cyber weapon causing physical destruction
- Demonstrated air-gap bypass via USB
- Revealed that safety assumptions about physical isolation are insufficient

---

## TRITON/TRISIS Analysis

TRITON (also known as TRISIS or HatMan) represents the most dangerous ICS malware discovered to date because it specifically targeted Safety Instrumented Systems (SIS) — the last line of defense preventing physical disasters.

### Background and Discovery

- Discovered: December 2017 at unnamed petrochemical facility in Saudi Arabia (later confirmed as SABIC Yanbu plant)
- Target: Schneider Electric Triconex Safety Instrumented System controllers
- Discovered by: FireEye/Mandiant (TRITON name), Dragos (TRISIS name), ICS-CERT (HatMan)
- Attribution: TEMP.Veles (FireEye) = XENOTIME (Dragos) = Russian Central Scientific Research Institute of Chemistry and Mechanics (CNIIHM / TsNIIkhM)

### Safety Instrumented Systems — Why They Matter

A SIS is an independent control system designed to bring a process to a safe state when dangerous conditions are detected. It operates on IEC 61511 / IEC 61508 standards.

```
Normal Operations:
  Process → DCS (control) → Normal operation maintained

Safety Scenario:
  Sensor detects over-pressure → SIS activates → Emergency shutdown (ESD)
  → Isolation valves closed → Flare system activated → Safe state achieved

TRITON Goal:
  Disable SIS → DCS attack proceeds → No automatic safety shutdown
  → Physical explosion / release of toxic materials
```

### Malware Architecture

**TRITON Framework (Python-based):**
- `triton.py`: Main controller and C2 communication
- `library/`: Triconex-specific protocol implementations
- `inject.bin` / `imain.bin`: Shellcode and payload for Triconex controller
- Custom implementation of the undocumented TriStation protocol (UDP port 1502)

**Attack Components:**
1. `TRITON.exe`: Framework launcher; communicates with SIS via TriStation protocol
2. `TRISIS` implant: Compiled C payload that runs on the Triconex controller itself
3. HatMan: Persistent implant maintaining access to SIS controller

**TriStation Protocol:**
- Proprietary Schneider Electric protocol (UDP 1502)
- Not normally monitored by ICS security tools
- TRITON reverse-engineered the protocol to send arbitrary commands
- Commands: read/write memory, download custom code, query controller state

### Attack Chain

```
Phase 1: IT Compromise
  Spear-phishing email → Initial IT foothold

Phase 2: OT Pivot
  Lateral movement through IT/OT boundary
  Compromised jump server / VPN concentrator

Phase 3: Engineering Workstation Compromise
  EWS targeted (runs Triconex TriStation software)
  EWS has legitimate access to SIS on UDP 1502

Phase 4: SIS Reconnaissance
  TRITON queries controller state, firmware version
  Maps SIS logic and safety trips

Phase 5: SIS Implant Deployment
  TRISIS payload deployed to Triconex controller
  Intended to allow attacker to disable safety trips on command

Phase 6: Accidental Discovery
  Logic error caused SIS to fail safe (controller halt)
  Operators noticed unexpected shutdown → investigation → discovery
```

### Detection Indicators

- UDP traffic on port 1502 from non-EWS systems
- TriStation protocol packets outside scheduled maintenance windows
- Unusual read/write operations to SIS from EWS (outside change windows)
- TRITON artifact files: `triton.exe`, `library/` directory, `inject.bin`
- Temporary files: `%TEMP%\~df563.tmp`, `win.exe`

### Lessons Learned

1. Air-gapping SIS from engineering network is insufficient if EWS is compromised
2. TriStation protocol monitoring was absent in most ICS security deployments
3. Unidirectional gateways between EWS and SIS would have prevented attack
4. TRITON deliberately failed safe (accidental) — a more sophisticated version would not
5. SIS firmware integrity checking was not implemented

---

## Industroyer/CrashOverride and Industroyer2

### Ukraine 2016: Industroyer v1

Industroyer (named by ESET) / CrashOverride (named by Dragos) was the first malware specifically designed to attack power grid infrastructure using native ICS protocols.

**Target:** Ukrainian power transmission system; Ukrenergo 330kV substations
**Date:** December 17, 2016
**Impact:** ~1 hour blackout in Kiev; 200MW load interrupted

**Architecture (modular):**

```
Launcher
  ├── Data Collector (network reconnaissance)
  ├── Backdoor (persistent C2 via Tor)
  ├── Protocol Payload Modules:
  │     ├── IEC 60870-5-101 (serial SCADA)
  │     ├── IEC 60870-5-104 (SCADA over TCP/IP)  ← primary attack vector
  │     ├── IEC 61850 MMS (substation automation)
  │     └── OPC DA (Windows-based SCADA data access)
  ├── DoS Module (Siemens SIPROTEC relay DoS via CVE-2015-5374)
  └── Wiper Module (covers tracks, destroys configuration)
```

**IEC-104 Attack Sequence:**
1. Enumerate ICS devices using protocol-native discovery
2. Connect to RTUs/protection relays using standard IEC-104 sessions
3. Issue `C_DC_NA_1` (Double Command) ASDU commands to open circuit breakers
4. Disable automatic reclosers (prevent self-healing)
5. SIPROTEC relay DoS prevents manual remote recovery

**MITRE ATT&CK for ICS:**
- T0855 (Unauthorized Command Message): IEC-104 commands to circuit breakers
- T0831 (Manipulation of Control): Opening circuit breakers
- T0813 (Denial of Control): SIPROTEC DoS preventing operator control
- T0872 (Indicator Removal): Wiper module

### Ukraine 2022: Industroyer2

**Target:** Ukrenergo high-voltage substations (110kV and 330kV)
**Date:** April 8, 2022 (prevented by CERT-UA and Eset intervention)
**Deployed alongside:** CaddyWiper (data destruction malware)

**Key differences from v1:**

| Aspect | Industroyer v1 | Industroyer2 |
|---|---|---|
| Architecture | Modular, multiple payload DLLs | Single binary executable |
| Protocols | IEC-101, IEC-104, IEC 61850, OPC DA | IEC-104 only |
| Configuration | Separate config files | Hardcoded substation targets |
| Sophistication | Higher | Simpler, more targeted |
| Companion malware | Wiper module | CaddyWiper (separate) |

**IEC-104 attack in Industroyer2:**
```
For each hardcoded substation IP:
  1. Establish IEC-104 TCP session (port 2404)
  2. Send STARTDT_ACT (start data transfer)
  3. Enumerate Information Object Addresses (IOAs) for circuit breakers
  4. Send C_DC_NA_1 (Double Command) with DCS=2 (execute OFF) to each IOA
  5. Repeat to prevent automatic reclose
```

---

## ICS Attack Methodology (MITRE ATT&CK for ICS)

MITRE ATT&CK for ICS is the definitive framework for mapping adversary behaviors in industrial environments. Reference: https://attack.mitre.org/matrices/ics/

### Initial Access

| Technique | ID | Description | Real-World Example |
|---|---|---|---|
| Drive-by Compromise | T0817 | Watering hole on vendor/engineering sites | Dragonfly/Havex |
| Spearphishing Attachment | T0865 | Malicious email attachments | BlackEnergy (2015) |
| Exploitation of Remote Services | T0866 | VPN/RDP exploitation | Colonial Pipeline |
| Remote Services | T0886 | Legitimate remote access abuse | Oldsmar Water |
| Supply Chain Compromise | T0862 | Trojanized software updates | Havex RAT |
| Replication Through Removable Media | T0847 | USB-based delivery | Stuxnet |
| Internet Accessible Device | T0883 | Direct attack of internet-exposed ICS | Shodan-exposed PLCs |

### Execution

| Technique | ID | Description |
|---|---|---|
| Command-Line Interface | T0807 | CLI execution on EWS/HMI |
| Scripting | T0853 | PowerShell/Python ICS interactions |
| Modify Controller Tasking | T0821 | Altering PLC task scheduling |
| Project File Infection | T0873 | Malicious code in Step 7/TIA Portal projects |
| User Execution | T0863 | Engineer opens malicious project file |

### Persistence

| Technique | ID | Description |
|---|---|---|
| Modify Program | T0889 | Persistent malicious PLC logic |
| System Firmware | T0857 | Firmware-level persistence on ICS devices |
| Module Firmware | T0839 | Compromised communication module firmware |
| Valid Accounts | T0859 | Legitimate OT credential abuse |

### Evasion

| Technique | ID | Description |
|---|---|---|
| Indicator Removal on Host | T0872 | Log clearing, file deletion (Industroyer wiper) |
| Masquerading | T0849 | Disguise malicious files as legitimate |
| Rootkit | T0851 | Kernel-level concealment (Stuxnet MrxCls) |
| Spoof Reporting Message | T0856 | Replay normal values to operator HMI |

### Discovery

| Technique | ID | Description |
|---|---|---|
| Network Connection Enumeration | T0840 | Map ICS network topology |
| Remote System Discovery | T0846 | Identify PLCs, RTUs, HMIs |
| Remote System Information Discovery | T0888 | Query PLC firmware, model, config |
| I/O Module Discovery | T0824 | Enumerate connected I/O modules |
| Wireless Sniffing | T0887 | Capture unencrypted wireless ICS protocols |

### Lateral Movement

| Technique | ID | Description |
|---|---|---|
| Default Credentials | T0812 | Factory-default PLC/HMI passwords |
| Exploitation of Remote Services | T0866 | Exploit EWS/SCADA server vulnerabilities |
| Program Download to Controller | T0843 | Push malicious code to PLC |
| Lateral Tool Transfer | T0867 | Move attack tools across OT network |

### Collection

| Technique | ID | Description |
|---|---|---|
| Automated Collection | T0802 | Scripted harvest of process data |
| Data from Information Repositories | T0811 | Historian data exfiltration |
| Detect Operating Mode | T0868 | Determine if PLC in run/program mode |
| Point and Tag Identification | T0861 | Map process variable tags |
| Screen Capture | T0852 | HMI screenshot collection (Dragonfly) |

### Impact

| Technique | ID | Description | Example |
|---|---|---|---|
| Denial of Control | T0813 | Prevent operators from controlling process | SIPROTEC DoS |
| Loss of Availability | T0826 | Render ICS unavailable | Ransomware IT impact |
| Loss of Control | T0827 | Remove operator ability to affect process | Industroyer |
| Loss of Productivity and Revenue | T0828 | Process disruption causing financial loss | Colonial Pipeline |
| Loss of Protection | T0829 | Disable safety systems | TRITON |
| Manipulation of Control | T0831 | Issue unauthorized commands | Industroyer CB commands |
| Manipulation of View | T0832 | Alter operator HMI display | Stuxnet replay |
| Loss of Safety | T0880 | Safety system failure | TRITON intent |
| Damage to Property | T0879 | Physical equipment damage | Stuxnet centrifuges |

---

## ICS Network Reconnaissance & Tools

### Passive Reconnaissance (Preferred — No Controller Impact)

Passive monitoring should always be the first choice. Active scanning can crash PLCs, corrupt process states, or trigger safety shutdowns.

```bash
# Wireshark/tshark — passive protocol identification
tshark -i eth0 -f "port 502 or port 102 or port 44818 or port 2404 or port 20000" \
  -T fields -e ip.src -e ip.dst -e tcp.port -e frame.protocols

# Zeek ICS protocol analysis
# /opt/zeek/share/zeek/base/protocols/ contains modbus, dnp3, s7comm parsers
zeek -C -i eth0 /path/to/ics-protocol-scripts/

# Nmap with ICS scripts (USE CAUTIOUSLY — can crash controllers)
nmap -sV --script modbus-discover -p 502 192.168.1.0/24
nmap --script s7-info -p 102 192.168.1.0/24
nmap --script enip-info -p 44818 192.168.1.0/24
nmap --script bacnet-info -p U:47808 192.168.1.0/24
nmap --script dnp3-enumerate -p 20000 192.168.1.0/24

# WARNING: Never run aggressive nmap scans against live OT networks
# -T4/-T5, --script-args, or UDP scanning can crash embedded controllers
```

### Shodan ICS Research Queries (Defense/Research Only)

```
# Internet-exposed Modbus devices
port:502 Modbus

# Siemens S7 PLCs
"Siemens S7" country:US

# EtherNet/IP (CIP) devices
port:44818 "Allen-Bradley"

# DNP3 devices
port:20000 "DNP3"

# GE SRTP (Series 90 PLCs)
port:18245

# Schneider Electric Modicon
port:502 "Schneider Electric"
```

### Modbus Exploitation with pymodbus

```python
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ConnectionException

# Connect to Modbus TCP device
client = ModbusTcpClient('192.168.1.100', port=502)

if client.connect():
    # Read coils (discrete outputs) — FC01
    coils = client.read_coils(0, 10, unit=1)
    print(f"Coils: {coils.bits}")

    # Read discrete inputs — FC02
    inputs = client.read_discrete_inputs(0, 10, unit=1)

    # Read holding registers — FC03 (most common)
    registers = client.read_holding_registers(0, 10, unit=1)
    print(f"Registers: {registers.registers}")

    # Read input registers — FC04
    input_regs = client.read_input_registers(0, 10, unit=1)

    # !! DANGEROUS — Write single register (FC06) — setpoint modification
    # result = client.write_register(100, 9999, unit=1)

    # !! DANGEROUS — Write multiple registers (FC16)
    # result = client.write_registers(100, [1000, 2000, 3000], unit=1)

    # !! DANGEROUS — Write single coil (FC05) — toggle discrete output
    # result = client.write_coil(0, True, unit=1)

    client.close()
```

### Siemens S7 Attacks

```bash
# Metasploit S7 enumeration
use auxiliary/scanner/scada/siemens_s7_info
set RHOSTS 192.168.1.0/24
set RPORT 102
run

# snap7 Python library for S7 interaction
# pip install python-snap7
```

```python
import snap7
from snap7.util import get_bool, set_bool

# Connect to S7-300 PLC
client = snap7.client.Client()
client.connect('192.168.1.200', 0, 1)  # IP, rack, slot

# Read data block
data = client.db_read(1, 0, 10)  # DB1, offset 0, 10 bytes

# Read CPU info
info = client.get_cpu_info()
print(f"Module: {info.ModuleTypeName.decode()}")

# Put PLC in STOP mode (!! DANGEROUS)
# client.plc_stop()

client.disconnect()
```

### ICS-Specific Security Tools

| Tool | Type | Description |
|---|---|---|
| Claroty Platform | Commercial/Passive | Asset discovery, vulnerability assessment, network monitoring |
| Dragos Platform | Commercial/Passive | Threat detection mapped to ATT&CK for ICS |
| Nozomi Guardian | Commercial/Passive | Behavioral anomaly detection, passive monitoring |
| Tenable OT Security | Commercial/Passive | Vulnerability scanning with passive and selective active |
| Plcscan | Open Source | PLC scanner supporting S7, Modbus |
| Redpoint (Digitalbond) | Open Source | NMAP scripts for ICS protocol enumeration |
| CyberX (now Microsoft Defender for IoT) | Commercial | OT asset inventory and threat detection |
| Claroty xDome | Commercial | ICS/OT endpoint protection |
| Aegis (Digitalbond) | Open Source | DNP3 fuzzing framework |
| GrassMarlin | Open Source (NSA) | Passive ICS network topology mapping |
| ISF (Industrial Security Framework) | Open Source | Modular ICS exploitation framework |

---

## OT Network Security Architecture

### Defense-in-Depth for OT

The goal of OT network architecture is to prevent IT compromises from becoming OT incidents, while maintaining operational visibility and vendor access requirements.

```
Internet
    │
[Perimeter Firewall]
    │
Corporate IT Network (Level 4-5)
    │
[IT/OT Boundary Firewall] ← Protocol-aware (Modbus/DNP3/IEC-104 inspection)
    │
IT/OT DMZ (Level 3.5)
  ├── Historian Replication Server (read-only mirror)
  ├── Jump Server / Bastion Host
  ├── Remote Access Gateway
  ├── Patch Management Server (offline updates)
  └── [Data Diode] ← Unidirectional: OT→IT only
    │
OT Supervisory Network (Level 3)
  ├── Process Historian (OSIsoft PI, Wonderware)
  ├── MES Systems
  └── Operations Workstations
    │
[Zone Firewall] ← Restrict to required ICS protocols only
    │
Control Network (Level 2)
  ├── SCADA Server
  ├── DCS Consoles
  ├── HMI Workstations
  └── Engineering Workstations (EWS)
    │
Field Network (Level 1)
  └── PLCs, RTUs, Field Devices
    │
Process Sensors/Actuators (Level 0)
```

### Data Diodes (Unidirectional Security Gateways)

Data diodes enforce one-way data flow using hardware or near-hardware mechanisms. They allow historian data to flow from OT to IT for business reporting without creating a return channel.

| Vendor | Product | Key Feature |
|---|---|---|
| Waterfall Security | Unidirectional Security Gateways | Hardware-enforced; no software bypass possible |
| Owl Cyber Defense | Talon | FPGA-based unidirectional transfer |
| Fox-IT DataDiode | DataDiode | Software-defined with hardware backing |
| Nexor | Sentinel | Government/defense grade |

**Use cases for data diodes:**
- Historian replication: OSIsoft PI to PI mirror, OT→IT
- SIEM log forwarding: OT events to IT SIEM without return channel
- Firmware distribution: from IT update server to OT network (requires reverse diode or separate channel)

### OT Remote Access

**Secure remote access requirements:**
- No persistent VPN into OT network (terminated in DMZ only)
- Vendor access: time-limited, monitored sessions through jump server
- MFA required for all remote access
- Session recording for all remote access (Privileged Access Management)
- Allowlisted commands/applications (deny all unless explicitly permitted)
- Dual-control for high-risk operations (four-eyes principle)

**Vendor access options:**
1. Jump server in DMZ with vendor connecting to jump server (OT access proxied)
2. Dedicated vendor access network (separate from operations network)
3. Hardware-based vendor portal (e.g., eWon, Secomea) with policy enforcement

### Protocol-Aware Firewalls

Standard firewalls operate on IP/port. ICS environments require deep packet inspection of industrial protocols to enforce allow/deny at the function code level.

```
# Example: Palo Alto Networks App-ID for Modbus
# Allow read operations, block write operations
Security Policy: OT-Modbus-Read-Only
  Source: HMI-workstations
  Destination: PLC-network
  Application: modbus
  Service: application-default
  Action: Allow
  Profile: ICS-anomaly-detection

# Custom App-ID for Modbus write function codes
# Block FC05 (Write Single Coil), FC06 (Write Single Register),
#       FC15 (Write Multiple Coils), FC16 (Write Multiple Registers)
# from non-engineering-station sources
```

### OT Asset Inventory

Passive asset discovery is mandatory — active scanning can disrupt OT operations.

| Platform | Discovery Method | Key Capability |
|---|---|---|
| Claroty | Passive network tap + selective active | Deep protocol parsing, vulnerability mapping |
| Dragos | Passive network tap | Threat intelligence, behavior detection |
| Nozomi Guardian | Passive network tap | Process variable baselining |
| Tenable OT | Passive + Tenable.sc active scan | CVE correlation, patch gap analysis |
| Microsoft Defender for IoT | Passive sensor | Azure integration, OT/IoT focus |

---

## ICS Security Standards & Frameworks

### IEC 62443

The primary international standard series for industrial cybersecurity. Developed by ISA and adopted by IEC.

**Standard series structure:**

| Standard | Title | Key Content |
|---|---|---|
| IEC 62443-1-1 | Terminology, concepts, models | Foundational definitions |
| IEC 62443-2-1 | Security management system | CSMS requirements for asset owners |
| IEC 62443-2-3 | Patch management | OT patching procedures |
| IEC 62443-2-4 | Supplier security requirements | IACS service provider requirements |
| IEC 62443-3-2 | Security risk assessment | Zone/conduit methodology, target SL |
| IEC 62443-3-3 | System security requirements | 51 system requirements across 7 foundational requirements |
| IEC 62443-4-1 | Product security development | Secure development lifecycle for ICS vendors |
| IEC 62443-4-2 | Component security requirements | Technical requirements for IACS components |

**Security Levels (SL):**

| Level | Threat Profile | Description |
|---|---|---|
| SL 1 | Casual / Unintentional | Protection against unintentional violation |
| SL 2 | Intentional, Simple Means | Protection against intentional attack with limited resources |
| SL 3 | Intentional, Sophisticated | Protection against sophisticated attack with moderate resources |
| SL 4 | Nation-State | Protection against nation-state-level attacks with extended resources |

**Zone and Conduit Model:**
- Zones: groups of assets with common security requirements
- Conduits: communication channels between zones; must be explicitly defined and controlled
- Every connection between zones must traverse a conduit (firewall, data diode)
- Each zone has a target Security Level based on risk assessment

### NIST SP 800-82 Rev 3

Published September 2023. Guide to Operational Technology (OT) Security.

**Key changes in Rev 3:**
- Updated threat landscape including ransomware, cloud OT, and remote access risks
- Expanded OT security program guidance
- ICS-specific control overlays for NIST SP 800-53 Rev 5
- Cloud, virtualization, and remote access considerations
- Supply chain risk management for OT

**Security program elements:**
1. Establish OT security governance and policy
2. Asset inventory (passive discovery mandatory)
3. Network architecture review and segmentation
4. Risk assessment (system characterization → threat identification → vulnerability identification → likelihood determination → impact analysis → risk determination)
5. Security controls implementation (800-53 Rev 5 OT overlay)
6. Configuration management
7. Incident response planning
8. Continuous monitoring

### NERC CIP (North American Electric Reliability Corporation Critical Infrastructure Protection)

Mandatory cybersecurity standards for North American bulk electric system (BES) operators.

| Standard | Title | Key Requirements |
|---|---|---|
| CIP-002 | BES Cyber System Categorization | Identify and categorize BES Cyber Systems as High/Medium/Low impact |
| CIP-003 | Security Management Controls | Cybersecurity policies and leadership accountability |
| CIP-004 | Personnel & Training | Background checks, access authorization, security training |
| CIP-005 | Electronic Security Perimeters | Define and protect Electronic Security Perimeters (ESP); control all access points |
| CIP-006 | Physical Security | Physical security plans, monitoring, visitor control |
| CIP-007 | Systems Security Management | Ports/services management, patch management, security event monitoring |
| CIP-008 | Incident Reporting & Response | Incident response plans, 1-hour reporting to E-ISAC/CISA |
| CIP-009 | Recovery Plans | Business continuity and recovery procedures for BES Cyber Systems |
| CIP-010 | Configuration Change Management | Baseline configurations, change control, vulnerability assessments |
| CIP-011 | Information Protection | Protect BES Cyber System information in storage and transit |
| CIP-013 | Supply Chain Risk Management | Vendor risk management for high/medium-impact BES systems |
| CIP-014 | Physical Security of Transmission Stations | Risk assessment of transmission substations |

**NERC CIP enforcement:**
- FERC (Federal Energy Regulatory Commission) has enforcement authority
- Violations can result in fines up to $1M per day per violation
- Registered entities must report violations to ERO/E-ISAC

### MITRE ATT&CK for ICS

- URL: https://attack.mitre.org/matrices/ics/
- 12 tactics, 83+ techniques
- Covers: Control Systems, Safety Systems, Engineering, Field Devices
- Integrated with MITRE D3FEND for defensive countermeasure mapping
- Used for: threat model coverage, detection development, red team planning

### Other Key References

| Resource | Description | URL |
|---|---|---|
| CISA ICS-CERT | Advisories, alerts, and vulnerability disclosures | https://www.cisa.gov/ics |
| CISA CSET | Cyber Security Evaluation Tool for ICS self-assessment | https://www.cisa.gov/resources-tools/services/cyber-security-evaluation-tool |
| Idaho National Lab | ICS security research, red team methodologies | https://inl.gov/cybersecurity |
| SANS ICS | ICS security training and certifications (GICSP, GRID) | https://www.sans.org/industrial-control-systems-security/ |
| Dragos Year in Review | Annual ICS threat landscape report | https://www.dragos.com/year-in-review/ |
| ICS-CERT Monitor | Historical newsletter archive | https://www.cisa.gov/resources-tools/resources/ics-cert-monitor |

---

## ICS Vulnerability Management

### Why OT Patching is Different

| IT Factor | OT Reality |
|---|---|
| Monthly patch cycles | No defined patch windows; uptime requirements (99.999%) |
| Automated patch deployment | Manual, vendor-certified patch process |
| Test environment available | Rarely exists; no production duplicate |
| OS upgrades accepted | 15-20 year device lifecycles; hardware may not support new OS |
| Third-party software updates | Vendor qualification required; patches must be certified |
| Security scanner deployment | Active scanning can crash PLCs |

### Virtual Patching

When physical patching is impossible (EOL systems, vendor certification delays), virtual patching via IDS/IPS rules can mitigate known vulnerabilities without changing the target system.

```
# Snort/Suricata rule for S7comm unauthorized stop command
alert tcp any any -> $OT_NETWORK 102 (
  msg:"ICS S7comm CPU Stop Command Detected";
  flow:established,to_server;
  content:"|03 00|";  # TPKT
  content:"|28|";     # S7comm function code for stop
  offset:17; depth:1;
  classtype:attempted-admin;
  sid:9000001; rev:1;
)

# Snort rule for Modbus write to restricted holding registers
alert tcp $EXTERNAL_NET any -> $OT_PLCS 502 (
  msg:"ICS Modbus Write to Critical Setpoint Register";
  flow:established,to_server;
  content:"|00 00 00 00|"; offset:0; depth:4;  # MBAP header
  byte_test:1,=,6,7;  # Function code 06 (Write Single Register)
  byte_test:2,>,99,8,big;  # Register address > 99 (restricted range)
  classtype:attempted-admin;
  sid:9000002; rev:1;
)
```

### ICS Vulnerability Tracking Sources

| Source | Description | Frequency |
|---|---|---|
| CISA ICS-CERT Advisories | Official US government ICS CVE disclosures | Continuous |
| Dragos Year in Review | ICS threat and vulnerability landscape | Annual |
| Claroty Biannual ICS Report | Vulnerability trends across ICS vendors | Semi-annual |
| Project Basecamp (DigitalBond) | PLC vulnerability research | Historical |
| S4 Conference | Leading ICS security research venue | Annual |
| SecurityMatters VulnDB | Commercial ICS vulnerability database | Continuous |

### Notable ICS Vulnerability Classes

**Siemens SIMATIC S7:**
- CVE-2019-13945 / CVE-2019-18340: Unauthenticated access to S7-1500 series
- CVE-2019-10929: S7comm-Plus vulnerability allowing unauthorized access
- Replay attack vulnerabilities in S7-300/400 due to lack of session authentication

**Schneider Electric:**
- CVE-2018-7844 to CVE-2018-7853: EcoStruxure remote code execution vulnerabilities
- Multiple Modicon M340 vulnerabilities (authentication bypass, DoS)

**Rockwell Automation FactoryTalk:**
- CVE-2012-6435 to CVE-2012-6437: FactoryTalk RCE via CIP protocol
- Multiple Studio 5000/RSLogix vulnerabilities

**General/Cross-Platform:**
- OPC DA running on unpatched Windows XP/2003 (extremely common)
- Default/hardcoded credentials in HMI software
- Unencrypted firmware updates via USB or FTP

---

## ICS Detection & Monitoring

### Detection Philosophy for OT

OT detection differs fundamentally from IT because:
1. Legitimate traffic is highly predictable (deterministic)
2. Process values have physical constraints (temperature cannot jump 100°C in 1 second)
3. Engineering changes should be rare and scheduled
4. Protocol function codes have expected usage patterns

### Network-Based Detection Approaches

**Baseline deviation detection:**
```
Normal: Modbus Read (FC03) from HMI to PLC every 500ms
Alert: Modbus Write (FC06) from any source — should be extremely rare
Alert: Any Modbus traffic outside scheduled maintenance window from EWS
Alert: Unknown source IP communicating on port 502
```

**Protocol anomaly detection:**
```
Alert: Malformed Modbus packet (invalid function code >127 without error bit)
Alert: DNP3 unsolicited response flooding (could indicate compromised RTU)
Alert: S7comm job message with unauthorized program download function (0x50)
Alert: IEC-104 ASDU type 45 (Single Command) or 46 (Double Command) from non-SCADA source
Alert: OPC UA anonymous authentication (NoSecurity endpoint) connection
```

**Asset behavior anomaly detection:**
- PLC transitions from RUN to PROG mode outside maintenance windows
- EWS connecting to PLC outside scheduled change windows
- New device appearing on OT network (unauthorized asset)
- DNS queries from Level 1/2 network (OT devices should not need DNS)
- HTTP/HTTPS traffic from OT network (C2 indicator)

### Dragos Platform

Dragos is purpose-built for OT threat detection with the deepest ICS protocol support.

**Key capabilities:**
- Asset identification via passive protocol parsing (300+ protocols)
- Vulnerability assessment mapped to discovered assets
- Threat behavior detection (TBs) mapped to ATT&CK for ICS
- Threat intelligence integration (Dragos WorldView)
- Playbook-driven analyst workflow
- Protocol and asset context preserved in investigations

**Detection coverage for major threat groups:**
- TRIDENT (TRITON-related): SIS access pattern detection
- CHERNOVITE (Industroyer2-related): IEC-104 command anomalies
- ELECTRUM: Engineering station access patterns
- KAMACITE (Sandworm initial access): IT/OT pivot detection

### Nozomi Networks Guardian

**Key capabilities:**
- Passive DPI for 100+ ICS/IoT protocols
- Machine learning-based behavioral anomaly detection
- Process data monitoring (correlate network with process variable changes)
- IT/OT network visibility in single pane
- Vulnerability assessment and CVE correlation
- Integration with Splunk, ServiceNow, Palo Alto XSOAR

### ICS SIEM Integration

```yaml
# Sample Splunk query for Modbus write operations
index=ics sourcetype=modbus_tcp
| where function_code IN (5, 6, 15, 16)  # Write function codes
| stats count by src_ip, dest_ip, function_code, register_address
| where count > 0
| eval risk = case(
    function_code=16 AND register_address < 100, "CRITICAL",
    function_code IN (5,6), "HIGH",
    1=1, "MEDIUM"
  )
| sort -risk
```

**Key log sources to integrate:**
- Historian: process variable data (baseline deviations)
- EWS: PLC programming software access logs
- HMI: operator login/logout, alarm acknowledgments, setpoint changes
- Jump server: all remote access sessions (record and log)
- ICS-aware IDS (Dragos, Claroty, Nozomi) alerts

---

## ICS Incident Response

### Key Differences from IT Incident Response

| IT IR | OT IR |
|---|---|
| Contain → Eradicate → Recover | Safety assessment → Contain → Notify OEM → Recover |
| Take system offline immediately | Cannot shut down power plant / water treatment arbitrarily |
| Standard forensic tools (FTK, Volatility) | Limited agents; PLC forensics requires OEM tools |
| OS-level visibility | PLCs have no OS logging; forensics from network captures |
| IR team works independently | Must coordinate with process engineers and operations |
| Recovery from backups within hours | PLC logic restoration requires testing; may take days |

### Incident Response Phases for ICS

**Phase 1: Safety First**
- Assess if process is in safe state before any IR actions
- Notify plant/site management and safety officer
- Determine if manual operation is possible if systems are taken offline
- Identify which systems are safety-critical vs. non-critical

**Phase 2: Containment (without disrupting safe process)**
- Network isolation: remove compromised EWS from network (not from process)
- Block lateral movement paths at IT/OT boundary
- Disable compromised accounts at AD level
- Do NOT take PLC offline unless process can be safely halted

**Phase 3: Evidence Collection**
- Network packet captures (out-of-band TAP — not inline — to avoid disruption)
- Historian data export (process variable timeline)
- HMI screenshots and alarm logs
- EWS forensic image (can be taken offline for imaging)
- Log collection from jump servers, firewalls, SCADA servers
- PLC logic dump (with OEM support) — compare against known-good backup

**Phase 4: Analysis**
- Timeline reconstruction using network captures and historian data
- Identify unauthorized Modbus/S7/IEC-104 commands in packet captures
- Compare current PLC logic to approved baseline
- Analyze EWS for malicious code, unauthorized project files
- Identify initial access vector (VPN logs, email, USB)

**Phase 5: Recovery**
- Restore PLC logic from verified backup (stored offline, hash-verified)
- Test restored logic before returning to production
- Apply emergency patches or configuration hardening
- Verify process values are within normal range before restart
- Confirm SIS functionality before starting process

**Phase 6: Post-Incident**
- Root cause analysis
- Regulatory notification (NERC CIP-008 requires 1-hour notification for high-impact; CISA reporting)
- Update playbooks and detection rules
- Implement preventive controls to prevent recurrence

### ICS IR Resources

| Resource | Contact | Description |
|---|---|---|
| CISA ICS-CERT | 888-282-0870 | 24/7 OT incident assistance; can deploy DART team |
| Dragos IR | dragos.com/services | OT-native IR with protocol analysis |
| Claroty IR | claroty.com | OT IR with asset context |
| Mandiant OT IR | fireeye.com/services | Experience with TRITON, Industroyer investigations |
| Nozomi Networks | nozominetworks.com/services | OT-focused IR |

### Lessons from Major ICS Incidents

**Colonial Pipeline (May 2021):**
- DarkSide ransomware hit IT network via compromised VPN account (no MFA)
- OT was proactively shut down as a precaution (not directly attacked)
- 5,500-mile pipeline offline for 6 days; $4.4M ransom paid
- Key lesson: MFA on all remote access; OT and IT recovery plans must be integrated
- Fuel shortages across southeastern US demonstrated cascading physical impact

**Oldsmar Water Treatment (February 2021):**
- Attacker accessed HMI via TeamViewer; attempted to raise NaOH to 111x normal
- Operator observed cursor moving and reversed change; no harm resulted
- Key lesson: remote access to HMI requires logging, MFA, and session recording; remove TeamViewer

**Ukraine Power Grid 2015:**
- BlackEnergy malware; attackers observed for 6 months before attack
- Spear-phishing → IT → OT pivot → HMI takeover → breakers opened
- Operators locked out; 225,000 customers lost power for 1-6 hours
- Key lesson: IT/OT boundary monitoring; HMI workstation hardening; operator lockout detection

---

## Physical Security for ICS

Physical security is an integral layer of ICS defense. Sophisticated nation-state actors often combine cyber and physical access.

### Control Room and Substation Security

**Physical access controls:**
- Perimeter fencing with anti-climb features around substations and plants
- Multi-layer badge access: perimeter → building → control room → server room
- Video surveillance with minimum 90-day retention
- Mantrap / airlock entry for high-security areas
- 24/7 security monitoring for unmanned substations
- Motion detection with alarm integration

**Tailgating and social engineering:**
- Two-person integrity rule: no single person left alone with critical equipment
- Visitor escorted at all times in OT areas
- Vendor access tied to specific systems with supervisor approval
- Badge readers with anti-passback enforcement

### Removable Media Controls

Removable media is a primary ICS attack vector (Stuxnet, Dragonfly, TRITON all used USB-based delivery).

```
# Group Policy: Disable USB storage on all OT workstations
Computer Configuration > Administrative Templates > System > Removable Storage Access
"All Removable Storage classes: Deny all access" = Enabled

# For legitimate patch delivery via USB:
1. Dedicated "clean" laptop for downloading patches (air-gapped from corporate)
2. USB scanning station (Dragos, Honeywell Secure Media Exchange)
3. Hash verification before installation
4. Document chain of custody for each USB device
```

**Honeywell Secure Media Exchange (SMX):**
- Hardware kiosk for scanning and approving USB devices
- Blocks unapproved devices from entering OT environment
- Logs all media access attempts
- Deployed at plant entrances

### Portable Device Policy

- No personal mobile phones in high-security OT areas (camera/wireless concerns)
- Dedicated OT laptops: never connected to internet or corporate IT
- Tablet/ruggedized device policy: pre-approved apps only, MDM-enrolled
- Bluetooth and Wi-Fi disabled on all OT workstations where possible

### Insider Threat in ICS

Insider threats in ICS environments are particularly dangerous due to authorized physical and logical access to critical systems.

**High-risk scenarios:**
- Disgruntled employee with PLC programming access (EWS access + process knowledge)
- Contractor with remote access credentials (hard to revoke; often persist after project)
- Supply chain insider: compromised vendor with support access

**Controls:**
- Separation of duties: no single individual should be able to modify PLC logic and approve the change
- Dual control for critical operations: two-person sign-off for setpoint changes above threshold
- User activity monitoring on EWS: record all PLC project opens, compiles, downloads
- Periodic access reviews: revoke contractor access immediately upon project completion
- Background checks for all personnel with OT access
- Whistleblower program for reporting suspicious behavior

---

## Quick Reference Checklists

### ICS Security Assessment Checklist

**Network Architecture:**
- [ ] IT/OT firewall in place with documented ruleset
- [ ] No direct connectivity from Level 4 to Level 2 or lower
- [ ] DMZ with historian replication and jump server
- [ ] Data diode for historian OT→IT data flow
- [ ] Remote access terminates in DMZ (not directly to OT)
- [ ] Protocol-aware firewall with ICS DPI capability

**Access Control:**
- [ ] Unique accounts for all OT users (no shared credentials)
- [ ] MFA on all remote access
- [ ] Privileged access management with session recording
- [ ] Account management process for contractor access (time-limited)
- [ ] EWS access restricted to authorized engineers
- [ ] Default credentials changed on all ICS devices

**Endpoint Security:**
- [ ] Application whitelisting on all HMI/EWS (no internet browsing)
- [ ] USB media controls (block or managed via SMX)
- [ ] Patch management process with risk-based scheduling
- [ ] Host-based monitoring (where agent deployment is feasible)
- [ ] Antivirus with offline signature updates

**Detection and Monitoring:**
- [ ] Passive ICS network monitoring (Dragos/Claroty/Nozomi)
- [ ] ICS protocol anomaly detection configured
- [ ] OT events forwarded to SIEM with ICS context
- [ ] Alert on PLC mode changes outside maintenance windows
- [ ] Alert on write operations from non-EWS sources

**Incident Response:**
- [ ] OT-specific IR plan documented and tested
- [ ] PLC logic backups stored offline with hash verification
- [ ] OEM support contacts current
- [ ] CISA ICS-CERT contact information posted
- [ ] Tabletop exercise conducted in last 12 months

---

*Reference compiled for cybersecurity professionals. All tool usage against live systems requires explicit authorization. ICS scanning carries risk of operational disruption — always use passive methods first.*
