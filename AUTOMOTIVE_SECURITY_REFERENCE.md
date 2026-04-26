# Automotive Security Reference

> Comprehensive reference for vehicle cybersecurity, CAN bus attacks, ECU security, OTA update integrity, V2X protocols, and automotive penetration testing.

---

## Table of Contents

1. [Automotive Attack Surface](#1-automotive-attack-surface)
2. [CAN Bus Security](#2-can-bus-security)
3. [Automotive Network Architecture](#3-automotive-network-architecture)
4. [ECU Security](#4-ecu-security)
5. [OTA Update Security](#5-ota-update-security)
6. [V2X (Vehicle-to-Everything) Security](#6-v2x-vehicle-to-everything-security)
7. [Key Fob and Immobilizer Security](#7-key-fob-and-immobilizer-security)
8. [ADAS and Autonomous Vehicle Security](#8-adas-and-autonomous-vehicle-security)
9. [Regulatory and Standards](#9-regulatory-and-standards)
10. [Automotive Penetration Testing](#10-automotive-penetration-testing)

---

## 1. Automotive Attack Surface

### 1.1 Vehicle Connectivity Interfaces

Modern vehicles are no longer isolated mechanical systems — they are rolling networks with dozens of external connectivity channels, each representing a distinct attack surface.

#### OBD-II Port
The On-Board Diagnostics II (OBD-II) port, mandated in all US vehicles since 1996 and EU vehicles since 2001, provides direct access to the vehicle's internal CAN bus network. Located under the dashboard, typically within 60 cm of the steering wheel, the OBD-II port uses a standardized 16-pin connector (SAE J1962) and exposes:

- **Pin 4/5**: Chassis and signal ground
- **Pin 6**: CAN High (ISO 15765-4 / SAE J2284)
- **Pin 7**: ISO 9141-2 K-Line
- **Pin 14**: CAN Low
- **Pin 15**: ISO 9141-2 L-Line
- **Pin 16**: Battery positive (12V)

Physical access to the OBD-II port allows an attacker to read and inject CAN frames, perform UDS diagnostic sessions, read/write ECU memory, and install persistent dongles (OBD-II trackers, insurance dongles) that maintain persistent network presence.

**Attack scenario**: An attacker with brief physical access (valet parking, car rental return, service center) can install a malicious OBD-II dongle that bridges the CAN bus to a cellular or Bluetooth radio, enabling remote access for weeks or months.

#### Bluetooth
Automotive Bluetooth (typically Bluetooth 4.x/5.x BR/EDR and BLE) is used for hands-free calling, audio streaming (A2DP), phone book access (PBAP), and increasingly for digital key functions. Attack vectors include:

- **BlueBorne (CVE-2017-1000251)**: Stack-based buffer overflow in Linux Bluetooth stack, affects many infotainment head units running Linux
- **BIAS (Bluetooth Impersonation Attacks)**: Exploits weaknesses in Bluetooth Classic authentication, allowing device impersonation without the link key
- **BLE pairing attacks**: MITM during pairing if Just Works mode is used
- **Fuzzing the Bluetooth stack**: Sending malformed HCI/L2CAP/RFCOMM/SDP packets to crash or exploit the infotainment system
- **CarWhisperer**: Classic tool demonstrating default PIN exploitation on hands-free kits

Bluetooth range is typically 10–100 meters, making parking lot proximity attacks feasible without requiring physical access.

#### Wi-Fi
Vehicles with Wi-Fi hotspot capability (4G/5G-based) or Wi-Fi-based software updates expose 802.11 attack surfaces:

- **WPA2 KRACK attacks**: Key Reinstallation Attacks affecting in-vehicle Wi-Fi clients
- **Evil twin access points**: Spoofing the vehicle's expected update server SSID
- **Guest network pivoting**: If infotainment Wi-Fi client is on same segment as CAN gateway
- **WPS vulnerabilities**: Some head units enable WPS with weak PIN implementations
- Tesla's infotainment system uses Wi-Fi for OTA downloads; Keen Security Lab demonstrated Wi-Fi-based attack chains in 2016-2020

#### Cellular (4G/5G)
Telematics Control Units (TCUs) provide always-on cellular connectivity for:
- eCall (emergency call) — mandatory in EU since 2018
- Remote diagnostics and OTA updates
- Stolen vehicle tracking
- Remote services (lock/unlock, start, climate control)
- V2N (Vehicle-to-Network) communications

Cellular attack surface includes:
- **SS7/Diameter attacks**: Location tracking and call interception via telecom backbone
- **IMSI catchers (Stingrays)**: Forcing cellular downgrade to 2G/3G where encryption is weaker
- **SIM cloning**: Physical SIM cards in older TCUs can be cloned if accessed
- **eSIM management interface**: Remote SIM provisioning attacks (SGP.02/SGP.22 vulnerabilities)
- **Backend API attacks**: TCU communicates with OEM cloud backend; API endpoints may be vulnerable to authentication bypass, IDOR, or injection

The TCU is a high-value target because it provides remote access to the vehicle from anywhere in the world. Compromise of the backend server combined with TCU vulnerability = mass remote vehicle compromise.

#### V2X: DSRC and C-V2X
Vehicle-to-Everything (V2X) communications enable vehicles to communicate with infrastructure, other vehicles, pedestrians, and the network. Two competing standards exist:

**DSRC (Dedicated Short-Range Communications)**:
- Based on IEEE 802.11p (WAVE - Wireless Access in Vehicular Environments)
- 5.9 GHz band (5.850–5.925 GHz in US, 5.875–5.905 GHz in EU)
- WAVE Short Message Protocol (WSMP) and IPv6 over WAVE
- Range: ~300-1000m
- Latency: <10ms
- Deployed in US infrastructure (USDOT pilots), Japan (ITS Connect)

**C-V2X (Cellular V2X)**:
- LTE-V2X (PC5 interface, Rel-14): Direct sidelink communication without network
- NR-V2X (5G NR, Rel-16): Enhanced for URLLC use cases
- Also supports Uu interface (via base station) for V2N
- Backed by Qualcomm, OEMs moving toward C-V2X for new deployments

Both technologies broadcast Basic Safety Messages (BSMs in US, CAMs in EU) at 10 Hz containing position, speed, heading, and size — creating significant privacy implications and spoofing attack surfaces.

### 1.2 External Attack Vectors

#### Key Fob Relay Attacks
Passive Entry Passive Start (PEPS) systems use low-frequency (125 kHz LF) wake signals and ultra-high-frequency (315/433/868 MHz UHF) response signals. Relay attacks work by:

1. Attacker 1 stands near the vehicle and broadcasts a fake LF wake signal using a portable relay device
2. Attacker 2 stands near the key fob (inside a house, restaurant, pocket) and captures the LF signal via a receive/transmit device
3. The key fob responds with its UHF unlock code
4. Attacker 1 relays the UHF response back to the vehicle
5. Vehicle unlocks as if the key fob is physically present

Commercial relay attack kits cost $200-$1000 and are openly sold. The attack takes under 60 seconds. Affected vehicles include virtually all PEPS-equipped cars without ultrawideband (UWB) ranging defense.

#### OTA Update Hijacking
Over-the-Air (OTA) update mechanisms can be hijacked via:
- **DNS hijacking**: Redirecting OTA server domains to attacker-controlled servers
- **BGP hijacking**: Rerouting IP traffic at the routing layer
- **Certificate pinning bypass**: If the vehicle client doesn't properly validate TLS certificates
- **Compromised update backend**: Supply chain attack on OEM's update infrastructure
- **Man-in-the-middle on unencrypted channels**: Older vehicles may use HTTP for update checks

#### Charging Infrastructure Attacks
EV charging infrastructure introduces new attack vectors:
- **OCPP (Open Charge Point Protocol)** vulnerabilities in charging station management
- **ISO 15118 (Vehicle-to-Grid communication)**: PLC-based communication over charging cable
  - Power Line Communication (PLC) provides IP connectivity between vehicle and EVSE
  - Researchers have demonstrated MITM attacks on ISO 15118 sessions
  - "Brokenwire" attack (2022): High-power electromagnetic interference disrupts CCS charging
- **Charging station network breaches**: SolarWinds-style supply chain attacks on charging networks
- **Malicious firmware in charging stations**: Could exfiltrate vehicle VINs, payment data

### 1.3 Physical Attack Vectors

#### OBD-II Dongle Attacks
Third-party OBD-II dongles (Metromile, Progressive Snapshot, fleet trackers) have been found to contain significant vulnerabilities:

- **Bosch Drivelog Connect dongle (2016)**: Unauthenticated Bluetooth, allowed CAN injection
- **Zubie GPS tracker**: Default credentials, unencrypted cloud communication
- **Progressive Snapshot**: Binary reverse-engineered showing minimal security
- Attack methodology:
  1. Purchase same dongle model used by target
  2. Reverse engineer firmware via JTAG or UART
  3. Identify authentication bypass or RCE vulnerability
  4. Exploit remotely via cellular (if dongle has SIM) or proximity (Bluetooth/Wi-Fi)

#### USB and CAN Injection
- **USB attacks on infotainment**: Autorun exploits, malformed media files triggering parser vulnerabilities (mp3, mp4, jpg parsers in infotainment systems), BadUSB-style attacks with malicious HID devices
- **CAN injection via diagnostics**: Physical access to OBD-II allows direct CAN frame injection
- **CAN injection via compromised ECU**: If one ECU is compromised, it can inject frames onto shared bus segments

### 1.4 Attack Surface Map

#### ECU Count in Modern Vehicles
Modern vehicles contain between 70 and 150+ ECUs (Electronic Control Units) depending on model and feature set:

| Domain | Typical ECUs | Examples |
|--------|-------------|---------|
| Powertrain | 5-15 | ECM, TCM, Battery Management, Fuel Injection |
| Chassis | 8-20 | ABS/ESC, EPS, Suspension Control, Brake Booster |
| Body | 15-30 | BCM, Door Modules, Seat Control, HVAC, Lighting |
| ADAS | 5-20 | Forward Collision, Lane Keep, Adaptive Cruise, Parking Assist |
| Infotainment | 3-8 | HMI, Audio Amplifier, Navigation, Rear Seat Entertainment |
| Telematics | 2-5 | TCU, eCall Module, V2X Unit |
| Safety | 3-8 | Airbag Control, Occupant Detection, Seatbelt Pretensioner |

A 2023 luxury vehicle may have 150 ECUs running 100+ million lines of code — more complex than many enterprise software systems.

#### Network Topology
Modern vehicle networks use a segmented architecture:

```
[Telematics/TCU] ←cellular→ [OEM Backend]
       |
[Central Gateway ECU] ←OBD-II port
       |
   ┌───┼───────────┬──────────────┐
   |   |           |              |
[CAN-Powertrain] [CAN-Chassis] [CAN-Body] [Automotive Ethernet/ADAS]
  ECM, TCM       ABS, EPS      BCM, Doors   Cameras, LIDAR, RADAR
```

The Central Gateway ECU (CGW) is critical security infrastructure — it bridges domains and should enforce firewall rules between segments. In practice, many CGWs have been found to pass messages with insufficient filtering.

### 1.5 High-Profile Automotive Hacks

#### Jeep Cherokee Remote Exploit (Miller & Valasek, 2015)
Charlie Miller and Chris Valasek published their attack at DEF CON 23, demonstrating complete remote compromise of a 2014 Jeep Cherokee via the cellular network:

**Attack chain**:
1. **Entry point**: Sprint cellular network — the Sprint SIM in the Harman Kardon head unit (UConnect) was on a carrier network that allowed Sprint subscribers to reach any other Sprint device by IP address
2. **Target the head unit**: UConnect ran a D-Bus service that was exploitable without authentication on the carrier network
3. **Pivot to CAN bus**: The head unit was connected to the V850 chip that had direct CAN bus access for audio/HVAC controls
4. **Re-flash the V850**: Wrote custom firmware to V850 to send arbitrary CAN frames
5. **Vehicle control**: Demonstrated steering (at low speed), brakes, acceleration, and disable

**Impact**: Fiat Chrysler recalled 1.4 million vehicles. The researchers had responsibly disclosed 9 months prior.

**Technical details**:
- UConnect ran QNX operating system
- D-Bus interface `com.harman.service.UpdateManager` was network-reachable
- GPS coordinates were broadcast in SSID of UConnect Wi-Fi
- V850 firmware update mechanism had no signature verification

#### Tesla Keen Lab Attacks (2016-2023)
Tencent Keen Security Lab published multiple attack chains against Tesla vehicles:

**2016 Attack (Model S)**:
- Entry via malicious Wi-Fi network at Tesla charging station
- Exploit in WebKit browser in infotainment
- Pivot to gateway ECU
- CAN bus control: brakes, door locks, seat movement
- Full remote control via internet while vehicle was moving at highway speed

**2017 Attack**:
- Autopilot spoofing via adversarial lane markings
- Demonstrated misleading the EyeQ vision processor

**2020 Attack (Model X)**:
- Key fob Bluetooth vulnerability
- BLE pairing attack allowing key cloning
- Physical ECU access via Falcon wing door controller

**2022/2023 Attacks**:
- CAN bus injection via in-vehicle charging port (J1772)
- MCU firmware analysis revealing hardcoded credentials

---

## 2. CAN Bus Security

### 2.1 CAN Bus Fundamentals

Controller Area Network (CAN), developed by Bosch in 1983 and standardized as ISO 11898, is the dominant in-vehicle network protocol. Understanding CAN is foundational for automotive security research.

#### Arbitration and Message Priority
CAN uses a multi-master, broadcast bus with non-destructive bitwise arbitration:

1. All nodes simultaneously begin transmitting their message ID
2. Each node monitors the bus while transmitting
3. A node transmitting a recessive bit (logic 1) that sees a dominant bit (logic 0) loses arbitration and stops transmitting
4. Lower message IDs win arbitration (ID 0x001 beats 0x002)
5. The winner continues transmission without interruption

**Security implication**: An attacker can guarantee message delivery by using low message IDs. By flooding with ID 0x000, legitimate high-priority messages can still get through (0x000 always wins), but an attacker using very low IDs can dominate the bus.

#### Broadcast Nature
Every message sent on a CAN bus is received by every node on that bus segment. There is no addressing — a node's CAN ID is a message type identifier, not a node address. Any ECU can receive any message.

**Security implication**: There is no confidentiality on CAN. Any device connected to the bus (OBD-II dongle, malicious ECU) can passively eavesdrop on all communications including vehicle speed, steering angle, key state, door lock status, etc.

#### CAN Bus Speed
- Low-speed CAN (ISO 11898-3): 10-125 kbps — body electronics
- High-speed CAN (ISO 11898-2): 125 kbps - 1 Mbps — powertrain, chassis
- CAN-FD (ISO 11898-1:2015): Up to 8 Mbps data phase — ADAS applications

### 2.2 CAN Frame Structure

```
 SOF  | Arbitration Field | Control Field |   Data Field   |  CRC  | ACK | EOF
  1   |    11 or 29 bits  |    6 bits     |   0-64 bytes   | 16+1  |  2  |  7
 bit  |  (standard/ext)   |  (IDE + DLC)  | (CAN-FD: 0-64) | bits  |bits | bits
```

**Standard Frame (11-bit ID)**:
- **SOF (Start of Frame)**: Single dominant bit marking frame start
- **Arbitration Field**: 11-bit Message ID + RTR (Remote Transmission Request) bit
- **IDE (Identifier Extension)**: 0 = standard frame, 1 = extended frame
- **r0**: Reserved bit
- **DLC (Data Length Code)**: 4 bits, values 0-8 indicating data byte count
- **Data Field**: 0-8 bytes of payload
- **CRC Field**: 15-bit CRC + 1 delimiter bit (polynomial: x^15 + x^14 + x^10 + x^8 + x^7 + x^4 + x^3 + 1)
- **ACK Field**: 1 ACK slot bit + 1 delimiter (any receiver acknowledges by writing dominant)
- **EOF**: 7 recessive bits

**Extended Frame (29-bit ID)**:
- 11-bit base ID + SRR (Substitute Remote Request) + IDE=1 + 18-bit extension ID

**CAN-FD Differences**:
- BRS (Bit Rate Switch): signals switch to faster data-phase bit rate
- ESI (Error Status Indicator)
- Data field: up to 64 bytes
- 21-bit CRC for data > 16 bytes

### 2.3 CAN Bus Vulnerabilities

#### No Authentication
CAN has zero authentication. Any node on the bus can send any message with any ID. There is no way for a receiving ECU to verify that a brake command came from the ABS ECU versus a malicious dongle in the OBD-II port.

**Attack implications**:
- Impersonate any ECU
- Send spoofed sensor readings (fake vehicle speed, fake steering angle)
- Send spoofed commands (disengage brakes, disable ESC, unlock doors)
- Inject diagnostic messages triggering ECU state changes

#### Replay Attacks
CAN frames contain no sequence numbers, timestamps, or nonces. A captured frame can be replayed at any time and will be accepted as legitimate.

**Example**: Capture the CAN frames transmitted when pressing the unlock button. Replay them later to unlock the vehicle — the ECU has no way to distinguish the replayed frame from a legitimate one.

#### Message Flooding / Denial of Service
CAN bus has finite bandwidth. Flooding the bus with high-priority messages causes:
- Legitimate messages to be delayed or dropped
- Critical safety systems (ABS, ESC, airbag) to lose communication
- ECU watchdog timeouts potentially causing ECU resets
- Bus-off condition: an ECU that detects too many errors enters bus-off state and stops participating

**Bus-off attack**: Deliberately cause bit errors on targeted ECU's transmissions by injecting dominant bits during the ACK slot, forcing the ECU into bus-off state (disconnected from bus). This can disable specific safety ECUs.

### 2.4 CAN Tools: CANhacker and SocketCAN

#### SocketCAN (Linux CAN Framework)
SocketCAN provides a standardized Linux kernel interface for CAN:

```bash
# Install can-utils
sudo apt-get install can-utils

# List CAN interfaces
ip link show type can

# Set CAN interface bitrate and bring up
sudo ip link set can0 type can bitrate 500000
sudo ip link set can0 up

# Verify interface is up
ip -details link show can0

# Dump all CAN traffic (raw)
candump can0

# Dump with timestamps and ASCII
candump -ta -x can0

# Dump specific ID range
candump can0,100:7FF

# Log to file
candump -l can0
# Creates candump-YYYY-MM-DD_HH-MM-SS.log

# Send a single CAN frame
# Format: cansend <interface> <ID>#<data>
cansend can0 7DF#0201050000000000

# Send extended frame
cansend can0 18DB33F1#0201050000000000

# Generate random CAN traffic for fuzzing
cangen can0 -g 1 -I r -L r -D r -v

# Replay a captured log
canplayer -I candump-2024-01-01_12-00-00.log

# Log and replay with timing
canlogger -l capture.log can0
canplayer -I capture.log -l 1

# Interactive CAN viewer
cansniffer can0

# CAN bus statistics
canstat can0

# CAN bit timing calculator
cal_cbt  # part of can-utils

# Virtual CAN for testing
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

#### Python-CAN Library
```python
import can

# Connect to interface
bus = can.interface.Bus(channel='can0', bustype='socketcan')

# Send a message
msg = can.Message(arbitration_id=0x7DF, data=[0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00], is_extended_id=False)
bus.send(msg)

# Receive messages
while True:
    msg = bus.recv(timeout=1.0)
    if msg:
        print(f"ID: {hex(msg.arbitration_id)}, Data: {msg.data.hex()}")

# Periodic sender
task = bus.send_periodic(msg, period=0.1)  # 100ms interval
import time; time.sleep(10)
task.stop()
```

#### CANalyzer / CANoe (Vector)
Professional tools used by OEMs and Tier 1 suppliers:
- Database-driven: loads .dbc files defining message/signal encoding
- Stimulation: send predefined or scripted messages
- CANalyzer: passive analysis and stimulation
- CANoe: full simulation including simulated ECU nodes (CAPL scripts)

```
# CAPL (CAN Access Programming Language) example
on message 0x301 {
    if (this.byte(0) > 100) {
        output(this);  // re-transmit
    }
}
```

#### Scapy Automotive Layers
```python
from scapy.contrib.automotive.obd.obd import OBD
from scapy.contrib.automotive.uds import UDS
from scapy.contrib.cansocket import CANSocket

# OBD-II query for engine RPM (PID 0x0C)
pkt = OBD()/OBD_S01(pid=[OBD_S01_PID_0x0C()])

# UDS ReadDataByIdentifier
uds_pkt = UDS()/UDS_RDBI(dataIdentifier=0xF190)  # Read VIN
```

### 2.5 OBD-II Diagnostic Protocol

OBD-II uses a request/response model on CAN. The standard diagnostic request address is 0x7DF (functional addressing, all ECUs respond) or 0x7E0-0x7E7 (physical addressing, specific ECU).

#### PID Structure
```
Request: [Length][Mode][PID][Padding...]
Response: [Length][Mode+0x40][PID][Data...]

Example - Request Engine RPM (Mode 01, PID 0x0C):
TX: 7DF#02 01 0C 00 00 00 00 00
RX: 7E8#04 41 0C XX XX 00 00 00
RPM = ((A*256)+B) / 4  where A=XX, B=XX
```

#### OBD-II Modes
| Mode | Description |
|------|-------------|
| 01 | Show current data (live sensor values) |
| 02 | Show freeze frame data (snapshot at fault) |
| 03 | Show stored DTCs (Diagnostic Trouble Codes) |
| 04 | Clear DTCs and stored values |
| 05 | Test results O2 sensor monitoring |
| 06 | Test results other component monitoring |
| 07 | Show pending DTCs |
| 08 | Control operation of on-board system |
| 09 | Request vehicle information (VIN, calibration IDs) |
| 0A | Permanent DTCs |

#### Common PIDs
| PID | Description | Formula |
|-----|-------------|---------|
| 0x04 | Engine load | A/2.55 % |
| 0x05 | Coolant temperature | A-40 °C |
| 0x0C | Engine RPM | ((A*256)+B)/4 RPM |
| 0x0D | Vehicle speed | A km/h |
| 0x1C | OBD standard | Enum |
| 0x2F | Fuel tank level | A/2.55 % |
| 0x51 | Fuel type | Enum |

### 2.6 UDS (ISO 14229) Protocol Attacks

Unified Diagnostic Services (UDS) is used by OEM tools and penetration testers. It operates on CAN (via ISO-TP, ISO 15765-2) or Ethernet (via DoIP, ISO 13400).

#### ISO-TP (ISO 15765-2) Transport Layer
UDS messages > 8 bytes require ISO-TP framing:

```
Single Frame (SF):   [0x0N][Data...]   where N = length (1-7 bytes)
First Frame (FF):    [0x1H][0xHL][Data...]   H+L = total length
Consecutive Frame:   [0x2N][Data...]   N = sequence number 0-F
Flow Control (FC):   [0x30][BS][ST min]   BS = block size, ST = separation time
```

#### UDS Services
| Service ID | Name | Common Attack Use |
|------------|------|-------------------|
| 0x10 | DiagnosticSessionControl | Session escalation to programming session |
| 0x11 | ECUReset | Reset ECU, cause DoS |
| 0x14 | ClearDiagnosticInfo | Delete fault codes |
| 0x19 | ReadDTCInformation | Enumerate faults |
| 0x22 | ReadDataByIdentifier | Read calibration, keys, config |
| 0x23 | ReadMemoryByAddress | Read ECU RAM/Flash |
| 0x27 | SecurityAccess | Bypass required for programming |
| 0x28 | CommunicationControl | Disable RX/TX of normal messages |
| 0x2E | WriteDataByIdentifier | Write VIN, calibration data |
| 0x31 | RoutineControl | Execute arbitrary routines |
| 0x34 | RequestDownload | Begin firmware download |
| 0x36 | TransferData | Transfer firmware blocks |
| 0x3E | TesterPresent | Keep session alive |

#### Session Escalation Attack
```
# Default session (0x01) - limited access
10 01  →  50 01 [timing]

# Switch to Extended Diagnostic Session (0x03)
10 03  →  50 03 [timing]

# SecurityAccess - request seed (0x27 subfunction 0x01)
27 01  →  67 01 [SEED: 4 bytes]

# Compute key from seed using OEM-specific algorithm
# Common: seed XOR with hardcoded value, or proprietary CMAC

# SecurityAccess - send computed key (0x27 subfunction 0x02)
27 02 [KEY: 4 bytes]  →  67 02  (success) OR  7F 27 35 (invalid key)

# Now in unlocked extended session: can read/write data identifiers
22 F1 90  →  VIN string
```

#### Security Access Bypass Techniques
1. **Algorithm reversing**: Extract security access algorithm from ECU firmware, compute key locally
2. **Timing side-channel**: Measure response time to infer partial key correctness
3. **Default keys**: Many ECUs use default or derivable seeds (seed = 0x00000000 → key = 0x00000000)
4. **Replay of valid seed/key pairs**: If no session binding, replaying a valid exchange may work
5. **Brute force**: 32-bit key space = 4 billion combinations; with 25ms attempt delay = 3.4 years; but many ECUs have lockout after 5 attempts

#### Memory Read Attack
```python
# UDS ReadMemoryByAddress (0x23)
# Format: 23 [addressAndLengthFormatIdentifier] [memoryAddress] [memorySize]
# addressAndLengthFormatIdentifier: upper nibble = length bytes of size, lower = length bytes of address

# Read 0xFF bytes starting at 0x08000000 (typical ARM Flash start)
23 14 08 00 00 00 FF
# Response: 63 [FF bytes of data]
```

### 2.7 CAN Injection Attack: Tesla Lockpicking (2023)

In 2023, researchers demonstrated a CAN injection attack to steal Tesla vehicles without physical key fobs:

**Attack overview**:
1. Gain physical access to headlight area (opens in <2 minutes with basic tools)
2. Connect to CAN bus via headlight wiring harness connector
3. Send specific CAN frames to authenticate a new key fob
4. The vehicle accepts the new key fob
5. Drive away

**Technical details**:
- The Bluetooth Low Energy (BLE) digital key authentication process sends challenge/response over CAN
- By injecting CAN frames that mimic the expected BLE authentication sequence, attackers could skip authentication
- Required: ~$100 in hardware (Raspberry Pi + MCP2515 CAN controller)
- Time to execute: ~2 minutes

This attack affected Model 3 and Model Y vehicles. Tesla pushed an OTA update within weeks adding CAN message authentication for key operations.

### 2.8 CAN Bus Intrusion Detection Systems

#### Anomaly-Based Detection
Traditional CAN IDS approaches:

**Message Frequency Analysis**:
- Each CAN ID has a predictable transmission interval (e.g., engine RPM transmitted every 10ms)
- Statistical baseline: mean and standard deviation of inter-message timing
- Alert on: messages arriving too frequently (injection), too infrequently (ECU failure)
- Implementation: sliding window average, CUSUM change detection

**Message Content Analysis**:
- Signal values have physical constraints (speed 0-350 km/h, RPM 0-8000)
- Cross-validate correlated signals (speed from wheel sensors should match GPS)
- Detect impossible state transitions (speed=0 while acceleration=1g)

**Entropy Analysis**:
- Injected messages often have different entropy characteristics than normal traffic
- Machine learning approaches: LSTM, autoencoders trained on normal traffic

**Limitations**:
- High false positive rate in normal driving variations
- No standard CAN IDS specification for automotive OEMs
- Computational constraints on gateway ECU

#### Deep Learning CAN IDS
Recent research uses neural networks:
- **OTIDS**: Uses RTR bit and time intervals
- **CANintelliIDS**: LSTM-based sequential anomaly detection
- **GAN-based**: Generative adversarial network to learn normal distribution, detect outliers

---

## 3. Automotive Network Architecture

### 3.1 Network Domains

Modern vehicles segment their electronics into functional domains, each with distinct security characteristics:

#### Powertrain Domain
Controls propulsion, transmission, and emissions:
- **ECM (Engine Control Module)**: Fuel injection, ignition timing, emission controls
- **TCM (Transmission Control Module)**: Gear selection, torque converter
- **HEV/BMS (Battery Management System)**: High-voltage battery state monitoring in EVs
- **Motor Control Module**: Inverter control in EVs/HEVs

**Security criticality**: CRITICAL — direct control of vehicle propulsion
**Bus speed**: High-speed CAN (500 kbps - 1 Mbps) or CAN-FD

#### Chassis Domain
Handles vehicle dynamics and stability:
- **ABS/ESC Module**: Anti-lock brakes, electronic stability control
- **EPS (Electric Power Steering)**: Steering assist
- **ACC (Adaptive Cruise Control)**: Longitudinal speed control
- **APA (Automated Parking Assist)**: Low-speed steering control

**Security criticality**: CRITICAL — direct control of vehicle trajectory
**Bus speed**: High-speed CAN (500 kbps) or FlexRay

#### Body Domain
Comfort, convenience, and passive safety:
- **BCM (Body Control Module)**: Central hub for body electronics
- **Door Modules**: Window, lock, mirror control
- **HVAC**: Climate control
- **Airbag Control Module**: Crash detection, pyrotechnic deployment

**Security criticality**: HIGH — airbag and lock control
**Bus speed**: Low/medium-speed CAN (125-250 kbps) or LIN via BCM

#### ADAS Domain
Advanced Driver Assistance Systems:
- **Fusion ECU**: Combines sensor data from camera, radar, lidar
- **Forward Camera**: Lane departure, traffic sign recognition
- **RADAR modules**: Adaptive cruise, blind spot monitoring
- **LIDAR unit** (premium/AV): 3D environmental mapping

**Security criticality**: CRITICAL for automation levels 3+
**Bus speed**: Automotive Ethernet (100BASE-T1, 1000BASE-T1)

#### Infotainment Domain
User interface and entertainment:
- **HMI (Head Unit)**: Touchscreen, display controller
- **Navigation ECU**: Map processing
- **Audio Amplifier DSP**: Sound processing
- **Rear Seat Entertainment**: Passenger displays

**Security criticality**: MEDIUM — but often acts as attack entry point
**Bus speed**: MOST (optical), Automotive Ethernet, CAN for vehicle data

#### Telematics Domain
External communications:
- **TCU (Telematics Control Unit)**: 4G/5G modem, GNSS receiver
- **eCall Module**: Emergency call hardware
- **V2X Unit**: DSRC/C-V2X radio

**Security criticality**: HIGH — internet-facing, potential remote entry point
**Bus speed**: Automotive Ethernet, CAN for vehicle data

### 3.2 Bus Protocol Comparison

| Protocol | Speed | Topology | Nodes | Use Case | Security |
|----------|-------|----------|-------|----------|---------|
| CAN (ISO 11898) | 1 Mbps | Bus | 32+ | Powertrain, chassis | No auth, no encryption |
| CAN-FD (ISO 11898-1) | 8 Mbps | Bus | 32+ | Higher BW CAN apps | No auth, no encryption |
| LIN (ISO 9141) | 20 kbps | Bus (master/slave) | 16 | Simple body actuators | No auth, no encryption |
| FlexRay (ISO 17458) | 10 Mbps | Bus/Star | 22 | Safety-critical chassis | Time-triggered, no crypto |
| MOST (MOST Coop) | 150 Mbps | Ring/Star | 64 | Infotainment multimedia | No security baseline |
| Automotive Ethernet | 100M-10G | Star | Unlimited | ADAS, backbone | 802.1AE MACsec available |

#### LIN (Local Interconnect Network)
LIN is a single-wire, low-cost serial protocol used for simple actuators and sensors that don't need CAN bandwidth:
- Applications: window switches, mirror adjust, seat position, HVAC flap motors, rain sensor
- Master-slave: one LIN master (typically BCM) coordinates all communication
- No collision detection, no error frames
- **Security**: Even weaker than CAN — no authentication at all, trivially injectable

#### FlexRay (ISO 17458)
Time-triggered protocol for safety-critical chassis applications:
- Deterministic: messages transmitted in predefined time slots
- Fault-tolerant: dual-channel redundancy option
- Used in: chassis dynamics (BMW X5 iDrive), brake-by-wire research
- **Security**: Time-triggered design provides some DoS resistance (flooding can't disrupt reserved slots), but still no authentication

#### Automotive Ethernet
The future backbone protocol for high-bandwidth applications:
- **100BASE-T1 (IEEE 802.3bw)**: 100 Mbps over single twisted pair, 15m range
- **1000BASE-T1 (IEEE 802.3bp)**: 1 Gbps over single twisted pair
- **10GBASE-T1 (IEEE 802.3ch)**: 10 Gbps, used for LIDAR/camera data aggregation
- Enables: 802.1Q VLANs, 802.1AE MACsec (frame-level encryption+authentication), 802.1X port auth
- **Security advantage**: Unlike CAN, Automotive Ethernet supports cryptographic security at the MAC layer

### 3.3 Gateway ECU (Central Gateway)

The Central Gateway ECU (CGW) is the vehicle's internal security boundary:

**Functions**:
- **Protocol translation**: CAN ↔ Automotive Ethernet ↔ LIN message conversion
- **Routing**: Forward only necessary messages between domains
- **Filtering**: Drop messages that should not cross domain boundaries
- **Rate limiting**: Prevent flooding attacks from propagating between domains
- **Diagnostics aggregation**: Single OBD-II connection point for all domains
- **Firewall**: Reject messages from unexpected source domains

**Security requirements (from AUTOSAR SecOC)**:
- Authenticate messages crossing domain boundaries using MACs
- Maintain freshness counters to prevent replay
- Log security events

**Common vulnerabilities found in CGW audits**:
- Insufficient filtering — messages from infotainment domain routed to powertrain without restriction
- Missing rate limiting — flooding in one domain propagates to all
- Diagnostics bypass — OBD-II port provides access to all domains without authentication
- Firmware update capability without signature verification

### 3.4 AUTOSAR Architecture

AUTOSAR (AUTomotive Open System ARchitecture) is the standard software architecture for ECU development.

#### Classic AUTOSAR
```
┌─────────────────────────────────┐
│     Application Layer           │  ← SWC (Software Components)
│  SWC1 │ SWC2 │ SWC3 │ SWC4    │
├─────────────────────────────────┤
│     RTE (Runtime Environment)   │  ← Inter-SWC communication
├─────────────────────────────────┤
│     Basic Software (BSW)        │
│  ┌──────────────────────────┐   │
│  │ Services Layer            │   │
│  │  SecOC │ Crypto │ NvM    │   │
│  ├──────────────────────────┤   │
│  │ ECU Abstraction Layer     │   │
│  ├──────────────────────────┤   │
│  │ Microcontroller Abs (MCAL)│   │
│  └──────────────────────────┘   │
├─────────────────────────────────┤
│     Hardware                    │
└─────────────────────────────────┘
```

#### Security-Relevant BSW Modules
- **SecOC (Secure Onboard Communication)**: MAC-based authentication for CAN/LIN messages
  - Uses CMAC-AES-128 or HMAC-SHA-256
  - Freshness Value Manager prevents replay
- **Crypto Stack (Crypto Driver → CSM → CryIf)**: Cryptographic services abstraction
- **SecureBoot**: Measurement and verification of software on startup
- **IdsM (Intrusion Detection System Manager)**: Collects and reports security events

#### AUTOSAR Adaptive (for ADAS/AV platforms)
- POSIX-based (typically QNX or Linux)
- Service-oriented architecture with SOME/IP protocol
- ARA (AUTOSAR Runtime for Adaptive Applications)
- Security modules: IAM (Identity and Access Management), cryptography, TLS

### 3.5 DoIP (Diagnostics over Internet Protocol)

ISO 13400 defines DoIP for vehicle diagnostics over standard IP networks (Ethernet):

**Architecture**:
```
[Diagnostic Tool] ←TCP 13400→ [Vehicle Edge Node / CGW] ←UDS→ [Target ECU]
```

**DoIP Port Numbers**:
- TCP 13400: Diagnostic session establishment
- UDP 13400: Vehicle announcement, entity discovery

**DoIP Message Types**:
| Message Type | Description |
|-------------|-------------|
| 0x0001 | Vehicle Identification Request |
| 0x0004 | Vehicle Announcement / ID Response |
| 0x0005 | Routing Activation Request |
| 0x0006 | Routing Activation Response |
| 0x8001 | Diagnostic Message |
| 0x8002 | Diagnostic Message Positive Ack |

**Security considerations**:
- Early implementations had no TLS — diagnostic sessions over cleartext TCP
- Routing Activation had no authentication — any host on vehicle Ethernet could send DoIP
- Attack: Connect laptop to vehicle OBD-II Ethernet port, send DoIP routing activation, run full UDS session against all ECUs

**Wireshark DoIP dissector**:
```
Filter: doip
Filter: tcp.port == 13400
```

### 3.6 Automotive Ethernet Switch Security

Modern vehicle architectures use Ethernet switches (e.g., NXP SJA1110, Marvell 88Q5050):

**Security features available**:
- **802.1Q VLAN isolation**: Separate ADAS cameras from infotainment
- **802.1AE MACsec**: Per-hop Ethernet frame encryption and authentication
  - Uses AES-128-GCM or AES-256-GCM
  - Provides confidentiality, integrity, and replay protection
  - Key exchange via MKA (MACsec Key Agreement, 802.1X-2010)
- **802.1X port authentication**: Authenticate ECUs before allowing network access
- **Port security**: Lock MAC addresses, prevent unauthorized ECU substitution
- **Storm control**: Rate-limit broadcast/multicast to prevent flooding

**Implementation gaps often found**:
- MACsec disabled by default to reduce latency and complexity
- Static pre-shared keys instead of MKA (key rotation not implemented)
- Switch management interface accessible without authentication on vehicle Ethernet

---

## 4. ECU Security

### 4.1 ECU Attack Surface: Firmware Extraction

Before analyzing ECU security, researchers extract firmware using hardware debug interfaces:

#### JTAG (Joint Test Action Group, IEEE 1149.1)
```
Pins: TDI, TDO, TCK, TMS, [TRST optional]
Voltage: 1.8V, 2.5V, 3.3V, or 5V depending on target

# OpenOCD configuration for common automotive MCU (Renesas RH850)
source [find interface/jlink.cfg]
transport select jtag
source [find target/renesas_rh850.cfg]

# Connect and halt
init
halt

# Read flash (0x00000000 - 0x00200000 = 2MB)
dump_image firmware.bin 0x00000000 0x00200000
```

**Finding JTAG on automotive PCB**:
1. Look for 0.1" or 0.05" header with 4-20 pins
2. Use JTAGulator or similar to auto-detect JTAG pins
3. Check PCB silkscreen for TDI/TDO/TCK/TMS labels
4. Measure with oscilloscope — TCK shows regular clock, TDO activity during reset

**JTAG protections and bypasses**:
- **Fuse/OTP disabling**: JTAG permanently disabled by blowing fuses during manufacturing
  - Bypass: voltage glitching to skip fuse check, or find test pads on PCB that bypass fusing
- **Password protection**: Some MCUs require JTAG password (e.g., TI MSP430, NXP Kinetis)
  - Bypass: brute force if password is short, or use fault injection
- **Secure debug**: ARM CoreSight authenticated debug — requires cryptographic authentication

#### UART (Universal Asynchronous Receiver Transmitter)
Many ECUs expose UART serial consoles for debugging:

```bash
# Find UART TX/RX with logic analyzer or oscilloscope
# Common baud rates: 9600, 38400, 57600, 115200, 460800

# Connect with screen
screen /dev/ttyUSB0 115200

# Or minicom
minicom -D /dev/ttyUSB0 -b 115200

# Common boot output to look for:
# U-Boot version strings
# Linux kernel boot messages
# Root shell on some debug builds
```

Boot console may allow:
- Interrupting U-Boot autoboot (press any key within 3 seconds)
- Running U-Boot commands to dump memory, load custom firmware
- If Linux: getty on serial → root shell

#### SPI Flash Extraction
Many ECUs store firmware in external SPI NOR flash (Winbond W25Qxxx, Macronix MX25Lxxx):

```bash
# Using flashrom with CH341A programmer
flashrom -p ch341a_spi -r firmware.bin

# Using Bus Pirate
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r firmware.bin

# Using custom Python with spidev (if Linux on extraction host)
# Identify flash chip: check PCB marking or JEDEC ID
flashrom -p ch341a_spi --flash-name
```

**In-circuit reading**: Use Pomona 5250 SOIC-8 clip to connect to flash chip without desoldering.

#### Firmware Reverse Engineering
After extraction:

```bash
# Identify firmware format
file firmware.bin
binwalk -B firmware.bin  # entropy and signature analysis

# Extract embedded filesystems
binwalk -e firmware.bin

# Identify architecture
cpu_rec firmware.bin  # probabilistic CPU architecture identifier

# Disassemble with Ghidra
# File → Import → firmware.bin
# Select processor: ARM Cortex-M, TriCore (Infineon), RH850 (Renesas), SH-4A (Renesas)

# Find interesting strings
strings -n 8 firmware.bin | grep -i "password\|key\|secret\|seed\|unlock"

# Look for UDS security access algorithm
# Search for XOR patterns, CRC polynomials, key derivation functions
```

### 4.2 Secure Boot Implementation

Secure boot ensures only authenticated software runs on an ECU.

#### Boot Chain of Trust
```
Boot ROM (immutable, in chip)
    ↓ Verifies signature of →
Bootloader Stage 1 (U-Boot SPL or OEM BL1)
    ↓ Verifies signature of →
Bootloader Stage 2 / Hypervisor
    ↓ Verifies signature of →
OS Kernel / RTOS Image
    ↓ Verifies signature of →
Application Software Components
```

#### Root of Trust
- **Hardware Root of Trust**: Asymmetric key pair where private key is stored in OTP/eFuse, public key is hash stored in eFuse
- **SHE (Secure Hardware Extension, HIS spec)**: Common in automotive MCUs (Infineon TC3xx, NXP S32)
  - 128-bit AES keys in hardware key slots
  - Boot MAC: CMAC over application code using SECRET_KEY, verified before execution
  - Cannot extract keys via software — only hardware attacks possible

#### ARM TrustZone Secure Boot (Cortex-A)
```
Secure World                    Normal World
-----------                     ------------
Secure Boot ROM                 Linux / Android Automotive
TF-A (Trusted Firmware-A)      Hypervisor (KVM/Xen)
OP-TEE OS                      TEE Client API
Trusted Applications            Guest VMs
```

#### Common Secure Boot Failures
1. **Missing signature verification on update path**: Secure boot checks initial image but OTA update installs without verification
2. **Downgrade attack**: Version number not checked — install old vulnerable firmware
3. **Debug build in production**: SecureBoot disabled in debug firmware left on production ECU
4. **Partial coverage**: Only kernel is checked, not kernel modules or userspace
5. **Clock glitch bypass**: Fault injection on signature verification comparison

### 4.3 HSM (Hardware Security Module) in Automotive

Automotive HSMs protect cryptographic keys and perform security-critical operations in isolated hardware.

#### SHE (Secure Hardware Extension)
HIS (Hardware Interface Specification) SHE was first standardized by automotive MCU vendors:
- 128-bit AES-128 hardware acceleration
- 10 pre-defined key slots (SECRET_KEY, MASTER_ECU_KEY, BOOT_MAC_KEY, RAM_KEY, 6x USER_KEYs)
- Key update protocol uses CMAC-based authenticated key exchange
- Boot MAC: ensures ECU will only run authenticated software

#### EVITA (E-safety Vehicle Intrusion proTected Applications)
EU research project defining three HSM security levels:

| Level | Crypto | Target Use | Key Protection |
|-------|--------|-----------|----------------|
| EVITA Light | 128-bit AES, SHA-256 | Body ECUs, actuators | Software isolation |
| EVITA Medium | 2048-bit RSA, ECC-256, AES-128 | Gateway, TCU | Hardware isolation (SHE-like) |
| EVITA Full | Same + RNG, dedicated secure core | Safety ECUs, HSM | Dedicated secure MCU |

#### HSM in Practice (NXP S32K, Infineon TC3xx)
```c
// Example: AUTOSAR Crypto Stack (CSM) calling HSM for MAC computation
Csm_MacGenerateStart(job_id, &CMAC_AES128_config);
Csm_MacGenerateUpdate(job_id, data_ptr, data_length);
Csm_MacGenerateFinish(job_id, mac_ptr, &mac_length, CRYPTO_FINISH_OP);
// Result: 16-byte CMAC computed in HSM, key never leaves HSM
```

#### SecOC (Secure Onboard Communication)
AUTOSAR SecOC uses HSM to authenticate CAN messages:
```
Message: [CAN Payload | Freshness Value (truncated) | MAC (truncated)]
MAC = CMAC-AES-128(SecOC_Key, [CAN_ID | Payload | Full_Freshness_Value])

Typical overhead: 4-byte freshness + 4-byte MAC appended to CAN payload
Total: reduces available payload by 8 bytes (DLC must accommodate)
```

### 4.4 Code Signing for Firmware Updates

#### Signing Chain
```
OEM Root CA (offline HSM)
    ↓ signs
OEM Code Signing CA (online HSM in build pipeline)
    ↓ signs
Firmware Image Manifest
    containing: firmware hash, version, target ECU ID, timestamp
```

#### Common Algorithms
- **RSA-2048 with PSS padding**: Widely deployed, 256-byte signature, slower verification
- **ECDSA P-256 (secp256r1)**: 64-byte signature, much faster verification, preferred for constrained MCUs
- **Ed25519**: Fastest, 64-byte signature, deterministic — increasingly adopted

```c
// Pseudo-code: ECU verifies firmware signature before flashing
int verify_firmware(uint8_t *image, uint32_t length, uint8_t *signature, uint8_t *pubkey) {
    uint8_t hash[32];
    sha256(image, length, hash);  // or SHA-384 for EVITA Full
    return ecdsa_verify(hash, signature, pubkey);  // returns 0 = valid
}
```

### 4.5 Trusted Execution Environment (TEE)

TEEs provide isolated execution for security-sensitive code on application processors (infotainment, ADAS):

#### OP-TEE on Automotive SoC
- TrustZone-based TEE for ARM Cortex-A processors
- Used in: infotainment SoC (Renesas R-Car, Qualcomm SA8155P)
- Security services: key storage, DRM, digital key (CCC), biometric authentication

**Attack surface**:
- TEE trusted applications have bugs (CVE-2017-1000412: OP-TEE TZP overflow)
- Secure monitor call (SMC) interface fuzzing
- Cache side-channel attacks (Spectre/Meltdown targeting TEE)

### 4.6 Memory Protection: MPU and Stack Canaries

#### MPU (Memory Protection Unit)
ARM Cortex-M MCUs include 8-16 MPU regions:
```c
// Configure MPU region for read-only Flash access
MPU->RBAR = 0x00000000 | MPU_RBAR_VALID_Msk | (0 << MPU_RBAR_REGION_Pos);
MPU->RASR = MPU_RASR_ENABLE_Msk
          | (0 << MPU_RASR_XN_Pos)      // Execute allowed
          | (0x06 << MPU_RASR_AP_Pos)   // Read-only priv+unpriv
          | (0x17 << MPU_RASR_SIZE_Pos) // 256KB region
          | MPU_RASR_S_Msk;             // Shareable
MPU->CTRL = MPU_CTRL_ENABLE_Msk | MPU_CTRL_PRIVDEFENA_Msk;
```

Common automotive MCU misconfigurations:
- No MPU configured (MPU disabled) — common in legacy code
- CAN receive buffers in executable memory — exploitable if CAN data is mis-parsed
- Stack and heap in same MPU region — stack overflow can corrupt heap

#### Stack Canaries in Automotive RTOS
```c
// GCC stack protector for safety-critical functions
__attribute__((stack_protect))
void process_uds_request(uint8_t *data, uint16_t length) {
    uint8_t local_buffer[64];  // canary placed before return address
    // If canary is overwritten by buffer overflow, __stack_chk_fail() is called
    memcpy(local_buffer, data, length);  // BUG: no bounds check — canary catches this
}
```

### 4.7 Debug Interface Protection

#### JTAG Fusing
Production ECUs should have JTAG disabled:
- **ARM CoreSight**: Set DEVICEEN = 0 in eFuse to permanently disable debug
- **Infineon TC3xx**: OCDS (On-Chip Debug Support) disable via UCB (User Configuration Block) bits
- **NXP S32K**: FTFA_FSEC[SEC] bit — if 0x02, debugger disabled; 0x00 = enabled

#### Secure Debug Authentication (SDA)
Modern MCUs support authenticated debug that allows authorized debugging (with OEM private key) while preventing unauthorized access:

```
Debug Tool                          ECU
----------                          ---
                ←── Debug Challenge (nonce)
Sign(nonce, OEM_debug_privkey) ──→
                ← Verify signature with OEM_debug_pubkey stored in eFuse
                ← If valid: enable debug access
```

Standards: ARM ADIv6 Authentication Interface, NXP Secure Debug Authentication Protocol

---

## 5. OTA Update Security

### 5.1 OTA Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     OEM Backend                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │  Update Mgmt │  │  Signing HSM │  │  Campaign Manager    │  │
│  │  System      │  │  (offline)   │  │  (rollout targeting) │  │
│  └──────┬───────┘  └──────────────┘  └──────────────────────┘  │
│         │                                                         │
│  ┌──────▼───────────────────────────────────────────────────┐   │
│  │              CDN / Delivery Network                       │   │
│  └──────────────────────────────┬────────────────────────────┘   │
└─────────────────────────────────┼───────────────────────────────┘
                                  │ HTTPS/TLS 1.3
                           ┌──────▼───────┐
                           │     TCU      │ ← Cellular (4G/5G)
                           └──────┬───────┘
                                  │ CAN / Automotive Ethernet
                    ┌─────────────▼────────────────┐
                    │   In-Vehicle OTA Manager      │
                    │   (typically on CGW or HMI)   │
                    └──┬──────────┬─────────────────┘
                       │          │
              ┌────────▼──┐  ┌───▼────────┐
              │  ECU 1    │  │   ECU 2    │
              │ (target)  │  │  (target)  │
              └───────────┘  └────────────┘
```

**Security requirements at each layer**:
1. Backend: HSM-protected signing keys, role-based access to update campaigns
2. CDN: TLS with certificate pinning by vehicle client
3. TCU: TLS verification, update package signature verification before passing to OTA manager
4. OTA Manager: Verify package signature, manage update sequencing, handle rollback
5. Target ECU: Verify firmware image hash/signature before flashing

### 5.2 UPTANE Framework

UPTANE is the industry-standard OTA security framework, developed by NYU Tandon, U Michigan, and SwRI, adopted by UNECE WP.29 Regulation 156.

#### Key Design Principles
UPTANE is designed to be secure even when:
- The CDN/delivery network is compromised
- The update server is compromised (partially)
- The update metadata is compromised (partially)
- The vehicle's network connection is intercepted

#### Repository Architecture

**Director Repository** (OEM-controlled, online):
- Knows which vehicles need which updates
- Generates signed targets metadata specifying: which ECUs get which images, at what version
- Each director metadata is vehicle-specific and time-limited

**Image Repository** (CDN, can be offline cache):
- Stores all firmware images
- Contains long-lived signed metadata about all available images
- Can be mirrored/replicated — compromise of image repository alone is insufficient to install malware

#### Metadata Hierarchy
```
Root Metadata (Root Keys, long-lived, offline)
    ↓ delegates to
Targets Metadata (lists firmware images with hashes)
Snapshot Metadata (current version of all targets metadata)
Timestamp Metadata (most recent snapshot, checked every session)
```

Each metadata is signed by role keys. Root key compromise requires re-rooting (threshold signature from old root keys + new root keys).

#### ECU Model

**Primary ECU** (gateway/OTA manager):
- Has full internet connectivity via TCU
- Downloads all metadata from both repositories
- Verifies full metadata chain
- Distributes firmware packages to secondary ECUs
- Collects and reports vehicle manifest to director

**Secondary ECUs** (individual target ECUs):
- Receive firmware from primary ECU (not internet)
- Perform partial verification (image hash + size)
- Report their current firmware version in ECU manifest

#### Verification Process
```
1. Primary downloads Timestamp metadata from Director → checks freshness
2. Primary downloads Snapshot metadata → checks all targets metadata versions
3. Primary downloads Targets metadata from Director → vehicle-specific targets
4. Primary downloads Targets metadata from Image Repository → image hashes
5. Primary cross-verifies: Director targets ∩ Image targets must match
6. Primary downloads firmware images, verifies against Image repository hashes
7. Primary distributes to Secondary ECUs with local targets metadata
8. Secondary verifies image hash matches targets metadata
9. Secondary reports success/failure in ECU manifest
10. Primary aggregates manifests, sends vehicle manifest to Director
```

#### Rollback Protection
UPTANE prevents rollback by:
- Version numbers in targets metadata: each new update increments version
- ECU manifest reports current version — Director can detect if ECU reports older version
- Snapshot metadata contains versions of all targets files — prevents downgrading targets metadata

### 5.3 OTA Threat Model

| Threat | UPTANE Mitigation |
|--------|-------------------|
| MITM on delivery network | TLS + metadata signatures (delivery compromise insufficient alone) |
| Compromised CDN | Image repository metadata signed offline, director cross-verification |
| Rollback attack | Version numbers in metadata, ECU manifest reporting |
| Unauthorized update (wrong ECU) | Director metadata is vehicle+ECU specific |
| Mix-and-match attack (old + new images) | Snapshot metadata ties all targets together |
| Endless data attack | Timestamp metadata expires (typically 1-24 hours) |
| Arbitrary software attack | Image repo metadata signed by offline keys |
| Compromised backend | Threshold signatures require multiple key holders |

### 5.4 Tesla OTA Architecture Reference

Tesla pioneered automotive OTA updates and has refined the process over 15+ years:

**Architecture highlights**:
- Full-vehicle updates (not just infotainment) — MCU, gateway, BMS, motor controllers
- Delta updates using binary diff (bspatch-style) to reduce download size
- Staged rollout: 1% → 10% → 50% → 100% with automatic rollback if telemetry shows increase in fault rates
- Dual-bank flash: current firmware in Bank A, new firmware written to Bank B, atomic switch on reboot
- Rollback: if new firmware fails to boot, automatically boots Bank A

**Security**: Tesla uses ECDSA-based code signing with HSM-stored keys at backend, TLS with certificate pinning on vehicle side. Update packages verified before installation.

### 5.5 Code Signing Details

#### RSA-2048 vs. ECDSA-256 for OTA

| Property | RSA-2048 | ECDSA P-256 |
|----------|----------|-------------|
| Key size | 2048 bits | 256 bits (private) |
| Signature size | 256 bytes | 64 bytes |
| Verify time (Cortex-M4) | ~200ms | ~50ms |
| Security level | ~112 bits | ~128 bits |
| Standard | PKCS#1 v2.1 | FIPS 186-4 |

**Recommended**: ECDSA P-256 with SHA-256 for all new designs.

### 5.6 Delta Update Security

Delta (differential) updates reduce bandwidth but introduce security considerations:

- **Algorithm**: bsdiff, xdelta3, or automotive-specific (e.g., Excelfore ePatch)
- **Threat**: Specially crafted delta files could exploit vulnerabilities in the delta application algorithm
- **Mitigations**:
  1. Sign the delta package itself with ECDSA
  2. After applying delta, verify SHA-256 of resulting image against signed expected hash
  3. Use bounded-memory delta algorithms designed for embedded systems (bspatch requires 2x image size in RAM)
  4. Apply delta to inactive flash bank, verify result before making active

---

## 6. V2X (Vehicle-to-Everything) Security

### 6.1 V2X Protocol Stack

#### DSRC / WAVE (IEEE 802.11p)
```
┌──────────────────────────────────┐
│  Safety Applications             │  ← BSM, SPAT, MAP, RSA messages
│  (SAE J2735 / J2945)             │
├──────────────────────────────────┤
│  Facilities Layer                │
│  (Message encoding / decoding)   │
├──────────────────────────────────┤
│  Security Layer                  │  ← IEEE 1609.2 (signing/encryption)
├──────────────────────────────────┤
│  Network Layer                   │  ← IEEE 1609.3 (WSMP, IPv6)
├──────────────────────────────────┤
│  Data Link Layer                 │  ← IEEE 1609.4 (multi-channel ops)
├──────────────────────────────────┤
│  Physical Layer                  │  ← IEEE 802.11p (OFDM, 5.9 GHz)
└──────────────────────────────────┘
```

#### C-V2X Protocol Stack
```
┌──────────────────────────────────┐
│  Safety Applications             │
├──────────────────────────────────┤
│  Security Layer (IEEE 1609.2)    │
├──────────────────────────────────┤
│  Facilities Layer                │
├──────────────────────────────────┤
│  PC5 Reference Point             │  ← Direct sidelink (no base station)
│  (LTE-V2X or NR-V2X)            │  or Uu interface (via network)
└──────────────────────────────────┘
```

### 6.2 V2X Message Types

#### BSM (Basic Safety Message) — SAE J2735
Transmitted at 10 Hz by all equipped vehicles, contains:
```
BSM {
  msgCnt          INTEGER (0..127),
  id              OCTET STRING (SIZE(4)),  ← temporary ID, changes periodically
  secMark         DSECond,
  lat             Latitude,
  long            Longitude,
  elev            Elevation,
  accuracy        PositionalAccuracy,
  speed           TransmissionAndSpeed,
  heading         Heading,
  angle           SteeringWheelAngle OPTIONAL,
  accelSet        AccelerationSet4Way OPTIONAL,
  brakes          BrakeSystemStatus OPTIONAL,
  size            VehicleSize OPTIONAL
}
```

**Privacy issue**: Even with pseudonym certificates, BSM trajectory data can be linked across pseudonym changes using location correlation, enabling long-term tracking.

#### SPAT (Signal Phase and Timing)
Transmitted by traffic infrastructure (RSU - Road Side Unit):
- Current phase of each signal group (red/yellow/green)
- Time to next phase change (min/max/likely)
- Enables green light speed advisory applications

#### MAP (Map Data Message)
Describes intersection topology:
- Lane geometry, connections, speed limits
- Reference to SPAT signal groups
- Used by vehicles to understand intersection layout

#### RSA (Roadside Alert)
Infrastructure warnings:
- Work zones, incidents, weather hazards
- Emergency vehicle approaching alerts

### 6.3 V2X PKI Architecture

V2X requires a large-scale, privacy-preserving PKI serving millions of vehicles.

#### Certificate Hierarchy
```
Root CA (offline, extremely restricted access)
    ↓
Intermediate CA (Policy CA / Subordinate CA)
    ↓
Pseudonym Certificate Authority (PCA)
    ↓
Pseudonym Certificates (short-lived, for vehicle use)

Root CA
    ↓
Long-Term Certificate Authority (LTCA)
    ↓
Enrollment Certificates (per vehicle, long-lived)
```

**Enrollment Certificates**: Device certificates tied to vehicle hardware (similar to device certificate). Used to authenticate to SCMS when requesting pseudonym certificates. Long-lived (5-10 years).

**Pseudonym Certificates**: Short-lived (1 week - few months), used to sign V2X messages. Vehicles hold a "butterfly" pool of pseudonyms and rotate them to prevent tracking.

### 6.4 SCMS (Security Credential Management System)

US architecture (USDOT SCMS Design):

```
┌──────────────────────────────────────────────────────────────┐
│                    SCMS                                       │
│  ┌────────────┐  ┌─────────────┐  ┌────────────────────┐   │
│  │ Root CA    │  │ Policy CA   │  │ Misbehavior        │   │
│  │ (offline)  │  │             │  │ Authority (MA)     │   │
│  └────────────┘  └─────────────┘  └────────────────────┘   │
│  ┌────────────┐  ┌─────────────┐  ┌────────────────────┐   │
│  │ Enrollment │  │ Pseudonym   │  │ Linkage Authority  │   │
│  │ CA (ECA)   │  │ CA (PCA)    │  │ (LA1, LA2)         │   │
│  └────────────┘  └─────────────┘  └────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

**Linkage Authority**: Enables revocation without breaking unlinkability. Two separate LAs each provide a linkage seed; combining both allows the MA to link pseudonyms back to an enrollment certificate for misbehaving vehicles — but neither LA alone can do this (threshold privacy).

**Butterfly Key Expansion**: Vehicle sends one request with a "cocoon" public key, PCA returns a large batch of pseudonym certificates encrypted such that vehicle can derive individual private keys using its butterfly private key seed. Privacy-preserving batch issuance.

### 6.5 IEEE 1609.2 Certificate Format

IEEE 1609.2 (WAVE Security Services) defines compact certificate format optimized for V2X:

```
Certificate {
  version         Uint8 (3),
  type            CertificateType (explicit | implicit),
  issuer          IssuerIdentifier,
  toBeSigned {
    id              CertificateId (linkageData | name | binaryId | none),
    cracaId         HashedId3,
    crlSeries       CrlSeries,
    validityPeriod  ValidityPeriod,
    region          GeographicRegion OPTIONAL,
    assuranceLevel  SubjectAssurance OPTIONAL,
    appPermissions  SequenceOfPsidSsp OPTIONAL,
    certIssuePermissions  SequenceOfPsidGroupPermissions OPTIONAL,
    verifyKeyIndicator    VerificationKeyIndicator
  },
  signature       Signature OPTIONAL
}
```

**Implicit certificates** (ECQV): Reduce certificate size by 50% by embedding public key reconstruction parameters instead of explicit public key. Used for pseudonym certs to save bandwidth.

### 6.6 V2X Attack Scenarios

#### Sybil Attack
An attacker creates multiple virtual vehicle identities (either through compromised devices or by replaying captured BSMs with modified IDs):
- Fabricate traffic congestion by reporting many fake vehicles
- Create fake accident scenes to cause GPS navigation rerouting
- Overwhelm RSU processing capacity with many simultaneous BSMs

**Detection**: Speed consistency checks (can a vehicle really be at position A and position B simultaneously?), direction/acceleration plausibility, RSU-based density analysis.

#### Replay Attack
Capture legitimate BSMs from a vehicle, replay them later:
- Make vehicle appear to still be at a location after it has left
- Cause intersection signal preemption by replaying emergency vehicle messages

**Prevention**: IEEE 1609.2 includes generation time in signed message; receivers reject messages older than threshold (typically 5 seconds).

#### Denial of Service
- **Radio jamming**: Disrupt 5.9 GHz band — simple and effective, illegal
- **Channel congestion**: Flood with valid-looking but useless messages to fill channel capacity
- **Certificate validation DoS**: Send messages with many different certificates forcing receivers to perform expensive ECDSA verifications

#### Position Falsification / GPS Spoofing
Transmit false GPS signals to cause vehicles to report incorrect positions in BSMs:
- Spoof GPS to incorrect location, vehicle transmits wrong position in BSM
- Cause AEB (autonomous emergency braking) by fabricating hazard at vehicle's true location

**Detection**: Cross-validation with other sensors (RADAR, camera range to reported vehicle), trajectory smoothness, Doppler consistency.

### 6.7 ETSI ITS Security (European Standard)

ETSI TS 103 097 defines V2X security for European ITS:

- **CAM (Cooperative Awareness Message)**: European equivalent of BSM
- **DENM (Decentralized Environmental Notification Message)**: Event-driven hazard warnings
- **Certificate Authority**: CPOC (C-ITS Point of Contact) root — multi-country trust list

---

## 7. Key Fob and Immobilizer Security

### 7.1 Rolling Code (Hopping Code) Mechanism

Traditional fixed-code key fobs were defeated by replay — attacker captures the signal, replays it. Rolling codes (hopping codes) solve this with synchronized counters:

**Operation**:
1. Both key fob and receiver share a secret key and a counter (synchronized)
2. On button press: fob transmits ENCRYPT(key, counter) + counter (or just counter index)
3. Receiver: decrypts/verifies, accepts if counter is within acceptable window (e.g., ±256 of expected)
4. Receiver advances its counter to match the received counter

**Resynchronization**: If counters drift (fob pressed outside vehicle range many times), receiver typically accepts up to 256 future codes to resynchronize.

#### KeeLoq Algorithm
KeeLoq is a proprietary 64-bit block cipher used in most automotive hopping code systems (Microchip Technology licensing):

**Vulnerabilities discovered**:
1. **Side-channel attack (Kasper et al., 2008)**: Power analysis on KeeLoq decryption chip extracts secret key in 10^5 measurements (~minutes)
2. **Meet-in-the-middle attack (Indesteege et al., 2008)**: Key recovery in 2^44 KeeLoq operations using specialized sliding window technique
3. **Manufacturer key derivation**: Many OEMs derive per-fob keys from a manufacturer master key + serial number. Extracting ONE fob's key via side-channel + knowing derivation function = compute ANY fob's key

**Practical impact**: A researcher who extracts one key fob from a vehicle of the same model can clone any key fob for that model line.

### 7.2 Relay Attack: Technical Details

**Hardware used**:
- Attacker 1 (near vehicle): Relay device with LF receiver + UHF transmitter, fits in briefcase
- Attacker 2 (near key fob): Relay device with LF transmitter + UHF receiver, fits in pocket
- Communication link between attacker 1 and 2: proprietary radio link, ~1km range

**Attack steps**:
```
Vehicle LF wake signal (125 kHz, 2-5m range)
    ↓ captured by Attacker 1's LF receiver
    ↓ forwarded via long-range radio link to Attacker 2
    ↓ Attacker 2's LF transmitter rebroadcasts
Key fob responds with UHF signal (315/433/868 MHz)
    ↓ captured by Attacker 2's UHF receiver
    ↓ forwarded via long-range radio link to Attacker 1
    ↓ Attacker 1's UHF transmitter rebroadcasts near vehicle
Vehicle accepts — door unlocks
```

Total latency increase: ~3-8ms — well within vehicle's acceptance window.

**Commercial kits**: Available online for $200-$1000. No technical skill required to operate.

### 7.3 Relay Attack Defense: UWB Ranging

Ultra-Wideband (UWB, IEEE 802.15.4a/z) enables precise ranging to prevent relay attacks:

**Physical principle**: UWB uses very short pulses (<2ns) allowing Time of Flight (ToF) measurements accurate to ~10cm. A relay attack adds latency (speed of light × added path length = ~1ns per 30cm relay distance). UWB detects this latency addition.

**Implementation**:
- **Apple AirTag / U1 chip**: UWB ranging used in iPhone Precision Finding
- **CCC Digital Key 3.0**: Requires UWB for passive entry — relay attacks physically prevented
- **BMW, Audi, Genesis**: Early adopters of UWB-based digital keys (2020-2022)

### 7.4 Immobilizer Protocols

Immobilizers prevent engine start without authenticated transponder (chip in key):

#### DST40 (Digital Signature Transponder)
Used in Texas Instruments transponders, deployed in many Toyota/Lexus vehicles:
- 40-bit key, challenge-response using proprietary cipher
- **Broken (Bono et al., 2005)**: Recovered 40-bit key in <1 second using specialized FPGA with rainbow tables
- Led to Toyota vehicles being vulnerable to key cloning

#### Hitag2
Philips/NXP 48-bit stream cipher used in Audi, BMW, Fiat, Honda, Volkswagen:
- Challenge-response with 48-bit key
- **Broken (Verdult et al., 2012)**: Key recovery in <1 minute with 8 authentication traces
- Attack: Capture 8 challenge-response pairs from the immobilizer antenna, compute key offline

#### AUT64 (Crypto-1)
Used in Megamos transponder (Volkswagen group vehicles):
- **Broken (Garcia et al., 2013)**: University of Birmingham - Volkswagen obtained injunction to suppress publication for 2 years
- Paper published in 2015 after court battle, exposing vulnerability in ~100 million vehicles

### 7.5 Key Fob Signal Analysis with RTL-SDR

```bash
# Capture key fob transmission (315 MHz US, 433.92 MHz EU, 868 MHz EU alternative)
rtl_sdr -f 315000000 -s 2000000 -g 40 capture.bin
# -f: center frequency in Hz
# -s: sample rate (2 MSps provides 2 MHz bandwidth around center)
# -g: gain (40 = ~40dB, may need tuning)

# Convert raw IQ to WAV for analysis
sox -r 2000000 -c 2 -b 8 -e unsigned-integer capture.bin capture.wav

# Analyze with Universal Radio Hacker (URH)
pip install urh
urh capture.bin
# URH auto-detects modulation (OOK/ASK is most common for key fobs)
# Can demodulate, find symbol boundaries, extract bit sequence
# Can identify rolling code structure vs. fixed portions

# Alternative: inspectrum
inspectrum capture.bin

# Decode OOK with Python
import numpy as np
data = np.frombuffer(open('capture.bin', 'rb').read(), dtype=np.uint8)
# Convert to complex IQ
iq = data.astype(float) - 128
iq_complex = iq[::2] + 1j * iq[1::2]
# Calculate envelope
envelope = np.abs(iq_complex)
# Threshold to get digital signal
digital = (envelope > np.mean(envelope)).astype(int)
print(''.join(map(str, digital[:200])))
```

### 7.6 TPMS Security: Tire Pressure Monitor Spoofing

TPMS sensors (mandated in US since 2008, EU since 2014) broadcast:
- Tire pressure, temperature, battery status
- Unique sensor ID (32-bit, used for anti-theft)
- Transmitted every 60-90 seconds at rest, more frequently while driving

**Protocol**: Typically FSK or Manchester-encoded OOK at 315 or 433.92 MHz.

**Attack**: Capturing and replaying TPMS packets, or generating packets with arbitrary sensor IDs, can:
- Trigger false TPMS warning on victim's dashboard (annoyance/distraction)
- Spoof sensor IDs to track a specific vehicle (privacy attack — sensor ID is static until battery replacement)
- If combined with vehicle following, correlate sensor ID to license plate

**Research (Rouf et al., 2010)**: Drive-by TPMS attacks demonstrated at highway speeds with $1500 in hardware.

### 7.7 CCC Digital Key Standard

Car Connectivity Consortium (CCC) Digital Key specification (v3.0 released 2021):

**Phases**:
- **Digital Key 2.0**: NFC-based (passive entry only when phone is near door handle)
- **Digital Key 3.0**: NFC + UWB (passive entry at distance, relay-attack resistant)

**Security architecture**:
- Key pair generated on phone's Secure Element (SE) or TEE
- OEM server provisions key certificate to phone
- Vehicle authenticates phone via challenge-response using public key on vehicle
- UWB ranging prevents relay attacks by verifying physical proximity

**Key sharing**: Owner can share digital keys with other phones with restrictions (time-limited, geo-fenced, valet mode = speed/area limited).

---

## 8. ADAS and Autonomous Vehicle Security

### 8.1 LiDAR Attack Surface

#### LiDAR Spoofing
LiDAR (Light Detection And Ranging) measures distance via Time-of-Flight of laser pulses (typically 905nm or 1550nm wavelength):

**Spoofing attack (Shin et al., 2017 — "Illusion and Dazzle")**:
- Precisely time laser pulses to arrive at LiDAR receiver synchronously with its expected reflection windows
- LiDAR adds fake points at attacker-controlled distances
- Can inject fake obstacles (causing unnecessary braking) or remove real obstacles (dangerous)
- Hardware: $60 in components (LIDAR receiver + laser diode + timing circuit)

**Blinding attack**:
- Overwhelm LiDAR receiver with high-power laser, saturating photodetectors
- Sensor returns no valid data in illuminated sector
- Can be done with invisible (IR) laser — no visible indication to driver

**Countermeasures**:
- Frequency diversity / wavelength diversity — attacker needs to match wavelength precisely
- Randomized pulse timing — harder to synchronize spoofed pulses
- Cross-validation with camera and RADAR
- Anomaly detection on point cloud (sudden appearance of stationary points)

#### LiDAR Physical Security
- **Mechanical LiDAR** (Velodyne HDL-64E): rotating mirror, physically larger attack target
- **Solid-state LiDAR** (Luminar, Mobileye EyeQ): MEMS or flash — different vulnerability profile

### 8.2 Camera Adversarial Examples

Neural network-based vision systems (YOLO, ResNet, EfficientDet) are vulnerable to adversarial perturbations:

**Physical adversarial patches (Eykholt et al., 2018 — "Robust Physical Perturbations")**:
- Specially crafted stickers on stop signs cause classifier to output "Speed Limit 45 mph" with >80% confidence
- Perturbation is robust to viewpoint changes, lighting, and print quality
- Required: access to sign, knowledge of model architecture (black-box attacks also possible)

**Attack types**:
- **L∞ perturbation**: Maximum per-pixel change bounded (imperceptible to humans)
- **Patch attack**: Localized printed patch that is conspicuous but effective
- **Shadow attack**: Natural shadow patterns adversarially placed on road surface
- **Light attack**: Projected adversarial patterns via laser or projector

**Adversarial example generation (FGSM)**:
```python
import torch
def fgsm_attack(image, epsilon, gradient):
    # Add perturbation in direction of gradient (increases loss = reduces correct class confidence)
    perturbed = image + epsilon * gradient.sign()
    # Clamp to valid pixel range
    return torch.clamp(perturbed, 0, 1)

# Get gradient of loss w.r.t. input
output = model(image)
loss = criterion(output, target_label)
model.zero_grad()
loss.backward()
gradient = image.grad.data
adversarial = fgsm_attack(image, epsilon=0.01, gradient=gradient)
```

**Camera sensor attacks**:
- **Blinding with laser**: IR laser pointed at camera sensor causes temporary blindness or permanent damage
- **Rolling shutter exploit**: Pulsed IR laser synchronized to camera's rolling shutter creates visual artifacts

### 8.3 RADAR Spoofing and Jamming

Automotive RADAR (typically 77 GHz FMCW — Frequency Modulated Continuous Wave):

**RADAR spoofing (Chauhan et al., 2020)**:
- Record RADAR chirp, retransmit with delay
- Vehicle RADAR interprets reflected signal as object at fake distance
- Can create ghost vehicles or suppress detection of real vehicles
- Hardware cost: ~$10,000 for 77 GHz equipment (decreasing)

**RADAR jamming**:
- Transmit noise in 77 GHz band, overwhelming RADAR return
- Disrupts adaptive cruise control and AEB
- Illegal under FCC regulations, but trivially implementable

**Countermeasures**:
- **Frequency hopping FMCW**: Randomize chirp start frequency
- **Phase-coded RADAR**: Each vehicle uses unique phase code — spoofed signal won't match code
- **Multi-static RADAR**: Cross-validate from multiple antenna positions

### 8.4 GPS Spoofing

GPS spoofing attacks generate fake GPS signals that override authentic satellite signals:

**Attack hardware**: HackRF One ($350) + GPS spoofing software (GPS-SDR-SIM, GPSJam) — can spoof GPS signals to any location/time.

**Automotive impacts**:
- Navigate autonomous vehicle to wrong destination
- Falsify V2X BSM position data
- Trigger geofenced features at wrong locations (e.g., geofenced speed limits)
- Manipulate route in ways that cause dangerous maneuvers

**High-profile incidents**:
- GPS spoofing in Black Sea (2017): 20+ ships reported positions in Gelendzhik airport
- GPS spoofing in Tehran (2011): US RQ-170 drone guided to forced landing via GPS spoofing
- Moscow GPS anomalies (2017-present): Kremlin-area GPS reports false positions in Vnukovo Airport

**Detection**:
- **RAIM (Receiver Autonomous Integrity Monitoring)**: Statistical consistency check on satellite signals
- **Multi-constellation**: GPS + GLONASS + Galileo + BeiDou — spoofer must spoof all simultaneously
- **IMU cross-validation**: GPS position should be consistent with accelerometer/gyroscope dead reckoning
- **RTK (Real-Time Kinematic)**: Differential GPS using local reference station — hard to spoof at centimeter level

### 8.5 Sensor Fusion Security

ADAS systems increasingly fuse multiple sensors to improve robustness:

**Fusion architecture**:
```
Camera (60° FOV, 100m)  ─────────────────────────────────┐
RADAR (120° FOV, 200m) ───────────────────────────────────┤→ Fusion ECU → Decision
LiDAR (360° FOV, 150m) ───────────────────────────────────┤   (Kalman filter,
GPS (global position)   ─────────────────────────────────┘   particle filter,
                                                               deep learning)
```

**Security approach**: Cross-validate sensor observations — an object detected by RADAR should also appear in camera and LiDAR FOV. Discrepancies trigger reduced confidence or alert.

**Failure modes**:
- **Single-point attacks**: Attacker exploits sensor type that isn't being cross-validated
- **Coordinated multi-sensor attacks**: Simultaneous LiDAR + camera attack — expensive but demonstrated in research
- **Temporal correlation**: Sensors have different update rates; attack timed to specific sensor cycle

### 8.6 ISO/SAE 21434 for ADAS Cybersecurity

ADAS systems fall under the ISO/SAE 21434 scope for cybersecurity engineering. ADAS-specific considerations:

**Threat scenarios for ADAS**:
- T1: Manipulation of environment perception (sensor spoofing)
- T2: Unauthorized access to vehicle control via compromised ADAS ECU
- T3: Data exfiltration of camera/LiDAR data (privacy)
- T4: Denial of service causing ADAS system fallback

**Risk assessment** (using TARA):
- Impact categories: Safety (SAF), Financial (FIN), Operational (OPE), Privacy (PRI)
- Attack feasibility: elapsed time, specialist expertise, window of opportunity
- Risk value: Impact × Feasibility → Cybersecurity goal

### 8.7 High-Definition Map Integrity

Level 3+ autonomous driving depends on HD maps (centimeter-level accuracy):

**Sources**: HERE HD Live Map, TomTom RoadDNA, Mobileye REM (Road Experience Management)

**Attack scenarios**:
- Corrupt map data to show non-existent lane markings
- Delete road feature causing vehicle to navigate into wrong lane
- Inject false speed limit data

**Security requirements**:
- Authenticated map updates via PKI-signed packages
- On-vehicle integrity verification of map tiles
- Sensor-to-map cross-validation (camera sees lane → compare to map lane)
- Freshness: map tiles include timestamp, vehicle rejects stale tiles

---

## 9. Regulatory and Standards

### 9.1 ISO/SAE 21434 Road Vehicle Cybersecurity Engineering

ISO/SAE 21434:2021 is the foundational automotive cybersecurity engineering standard, defining requirements across the full vehicle lifecycle.

#### CSMS (Cybersecurity Management System)
Organizational capability requirements:
- **Cybersecurity policies**: Documented policies for cybersecurity management
- **Competence**: Personnel with relevant automotive cybersecurity skills
- **Tools and methods**: Defined processes for TARA, secure development, testing
- **Supplier management**: Cybersecurity requirements flowed down to Tier 1/2 suppliers
- **Incident response**: Defined process for detecting and responding to cybersecurity incidents
- **Cybersecurity monitoring**: Post-production monitoring for new threats and vulnerabilities

#### TARA (Threat Analysis and Risk Assessment)
Structured methodology for identifying and evaluating cybersecurity risks:

**Step 1: Item Definition**
- Define system boundaries
- Identify external interfaces (OBD-II, Bluetooth, cellular, etc.)
- Describe functionality and dependencies

**Step 2: Asset Identification**
Assets are components, data, or functions with cybersecurity relevance:
- *Damage scenarios*: What could go wrong if asset is compromised?
- *Impact rating*: Assess impact on Safety, Financial, Operational, Privacy
- *Impact value*: Negligible (1) → Severe (4)

**Step 3: Threat Scenario Identification**
Using STRIDE or similar methodology:
- Spoofing (claim false identity)
- Tampering (unauthorized modification)
- Repudiation (deny action)
- Information Disclosure (unauthorized access)
- Denial of Service
- Elevation of Privilege

**Step 4: Attack Path Analysis**
- Attack feasibility factors:
  - Elapsed time: <1 day (0), <1 week (1), <1 month (4), <6 months (10), <3 years (17)
  - Specialist expertise: layman (0), proficient (3), expert (6), multiple experts (8)
  - Knowledge of item: public (0), restricted (3), confidential (7), strictly confidential (11)
  - Window of opportunity: unlimited (0), easy (1), moderate (4), difficult (10)
  - Equipment: standard (0), specialized (4), bespoke (7)

**Step 5: Risk Determination**
- Risk = Impact × Attack Feasibility
- Risk values: Unreasonable → Tolerable → Acceptable
- Determines cybersecurity goals and requirements

#### TARA Example: OBD-II Port

| Asset | Damage Scenario | Impact | Attack Path | Feasibility | Risk |
|-------|----------------|--------|-------------|-------------|------|
| CAN bus (via OBD-II) | Attacker injects brake commands causing accident | Safety-4 | Physical OBD-II access + CAN injection tool | Low (physical access required, $50 tool) | High |
| ECU firmware (via UDS) | Install malicious firmware enabling persistent access | Safety-4 | UDS security access bypass, UDS download | Medium (needs protocol knowledge) | High |
| DTCs | Read fault codes to learn maintenance history | Privacy-2 | Read UDS diagnostic data | Very Low (no authentication) | Medium |

### 9.2 UNECE WP.29 Regulation 155

UN Regulation 155 (Cybersecurity and Cybersecurity Management System) entered into force January 2021:

**Scope**: Applies to vehicles in UN ECE member states, mandatory for new vehicle type approvals:
- M1/M2 (passenger cars, minibuses): Mandatory from July 2022
- N1/N2 (light/medium commercial): Mandatory from July 2022
- L (motorcycles, light quadricycles): Under consideration
- Heavy vehicles: Phased schedule

**Requirements summary**:
1. OEM must implement and maintain a CSMS (per ISO 21434 concept)
2. CSMS must be certified by a Technical Service (TUEV, Dekra, etc.)
3. Vehicle type approval requires cybersecurity assessment
4. OEM must demonstrate: risk management, secure development, testing, incident response
5. Post-production: monitor, detect, respond to cybersecurity incidents for vehicle's service life

**Certification process**:
```
OEM → Implements CSMS
    → Applies to Technical Service for CSMS Certification
    → Technical Service audits CSMS against UN R155 requirements
    → Issues CSMS Certificate (valid 3 years, renewable)
OEM → Applies for Vehicle Type Approval with cybersecurity assessment
    → Type Approval Authority reviews cybersecurity assessment
    → Issues type approval certificate
```

### 9.3 UNECE WP.29 Regulation 156

UN Regulation 156 (Software Update and Software Update Management System) specifically addresses OTA:

**Requirements**:
- OEM must implement SUMS (Software Update Management System)
- SUMS must ensure: software update integrity, authorization, documentation
- Vehicle must authenticate update packages (signature verification)
- Rollback protection required
- Vehicle in an operational state after update (defined process for failed update recovery)
- Record of all software updates in vehicle (update log accessible to authorities)

**Applies to same vehicle categories as R155, same timeline.**

### 9.4 NHTSA Cybersecurity Best Practices

NHTSA (National Highway Traffic Safety Administration) published Cybersecurity Best Practices for Modern Vehicles (2016, updated 2022):

**Key recommendations**:
1. **Risk management**: Use structured risk assessment (similar to TARA)
2. **Security by design**: Build security in from concept, not as afterthought
3. **Defense in depth**: Multiple independent security layers
4. **Minimize attack surface**: Disable unused interfaces, remove debug functionality
5. **Penetration testing**: Test against real-world attacks
6. **Supply chain**: Extend security requirements to suppliers
7. **Incident response**: Coordinate vulnerability disclosure, coordinate response
8. **Information sharing**: Participate in Auto-ISAC

**NHTSA authority**: Does not mandate specific cybersecurity requirements (unlike WP.29); relies on voluntary best practices and FMVSS (Federal Motor Vehicle Safety Standards) if safety impact demonstrated.

### 9.5 Auto-ISAC Best Practices

Auto-ISAC (Automotive Information Sharing and Analysis Center) published 7 best practice areas:

| Area | Description |
|------|-------------|
| 1. Governance | Executive commitment, cybersecurity policy, resources |
| 2. Risk Assessment & Management | TARA methodology, risk-based prioritization |
| 3. Security by Design | Secure SDLC, threat modeling, security requirements |
| 4. Threat Detection & Protection | Monitoring, IDS/IPS, access controls |
| 5. Incident Response & Recovery | IR plan, forensics capability, remediation |
| 6. Awareness & Training | Security training for all relevant staff |
| 7. Collaboration & Engagement | ISAC participation, coordinated disclosure |

### 9.6 SAE J3061: Cybersecurity Guidebook

SAE J3061:2016 (Cybersecurity Guidebook for Cyber-Physical Vehicle Systems) was the predecessor to ISO 21434:

**Key concepts introduced**:
- **Cybersecurity lifecycle**: Concept → Development → Production → Post-production
- **Cybersecurity Case**: Documentation demonstrating cybersecurity goals are met
- **HARA-analog for cybersecurity**: Cyber Hazard Analysis and Risk Assessment
- Mapping to functional safety (ISO 26262) — cybersecurity and safety interaction

**Status**: Superseded by ISO/SAE 21434 but still referenced; J3061 more process-prescriptive, 21434 more goal-based.

---

## 10. Automotive Penetration Testing

### 10.1 Test Lab Setup

A professional automotive penetration test lab requires:

#### Hardware
- **CAN bus simulator / vehicle bus tester**: Vector CANcase, Kvaser Leaf, or PEAK PCAN-USB
- **Hardware-in-the-loop (HIL) test bench**: Actual ECUs from target vehicle connected to simulated vehicle environment
- **Real vehicle**: Dedicated test vehicle (preferred — tests real integrations)
- **OBD-II breakout board**: Splitter allowing tools to connect alongside vehicle
- **JTAG/SWD debug probes**: Segger J-Link, Black Magic Probe, OpenOCD-compatible
- **Logic analyzers / oscilloscopes**: Saleae Logic 8/16, Rigol DS1054Z
- **RF equipment**: RTL-SDR, HackRF One (or PortaPack), Proxmark3, Flipper Zero
- **Programming hardware**: CH341A SPI flash programmer, Bus Pirate

#### Software Environment
- **Kali Linux VM**: Full security toolset
- **SocketCAN**: Linux CAN interface framework
- **Wireshark with automotive plugins**: DoIP dissector, ISO-TP support
- **CANalyzer/CANoe** (if budget allows): Professional OEM-grade analysis
- **Ghidra / IDA Pro**: Firmware reverse engineering
- **Python**: python-can, scapy automotive layers, custom scripts

### 10.2 Automotive Tool Reference

#### CANalyzer (Vector Informatik)
Professional tool used by OEMs and Tier 1 suppliers for CAN/LIN/FlexRay/Ethernet analysis:
- Database-driven: load .dbc files to decode messages into engineering units
- Logging: high-speed binary logging, post-processing
- Stimulation: send preconfigured or scripted messages
- Statistics: bus load, error frames, timing analysis

#### Wireshark with DoIP Dissector
```
# Filter DoIP traffic
doip

# Filter by message type
doip.message_type == 0x8001  # Diagnostic messages only

# Follow a UDS session
tcp.stream eq <stream_number>

# Filter ISO-TP reassembled UDS
uds
```

#### Scapy Automotive Layers
```python
from scapy.contrib.automotive.obd.obd import OBD
from scapy.contrib.automotive.uds import UDS, UDS_SA, UDS_RDBI
from scapy.contrib.cansocket_native import NativeCANSocket
from scapy.contrib.isotp import ISOTPNativeSocket

# ISOTP socket for UDS
sock = ISOTPNativeSocket('can0', tx_id=0x7DF, rx_id=0x7E8)

# UDS Security Access - Request Seed
req = UDS()/UDS_SA(securityAccessType=0x01)
resp = sock.sr1(req, timeout=2)
seed = resp[UDS_SA].securitySeed
print(f"Seed: {seed.hex()}")

# Compute key (example: simple XOR with 0xDEADBEEF)
key = int.from_bytes(seed, 'big') ^ 0xDEADBEEF
key_bytes = key.to_bytes(len(seed), 'big')

# UDS Security Access - Send Key
key_req = UDS()/UDS_SA(securityAccessType=0x02, securityKey=key_bytes)
resp = sock.sr1(key_req, timeout=2)
print(f"Security access: {'granted' if resp.service == 0x67 else 'denied'}")
```

### 10.3 ECU Fuzzing with caringcaribou

caringcaribou is an open-source automotive security tool designed for CAN bus discovery and fuzzing:

```bash
# Install
pip install caringcaribou

# Discovery: find ECUs responding to UDS diagnostic requests
cc uds discovery --min 0x00 --max 0x7FF

# Enumerate supported UDS services on specific ECU
cc uds services 0x7E0

# Fuzz with random CAN frames
cc fuzzer random --min-id 0x000 --max-id 0x7FF --min-data 0 --max-data 8

# UDS scanning - identify session types
cc uds sessions 0x7E0

# XCP discovery (calibration protocol)
cc xcp discovery

# Send specific UDS service
cc uds send 0x7DF 22 F1 90  # Read VIN

# DoIP discovery
cc doip discovery

# Listener - capture and display CAN traffic
cc listener
```

#### Custom Fuzzing Script
```python
import can, random, time

bus = can.interface.Bus(channel='can0', bustype='socketcan')

def fuzz_uds(target_id, service_id, count=1000):
    # Fuzz a specific UDS service with random sub-functions and data
    for i in range(count):
        # Random payload 1-7 bytes (leaving room for length byte in UDS)
        payload_len = random.randint(1, 7)
        payload = bytes([service_id] + [random.randint(0, 255) for _ in range(payload_len - 1)])
        frame_data = bytes([len(payload)]) + payload + bytes(8 - len(payload) - 1)

        msg = can.Message(arbitration_id=target_id, data=frame_data, is_extended_id=False)
        try:
            bus.send(msg)
            # Check for response
            resp = bus.recv(timeout=0.1)
            if resp and resp.arbitration_id == (target_id + 8):  # typical response offset
                print(f"[{i}] Request: {frame_data.hex()} → Response: {resp.data.hex()}")
        except Exception as e:
            print(f"Error: {e}")
        time.sleep(0.005)  # 5ms between frames

fuzz_uds(0x7E0, 0x27)  # Fuzz SecurityAccess service
```

### 10.4 MITRE ATT&CK for Vehicles

MITRE has been developing ATT&CK for connected vehicles. Key tactic areas applicable to automotive:

| Tactic | Automotive Examples |
|--------|---------------------|
| Initial Access | OBD-II port, Bluetooth exploit, cellular network attack |
| Execution | UDS routine control, CAN frame injection |
| Persistence | Flash modified firmware, install rogue OBD dongle |
| Privilege Escalation | UDS session escalation (default → extended → programming) |
| Defense Evasion | Disable security access logging, suppress DTC codes |
| Credential Access | Extract seed/key from security access session |
| Discovery | UDS service enumeration, CAN ID scanning |
| Lateral Movement | Pivot from infotainment to CAN bus via CGW |
| Collection | Read vehicle telemetry, GPS position, driving data |
| Impact | Brake injection, steering manipulation, engine shutdown |

### 10.5 Bug Bounty Programs

#### Tesla
- **Platform**: Bugcrowd
- **URL**: https://bugcrowd.com/tesla
- **Scope**: All Tesla vehicles, mobile apps, API, web infrastructure
- **Notable payouts**:
  - Remote code execution in infotainment: up to $15,000
  - CAN bus injection via remote vector: up to $35,000
  - Key bypass / authentication bypass: $10,000-$20,000
- **Hall of Fame**: Keen Security Lab, white-hat researchers globally

#### General Motors
- **Program**: GM Vulnerability Disclosure Program
- **Platform**: HackerOne
- **Scope**: OnStar, MyChevrolet/GMC/Buick/Cadillac apps, connected vehicle API
- **Focus**: Remote access vulnerabilities, API security, mobile app security

#### Stellantis
- **Brands**: Chrysler, Dodge, Jeep, Ram, Fiat, Maserati, Alfa Romeo
- **Platform**: Bugcrowd
- **Scope**: Vehicle connectivity, UConnect, mobile apps
- **Background**: Established after Jeep Cherokee incident; FCA was among first OEMs to launch formal program

#### Ford
- **Program**: Ford Vulnerability Disclosure Program
- **Platform**: Bugcrowd
- **Scope**: Ford.com, FordPass, SYNC infotainment, connected vehicle services

#### Volkswagen Group
- **Responsible Disclosure**: security@vw-group.com
- **Scope**: VW, Audi, SEAT, Skoda, Porsche, Bentley, Lamborghini connected services

### 10.6 Responsible Disclosure in Automotive Context

Automotive responsible disclosure has unique considerations:

**Challenges**:
- **Safety impact**: A critical vulnerability could affect millions of vehicles in ways that could cause accidents — disclosure timelines must account for OTA remediation
- **OTA availability**: Not all ECUs are OTA-updatable; some require dealer service
- **Long model cycles**: Vulnerabilities may affect 10+ year production runs with existing vehicles that can't be updated
- **Legal risk**: Researchers face CFAA (Computer Fraud and Abuse Act) exposure; some have faced legal threats (VW/Garcia case)

**Best practices for researchers**:
1. **Contact CERT/CC or Auto-ISAC first**: If OEM disclosure process is unclear
2. **Notify OEM security team directly**: Most OEMs have psirt@ or security@ address
3. **Provide 90-day disclosure timeline**: Standard industry norm (ISO 29147 / 30111)
4. **Request extension if OTA is in progress**: Allow up to 180 days if remediation is complex
5. **Coordinate with NHTSA**: For safety-critical vulnerabilities, consider notifying NHTSA simultaneously
6. **Document everything**: Preserve records of disclosure communications

**CVD (Coordinated Vulnerability Disclosure) for automotive — ISO/SAE 21434 reference**:
- Clause 12: Cybersecurity incident response
- Triage: classify impact using CVSS-AV + automotive severity modifiers
- Remediation: develop, test, and validate fix
- OTA deployment: staged rollout with monitoring
- CVE assignment via CNA (OEM or CERT)

---

## Appendix A: Quick Reference — CAN IDs and OBD-II

### Common OBD-II CAN IDs
| ID | Direction | Description |
|----|-----------|-------------|
| 0x7DF | TX (tester) | Functional addressing — all ECUs |
| 0x7E0 | TX (tester) | Physical addressing — ECM |
| 0x7E1 | TX (tester) | Physical addressing — TCM |
| 0x7E8 | RX (ECM) | Response from ECM |
| 0x7E9 | RX (TCM) | Response from TCM |
| 0x18DB33F1 | TX (ext) | Extended functional address |
| 0x18DAF110 | RX (ext) | Extended response address (ECU 0x10) |

### UDS Negative Response Codes
| NRC | Code | Description |
|-----|------|-------------|
| 0x10 | generalReject | General rejection |
| 0x11 | serviceNotSupported | Service not supported |
| 0x12 | subFunctionNotSupported | Sub-function not supported |
| 0x13 | incorrectMessageLengthOrInvalidFormat | Wrong length |
| 0x22 | conditionsNotCorrect | Not in correct state |
| 0x24 | requestSequenceError | Wrong order |
| 0x25 | noResponseFromSubnetComponent | Sub-component timeout |
| 0x31 | requestOutOfRange | Parameter out of range |
| 0x33 | securityAccessDenied | Security access rejected |
| 0x35 | invalidKey | Wrong security key |
| 0x36 | exceededNumberOfAttempts | Too many failed attempts |
| 0x37 | requiredTimeDelayNotExpired | Lockout timer active |
| 0x70 | uploadDownloadNotAccepted | Cannot accept transfer |
| 0x71 | transferDataSuspended | Transfer interrupted |
| 0x72 | generalProgrammingFailure | Flash write error |
| 0x78 | requestCorrectlyReceivedResponsePending | Processing (wait) |
| 0x7E | subFunctionNotSupportedInActiveSession | Wrong session |
| 0x7F | serviceNotSupportedInActiveSession | Wrong session |

---

## Appendix B: Key Tools Summary

| Tool | Purpose | Platform |
|------|---------|---------|
| candump | CAN frame capture | Linux (SocketCAN) |
| cansend | Send CAN frames | Linux (SocketCAN) |
| canplayer | Replay CAN logs | Linux (SocketCAN) |
| cansniffer | Real-time CAN monitor | Linux (SocketCAN) |
| python-can | CAN Python library | Cross-platform |
| Scapy (automotive) | CAN/UDS/OBD packet crafting | Linux |
| caringcaribou | ECU discovery and fuzzing | Linux |
| CANalyzer | Professional CAN analysis | Windows |
| CANoe | Professional CAN simulation | Windows |
| Wireshark | Protocol analysis (DoIP, ISO-TP) | Cross-platform |
| Ghidra | ECU firmware RE | Cross-platform |
| IDA Pro | ECU firmware RE (commercial) | Cross-platform |
| OpenOCD | JTAG/SWD debugging | Cross-platform |
| flashrom | SPI flash reading/writing | Linux |
| binwalk | Firmware analysis | Linux |
| URH (Universal Radio Hacker) | RF signal analysis | Cross-platform |
| rtl_sdr | SDR capture (RTL-SDR dongle) | Linux |
| HackRF tools | Wide-band SDR | Cross-platform |
| Proxmark3 | RFID/NFC/key fob analysis | Linux |
| Flipper Zero | Multi-protocol RF/hardware tool | Dedicated hardware |
| GPS-SDR-SIM | GPS spoofing | Linux |

---

## Appendix C: Standards and References

| Standard | Title | Scope |
|----------|-------|-------|
| ISO/SAE 21434:2021 | Road Vehicles — Cybersecurity Engineering | Cybersecurity lifecycle |
| ISO 26262:2018 | Road Vehicles — Functional Safety | Safety lifecycle |
| ISO 14229 (UDS) | Unified Diagnostic Services | ECU diagnostics |
| ISO 15765 (ISO-TP) | Diagnostic Communication over CAN | CAN transport layer |
| ISO 13400 (DoIP) | Diagnostic Communication over IP | Ethernet diagnostics |
| ISO 11898 | CAN bus standard | Physical/data link |
| SAE J1979 / ISO 15031 | OBD-II standard | Emissions diagnostics |
| SAE J2735 | V2X message set dictionary | BSM, SPAT, MAP messages |
| SAE J3061 | Cybersecurity Guidebook | Process framework |
| IEEE 802.11p | WAVE (V2X radio) | DSRC physical layer |
| IEEE 1609.2 | WAVE security | V2X certificate format |
| UNECE R155 | Cybersecurity type approval | Regulatory |
| UNECE R156 | Software update type approval | Regulatory |
| CCC Digital Key 3.0 | Digital car key | NFC/UWB key sharing |
| AUTOSAR SecOC | Secure Onboard Communication | CAN message authentication |
| HIS SHE | Secure Hardware Extension | Automotive HSM spec |
| EVITA | Vehicle HSM levels | Security hardware |

---

*Last updated: 2026 | Maintained as part of TeamStarWolf cybersecurity reference library*
