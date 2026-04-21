# Radio Frequency (RF) Security

Radio frequency security is the discipline of assessing, attacking, and defending wireless communication systems. Modern infrastructure relies heavily on RF: cellular networks, satellite communications, building access control (RFID/NFC), industrial wireless sensors, vehicle key systems, drone control links, and emergency services all transmit data through the air. Unlike wired networks, RF signals propagate through walls, across streets, and in some cases across continents — and historically, the assumption that only expensive specialized hardware could receive these signals has led to widespread deployment of insecure wireless protocols.

The security practitioner who understands RF has access to an attack surface that most organizations have never audited. Key areas include: signal interception and analysis, protocol reverse engineering, replay and injection attacks, jamming, credential cloning (RFID/NFC), and GPS manipulation. This discipline bridges hardware, software, and physics — and tools like the RTL-SDR have made entry-level research accessible for under $30.

---

## Where to Start

| Level | Focus | Resources |
|-------|-------|-----------|
| **Foundation** | Radio theory, modulation, spectrum basics; SDR setup; passive reception | [RTL-SDR Quick Start](https://www.rtl-sdr.com/rtl-sdr-quick-start-guide/), [hamstudy.org](https://hamstudy.org/) Technician exam, GQRX/SDR# setup |
| **Practitioner** | Protocol analysis with URH; RFID/NFC cloning with Proxmark3; replay attacks; 802.11 wireless attacks | [Universal Radio Hacker docs](https://github.com/jopohl/urh/wiki), [Proxmark3 docs](https://github.com/RfidResearchGroup/proxmark3/wiki), Hak5 tutorials |
| **Advanced** | GNU Radio custom signal processing; ZigBee/Z-Wave exploitation; GPS spoofing research; CAN bus wireless attack surfaces; custom firmware for HackRF | [GNU Radio Tutorials](https://wiki.gnuradio.org/index.php/Tutorials), academic papers (IEEE S&P, USENIX Security), DEF CON RF Village talks |

---

## Free Training

| Resource | Type | URL |
|----------|------|-----|
| RTL-SDR Blog Tutorials | Web tutorials | [rtl-sdr.com](https://www.rtl-sdr.com/category/tutorial/) |
| GNU Radio Academy | Video course | [gnuradio.org](https://wiki.gnuradio.org/index.php/Tutorials) |
| HackRF One Documented Examples | Documentation | [hackrf.readthedocs.io](https://hackrf.readthedocs.io/en/latest/) |
| DEF CON RF Village Talks | Video | [YouTube - DEF CON](https://www.youtube.com/@DEFCONConference) |
| Hak5 RF Security Playlist | Video | [hak5.org](https://hak5.org/) |
| Michael Ossmann's SDR Course | Video | [greatscottgadgets.com](https://greatscottgadgets.com/sdr/) |
| Ham Radio Technician Study | Interactive | [hamstudy.org](https://hamstudy.org/) |
| OpenSecurityTraining2 | Course | [ost2.fyi](https://ost2.fyi/) |
| ARRL Technical Information Service | Documents | [arrl.org](https://www.arrl.org/technical-information-service) |

---

## RF Attack Techniques

### Replay Attacks

A replay attack captures a legitimate wireless transmission and retransmits it to trigger the same action. The attack works whenever a protocol uses static (unchanging) codes with no freshness mechanism (nonce, timestamp, rolling code).

**Classic example: Fixed-code garage doors and remote controls**
Early garage door systems, many car key fobs from the 1990s-2000s, and cheap IoT devices (433 MHz door/window sensors, remote outlets) transmit the same binary sequence every time. Capture once with an RTL-SDR or HackRF, replay with HackRF or YARD Stick One, and the receiver cannot distinguish the replay from the original.

**Rolling codes (KeeLoq, AUT64)** were introduced to defeat replay attacks. They advance a counter synchronized between transmitter and receiver. However, rolling code implementations have been attacked via:
- **RollJam** (Samy Kamkar, 2015) — jams and captures the first transmission while the victim unknowingly sends a second; replays the first captured code immediately; holds the second for future use
- **Implementation flaws** — some vehicles accept codes out of sequence within a wide window

**Detection**: RF spectrum monitoring for unexpected transmissions in access control frequency bands.

---

### Deauthentication (802.11 WiFi)

The 802.11 management frame deauthentication attack exploits a fundamental design flaw: in 802.11 (prior to 802.11w/PMF), deauthentication frames are unauthenticated. Any station can forge a deauth frame from the AP's MAC address, disconnecting clients.

**Why it still matters in 2024**:
- Legacy devices (IoT, industrial sensors, older laptops) often don't support PMF
- Even modern devices may fall back to open (non-PMF) connections
- Used as a precursor to evil twin / KARMA attacks to force clients to reconnect to a rogue AP
- Effective denial-of-service against WiFi-controlled devices (drones, IP cameras, smart locks)

**Mitigation**: Enable 802.11w (PMF) on APs; use WPA3 (requires PMF); segment IoT devices.

**Tools**: `aireplay-ng` (aircrack-ng suite), `mdk4`, ESP32 Marauder

---

### ZigBee & Z-Wave Attacks

**ZigBee** (IEEE 802.15.4, 2.4 GHz) and **Z-Wave** (800-900 MHz, region-dependent) are low-power mesh protocols widely used in smart home devices, industrial sensors, and building automation.

**ZigBee attack surface**:
- **Unencrypted coordinator traffic** — during device pairing, many implementations broadcast the network key in cleartext ("ZigBee key transport")
- **Default / hardcoded keys** — "ZigBeeAlliance09" is the default global trust center link key used by many devices
- **Packet injection** — malicious frames can trigger actuators (locks, smart plugs) on networks with weak key management
- **Replay** — ZigBee sequence numbers are short; some implementations accept replayed frames

**Tools**:
- [KillerBee](https://github.com/riverloopsec/killerbee) — ZigBee attack framework; works with RZUSBSTICK and ApiMote hardware
- [Scapy ZigBee layer](https://scapy.readthedocs.io/) — packet crafting
- Ubertooth One (for BLE, related protocol)

**Z-Wave attack surface**:
- Earlier S0 security used a fixed key derivation; S2 (2017+) significantly improved security
- S0 devices remain widely deployed; can capture and decrypt S0 traffic with YARD Stick One + [Z-Wave dissectors](https://github.com/baol/waving-z)
- Physical layer: Z-Wave uses FSK modulation; HackRF can capture raw signals for analysis

---

### RFID & NFC Cloning

**RFID** (Radio Frequency Identification) and **NFC** (Near Field Communication) are contact-less identification technologies widely deployed in physical access control, transit cards, payment systems, and asset tracking.

**Frequency bands and common systems**:
| Frequency | Technology | Common Systems |
|-----------|-----------|----------------|
| 125 kHz LF | EM4100, HID Prox, AWID | Older building access cards (extremely common, no encryption) |
| 13.56 MHz HF | MIFARE Classic, MIFARE DESFire, HID iCLASS, ISO 14443 | Modern access cards, transit (NFC-compatible) |
| 860-960 MHz UHF | EPC Gen2 (ISO 18000-6) | Asset tracking, warehouse management |

**Attack techniques**:

*125 kHz (LF) cloning*: EM4100 and most HID Prox cards transmit their ID in cleartext with no authentication. A reader within a few centimeters (or up to ~50 cm with a long-range reader) can read and clone these cards. This is not a flaw — it is by design. The Proxmark3 and Flipper Zero can read and write these cards in seconds.

*MIFARE Classic*: Used in hundreds of millions of access cards and transit systems worldwide. Uses a proprietary "Crypto-1" cipher that was fully reverse engineered in 2008 (Verdult et al.). Standard attacks:
- **Darkside attack** — recover one key without prior knowledge
- **Nested attack** — recover all keys once one is known
- **MFOC / MFCUK** tools implement these attacks

*MIFARE DESFire EV1/EV2/EV3*: Uses 3DES/AES; significantly more secure; no known practical cryptographic break; attacks focus on implementation flaws and key management

*iCLASS*: HID iCLASS uses a proprietary algorithm; master key was extracted in 2010 via reverse engineering; legacy iCLASS is vulnerable. iCLASS SE/Seos uses AES and is more robust.

**Tools**:
- **[Proxmark3 RDV4](https://proxmark.com/)** — the professional standard for RFID security research; supports LF and HF; runs the [RRG/iceman firmware](https://github.com/RfidResearchGroup/proxmark3)
- **[Flipper Zero](https://flipperzero.one/)** — consumer-friendly RFID/NFC reader/writer; good for field assessments
- **[ACR122U](https://www.acs.com.hk/en/products/3/acr122u-usb-nfc-reader/)** — cheap USB NFC reader; works with libnfc and MFOC

---

### GPS Spoofing

GPS receivers compute position by measuring time-of-arrival differences from multiple satellites. Critically, civilian GPS signals are unencrypted and unauthenticated — any transmitter can broadcast fake GPS signals.

**Impact**:
- Vehicle navigation manipulation
- Drone redirection (most consumer drones home on GPS)
- Timestamp manipulation (affects financial systems, cellular networks, NTP)
- Ship/aircraft navigation in adversarial environments

**Proof-of-concept history**:
- 2011: Iran claimed GPS spoofing of a US RQ-170 drone
- 2013: Humphreys et al. demonstrated spoofing a yacht's navigation
- 2017-present: Widespread GPS spoofing around conflict zones documented by organizations including the [C4ADS GPS Spoofing Tracker](https://c4ads.org/)

**Technical approach**: Broadcast GPS signals at higher power than real satellites, with crafted pseudorange data placing the receiver at the attacker-desired location. Requires SDR with transmit capability (HackRF, USRP) and software like [GPS-SDR-SIM](https://github.com/osqzss/gps-sdr-sim).

**Defenses**: Multi-constellation receivers (GPS + GLONASS + Galileo + BeiDou); inertial navigation cross-checking; signal strength anomaly detection; Galileo's OSNMA (Open Service Navigation Message Authentication, in deployment 2024)

**Legal warning**: Transmitting on GPS frequencies (L1: 1575.42 MHz, L2: 1227.60 MHz) without authorization is illegal in virtually all jurisdictions. Research must be conducted in Faraday cages or with appropriate FCC experimental licenses.

---

## Tools & Repositories

### Receivers (Passive Interception)

| Tool | Cost | Frequency Range | Notes |
|------|------|----------------|-------|
| [RTL-SDR Blog V4](https://www.rtl-sdr.com/buy-rtl-sdr-dvb-t-dongles/) | ~$30 | 500 kHz–1.75 GHz | Best entry-level; improved LF performance |
| [Airspy HF+](https://airspy.com/airspy-hf-discovery/) | ~$170 | 9 kHz–31 MHz / 60–260 MHz | Exceptional HF/VHF sensitivity |
| [KerberosSDR](https://www.rtl-sdr.com/ksdr/) | ~$150 | RTL-SDR x4 | Coherent RX for direction finding |
| [SDRplay RSP1C](https://www.sdrplay.com/) | ~$120 | 1 kHz–2 GHz | Good sensitivity, wider range |

### Transceivers (Transmit + Receive)

| Tool | Cost | Range | Notes |
|------|------|-------|-------|
| [HackRF One](https://greatscottgadgets.com/hackrf/) | ~$340 | 1 MHz–6 GHz | Half-duplex; the standard; open hardware |
| [YARD Stick One](https://greatscottgadgets.com/yardstickone/) | ~$100 | Sub-1 GHz | Purpose-built for sub-GHz protocol attacks |
| [USRP B200](https://www.ettus.com/all-products/ub200-kit/) | ~$700 | 70 MHz–6 GHz | Full-duplex; professional/research use |
| [LimeSDR](https://limemicro.com/products/boards/limesdr/) | ~$300 | 100 kHz–3.8 GHz | Full-duplex; open hardware |

### RFID/NFC Tools

| Tool | Notes |
|------|-------|
| [Proxmark3 RDV4](https://proxmark.com/) | Professional LF/HF RFID research; iceman firmware recommended |
| [Flipper Zero](https://flipperzero.one/) | Multi-tool; RFID/NFC + Sub-GHz + IR |
| [ACR122U](https://www.acs.com.hk/) | Cheap USB NFC; works with libnfc, MFOC |
| [ChameleonMini](https://kasper-oswald.de/gb/chameleonmini/) | RFID emulator; simulates multiple card types |

### Software Frameworks

| Tool | URL | Purpose |
|------|-----|---------|
| GNU Radio | [gnuradio.org](https://www.gnuradio.org/) | Signal processing framework; flow-graph based |
| Universal Radio Hacker | [github.com/jopohl/urh](https://github.com/jopohl/urh) | Protocol reverse engineering |
| GQRX | [gqrx.dk](https://gqrx.dk/) | General SDR receiver, spectrum analysis |
| SDR# | [airspy.com/download](https://airspy.com/download/) | Windows SDR receiver |
| Inspectrum | [github.com/miek/inspectrum](https://github.com/miek/inspectrum) | Offline IQ file analysis |
| KillerBee | [github.com/riverloopsec/killerbee](https://github.com/riverloopsec/killerbee) | ZigBee attack framework |
| Scapy | [scapy.net](https://scapy.net/) | Packet crafting (802.11, ZigBee, BT layers) |
| Aircrack-ng | [aircrack-ng.org](https://www.aircrack-ng.org/) | 802.11 audit suite |
| bettercap | [bettercap.org](https://www.bettercap.org/) | Network/RF Swiss Army knife |
| gr-gsm | [github.com/ptrkrysik/gr-gsm](https://github.com/ptrkrysik/gr-gsm) | GSM capture and analysis |
| GPS-SDR-SIM | [github.com/osqzss/gps-sdr-sim](https://github.com/osqzss/gps-sdr-sim) | GPS signal simulation (research only) |

### Key GitHub Repositories

| Repository | Description |
|-----------|-------------|
| [RfidResearchGroup/proxmark3](https://github.com/RfidResearchGroup/proxmark3) | Iceman Proxmark3 firmware (community standard) |
| [jopohl/urh](https://github.com/jopohl/urh) | Universal Radio Hacker |
| [osmocom/rtl-sdr](https://gitea.osmocom.org/sdr/rtl-sdr) | RTL-SDR drivers |
| [merbanan/rtl_433](https://github.com/merbanan/rtl_433) | Decode 433/315 MHz IoT sensor protocols |
| [EliasOenal/multimon-ng](https://github.com/EliasOenal/multimon-ng) | Pager (POCSAG/FLEX) and other protocol decoding |
| [flightaware/dump1090](https://github.com/flightaware/dump1090) | ADS-B aircraft transponder decoder |
| [ptrkrysik/gr-gsm](https://github.com/ptrkrysik/gr-gsm) | GSM analysis with GNU Radio |
| [samyk/poisontap](https://github.com/samyk/poisontap) | Related: USB network implant by Samy Kamkar |

---

## ATT&CK Coverage

RF security techniques map to several MITRE ATT&CK and ATT&CK for ICS/Mobile tactics:

| Technique | ATT&CK ID | RF Attack |
|-----------|-----------|-----------|
| **Network Sniffing** | T1040 | Passive RF interception of wireless protocols |
| **Adversary-in-the-Middle** | T1557 | Rogue AP (evil twin), GSM IMSI catcher |
| **Wireless Compromise** | T1465 (Mobile) | Deauth + evil twin, rogue AP |
| **Exfiltration Over Alternative Protocol** | T1048 | RF covert channel, exfil via sub-GHz |
| **Replay Attack** | ICS: T0830 | Key fob replay, RFID card replay |
| **Exploitation of Remote Services** | T1210 | ZigBee key capture → device control |
| **Physical Access** | (multiple) | RFID cloning to bypass access control |
| **Denial of Service** | T1499 | RF jamming of GPS, cellular, WiFi |
| **Credential Access via Physical** | T1556 | RFID credential cloning (Proxmark3) |
| **Spoof GPS** | ICS-adjacent | GPS spoofing of OT/navigation systems |

**Note**: ATT&CK coverage for RF is most developed in the ICS matrix and the Mobile matrix. The Enterprise matrix covers wireless primarily under Network effects.

---

## Legal & Ethical Considerations

RF security research exists in a complex legal environment:

- **Receiving**: Generally legal everywhere (with exceptions for some encrypted communications in some jurisdictions, e.g., wiretapping laws)
- **Transmitting**: Requires authorization. In the US, unlicensed transmission on most frequencies is regulated by the FCC. Exceptions include ISM bands (but even here, power limits apply) and Part 15 devices.
- **RFID cloning**: May violate Computer Fraud and Abuse Act (CFAA) in the US if used to access systems without authorization; always obtain written permission for assessments
- **Cellular attacks** (IMSI catchers, deauth): Federal crimes in the US without authorization; surveillance device laws vary by state
- **GPS jamming**: A federal crime in the US regardless of context; FCC takes enforcement seriously

Always operate within the scope of authorized engagements. For research, obtain an FCC Experimental License for novel transmissions.

---


---

## RF Attack Techniques (Extended)

### Software-Defined Radio (SDR) Fundamentals

- SDR: Replace hardware components with software; one device covers wide frequency range
- Receive-only tools: RTL-SDR (~$25 USB dongle); covers 500kHz-1.7GHz
- Transmit+receive: HackRF One (1MHz-6GHz), USRP B200 (70MHz-6GHz), LimeSDR
- Software: GNU Radio (signal processing toolkit), GQRX (spectrum analyzer GUI), URH (Universal Radio Hacker)

### RollJam Attack (Samy Kamkar) — Detailed

- Target: Rolling code car locks, garage doors using KeeLoq or similar
- Mechanism: Jam the signal while recording; victim presses button again; record second code; now possess both codes — first use is already invalidated, but second code is still valid
- Implementation: HackRF + custom firmware or RTL-SDR + software-defined jammer
- Rolling code (KeeLoq): Challenge-response prevents simple replay; but still vulnerable to RollJam attack

### ADS-B Security (Aviation)

- ADS-B: Automatic Dependent Surveillance-Broadcast; aircraft broadcast position/speed/ID unencrypted at 1090 MHz
- No authentication: Anyone can inject fake aircraft (ghost plane attacks)
- SDR reception: `dump1090 --interactive` — receive all aircraft in range with RTL-SDR
- Attack tool: `ADSB-Out` — inject fake flight data; demonstrated at DEF CON
- Defense: Multi-sensor validation (MLAT — multilateration confirms position); FAA/ICAO working on ADS-B authentication (ADS-B+ / ACAS)

### Bluetooth Attacks

- BlueBorne (2017): RCE over Bluetooth without pairing; CVE-2017-0781; affected all major OS
- Bluejacking: Send unsolicited messages to discoverable devices (nuisance, not threat)
- Bluesnarfing: Unauthorized access to Bluetooth device data (contacts, calendar)
- KNOB attack (CVE-2019-9506): Force short encryption key; brute force session
- BLE GATT scanning: Enumerate Bluetooth Low Energy services and characteristics without pairing
- Ubertooth One: ~$120 Bluetooth monitoring/sniffing hardware; demodulates Bluetooth Classic

### ZigBee / Z-Wave / MQTT Attacks (Extended)

- ZigBee: IEEE 802.15.4; smart home and IoT; 2.4GHz; killerbee framework for testing
- Z-Wave: Proprietary; smart home; 900MHz band; Z-Wave JS for research
- MQTT: Application layer protocol for IoT; broker-based pub/sub; usually port 1883 (unencrypted) or 8883 (TLS)
  - Attack: `mosquitto_sub -h TARGET -t '#'` — subscribe to ALL topics; reveals all sensor data
  - Authentication bypass: Default no-auth brokers; guest accounts on Mosquitto
  - Payload injection: Publish commands to control actuators (locks, HVAC, lights)

### RFID/NFC Attacks — Extended Detail

- 125kHz RFID (HID Prox, EM4100): No encryption; clonable in seconds with Proxmark3 or Flipper Zero
- 13.56MHz MIFARE Classic: Proprietary Crypto-1 cipher; fully broken (mfoc, mfcuk attacks)
- 13.56MHz MIFARE DESFire EV2: AES-128; much harder; limited attack surface
- NFC relay attack: Relay card transaction over distance; PoC demonstrated for VISA contactless
- Proxmark3: Full RFID/NFC research platform; read, write, simulate, attack

---

## RF Defense and Detection

### Signal Monitoring and Threat Detection

- RF spectrum monitoring: SDR + spectrum analyzer to detect rogue transmitters, jammers, ADS-B injectors
- Wireless IDS (WIDS): Detect rogue APs, deauth flooding, karma attacks (hostapd-wpe)
- Bluetooth monitoring: Ubertooth + BlueZ tools for unauthorized Bluetooth device detection
- TSCM (Technical Surveillance Countermeasures): Professional RF bug sweeping; detect hidden transmitters

### Hardening Wireless Infrastructure

| Control | Implementation | Protects Against |
|---------|---------------|-----------------|
| WPA3 (SAE) | Replace WPA2 with WPA3 on all APs | PMKID attacks; dictionary attacks; KRACK |
| 802.1X (WPA2-Enterprise) | Radius server with EAP-TLS certificates | Credential-based attacks; evil twin |
| SSID segregation | Separate SSIDs for IoT, guest, corporate | Lateral movement from compromised IoT devices |
| Rogue AP detection | WIDS (Cisco CleanAir, Mist, Aruba RAPIDS) | Evil twin, karma attacks |
| RF shielding | Faraday enclosures for secure rooms | RF eavesdropping, TEMPEST |
| Disable Bluetooth | MDM policy; disable when not needed | Bluetooth attacks (BlueBorne) |
| Disable NFC when not in use | MDM policy for mobile devices | NFC relay/skim attacks |

---

## RF Security Tools Reference

| Tool | Type | Frequency | Use Case |
|------|------|-----------|----------|
| RTL-SDR | Receive-only | 500kHz-1.7GHz | Spectrum monitoring, ADS-B, FM |
| HackRF One | TX+RX | 1MHz-6GHz | Full spectrum analysis, replay attacks |
| USRP B200 | TX+RX (high-quality) | 70MHz-6GHz | Professional research, LTE analysis |
| Flipper Zero | Multi-protocol | Sub-GHz+NFC+RFID | Physical/RF pen testing |
| Proxmark3 RDV4 | RFID/NFC | LF+HF | RFID cloning, NFC attacks |
| Ubertooth One | Bluetooth sniff | 2.4GHz | Bluetooth Classic monitoring |
| GNU Radio | Software toolkit | Any (with hardware) | Custom signal processing |
| GQRX | Spectrum analyzer | Any (with SDR) | Visual spectrum monitoring |
| Universal Radio Hacker (URH) | Signal analysis | Any (with SDR) | Decode, analyze, fuzz RF protocols |
| KillerBee | ZigBee framework | 2.4GHz | ZigBee sniffing and attacks |

---

## Related Disciplines

- [hardware-security.md](hardware-security.md) — PCB analysis, firmware extraction, hardware RE; often paired with RF for embedded wireless device assessments
- [iot-security.md](iot-security.md) — IoT devices are primary consumers of ZigBee, Z-Wave, 433 MHz, and BLE protocols
- [physical-security.md](physical-security.md) — RFID/NFC assessment is a core component of physical penetration testing
- [hacker-hobbies.md](hacker-hobbies.md) — SDR, ham radio, and locksport as foundational skill-building activities
