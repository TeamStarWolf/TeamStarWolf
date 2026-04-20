# Hacker Culture Hobbies

Hacker culture extends far beyond professional security work. At its core, hacking is a mindset — curiosity, creativity, and a drive to understand how things work at a fundamental level. DEF CON, the world's largest hacker conference, organizes this curiosity into **villages**: dedicated spaces where practitioners teach hands-on skills in everything from lockpicking to car hacking to radio communications. These hobbies are not just fun — they build the foundational intuition that separates a skilled security practitioner from someone who only knows tool syntax. Understanding *why* a lock pin sets, *why* a radio signal leaks information, or *why* a CAN bus has no authentication directly informs how you think about attack surfaces and defenses.

---

## Locksport & Physical Bypass

Locksport is the sport of picking locks as a hobby. It teaches physical security concepts that directly translate to red team assessments, social engineering engagements, and physical penetration testing.

### Why It Matters for Security

Most buildings rely on pin tumbler locks that were designed in the 1800s. Understanding the mechanical tolerances that make picking possible — manufacturing variance creating a "binding order" of pins — teaches you to look for similar exploitable tolerances in digital systems. A lock that looks secure on paper (5 pins, hardened shackle) can be defeated in seconds if its manufacturing quality is poor.

### Core Techniques

| Technique | Description | Skill Level |
|-----------|-------------|-------------|
| Single Pin Picking (SPP) | Setting each pin individually using tension and a pick | Beginner → Advanced |
| Raking | Rapid back-and-forth movement to randomly set pins | Beginner |
| Bump Key | Percussive attack that momentarily floats all pins | Beginner (requires bump key) |
| Bypass Attacks | Exploiting design flaws (shimming, loiding, impressioning) | Intermediate |
| RFID/NFC Cloning | Duplicating proximity card credentials | Intermediate |

### Tools & Manufacturers

- **[Southord](https://www.southord.com/)** — affordable beginner sets, good for learning
- **[Peterson](https://www.thinkpeterson.com/)** — high-quality steel picks preferred by serious practitioners
- **[Sparrows](https://www.sparrowslockpicks.com/)** — excellent value, wide variety including specialty tools
- **[Proxmark3](https://proxmark.com/)** — the gold standard for RFID/NFC research and credential cloning (also used professionally for access control assessments)
- **[Flipper Zero](https://flipperzero.one/)** — portable multi-tool with RFID/NFC reader/writer, Sub-GHz radio, and more

### Community & Learning

- **[TOOOL](https://toool.us/)** (The Open Organisation Of Lockpickers) — organizes Locksport International and runs villages at DEF CON and other conferences
- **[LockPickingLawyer](https://www.youtube.com/@LockPickingLawyer)** (YouTube) — ~5 million subscribers; concise, educational teardowns of virtually every consumer lock
- **[BosnianBill](https://www.youtube.com/@BosnianBill)** (YouTube) — deeper dives, often with LPL; explains *why* locks fail
- **Belt Ranking System** — Locksport International uses a colored belt system (white through black) to rank picking skill, gamifying progression

### Legal Note

Laws on carrying lockpicks vary by jurisdiction. In most US states, picks are legal to own but may require "intent to commit burglary" for criminal liability. Always verify local laws and only pick locks you own or have explicit permission to pick.

---

## Electronics & Maker Culture

Electronics skills are the foundation of hardware security work. A security practitioner who can read a schematic, probe a circuit, and modify firmware has capabilities that purely software-focused practitioners lack.

### Why It Matters for Security

Modern attacks increasingly target the boundary between hardware and software: bootloaders, firmware, embedded controllers, and physical interfaces. The maker movement has democratized electronics education to the point where a $4 Arduino can demonstrate buffer overflows in embedded C, and a $10 ESP32 can perform WiFi deauthentication attacks.

### Essential Skills & Tools

**Soldering** is the gateway skill. Being able to solder gives you access to:
- Attaching UART/JTAG headers to devices for firmware extraction
- Modifying hardware (glitching attacks, hardware implants)
- Building custom tools and adapters

**Test Equipment**
- **Multimeter** — voltage, continuity, resistance; essential for tracing circuits and identifying power rails
- **Logic Analyzer** — captures digital signals (UART, SPI, I2C, JTAG); [Saleae Logic](https://www.saleae.com/) is the professional standard; [cheap clones](https://sigrok.org/wiki/Supported_hardware) work with sigrok/PulseView
- **Oscilloscope** — visualizes analog signals; critical for side-channel attacks (power analysis); entry-level: Rigol DS1054Z

**Development Platforms**
| Platform | Use Cases |
|----------|-----------|
| Arduino Uno/Nano | Learning embedded C, basic attack prototypes |
| ESP32 | WiFi/BT research, cheap wireless attack tools, [ESP32 Marauder](https://github.com/justcallmekoko/ESP32Marauder) |
| Raspberry Pi 4/5 | Full Linux: Pi-hole (DNS sinkhole), Kali Linux builds, network monitoring |
| Pi Zero W | Ultra-small form factor: BadUSB attacks, drop implants, covert monitoring |
| Raspberry Pi Pico | Microcontroller-class, cheap, RP2040 chip |

**Notable Security Projects**
- **[Pi-hole](https://pi-hole.net/)** — network-level ad/tracker blocking via DNS; teaches DNS architecture
- **[Kali on Raspberry Pi](https://www.kali.org/docs/arm/raspberry-pi-full-fat/)** — portable pentesting platform
- **BadUSB with Pi Zero** — emulates HID devices (keyboard/mouse) to deliver payloads; teaches USB attack surfaces
- **Wireless monitoring** — capture 802.11 probe requests, passive WiFi reconnaissance

**[Flipper Zero](https://flipperzero.one/)**
The Flipper Zero deserves special mention as a purpose-built hacker multi-tool. It combines: Sub-GHz radio (315/433/868/915 MHz), RFID/NFC reader/writer, infrared transceiver, iButton reader, GPIO pins, and a Bad USB mode. It is educational precisely because it makes previously complex attacks tangible and observable.

### Learning Resources
- **[Hackaday](https://hackaday.com/)** — daily hardware/electronics news and project writeups
- **[MAKE Magazine](https://makezine.com/)** — maker culture, project ideas
- **[Adafruit Learning System](https://learn.adafruit.com/)** — high quality beginner tutorials

---

## Software Defined Radio (SDR)

Software Defined Radio (SDR) replaces traditional radio hardware circuits with software running on a general-purpose computer. Where a traditional radio has fixed analog circuits for filtering and demodulation, an SDR uses a wideband analog-to-digital converter to capture raw radio frequency data, which software then processes. This means a single piece of hardware can receive (and in some cases transmit) virtually any signal in its frequency range — AM/FM broadcast, aircraft transponders, weather satellites, pager systems, garage door openers, and much more.

### Why It Matters for Security

Modern infrastructure communicates wirelessly. RFID access cards, garage doors, car key fobs, building sensors, utility meters (AMR/AMI), and industrial SCADA systems all transmit RF signals. Many of these protocols were designed with the assumption that receivers were expensive specialty hardware. SDR demolishes that assumption: a $25 USB dongle can now receive what previously required thousands of dollars of equipment. Security practitioners use SDR to:
- Understand wireless attack surfaces
- Capture and analyze unknown protocols
- Replay captured signals (replay attacks)
- Assess RF security of physical security systems

### Getting Started: The RTL-SDR

The **[RTL-SDR Blog V4 dongle](https://www.rtl-sdr.com/buy-rtl-sdr-dvb-t-dongles/)** (~$30) is the entry point. Originally designed as a cheap DVB-T TV tuner, a researcher discovered the chip could be put into a raw data streaming mode, birthing the RTL-SDR ecosystem. It covers approximately 500 kHz to 1.75 GHz.

**Software**
| Tool | Platform | Use Case |
|------|----------|----------|
| [GQRX](https://gqrx.dk/) | Linux/macOS | General-purpose SDR receiver, spectrum analyzer |
| [SDR#](https://airspy.com/download/) (SDRSharp) | Windows | Popular Windows SDR receiver |
| [CubicSDR](https://cubicsdr.com/) | Cross-platform | Open source, clean interface |
| [Universal Radio Hacker (URH)](https://github.com/jopohl/urh) | Cross-platform | Protocol analysis and reverse engineering |
| [GNU Radio](https://www.gnuradio.org/) | Cross-platform | Powerful signal processing framework; build flowgraphs |
| [Inspectrum](https://github.com/miek/inspectrum) | Linux/macOS | Offline signal analysis from recorded IQ files |

### Beginner Projects

**ADS-B Aircraft Tracking** — Commercial aircraft broadcast their position, altitude, speed, and callsign on 1090 MHz using ADS-B (Automatic Dependent Surveillance-Broadcast). With an RTL-SDR and [dump1090](https://github.com/flightaware/dump1090) or [ADS-B Exchange](https://www.adsbexchange.com/), you can build your own radar display. This project teaches signal reception, decoding, and data visualization — and illustrates that aircraft broadcast identifying information to anyone who listens.

**NOAA Weather Satellites** — NOAA 15/18/19 broadcast APT (Automatic Picture Transmission) weather images at 137 MHz. A V-dipole antenna and [WXtoImg](https://wxtoimgrestored.xyz/) lets you receive real-time satellite images. Teaches orbital mechanics, antenna theory, and FM demodulation.

**Pager Decoding** — POCSAG and FLEX pager protocols transmit on VHF/UHF. Many hospital, emergency service, and commercial pager systems still broadcast plaintext messages. Tools: [PDW](http://www.discriminator.nl/pdw/index-en.html) (Windows), [multimon-ng](https://github.com/EliasOenal/multimon-ng). Teaches that legacy protocols often have zero security.

**433 MHz IoT Sensor Capture** — Cheap weather stations, door/window sensors, temperature sensors, and tire pressure monitors transmit on 433 MHz or 315 MHz with no authentication. URH can decode these signals and identify the protocol. Replay attacks against garage doors, gate openers, and remote controls often work because manufacturers use simple fixed codes.

### Going Further: HackRF One

The **[HackRF One](https://greatscottgadgets.com/hackrf/)** (~$340) by Great Scott Gadgets adds *transmit* capability: 1 MHz to 6 GHz, half-duplex. This enables:
- **Replay attacks** — capture a key fob signal, replay it to unlock the target
- **GPS spoofing** (research, controlled environments only)
- **Jamming research** (subject to strict legal restrictions)
- **Cellular protocol research**

### Legal Warning

Transmitting on licensed frequencies without authorization is illegal in most jurisdictions (FCC Part 97 in the US). Use HackRF-class transmitters only in controlled environments, Faraday cages, or with appropriate licenses. Receiving is generally legal everywhere.

---

## Amateur Radio (Ham Radio)

Amateur radio (ham radio) is a licensed radio communications service that allows individuals to experiment with radio technology. Unlike other radio hobbies, ham radio operators can legally transmit across a huge range of frequencies, build their own equipment, and communicate globally.

### Why It Matters for Security

Ham radio is the original hacker radio culture. The FCC Technician license exam covers antenna theory, propagation, RF safety, and basic electronics — all directly relevant to understanding wireless attack surfaces. Many professional RF security researchers hold ham licenses not just for the legal transmit privileges, but because the licensing process forces you to learn the *physics* of radio in a structured way.

### Getting Licensed

- **FCC Technician License** — entry level; covers VHF/UHF; costs $15 exam fee (2023+); no Morse code required
- **Study resources**: [hamstudy.org](https://hamstudy.org/) (free, adaptive flashcards), [ARRL Ham Radio License Manual](http://www.arrl.org/ham-radio-license-manual)
- **[ARRL](https://www.arrl.org/)** (American Radio Relay League) — the US amateur radio organization; publishes the Handbook, organizes exams

### What You Learn

- **Antenna theory** — gain, directivity, impedance matching; directly applies to understanding WiFi/cellular signal propagation
- **Propagation** — how signals travel; relevant to understanding attack range and geographic targeting
- **Modulation** — AM, FM, SSB, digital modes; foundation for understanding all wireless protocols
- **RF safety** — power limits, exposure calculations; relevant to SAR and legal compliance

---

## Badge Hacking

DEF CON has issued custom electronic badges since 1998, with badges growing progressively more complex over the years. Each badge contains a puzzle — sometimes spanning multiple layers of cryptography, steganography, hardware debugging, and reverse engineering — that the hacker community works collectively to solve.

### Why It Matters for Security

Badge hacking is a microcosm of real hardware security research. Solving a DEF CON badge typically involves:
- **PCB analysis** — identifying components, tracing circuits
- **JTAG/SWD debugging** — attaching a debugger to read firmware
- **Firmware reverse engineering** — disassembling extracted binaries
- **Protocol reverse engineering** — badges often communicate with each other
- **Cryptographic challenges** — ciphers embedded in artwork, audio, or RF signals

### Resources

- **[Hackaday DEF CON Badge coverage](https://hackaday.com/tag/defcon-badge/)** — detailed annual teardowns
- **[Joe Grand](https://www.youtube.com/@JoeGrand)** (YouTube / Grand Idea Studio) — hardware hacker who designed several DEF CON badges; excellent hardware RE content
- **[DEF CON Badge Forums](https://forum.defcon.org/)** — community solving efforts

---

## Car Hacking

Modern vehicles are rolling networks. A typical car contains 50–150 Electronic Control Units (ECUs) communicating over multiple networks, most notably the **Controller Area Network (CAN bus)**. CAN was designed in the 1980s for reliability, not security — there is no authentication, no encryption, and any node on the bus can send messages to any other node.

### Why It Matters for Security

Car hacking illustrates a broader truth: safety-critical systems were often designed before security was a concern. The same issues appear in medical devices, industrial control systems, and aviation. Understanding CAN bus attacks builds intuition for assessing any legacy embedded network.

### Core Concepts

**CAN Bus** — A two-wire differential bus where every node receives every message. Messages have an 11-bit or 29-bit arbitration ID but no source address or authentication. An attacker with physical access to the OBD-II port (or wireless access via a compromised head unit/TCU) can inject arbitrary CAN frames.

**OBD-II** — Standardized diagnostic port present in all US vehicles since 1996. Located under the dashboard. Provides direct access to the CAN bus.

**Attacks**
- **Spoofing** — inject CAN frames with forged arbitration IDs to control ECUs (lock/unlock doors, disable brakes in research settings)
- **Fuzzing** — send random CAN frames to discover undocumented behavior
- **Replay** — capture and replay legitimate CAN sequences
- **Remote attack surface** — infotainment systems, Bluetooth, cellular TCUs can provide remote entry to the CAN bus

### Learning Tools

| Tool | Description |
|------|-------------|
| [ICSim](https://github.com/zombieCraig/ICSim) | Instrument Cluster Simulator; safe CAN bus learning environment |
| [can-utils](https://github.com/linux-utils/can-utils) | Linux CAN bus tools (candump, cansend, cangen) |
| [CANalyzer](https://www.vector.com/int/en/products/products-a-z/software/canalyzer/) | Professional CAN analysis (expensive; Vector) |
| [USB2CAN / CANable](https://canable.io/) | Cheap USB-to-CAN adapter for Linux |
| [Caring Caribou](https://github.com/CaringCaribou/caringcaribou) | CAN security tool |

### Resources

- **[The Car Hacker's Handbook](https://nostarch.com/carhacking)** — Craig Smith; [free PDF available](http://opengarages.org/handbook/)
- **[Car Hacking Village](https://www.carhackingvillage.com/)** — DEF CON village with hands-on car hacking labs
- **[Open Garages](http://opengarages.org/)** — open community for vehicle security research

---

## Drone Security

Unmanned Aerial Vehicles (UAVs) introduce unique security considerations: they communicate wirelessly, often use consumer-grade protocols with weak or no authentication, and can carry payloads (cameras, network attack tools, etc.).

### Why It Matters for Security

Drone threats range from corporate espionage (optical surveillance, WiFi/cellular sniffing at altitude) to physical security bypass (dropping payloads over perimeters). Understanding drone RF protocols helps defenders build detection and response capabilities.

### Protocol Analysis

Most consumer drones use proprietary protocols in the 2.4 GHz and 5.8 GHz ISM bands. Some use standard RC protocols (SBUS, CRSF, ExpressLRS). DJI drones use **OcuSync** and **O3** — partially reverse engineered by the community.

**Tools & Techniques**
- **HackRF One / USRP** — wideband capture of drone control and video link signals
- **[DroneID](https://github.com/proto17/dji_droneid)** — decoding DJI's DroneID broadcast (Remote ID)
- **[OpenDroneID](https://github.com/opendroneid/opendroneid-core-c)** — FAA Remote ID implementation
- **Wireshark + 802.11** — many drones use WiFi-based control links that can be analyzed with standard tools
- **Deauth attacks** — WiFi-controlled drones are vulnerable to 802.11 deauthentication (note: illegal against drones you don't own)
- **GPS spoofing** — consumer GPS receivers can be tricked; demonstrated to redirect drones

### Resources

- **[Drone Hacking Village](https://villagefoundation.com/)** — DEF CON village (check current year's villages)
- **[Samy Kamkar's SkyJack](https://samy.pl/skyjack/)** — classic 2013 drone hijacking proof-of-concept

---

## DEF CON Villages Reference

DEF CON villages are semi-independent spaces within the conference where specific communities run hands-on activities, talks, and competitions. The village model emerged because DEF CON grew too large for a single track to cover all hacker interests.

| Village | Focus Area |
|---------|------------|
| [Aerospace Village](https://aerospacevillage.org/) | Aviation/space cybersecurity, ADS-B, ACARS |
| [AI Village](https://aivillage.org/) | AI/ML security, adversarial ML, LLM attacks |
| [AppSec Village](https://www.appsecvillage.com/) | Web application security |
| [Biohacking Village](https://www.villageb.io/) | Medical device security, health tech |
| [Blockchain Village](https://blockchainvillage.net/) | Crypto/DeFi security, smart contract auditing |
| [Car Hacking Village](https://www.carhackingvillage.com/) | CAN bus, ECU, automotive security |
| [Cloud Village](https://cloud-village.org/) | Cloud infrastructure security |
| [Crypto & Privacy Village](https://cryptovillage.org/) | Cryptography, privacy tech |
| [DC Demo Labs](https://www.defcon.org/) | Live tool demos |
| [Ham Radio Village](https://hamradiovillage.org/) | Amateur radio, license exams on-site |
| [Hardware Hacking Village](https://www.dc-hhv.com/) | PCB analysis, JTAG, soldering, RE |
| [ICS Village](https://www.icsvillage.com/) | Industrial control systems, SCADA, OT |
| [IoT Village](https://www.iotvillage.org/) | Consumer IoT security, embedded devices |
| [Lock Bypass Village](https://toool.us/) | Physical security, lockpicking (TOOOL) |
| [Misinfo Village](https://misinfovillage.org/) | Misinformation, OSINT |
| [Mobile Hacking Village](https://mobilehackingvillage.com/) | iOS/Android security |
| [Password Village](https://passwordvillage.org/) | Password cracking, hash analysis |
| [Packet Hacking Village](https://www.wallofsheep.com/) | Network analysis, "Wall of Sheep" |
| [Red Team Village](https://redteamvillage.io/) | Offensive security techniques |
| [RF Village](https://rfvillage.org/) | Radio frequency security, SDR |
| [Recon Village](https://reconvillage.org/) | OSINT, reconnaissance |
| [Social Engineering Village](https://www.se-village.org/) | Social engineering, vishing, pretexting |
| [Skytalks](https://skytalks.info/) | Off-record, sensitive talks |
| [Voting Village](https://votingvillage.org/) | Election security, voting machine research |
| [Wireless Village](https://wirelessvillage.ninja/) | WiFi, Bluetooth, ZigBee, wireless protocols |

---

## Hacker Conferences

| Conference | Location | Focus |
|------------|----------|-------|
| [DEF CON](https://defcon.org/) | Las Vegas, NV (August) | The largest hacker conference; villages, talks, CTF |
| [Black Hat USA](https://www.blackhat.com/) | Las Vegas, NV (August) | Professional security briefings and trainings; vendor-heavy |
| [BSides](http://www.securitybsides.com/) | Worldwide (various dates) | Community-organized local conferences; free/cheap; great for networking |
| [ShmooCon](https://www.shmoocon.org/) | Washington, D.C. (January) | East Coast hacker culture; notoriously hard-to-get tickets |
| [THOTCON](https://www.thotcon.org/) | Chicago, IL (spring) | Midwest hacker con; strong CTF culture |
| [ToorCon](https://toorcon.net/) | San Diego, CA | West Coast; tech-focused |
| [GrrCON](https://grrcon.com/) | Grand Rapids, MI | Midwest; corporate/enterprise security |
| [DerbyCon](https://twitter.com/derbycon) | Louisville, KY (retired 2019) | Well-loved community con; legacy content on YouTube |

**Tip**: Start with your local BSides. Tickets are free or very cheap, talks are community-submitted, and the hallway track (conversations outside scheduled talks) is often more valuable than the sessions.

---

## Learning Resources

| Resource | Type | Topic |
|----------|------|-------|
| [RTL-SDR Blog](https://www.rtl-sdr.com/) | Website/Tutorials | SDR, RTL-SDR projects |
| [HackRF Wiki](https://hackrf.readthedocs.io/) | Documentation | HackRF One usage |
| [GNU Radio Tutorials](https://wiki.gnuradio.org/index.php/Tutorials) | Tutorials | Signal processing |
| [The Car Hacker's Handbook](http://opengarages.org/handbook/) | Free PDF Book | Automotive security |
| [LockPickingLawyer](https://www.youtube.com/@LockPickingLawyer) | YouTube | Lockpicking, lock reviews |
| [Hak5](https://hak5.org/) | YouTube/Products | Hardware attack tools, tutorials |
| [Hackaday](https://hackaday.com/) | Blog | Hardware, electronics, security |
| [Joe Grand (Grand Idea Studio)](https://www.youtube.com/@JoeGrand) | YouTube | Hardware RE, badge hacking |
| [hamstudy.org](https://hamstudy.org/) | Study Tool | Ham radio license exam prep |
| [ARRL Handbook](https://www.arrl.org/arrl-handbook-2024) | Book | Comprehensive amateur radio reference |
| [Proxmark Forums](https://forum.proxmark.org/) | Forum | RFID/NFC research community |
| [/r/lockpicking](https://reddit.com/r/lockpicking) | Community | Belt ranking, advice, picks |
| [/r/RTLSDR](https://reddit.com/r/RTLSDR) | Community | SDR projects, help |

---

## Related Disciplines

- [physical-security.md](physical-security.md) — Physical penetration testing, social engineering, access control assessments
- [hardware-security.md](hardware-security.md) — PCB analysis, firmware extraction, JTAG/UART, embedded RE
- [iot-security.md](iot-security.md) — IoT device security, embedded Linux, consumer device research
- [radio-frequency-security.md](radio-frequency-security.md) — Professional RF security work, wireless protocol analysis
- [social-engineering.md](social-engineering.md) — Human-layer attacks, pretexting, physical social engineering
