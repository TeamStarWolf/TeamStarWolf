# SDR & RF Security Reference Library

> A professional cybersecurity reference for Software-Defined Radio and RF security research, penetration testing, and defensive operations.

---

## Table of Contents

1. [SDR Fundamentals & Hardware](#1-sdr-fundamentals--hardware)
2. [GNU Radio](#2-gnu-radio)
3. [RTL-SDR & Common Tools](#3-rtl-sdr--common-tools)
4. [HackRF One](#4-hackrf-one)
5. [Wireless Protocol Analysis](#5-wireless-protocol-analysis)
6. [P25 & Public Safety Radio](#6-p25--public-safety-radio)
7. [Replay & Signal Injection](#7-replay--signal-injection)
8. [Kismet Wireless Monitor](#8-kismet-wireless-monitor)
9. [RFID, NFC & TPMS](#9-rfid-nfc--tpms)
10. [Defensive RF & Legal Framework](#10-defensive-rf--legal-framework)

---

## 1. SDR Fundamentals & Hardware

### What is Software-Defined Radio?

Software-Defined Radio (SDR) is a radio communication system where components traditionally implemented in hardware (mixers, filters, amplifiers, modulators/demodulators, detectors) are instead implemented by means of software on a personal computer or embedded system. An SDR system typically consists of:

- **RF Front-end**: Antenna, low-noise amplifier (LNA), bandpass filter, and analog-to-digital converter (ADC)
- **Digital Back-end**: Software running on a CPU/FPGA that performs signal processing
- **Host Interface**: USB, PCIe, Ethernet, or direct FPGA I/O

### RF Fundamentals

**Frequency & Wavelength**
- Wavelength (lambda) = Speed of Light (c) / Frequency (f): lambda = 3x10^8 / f
- HF: 3-30 MHz | VHF: 30-300 MHz | UHF: 300 MHz-3 GHz | SHF: 3-30 GHz
- Propagation varies: HF bounces off ionosphere; VHF/UHF line-of-sight; SHF requires dishes

**Modulation Types**

| Type | Full Name | Description | Common Use |
|------|-----------|-------------|------------|
| AM | Amplitude Modulation | Varies signal amplitude | AM broadcast, aviation voice |
| FM | Frequency Modulation | Varies signal frequency | FM broadcast, VHF voice |
| SSB | Single Sideband | AM with carrier + one sideband suppressed | HF amateur, maritime |
| FSK | Frequency Shift Keying | Digital FM (two frequencies = 0/1) | Paging, AFSK packet |
| GFSK | Gaussian FSK | FSK with Gaussian filter to reduce bandwidth | Bluetooth, Zigbee |
| PSK | Phase Shift Keying | Varies carrier phase | BPSK, QPSK in digital links |
| QAM | Quadrature Amplitude Modulation | Combines AM + PM for high data rates | LTE, WiFi, cable TV |
| OFDM | Orthogonal FDM | Multiple subcarriers simultaneously | LTE, 802.11 WiFi, DAB |

**IQ (In-Phase / Quadrature) Sampling**

IQ samples represent the full complex baseband signal:
- I = In-phase component (real)
- Q = Quadrature component (imaginary, 90 degrees shifted)
- Complex sample: s(t) = I(t) + jQ(t)
- Enables capture of both amplitude and phase information
- Most SDR hardware outputs 8-bit or 16-bit IQ pairs at a configurable sample rate

**Nyquist-Shannon Sampling Theorem**
- Minimum sample rate must be at least 2x the highest frequency of interest
- RTL-SDR samples at 2.4 MSPS captures up to 1.2 MHz of instantaneous bandwidth
- Aliasing occurs when signals exceed Nyquist limit; use anti-aliasing filters

**Bandwidth vs. Sample Rate**
- Instantaneous bandwidth = sample rate (Hz)
- Wider bandwidth captures more spectrum simultaneously at the cost of more CPU load
- Typical trade-off: HackRF at 20 MSPS captures 20 MHz bandwidth at once

### SDR Hardware Comparison

| Device | Price | Frequency Range | Max BW | Duplex | ADC Bits | TX? | Notes |
|--------|-------|-----------------|--------|--------|----------|-----|-------|
| RTL-SDR v3 | $25 | 500 kHz-1.75 GHz | 2.4 MHz | RX only | 8-bit | No | Best entry-level; direct sampling for HF |
| HackRF One | $300 | 1 MHz-6 GHz | 20 MHz | Half | 8-bit | Yes | Open-source; ~15 dBm TX; no simultaneous RX+TX |
| USRP B210 | $1,100 | 70 MHz-6 GHz | 56 MHz | Full | 12-bit | Yes | Research-grade; MIMO capable; FPGA-based |
| LimeSDR | $300 | 100 kHz-3.8 GHz | 61.44 MHz | Full | 12-bit | Yes | Open hardware; FPGA; LMS7002M chipset |
| Airspy R2 | $169 | 24-1,800 MHz | 10 MHz | RX only | 12-bit | No | High dynamic range; excellent sensitivity |
| Airspy HF+ | $199 | DC-31 MHz / 60-260 MHz | 660 kHz | RX only | 18-bit | No | Exceptional HF/VHF performance |
| KerberosSDR | $150 | 24 MHz-1.75 GHz | 2.4 MHz x4 | RX only | 8-bit x4 | No | 4-channel coherent; direction finding; based on RTL-SDR |
| SDRplay RSPdx | $200 | 1 kHz-2 GHz | 10 MHz | RX only | 14-bit | No | Wide coverage; HDR mode below 2 MHz |

### Antenna Selection by Frequency Band

| Frequency | Antenna Type | Notes |
|-----------|-------------|-------|
| HF (3-30 MHz) | End-fed halfwave (EFHW), random wire + tuner, magnetic loop | Long antennas; portable loops for noise rejection |
| VHF (30-300 MHz) | Dipole, J-pole, 5/8 wave vertical | Simple builds; good omnidirectional coverage |
| UHF (300-3000 MHz) | Discone (wideband), Yagi (directional), patch | Discone for scanning; Yagi for point-to-point |
| 433/868/915 MHz | Whip, rubber duck, helical | IoT, keyfobs, TPMS, weather stations |
| 2.4 / 5 GHz | Panel, parabolic dish, biquad | WiFi; high gain for long range |
| 1090 MHz ADS-B | Coaxial collinear (CoCo), 1/4 wave ground plane | Vertical polarization for omnidirectional aircraft coverage |

**Log-Periodic Dipole Array (LPDA)**: Covers wide frequency range (e.g., 100 MHz-3 GHz) with consistent gain; ideal for EMC and general-purpose scanning.

**Impedance Matching**: Most SDR inputs are 50 ohm; antennas must match or use a balun/unun transformer.

### RF Safety & Legal Framework

**FCC Regulatory Framework (CFR Title 47)**
- **Part 15**: Unlicensed intentional and unintentional radiators; governs consumer electronics
  - 15.247: Spread spectrum devices (WiFi, Bluetooth, Zigbee) in ISM bands
  - 15.249: Intentional radiators in ISM bands with field strength limits
- **Part 97**: Amateur Radio Service - requires license (Technician, General, Extra)
  - Permits operation across HF/VHF/UHF/SHF bands with power up to 1,500W PEP
  - Prohibits encryption of messages except for control of satellites; no commercial use
- **Part 90**: Private Land Mobile Radio; covers public safety, business, industrial
- **Part 22/24/25/27**: Commercial cellular, PCS, satellite services - TRANSMIT PROHIBITED without license

**Legal Considerations for SDR Security Research**
- Receiving (passive monitoring) of most signals is legal under 47 U.S.C. ss 705 with exceptions
- ECPA (18 U.S.C. ss 2511) prohibits interception of electronic communications; cellular is covered
- P25, cellular, and APCO-protected transmissions may not be retransmitted
- Transmitting without authorization violates 47 U.S.C. ss 333 (intentional interference) - felony
- Active injection, jamming, and replay on licensed bands requires explicit authorization

### Calibration & Configuration

**PPM Calibration with kalibrate-rtl**
```bash
# Scan for GSM base stations to use as frequency references
kal -s GSM900 -g 40
# Calibrate against a known channel (e.g., channel 52 at offset)
kal -c 52 -g 40 -e 0
# Example output: average absolute error: 3.141 ppm
# Apply correction: rtl_sdr -p 3 (rounds to nearest integer)
```

**Gain Staging**
- RF Gain: Applied at the antenna port; increases sensitivity but also noise
- IF Gain: Applied to intermediate frequency stage
- BB (Baseband) Gain: Applied in digital domain
- Optimal: Set RF gain just high enough to lift desired signals above noise floor; avoid ADC clipping
- AGC (Automatic Gain Control): Available on some devices; useful for unknown signal environments

**Connector Types**
- SMA (SubMiniature version A): 50 ohm; common on RTL-SDR, HackRF, USRP; M/F pairs
- BNC (Bayonet Neill-Concelman): 50 ohm or 75 ohm; quick-connect; common on test equipment
- N-type: Weatherproof; larger; used on high-power and outdoor antennas
- MCX/MMCX: Miniature; found on some dongles and embedded boards
- Adapters: SMA-F to BNC-M, SMA-M to N-F, etc.; quality matters at GHz frequencies

---

## 2. GNU Radio

### Overview

GNU Radio is a free and open-source software development toolkit that provides signal processing blocks to implement software radios. It is used heavily in hobbyist, academic, and professional RF security research.

- **Language**: Primarily Python (blocks can be C++ for performance)
- **Version**: GNU Radio 3.10.x (current); 3.9.x widely deployed
- **Website**: https://www.gnuradio.org
- **Installation**: `sudo apt install gnuradio` (Ubuntu/Debian)

### GNU Radio Companion (GRC)

GRC is the graphical flow graph editor for GNU Radio:
- Drag-and-drop signal processing blocks
- Connects blocks with streams (complex, float, byte, etc.)
- Generates Python script from flow graph (.grc -> .py)
- Supports hierarchical blocks (sub-flow-graphs)

**Essential Blocks**

| Block | Category | Description |
|-------|----------|-------------|
| osmocom Source | Sources | Universal SDR input (RTL-SDR, HackRF, USRP, LimeSDR) |
| osmocom Sink | Sinks | Universal SDR output (TX-capable hardware) |
| Throttle | Misc | Limits throughput for file/simulation (not needed with real HW) |
| Low Pass Filter | Filters | Removes out-of-band signals; specify cutoff + transition width |
| High Pass Filter | Filters | Removes low-frequency interference |
| Band Pass Filter | Filters | Passes a specific frequency band |
| Rational Resampler | Resamplers | Changes sample rate by rational fraction (decimation/interpolation) |
| Multiply Const | Math | Scales signal amplitude |
| Add | Math | Adds two signal streams |
| QT GUI Frequency Sink | GUI | Real-time FFT spectrum display |
| QT GUI Waterfall Sink | GUI | Scrolling time-frequency spectrogram |
| QT GUI Time Sink | GUI | Time-domain waveform display |
| WBFM Receive | Demod | Wideband FM demodulation (stereo capable) |
| NBFM Receive | Demod | Narrowband FM demodulation |
| AM Demod | Demod | Amplitude modulation demodulation |
| PSK Demod | Demod | Phase shift keying demodulation |
| File Source | Sources | Read IQ data from file (complex float32 format) |
| File Sink | Sinks | Write IQ samples to file |
| Audio Sink | Sinks | Play demodulated audio through system sound |
| Multiply | Math | Complex multiply - used for frequency shifting |
| Signal Source | Sources | Generate tones, noise, sweeps |

### FM Broadcast Demodulation Flow Graph

```
RTL-SDR Source (freq=88.5MHz, samp_rate=2.4MHz)
  -> Low Pass Filter (cutoff=100kHz, transition=10kHz)
  -> Rational Resampler (decimate by 12, out samp_rate=200kHz)
  -> WBFM Receive (audio_decimation=10, out=20kHz)
  -> Multiply Const (volume=0.3)
  -> Audio Sink (sample_rate=48kHz, with final resampler)
```

### Python-Based Signal Processing

```python
import numpy as np
from scipy import signal
import matplotlib.pyplot as plt

# Load IQ data captured by RTL-SDR (complex float32)
samples = np.fromfile('capture.iq', dtype=np.complex64)

# Compute and display FFT
fft = np.fft.fftshift(np.fft.fft(samples[:4096]))
freqs = np.fft.fftshift(np.fft.fftfreq(4096, d=1/2.4e6))
plt.plot(freqs / 1e6, 20 * np.log10(np.abs(fft) + 1e-10))
plt.xlabel('Frequency (MHz offset)')
plt.ylabel('Power (dBFS)')
plt.title('Spectrum')
plt.show()

# Simple FM demodulation
def fm_demod(samples):
    phase = np.angle(samples)
    demod = np.diff(np.unwrap(phase))
    return demod

audio = fm_demod(samples)

# Design a low-pass filter
nyq = 2.4e6 / 2
b, a = signal.butter(5, 100e3 / nyq, btype='low')
filtered = signal.lfilter(b, a, samples)
```

### OOT (Out-of-Tree) Module Creation

```bash
# Create new OOT module
gr_modtool newmod my_module
cd gr-my_module

# Add a new block (sync block: output rate = input rate)
gr_modtool add my_block
# Choose: sync, decimator, interpolator, general, source, sink

# Module structure
# gr-my_module/
#   CMakeLists.txt
#   cmake/
#   docs/
#   grc/           -- GRC block definitions (.block.yml)
#   include/gnuradio/my_module/
#   lib/           -- C++ implementation
#     my_block_impl.cc
#   python/my_module/
#     my_block.py  -- Python block alternative
#   examples/

# Build and install
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make -j$(nproc)
sudo make install
sudo ldconfig
```

### Key OOT Module Ecosystem for Security

**gr-osmosdr**
- Universal hardware abstraction layer for GNU Radio
- Supports: RTL-SDR, HackRF, USRP, LimeSDR, Airspy, bladeRF, SoapySDR
- Usage: `osmosdr.source(args="rtl=0,gain=40")` or `osmosdr.source(args="hackrf=0")`
- SoapySDR backend enables even broader hardware support

**gr-satellites**
- Decodes 40+ satellite beacon protocols
- Supports FUNcube, AO-73, FUNCUBE-1, Tianwang-1, and many CubeSats
- Installation: `pip install gr-satellites` or build from source
- Usage: `gr_satellites <satellite_name> --wavfile input.wav`

**gr-gsm**
- GSM downlink capture and analysis
- `grgsm_livemon` - real-time GSM channel monitor with Wireshark integration
- `grgsm_decode` - offline GSM burst decoding
- Captures BCCH, SDCCH, TCH channels; useful for base station analysis

**gr-ais**
- AIS (Automatic Identification System) decoding for ship tracking
- Decodes NMEA sentences from 161.975 MHz and 162.025 MHz
- Feeds into OpenCPN or online AIS aggregators

**gr-ieee802-11**
- IEEE 802.11a/g/p (WiFi) physical layer implementation in GNU Radio
- Enables packet injection and reception research at PHY level
- Useful for studying OFDM-based protocols and custom frame injection

### IQ Recording and Replay

```bash
# Record IQ with rtl_sdr (raw binary, complex uint8)
rtl_sdr -f 433.92e6 -s 2.4e6 -n 24000000 capture_433.cu8

# Convert cu8 to cf32 for GNU Radio
python3 -c "
import numpy as np
d = np.fromfile('capture_433.cu8', dtype=np.uint8)
c = (d.astype(np.float32) - 127.5) / 127.5
iq = c[::2] + 1j*c[1::2]
iq.astype(np.complex64).tofile('capture_433.cf32')
"

# GNU Radio replay flow
# File Source (capture_433.cf32, complex, Repeat=Yes)
# -> osmocom Sink (hackrf=0, Freq=433.92MHz, Samp Rate=2.4MSPS)
```

**gr-iqrecorder**
- Supports threshold-based recording (squelch trigger)
- Configurable segment duration, file naming by timestamp
- Useful for automated capture of intermittent transmissions

---

## 3. RTL-SDR & Common Tools

### RTL-SDR Hardware Overview

The RTL-SDR is based on the Realtek RTL2832U DVB-T chipset combined with a tuner IC (most commonly Rafael Micro R820T2). Originally designed for digital TV reception, the raw IQ output mode was discovered by Eric Fry in 2012, spawning the RTL-SDR community.

**RTL-SDR v3 (rtl-sdr.com)**
- Frequency: 500 kHz-1.75 GHz (direct sampling for HF below 24 MHz)
- Sample rate: 225001-300000 or 900001-3200000 samples/sec (2.4 MSPS stable)
- ADC: 8-bit (limited dynamic range ~48 dB)
- Bias-T: 4.5V for powered antennas (LNA, filtered antennas)
- Linux: `sudo apt install rtl-sdr`; Windows: Zadig driver (WinUSB)

### Core RTL-SDR Command-Line Tools

**rtl_sdr - Basic IQ Capture**
```bash
# Capture 10 seconds of IQ at 433.92 MHz, 2.4 MSPS, gain 40 dB
rtl_sdr -f 433920000 -s 2400000 -g 40 -n 24000000 output.cu8

# With PPM correction and automatic gain
rtl_sdr -f 162400000 -s 250000 -p 3 -g 0 noaa_wx.cu8

# Pipe to another tool
rtl_sdr -f 433920000 -s 2400000 - | some_decoder
```

**rtl_fm - FM Demodulation**
```bash
# NOAA Weather Radio (NFM)
rtl_fm -f 162.400M -M fm -s 22050 | aplay -r 22050 -f S16_LE

# Police scanner (NFM, squelch level 5)
rtl_fm -f 154.800M -M fm -s 22050 -l 5 | aplay -r 22050 -f S16_LE

# Wideband FM broadcast
rtl_fm -f 88.5M -M wbfm -s 200000 -r 48000 | aplay -r 48000 -f S16_LE

# Multiple frequencies (scanning mode)
rtl_fm -f 154.8M -f 155.3M -f 156.8M -M fm -s 22050 | aplay -r 22050 -f S16_LE

# Air traffic control (AM mode)
rtl_fm -f 121.5M -M am -s 12000 | aplay -r 12000 -f S16_LE
```

**rtl_tcp - Network SDR Server**
```bash
# Start server on all interfaces, port 1234
rtl_tcp -a 0.0.0.0 -p 1234 -f 100000000 -g 40

# Connect with SDR# or GQRX using RTL-SDR (TCP) source
# Allows remote SDR access over LAN or internet (VPN recommended)
# Multiple clients NOT supported - single connection only
```

**rtl_power - Frequency Sweep / Spectrum Survey**
```bash
# Sweep FM broadcast band, 125kHz steps, 10-second intervals, run once
rtl_power -f 88M:108M:125k -i 10 -1 fm_band.csv

# Sweep 400-500 MHz continuously, write CSV
rtl_power -f 400M:500M:100k -i 5 output.csv

# Visualize with heatmap.py (from rtl-sdr repository)
python3 heatmap.py output.csv heatmap.png

# Unlimited continuous sweep
rtl_power -f 24M:1800M:1M -i 10 fullband.csv
```

**rtl_433 - 433 MHz ISM Band Sensor Decoder**
```bash
# Auto-detect all supported protocols, JSON output
rtl_433 -F json -G

# Specific frequency
rtl_433 -f 915M -F json

# Log to file
rtl_433 -F json:sensors.json -G

# Specific protocols only (TPMS, weather stations)
rtl_433 -R 59 -R 64 -F json   # R59=TPMS, R64=AcuRite

# MQTT output for home automation
rtl_433 -F "mqtt://localhost:1883,retain=0,devices=rtl433/[MODEL]/[ID]" -G
```

### GUI Applications

**SDR# (SDRSharp) - Windows**
- URL: https://airspy.com/download/
- Architecture: Plugin-based (.NET); supports RTL-SDR, Airspy, HackRF via plugins
- Features: Real-time spectrum, waterfall, AM/FM/SSB/CW demodulation
- Key Plugins:
  - **Frequency Manager**: Save and organize bookmarks
  - **DSD+ Integration**: Real-time P25/DMR/NXDN decoding via virtual audio cable
  - **FreqEdit**: Frequency list editor
  - **Scanner Plugin**: Automatic scanning of frequency lists
- Configuration: SDRSharp.exe.Config sets sample rate, audio device, and plugins
- Set bufferSize and frontendPlugin for stability

**GQRX - Linux/macOS**
```bash
sudo apt install gqrx-sdr

# Launch
gqrx

# Configuration: Edit -> Preferences
# I/O Devices: Device string: rtl=0,gain=40,bias=1
# Audio: ALSA or PulseAudio output
```
- Features: Recording (wav/raw IQ), bookmarks, remote control via TCP port 7356
- Remote control: `echo "F 145800000" | nc localhost 7356` (set frequency to 145.8 MHz)

**CubicSDR - Cross-platform**
- Based on SoapySDR/liquid-dsp
- Supports Windows/Linux/macOS
- Features: Bookmark manager, band plans, audio streaming server

### ADS-B Aircraft Tracking

**dump1090**
```bash
# Install
sudo apt install dump1090-mutability

# Run with network output and interactive display
dump1090 --net --interactive --gain -10 --ppm 0

# Network ports:
#   30002: raw Beast binary data
#   30003: SBS-1 (BaseStation) format
#   8080: Built-in web map (--net-http-port 8080)

# FlightAware PiAware
sudo apt install piaware
piaware-config flightaware-user YOUR_EMAIL
piaware-config flightaware-password YOUR_PASS
sudo systemctl start piaware
```

**dump978 - UAT 978 MHz (US Only)**
```bash
# Capture raw UAT
rtl_sdr -f 978000000 -s 2083334 -g 48 - | dump978-fa | uat2esnt | nc 127.0.0.1 30005
```

### Pager & APRS Decoding

**multimon-ng**
```bash
# POCSAG pager decoding (152.24 MHz example)
rtl_fm -f 152.24M -M fm -s 22050 -g 40 | multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 /dev/stdin

# FLEX pager protocol
rtl_fm -f 929.5625M -M fm -s 22050 | multimon-ng -t raw -a FLEX /dev/stdin

# APRS decoding (144.39 MHz in North America)
rtl_fm -f 144.39M -M fm -s 22050 -g 40 | multimon-ng -t raw -a AFSK1200 /dev/stdin

# DTMF tone detection
rtl_fm -f 446.000M -M fm -s 22050 | multimon-ng -t raw -a DTMF /dev/stdin

# EAS (Emergency Alert System)
rtl_fm -f 162.400M -M fm -s 22050 | multimon-ng -t raw -a EAS /dev/stdin
```

---

## 4. HackRF One

### Overview

HackRF One is an open-source software-defined radio peripheral capable of transmission and reception from 1 MHz to 6 GHz. Designed and released as open source hardware by Great Scott Gadgets, it is a widely used platform for RF security research.

**Key Specifications**
- Frequency: 1 MHz - 6 GHz
- Sample rate: 2-20 MSPS (complex IQ)
- ADC/DAC: 8-bit
- Duplex: Half-duplex only (cannot TX and RX simultaneously)
- TX power: ~15 dBm (approximately 32 mW) maximum; lower at extremes of frequency range
- Interface: USB 2.0 High Speed
- Antenna connector: SMA female
- Open-source: Hardware schematics and firmware freely available (github.com/greatscottgadgets/hackrf)

### Command-Line Tools

**hackrf_info - Device Information**
```bash
hackrf_info
# Output:
# hackrf_info version: git-a9945ac
# Found HackRF:  Index: 0
# Board ID Number: 2 (HackRF One)
# Firmware Version: 2023.01.1 (API:1.07)
# Part ID Number: 0xa000cb3c 0x00614764
# Serial number: 0000000000000000XXXXXXXXXXXX
# Hardware Revision: r9
```

**hackrf_transfer - RX and TX**
```bash
# RECEIVE: Capture at 433.92 MHz, 2 MSPS
hackrf_transfer -r capture.bin -f 433920000 -s 2000000 -l 40 -g 24 -n 20000000

# TRANSMIT: Replay captured signal
hackrf_transfer -t capture.bin -f 433920000 -s 2000000 -x 40

# TX with amplifier enabled (adds ~11 dB, use carefully)
hackrf_transfer -t signal.bin -f 915000000 -s 2000000 -x 47 -a 1

# Parameters:
#   -r : receive to file
#   -t : transmit from file
#   -f : frequency in Hz
#   -s : sample rate in Hz (2M-20M)
#   -l : LNA gain (RX) 0-40 dB in 8 dB steps
#   -g : VGA gain (RX) 0-62 dB in 2 dB steps
#   -x : TX VGA gain 0-47 dB in 1 dB steps
#   -a : amp enable (1=on, adds ~11 dB)
#   -n : number of samples to transfer
```

**hackrf_sweep - Wideband Spectrum Analysis**
```bash
# Sweep 2400-2500 MHz (2.4 GHz WiFi band)
hackrf_sweep -f 2400:2500 -l 40 -g 20 -w 100000 -B -N 10

# Full ISM band sweep
hackrf_sweep -f 433:435 -l 32 -g 20 -w 50000

# Parameters:
#   -f : frequency range low:high in MHz
#   -l : LNA gain
#   -g : VGA gain
#   -w : bin width in Hz
#   -B : binary output (faster)
#   -N : number of sweeps (omit for continuous)

# Output to CSV for visualization
hackrf_sweep -f 88:108 -l 40 -g 20 -w 125000 > sweep.csv
```

### Firmware Update

```bash
# Put HackRF in DFU mode: hold DFU button while plugging in USB
# Verify DFU mode
dfu-util -l

# Flash firmware (download from GitHub releases)
hackrf_spiflash -w hackrf_one_usb.bin

# Or use hackrf_update
hackrf_update hackrf_one_usb.dfu

# Verify after flash
hackrf_info | grep Firmware
```

### Portapack H2 with Mayhem Firmware

The Portapack H2 is a companion board that attaches to HackRF One, adding a screen, controls, speaker, and microSD card for fully standalone operation.

**Mayhem Firmware** - community firmware with extensive security features:
- URL: https://github.com/portapack-mayhem/mayhem-firmware
- Flash: Copy .bin to SD card root, or use hackrf_update

**Mayhem Features**

| Mode | Description |
|------|-------------|
| Spectrum Analyzer | Real-time spectrum 1 MHz - 6 GHz |
| Receiver | AM, NFM, WFM, POCSAG, AIS, ADS-B, SSTV |
| Transmitter | OOK, FSK, AFSK, Morse, microphone |
| Scanner | Multi-frequency scanning with audio |
| Jammer Detection | Identify jamming activity |
| POCSAG | Full pager decode with address filtering |
| Weather | RTL-433 type weather station decoding |
| GPS Sim | GPS satellite signal simulation |
| Sigfox Rx | Sigfox IoT protocol reception |
| NRF Sniff | nRF24L01 packet capture |

### Replay Attacks with HackRF

```bash
# Step 1: Capture target signal (e.g., garage door at 315 MHz)
hackrf_transfer -r garage_capture.bin -f 315000000 -s 2000000 -l 40 -g 24 -n 10000000

# Step 2: Analyze in inspectrum or URH to understand signal
inspectrum garage_capture.bin

# Step 3: Trim to exact signal burst (Python)
python3 -c "
import numpy as np
d = np.fromfile('garage_capture.bin', dtype=np.int8)
iq = d[::2].astype(np.float32)/127 + 1j*d[1::2].astype(np.float32)/127
power = np.abs(iq)**2
start = np.where(power > 0.01)[0][0]
end = np.where(power > 0.01)[0][-1]
trimmed = iq[max(0,start-1000):end+1000].astype(np.complex64)
out = np.zeros(len(trimmed)*2, dtype=np.int8)
out[::2] = (trimmed.real * 127).astype(np.int8)
out[1::2] = (trimmed.imag * 127).astype(np.int8)
out.tofile('garage_trimmed.bin')
"

# Step 4: Replay signal
hackrf_transfer -t garage_trimmed.bin -f 315000000 -s 2000000 -x 40
```

### HackRF in GNU Radio for TX

```python
import osmosdr

# TX Sink block configuration
tx_sink = osmosdr.sink(args="hackrf=0")
tx_sink.set_sample_rate(2e6)
tx_sink.set_center_freq(433.92e6)
tx_sink.set_freq_corr(0)
tx_sink.set_gain(0)        # HackRF: RF amp (0 or 14 dB)
tx_sink.set_if_gain(32)    # IF gain (0-47)
tx_sink.set_bb_gain(0)     # BB gain (not used in TX)
tx_sink.set_antenna("TX/RX")
tx_sink.set_bandwidth(2e6)
```

### HackRF vs RTL-SDR Selection Guide

| Use Case | Recommended | Reason |
|----------|-------------|--------|
| Passive monitoring / scanning | RTL-SDR v3 | Cheaper, lower noise figure for RX |
| Replay attacks | HackRF One | TX capability required |
| Signal injection | HackRF One | TX capability required |
| Wide instantaneous bandwidth | HackRF One | 20 MHz vs 2.4 MHz |
| HF reception | RTL-SDR v3 (direct sampling) | Better HF performance below 30 MHz |
| Full-duplex research | USRP B210 | Only device with true simultaneous TX+RX |
| Budget spectrum surveying | RTL-SDR v3 | $25 vs $300 |
| Sub-1MHz operation | LimeSDR | HackRF's 1 MHz lower limit |

---

## 5. Wireless Protocol Analysis

### GSM / 2G Analysis

**gr-gsm**
```bash
# Install
sudo apt install gr-gsm

# Live GSM downlink monitor with Wireshark integration
grgsm_livemon
# Opens GRC flow graph; set frequency to a local GSM channel
# In Wireshark: filter "gsmtap" to see decoded frames

# Find local GSM channels first
kal -s GSM900 -g 40      # Scan ARFCN channels
kal -s GSM1800 -g 40     # DCS band
kal -c 85 -g 40 -e 0     # Calibrate on channel 85

# Offline decode (captured file)
grgsm_decode -c gsm_capture.cfile -a BCCH -m GSM900

# Headless version for scripting
grgsm_livemon_headless -f 939.4M
```

**Understanding GSM Channels**
- BCCH (Broadcast Control Channel): Cell identity, LAC (Location Area Code), CID (Cell ID)
- SDCCH (Standalone Dedicated Control Channel): SMS, location updates
- TCH (Traffic Channel): Voice calls
- PCH (Paging Channel): Device paging (IMSI/TMSI visible)

**IMSI Catcher Detection**
```bash
# Record LAC/CID mappings over time and look for anomalies
# Legitimate cells: consistent LAC/CID, proper timing advance
# Rogue cells: too-strong signal, missing neighbor cells, drops to 2G unexpectedly

# kalibrate-rtl to find cells
kal -s GSM900 -g 40 2>&1 | grep "chan:"

# Known IMSI-catcher indicators:
#  - Cell appears/disappears rapidly
#  - Unusually high signal strength
#  - Only one cell visible (no neighbors)
#  - BCCH missing encryption flags in system info
```

### LTE / 4G Analysis

**srsRAN (formerly srsLTE)**
```bash
# Install
sudo apt install srslte   # or build from source

# LTE Cell Scanner
sudo srsue --rf.device_name=uhd --rf.device_args="type=b200"
# Or with HackRF (SoapySDR):
sudo srsue --rf.device_name=soapy --rf.device_args="hackrf"

# LTE EARFCN calculator
# Band 4: 2110-2155 MHz DL; DL EARFCN = 1950 + (f_DL - 2110) * 10

# LTE Layer 3 capture
# srsRAN outputs decoded RRC (Radio Resource Control) messages
# Use Wireshark with 'lte-rrc' dissector for analysis
# Cell Search reads MIB (Master Information Block) and SIB (System Information Blocks)
```

### Bluetooth Analysis

**Ubertooth One**
```bash
# Install tools
sudo apt install ubertooth

# BLE (Bluetooth Low Energy) packet capture
ubertooth-btle -f -c capture.pcap

# Follow a specific BLE connection
ubertooth-btle -f -A 37   # Advertising channel 37
ubertooth-btle -t AA:BB:CC:DD:EE:FF  # Follow target device

# Classic Bluetooth LAP scan
ubertooth-scan -s

# Frequency hopping analysis
ubertooth-specan   # Real-time spectrum analyzer mode

# Piconet following (Classic BT)
ubertooth-follow -l <LAP> -u <UAP>
```

**crackle - BLE Key Cracking**
```bash
# If LE Legacy pairing (Just Works or Passkey) was captured
crackle -i capture.pcap -o decrypted.pcap

# crackle recovers the TK (Temporary Key) for legacy pairing
# LE Secure Connections (LESC) using ECDH is NOT vulnerable to crackle
```

**BtleJuice - BLE MITM Framework**
```bash
# Node.js based BLE MITM proxy
npm install -g btlejuice
btlejuice-proxy &    # On proxy machine
btlejuice --target AA:BB:CC:DD:EE:FF   # On interceptor
# Web UI at http://localhost:8080 shows all GATT traffic
```

### Zigbee / IEEE 802.15.4

**KillerBee Framework**
```bash
# Install
pip install killerbee

# Discover networks
zbstumbler -i /dev/ttyUSB0

# Capture packets on channel 15
zbdump -i /dev/ttyUSB0 -c 15 -w zigbee_cap.pcap

# Replay captured frames
zbreplay -i /dev/ttyUSB0 -c 15 -r zigbee_cap.pcap

# Find devices
zbfind -i /dev/ttyUSB0

# Analyze in Wireshark (add network key in Wireshark ZigBee prefs)
wireshark -r zigbee_cap.pcap

# Well-known default Zigbee key (many consumer devices):
# 5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39
```

**Zigbee Security Notes**
- Network encryption: AES-128-CCM* (IEEE 802.15.4 security suite)
- Default/hardcoded network keys common in consumer devices
- Over-the-air key transport (Trust Center link key) can be sniffed at join time

### Z-Wave Analysis

- Z-Wave: 908.42 MHz (US), 868.42 MHz (EU); proprietary but documented
- Z-Wave Me Stick or EZMultiPli: USB Z-Wave controller
- zniffer: Z-Wave packet analyzer (Silicon Labs tool)
- Security: S0 (weak, shared network key), S2 (strong, ECDH+AES-128)

### LoRa / LoRaWAN

```bash
# gr-lora - GNU Radio LoRa receiver
# Install: https://github.com/rpp0/gr-lora

# LoRa parameters
# Spreading Factor (SF): 7-12 (higher SF = longer range, lower data rate)
# Bandwidth: 125/250/500 kHz
# Coding Rate: 4/5 to 4/8

# LoRaWAN security
# 1.0.x: AES-128 NwkSKey + AppSKey derived from root AppKey at OTAA join
# 1.1: Separate NwkKey and AppKey; replay protection improved
# Attack: Capture join request/accept; if AppKey known, derive session keys

# ChirpOTLE - LoRa/LoRaWAN test framework
# git clone https://github.com/seemoo-lab/chirpotle
# Supports bit-level manipulation of LoRa frames

# Semtech UDP packet forwarder: plain UDP, no authentication
# Gateway impersonation possible on LAN
```

### NB-IoT & Sigfox

**Sigfox**
- 868 MHz (EU), 902 MHz (US); ultra-narrowband (100 Hz UNB)
- DBPSK uplink, GFSK downlink; 12 bytes payload max
- No end-to-end encryption by default in early devices

**NB-IoT**
- Subset of LTE; operates in-band, guard-band, or standalone
- Encrypted (LTE security: AES, SNOW 3G, ZUC)
- Analysis requires LTE-capable SDR (USRP/LimeSDR) and srsRAN

### RF Fingerprinting

RF fingerprinting identifies specific hardware devices based on subtle RF characteristics:
- **Clock offsets**: Crystal oscillator variations create frequency offsets unique per device
- **Transient analysis**: Power-on/off transients are hardware-specific
- **IQ imbalance**: Manufacturing variations create measurable I/Q offset patterns
- **Phase noise**: Oscillator quality differences are fingerprint-able

```python
# Simple clock offset fingerprinting using RTL-433 TPMS data
# Each TPMS sensor has a unique 32-bit ID + clock drift fingerprint
# Cross-correlate sensor IDs seen at multiple locations for tracking
```

---

## 6. P25 & Public Safety Radio

### P25 Overview

APCO Project 25 (P25) is a suite of standards for digital radio communications for public safety agencies developed by the Association of Public-Safety Communications Officials International (APCO).

**P25 Phase 1 vs Phase 2**

| Feature | Phase 1 | Phase 2 |
|---------|---------|---------|
| Modulation | C4FM (4-level FSK) | TDMA (2-slot) |
| Channel width | 12.5 kHz | 6.25 kHz effective |
| Voice codec | IMBE (8 kbps) | AMBE+2 (6.4 kbps) |
| Capacity | 1 call per channel | 2 calls per channel |
| Adoption | Widespread (legacy) | Growing (new deployments) |
| Trunking | FDMA-based | TDMA-based |

**P25 Trunking Systems**
- Control channel broadcasts system information; subscriber radios monitor it
- When call initiated: control channel assigns a voice channel (grant)
- Multi-site trunking: RFSS (RF Subsystem) links multiple sites via IP

### op25 - P25 Decoder

```bash
# Install op25
sudo apt install gnuradio gr-osmosdr
git clone https://github.com/boatbod/op25
cd op25 && mkdir build && cd build
cmake .. && make -j4 && sudo make install

# Basic P25 receiver (single channel)
cd op25/op25/apps
python3 rx.py --args "rtl" -N "LNA:40" -f 851.3M -S 960000   -o 48000 -q 0 -d 0 -v 1

# Trunked system with trunking.tsv
python3 rx.py --args "rtl" -N "LNA:40" -T trunking.tsv   -f 851.3375M -S 960000 -o 48000

# Multi-site with multiple RTL-SDR dongles
python3 rx.py --args "rtl=0" -N "LNA:40" -T site1.tsv &
python3 rx.py --args "rtl=1" -N "LNA:40" -T site2.tsv &
```

**Control Channel Message Types (TSDU)**
- RFSS Status Broadcast: site ID, RFSS ID
- Network Status Broadcast: NAC, system ID
- Group Voice Channel Grant: assigns voice frequency to TGID
- Unit-to-Unit Voice Channel Grant
- Adjacent Site Status Broadcast: neighbor site frequencies

### P25 Encryption

| Type | Algorithm | Key Length | Status |
|------|-----------|------------|--------|
| DES-OFB | DES | 56-bit | Deprecated; vulnerable |
| AES-256 | AES | 256-bit | FIPS compliant; recommended |
| RC4 | RC4 | Variable | Non-standard; some legacy systems |
| ADP | DES variant | 40-bit | Export-restricted; obsolete |
| None | - | - | Clear voice; common in practice |

### P25 Security Vulnerabilities (Research Context)

These vulnerabilities have been publicly documented by academic researchers (Temple University, SIT, EFF):

1. **Unencrypted Inter-Site Links (ISSI/CSSI)**
   - Inter-RF Subsystem Interface (ISSI) and Console Subsystem Interface (CSSI)
   - Many deployments route these over unencrypted IP
   - An attacker with backhaul network access can passively monitor all calls

2. **OTAR (Over-The-Air Rekeying) Weaknesses**
   - P25 OTAR designed for key delivery over RF
   - If encryption key management is flawed, keys may be interceptable
   - Requires listening on control/dedicated channels during key update cycles

3. **Unencrypted Emergency Alerts**
   - P25 standard does NOT require encryption of emergency alert messages
   - Subscriber UNIT IDs (equivalent to IMSI) visible in emergency traffic
   - Enables tracking of individual radios in emergency situations

4. **Rogue Transmitter Risk**
   - P25 Phase 1 has no cryptographic authentication of control channel
   - Spoofed control channel can redirect radios to attacker-controlled frequency
   - Proof-of-concept demonstrated in academic settings

5. **Voice Quality Fingerprinting**
   - Even without key, IMBE vocoder parameters can statistically identify speakers
   - Applicable to encrypted traffic analysis

### P25 Phase 1 Protocol Capture

```bash
# Using op25 to decode control channel
# First, identify P25 control channel (listed on RadioReference.com)
# or scan with SDRTrunk / UniTrunker

# SDRTrunk - Java-based P25/DMR trunked system decoder
# Download: https://github.com/DSheirer/sdrtrunk
java -jar sdrtrunk.jar

# RadioReference database
# https://www.radioreference.com - find local P25 systems, NAC, control freqs
```

### Digital Voice Codecs

**DMR (Digital Mobile Radio) - ETSI TS 102 361**
```bash
# DSD+ (Digital Speech Decoder Plus) - Windows
dsd -i /dev/dsp -o /dev/dsp1 -fp   # P25 decode from audio

# MMDVM - Multi-Mode Digital Voice Modem
# Open-source repeater firmware supporting DMR, P25, YSF, NXDN
# Used in amateur and commercial infrastructure
```

**Other Digital Voice Protocols**

| Protocol | Modulation | Codec | Notes |
|----------|-----------|-------|-------|
| NXDN | 4FSK / FDMA | AMBE+2 | Kenwood/Icom proprietary |
| ProVoice | EDACS | Vector Sum Excited | Motorola iDEN derivative |
| EDACS | FSK | IMBE | Ericsson; largely obsolete |
| LTR | 5-tone FSK | Analog | Logic Trunked Radio; simple |
| Passport | MDC | Analog/Digital | Motorola; mostly obsolete |

### Scanner Programming

**Uniden HomePatrol 2**
- Built-in database of US/Canada systems; GPS-based auto-programming
- P25 Phase 1 and Phase 2 with optional upgrade

**Uniden SDS100 / SDS200**
- P25 Phase 1 and Phase 2 digital trunking
- Analog/Digital mixed; conventional and trunked
- RSS (Radio System Software) programming

**Whistler TRX-2**
- Supports P25 P1/P2, DMR, NXDN, ProVoice
- Discrim output jack for DSD+ integration

**Programming with RadioReference**
- Export system data, import to Sentinel (Uniden) or EZ-Scan (Whistler)
- Include all site frequencies, NAC values, TGID lists

---

## 7. Replay & Signal Injection

### Replay Attack Methodology

A replay attack captures a legitimate RF transmission and re-transmits it verbatim to trigger the same action. This is effective against systems that use fixed codes without challenge-response mechanisms.

**General Workflow**
1. Identify target: determine frequency, modulation, protocol
2. Capture IQ: record raw IQ data including target transmission
3. Analyze: demodulate, decode, identify packet boundaries
4. Trim: isolate the specific transmission of interest
5. Replay: retransmit with same parameters using HackRF or similar

```bash
# Step 1: Find frequency with rtl_power or spectrum scan
rtl_power -f 300M:500M:100k -i 5 -1 scan.csv
# Identify signal near 315/433 MHz (common keyfob bands)

# Step 2: Capture at identified frequency
hackrf_transfer -r keyfob_capture.bin -f 315000000 -s 2000000 -l 40 -g 24

# Step 3: Load in inspectrum for visualization
inspectrum -r 2000000 keyfob_capture.bin
# Or Universal Radio Hacker (URH)
urh keyfob_capture.bin

# Step 4: Trim to signal burst

# Step 5: Replay
hackrf_transfer -t keyfob_capture.bin -f 315000000 -s 2000000 -x 40
```

### Fixed-Code Systems (Vulnerable)

Many older consumer devices use fixed codes with no replay protection:

- **Garage door openers** (pre-2000 era): 8-12 bit DIP switch codes; 512-4096 possibilities
  - Code-grabbing: capture transmissions to decode
  - Brute force: transmit all codes sequentially with HackRF
- **Simple car remotes** (pre-1995): Fixed code OOK transmissions
- **RF power switches** (433 MHz ISM): Nearly all use fixed OOK codes
- **Wireless doorbells**: Fixed code; typically no consequences beyond nuisance
- **Remote keyless entry (old)**: Princeton TP521x and similar fixed-code ICs

### Rolling Code Systems (KeeLoq)

Rolling codes (also called "hopping codes") change with each transmission to prevent simple replay.

**KeeLoq Algorithm**
- Developed by Microchip Technology; used in many car remotes, garage doors
- Each press generates a new 64-bit codeword using a proprietary NLFSR cipher
- Manufacturer seed key + serial number = per-device key
- Both sides maintain synchronized counter; receiver accepts window of ~256 future codes

**RollJam Attack (Samy Kamkar, DEF CON 23)**
1. Attacker device continuously jams the target frequency
2. Victim presses button: signal is jammed AND captured
3. Victim presses button again (thinking first press failed): second signal captured
4. First code was captured; victim's receiver received the second code
5. Attacker retransmits first captured code later, which is still valid in the window
6. Attacker retains second code for future use, giving permanent access

```
RollJam hardware: 2x RTL-SDR (RX), 2x CC1101 (jam + replay)
Kamkar's PoC: https://github.com/samyk/opensesame
```

**KeeLoq Cryptanalysis**
- Academic break (Bono et al., 2007): 2^50 complexity with 2^16 known plaintexts
- Side-channel attacks: power analysis on keyfob during transmission
- Practical implication: with enough captures + computation, key recovery is possible
- Mitigation: Modern AES-based protocols replace KeeLoq in newer designs

### Universal Radio Hacker (URH)

URH is a complete suite for wireless protocol investigation with SDR support.

```bash
# Install
pip install urh

# Launch GUI
urh

# Key workflows in URH:
# 1. Recording: Configure SDR, set frequency, record signal
# 2. Analysis: Demodulate (ASK/FSK/PSK), set bit length, view bits
# 3. Protocol Analysis: Auto-detect packet boundaries, color-code fields
# 4. Encoding: Apply Manchester, NRZ, NRZI, Differential coding
# 5. Fuzzing: Define fields, generate mutation campaigns
# 6. Simulation: Build protocol state machines, simulate device conversations

# Command-line mode
urh_cli --device RTL-SDR --frequency 433920000 --sample-rate 2000000   --bandwidth 2000000 --gain 40 record keyfob.complex
```

**URH Protocol Analysis Features**
- Auto-interpretation of OOK/ASK/FSK/PSK signals
- Preamble, sync word, length field auto-detection
- Hexadecimal and binary bit views
- CRC calculation and verification
- Custom decoding plugin support (Python)

### TPMS (Tire Pressure Monitoring System) Analysis

TPMS sensors broadcast at 315/433 MHz unencrypted with a fixed sensor ID:

```bash
# Read TPMS data with rtl_433
rtl_433 -R 59 -F json 2>&1 | grep -i tpms

# Example output:
# {"time": "2024-01-15 10:23:45", "protocol": 59, "model": "Toyota",
#  "id": "0xA1B2C3D4", "pressure_PSI": 32.5, "temperature_C": 22, "flags": 0}

# Privacy concern: Sensor IDs are globally unique and fixed for life of tire
# Multiple receivers along a road can track vehicle movement using ID correlation
# TPMS spoofing can trigger low-pressure warnings in nearby vehicles
```

### Drone Signal Analysis

```bash
# DJI OcuSync - 2.4/5.8 GHz FHSS
# SDR capture requires fast SDR (USRP/LimeSDR) at 20+ MSPS

# FPV (First Person View) video links
# Analog FPV: 5.8 GHz; demodulate with WBFM in GNU Radio
# Digital FPV (DJI FPV, Walksnail, HDZero): Proprietary digital; harder to decode

# drone-detect - detect DJI drones by RF signature
# Uses power spectral density analysis of OcuSync hopping pattern
```

### GPS Spoofing

**GPS-SDR-SIM + HackRF**
```bash
# GPS-SDR-SIM generates GPS satellite signals
git clone https://github.com/osqzss/gps-sdr-sim
cd gps-sdr-sim && gcc gpssim.c -lm -o gps-sdr-sim

# Generate GPS signal for a specific location
./gps-sdr-sim -e brdc3540.14n -l 37.7749,-122.4194,100 -b 8 -d 30 -o gps_sim.bin

# Transmit with HackRF (AUTHORIZED LAB ENVIRONMENTS ONLY)
hackrf_transfer -t gps_sim.bin -f 1575420000 -s 2600000 -a 1 -x 0

# GPS spoofing mitigations:
#  - Cross-correlation between multiple GNSS constellations (GPS + GLONASS + Galileo)
#  - Inertial navigation cross-check
#  - Receiver autonomous integrity monitoring (RAIM)
#  - Encrypted timing signals (SAASM, M-code military GPS)
```

### RF Jamming Detection

```bash
# Detect jamming by monitoring received signal quality
# Key indicators:
# 1. Sudden increase in noise floor across wide bandwidth
# 2. Loss of expected signals (cellular, GPS, WiFi)
# 3. Narrowband vs wideband jamming signatures

# Establish baseline then detect anomalies
hackrf_sweep -f 824:894 -l 40 -g 20 -w 100000 > baseline.csv
# ...time passes...
hackrf_sweep -f 824:894 -l 40 -g 20 -w 100000 > current.csv
# Compare baseline vs current in a custom Python analysis script
```

### ADS-B Signal Injection Research

ADS-B (1090 MHz) has no authentication in legacy Mode S/ADS-B Out. Aircraft identities, positions, and velocities are trusted by ATC. BeastBlaster and similar research tools demonstrate injection in shielded lab environments (Faraday cage). ADS-B version 2 and ACAS X introduce integrity monitoring. FAA/ICAO are working on ADS-B authentication via ground-based monitoring networks.

---

## 8. Kismet Wireless Monitor

### Overview

Kismet is an open-source wireless network detector, packet sniffer, wardriver, and intrusion detection system. It supports multiple RF protocols through a modular data source architecture.

- **Website**: https://www.kismetwireless.net
- **GitHub**: https://github.com/kismetwireless/kismet
- **Architecture**: Server/client split; web UI or CLI clients; REST API
- **Installation**: `sudo apt install kismet` or build from source

### Architecture

```
[RF Data Sources]      [Kismet Server]     [Clients]
  WiFi (phy80211)   ->  kismet_server   ->   Web UI (port 2501)
  Bluetooth (hci)   ->  (C++ core)      ->   kismet_client (CLI)
  RTL-SDR sources   ->  kismetdb log    ->   REST API
  Zigbee (ticc2531) ->  PCAP log        ->   Wireshark (via TCP)
  Remote sources    ->  Alert engine    ->   MQTT publisher
```

### Configuration

**Main Config: /etc/kismet/kismet.conf**
```conf
# Log settings
log_prefix=/var/log/kismet/
log_types=kismet,pcapng,pcapkismet
log_title=Wardriving_%Y%m%d

# GPS settings
gps=gpsd:host=localhost,port=2947,reconnect=true

# Alert settings
alertbacklog=50
alertrate=10/min

# Server bind
httpd_port=2501
httpd_bind_address=127.0.0.1
```

**Data Source Configuration (/etc/kismet/kismet_site.conf)**
```conf
# WiFi monitor mode interface
source=wlan0:name=wifi0,channel=6,ht_channels=true

# Multiple WiFi interfaces
source=wlan0:name=wifi0-2.4ghz
source=wlan1:name=wifi1-5ghz

# Bluetooth via HCI
source=hci0:name=bt0,type=linuxbt

# Zigbee (TI CC2531 USB stick)
source=/dev/ttyACM0:name=zigbee0,type=ticc2531

# RTL-SDR integrations
source=rtl433_0:name=rtl433,type=rtl433     # 433 MHz sensors
source=rtladsb_0:name=adsb,type=rtladsb     # ADS-B 1090 MHz
source=rtlamr_0:name=amr,type=rtlamr        # AMR utility meters
```

### Starting Kismet

```bash
# Start server (foreground)
kismet -c wlan0

# Start as service
sudo systemctl enable kismet
sudo systemctl start kismet

# Connect to web UI: http://localhost:2501
# CLI client: kismet_client

# Check status
curl http://localhost:2501/system/status.json | python3 -m json.tool
```

### REST API Reference

```bash
BASE="http://localhost:2501"
AUTH="admin:PASSWORD"

# All tracked devices
curl -u $AUTH "$BASE/devices/views/all/devices.json?fields=kismet.device.base.macaddr,kismet.device.base.name,kismet.device.base.signal"

# WiFi SSIDs seen
curl -u $AUTH "$BASE/phy/phy80211/ssids/views/ssids.json"

# Devices by PHY type
curl -u $AUTH "$BASE/devices/views/phy-IEEE802.11/devices.json"

# Last 10 minutes of devices
curl -u $AUTH "$BASE/devices/last-time/-600/devices.json"

# Alerts
curl -u $AUTH "$BASE/alerts/all_alerts.json"

# Server system info
curl -u $AUTH "$BASE/system/status.json"

# GPS location
curl -u $AUTH "$BASE/gps/location.json"

# Data source status
curl -u $AUTH "$BASE/datasource/all_sources.json"

# API key creation
curl -u admin:PASSWORD -X POST "$BASE/auth/apikey/generate.json"   -d '{"name":"my_key","role":"readonly","expiration":0}'
```

### Alert System

| Alert | Trigger | Severity |
|-------|---------|----------|
| APSPOOF | AP spoofing detected (SSID with changed BSSID) | HIGH |
| BSSTIMESTAMP | BSS timestamp manipulation (potential replay) | MEDIUM |
| CRYPTODROP | Network dropped from encrypted to open | HIGH |
| ADHOCCONFLICT | Ad-hoc network using infrastructure SSID | MEDIUM |
| KARMASPOOF | KARMA attack (AP responding to all probes) | HIGH |
| PROBENOJOIN | Excessive probes without association | LOW |
| DEAUTHFLOOD | Deauthentication flood | HIGH |
| DISCONFLOOD | Disassociation flood | HIGH |
| BCASTDISCON | Broadcast disassociation (likely deauth attack) | HIGH |
| LONGSSID | Unusually long SSID (buffer overflow attempts) | MEDIUM |
| NONCEDEGRADE | WPA nonce downgrade detected | CRITICAL |

```conf
# Alert configuration in kismet.conf
alert=CRYPTODROP,10/min,1/sec
alert=DEAUTHFLOOD,25/min,5/sec
```

### Wardriving Setup

```bash
# Install gpsd for GPS
sudo apt install gpsd gpsd-clients

# Configure GPS device: /etc/default/gpsd
# DEVICES="/dev/ttyUSB0"
# GPSD_OPTIONS="-n"

sudo systemctl start gpsd
cgps -s   # Verify GPS fix

# Start Kismet with GPS
kismet -c wlan0
```

### Remote Capture Sources

```bash
# On remote sensor (e.g., Raspberry Pi)
sudo apt install kismet-capture-linux-wifi

# Start remote capture pointing to central Kismet server
sudo kismet_cap_linux_wifi --source wlan0   --connect 192.168.1.100:3501 --tcp

# Add remote source via REST API
curl -u admin:PASS -X POST "http://localhost:2501/datasource/add_source.json"   -d '{"definition":"tcp://192.168.1.50:3501/wlan0"}'
```

### Wireshark Integration

```bash
# Real-time WiFi capture from Kismet to Wireshark
# Kismet exposes pcap over TCP on port 3002
wireshark -k -i TCP@localhost:3002

# Filter in Wireshark: wlan.bssid == aa:bb:cc:dd:ee:ff
```

### Device Fingerprinting

Kismet's fingerprinting engine uses:
- **OUI (Organizationally Unique Identifier)**: First 3 octets of MAC identifies manufacturer
- **Probe request SSIDs**: List of known network names reveals device history
- **IE (Information Element) fingerprinting**: Vendor-specific IE ordering is OS-specific
- **Timing patterns**: Beacon intervals, power save patterns
- **Protocol behavior**: EAPOL timing, association request capabilities

Cross-protocol correlation: Kismet correlates Bluetooth and WiFi devices seen at the same time and location. Same manufacturer OUI prefix on both Bluetooth and WiFi MACs often indicates same physical device.

---

## 9. RFID, NFC & TPMS

### RFID Frequency Bands

| Band | Frequency | Range | Standards | Common Tags |
|------|-----------|-------|-----------|-------------|
| LF | 125-134 kHz | <10 cm | ISO 11784/11785 | HID Prox, EM4100, AWID, Indala, T5577 |
| HF | 13.56 MHz | <1 m | ISO 14443, ISO 15693 | Mifare Classic/DESFire, iCLASS, LEGIC, NFC |
| UHF | 860-960 MHz | 1-12 m | EPC Gen2 (ISO 18000-6C) | Supply chain, inventory, access |
| SHF | 2.45 GHz | <1 m | ISO 18000-4 | Active tags, vehicle ID |

### Proxmark3 - RFID Analysis Tool

Proxmark3 is the industry-standard RFID security research tool, supporting LF and HF analysis, cloning, emulation, and fuzzing.

```bash
# Connect to Proxmark3 (USB)
pm3   # or proxmark3 /dev/ttyACM0

# --- LF Commands ---

# Scan for unknown LF tag
lf search

# Read EM4100 (125kHz)
lf em 4100 read

# Clone EM4100 to T5577 blank card
lf em 4100 clone --id 0x123456789A

# Read HID Prox
lf hid read

# Clone HID Prox card
lf hid clone -r 2006F0B5D7   # raw hex value from lf hid read

# Brute force HID facility code
lf hid brute -f 101   # facility code 101, all card numbers

# Read Indala
lf indala read

# T5577 write (generic LF writable blank)
lf t55xx write -b 0 -d 00148040   # write config block
lf t55xx detect                    # detect card after write

# --- HF Commands ---

# Scan for HF tag
hf search

# Mifare Classic operations
hf mf autopwn                              # automated key recovery + dump
hf mf rdsc -s 0 -k FFFFFFFFFFFF           # read sector 0 with key A
hf mf nested --blk 0 -a -k FFFFFFFFFFFF   # nested attack from known key
hf mf darkside                            # darkside attack (some tags)
hf mf chk --1k -f mfc_default_keys.dic   # dictionary key check
hf mf dump --1k                           # dump all sectors to file

# Write dump to magic card
hf mf cload -f hf-mf-dump.bin

# Mifare DESFire
hf mfdes info
hf mfdes getuid

# HID iCLASS
hf iclass info
hf iclass read
hf iclass clone -f iclass_dump.bin

# NFC operations
hf 14a info                                                      # ISO 14443A info
hf 14a apdu -s -d 00A4040007A0000000031010   # send APDU command

# LEGIC
hf legic info
hf legic read
```

**Proxmark3 Emulation**
```bash
# Emulate an EM4100 tag
lf em 4100 sim --id 0x123456789A

# Emulate HID Prox
lf hid sim -r 2006F0B5D7

# Emulate Mifare Classic
hf mf sim -u 01020304 -t 1   # 1K, custom UID

# Emulate with saved dump file
hf mf esave -f saved_card.bin   # save to emulator memory
hf mf sim                        # simulate from emulator memory
```

### Chameleon Mini / Tiny

```bash
# Chameleon Mini: versatile NFC/RFID emulator with logging
# Connect via USB-Serial (115200 baud)

# Commands (via terminal: minicom, screen, PuTTY)
CONFIGURATION=MF_CLASSIC_1K    # Set emulation mode
UID=01020304                   # Set emulated UID
BUTTON=CYCLE_SETTINGS          # Button behavior
LOGMODE=MEMORY                 # Log card interactions to memory
LOGDOWNLOAD                    # Download log data

# Modes available:
# ISO14443A_SNIFF    -- passive sniffing
# MF_CLASSIC_1K     -- Mifare 1K emulation
# MF_CLASSIC_4K     -- Mifare 4K emulation
# MF_ULTRALIGHT     -- Mifare Ultralight emulation
# ISO15693_SNIFF    -- ISO 15693 sniff
# VICINITY          -- ISO 15693 emulation
```

### NFC Tools & Libraries

**libnfc (Linux)**
```bash
sudo apt install libnfc-bin libnfc-dev

# Scan for NFC reader
nfc-scan-device

# List tags
nfc-list

# Read/write Mifare Classic (requires keys)
nfc-mfclassic r a dump.mfd FFFFFFFFFFFF   # read with key A
nfc-mfclassic w a dump.mfd FFFFFFFFFFFF   # write with key A
nfc-mfclassic W a dump.mfd FFFFFFFFFFFF   # write including UID block (magic cards)

# Poll for tags
nfc-poll
```

**nfcpy (Python)**
```python
import nfc
import binascii

def connected(tag):
    print(f"Tag: {tag}")
    if isinstance(tag, nfc.tag.tt2.MifareUltralight):
        data = tag.read(4)   # read page 4
        print(f"Data: {binascii.hexlify(data)}")
    return True

with nfc.ContactlessFrontend('usb') as clf:
    clf.connect(rdwr={'on-connect': connected})
```

### Mifare Classic Vulnerabilities

**CRYPTO1 Cipher Weaknesses**
- Proprietary stream cipher; specifications reverse-engineered in 2008
- 48-bit key; ~2^48 brute force space is infeasible without attacks
- Nested Authentication Attack (Nohl et al.):
  - Requires one known sector key
  - Random number generator in tag is predictable; reduces key space to ~2^16
  - `hf mf nested` in Proxmark3 exploits this
- Darkside Attack (Courtois, 2009):
  - Works without any known key
  - Exploits parity bit information leakage in NACK responses
  - `hf mf darkside` in Proxmark3
- Hardcoded Default Keys:
  - Many deployments use: FFFFFFFFFFFF, A0A1A2A3A4A5, D3F7D3F7D3F7
  - Dictionary attack covers most real-world deployments

**Mifare DESFire Security**
- DES/3DES/AES encryption (DESFire EV1: 3DES; EV2/EV3: AES-128)
- Mutual authentication before access to application data
- EV3 includes Transaction MAC for cryptographic transaction integrity
- No known practical cryptographic breaks

### TPMS Sensor Tracking & Privacy

```bash
# TPMS sensor IDs are fixed and globally unique (32-bit)
# Sensors broadcast every 60-90 seconds while vehicle is moving

# rtl_433 TPMS capture (all protocols)
rtl_433 -R 59 -R 60 -R 61 -R 62 -R 63 -R 64 -F json 2>&1

# Common TPMS protocols in rtl_433:
# R59: Toyota/Lexus TPMS
# R60: Hyundai TPMS
# R61: Ford TPMS
# R95: Subaru TPMS
# R236: Renault TPMS

# Vehicle tracking via TPMS:
# Multiple receivers at fixed points log sensor IDs + timestamps
# Cross-reference to identify vehicle movement patterns
# Academic paper: "TPMS: A New Driver for Location Privacy Research"
```

### Payment Card NFC (EMV)

Non-sensitive data is readable without PIN: card number, expiry, recent transaction metadata.

**NFC Relay Attack Concept**
- Attacker device near victim's card (relay point 1)
- Another attacker device at point-of-sale terminal (relay point 2)
- Data relayed in real-time via internet/LAN
- Mitigations: RFID-blocking wallet inserts; transaction velocity checks; contactless limits requiring PIN above threshold

### UHF RFID (EPC Gen2) Security

- EPC Gen2: ISO 18000-6C; 860-960 MHz; 1-12 meter range
- Used in supply chain, retail, access control
- Security: 32-bit password for kill/access (easily brute-forced)
- TID (Tag Identifier): Unique, factory-programmed; fingerprint possible
- Eavesdropping range: passive sniffing up to 10x active read range
- Long-range reader (90 cm range) + Raspberry Pi = covert inventory tracking

---

## 10. Defensive RF & Legal Framework

### RF Monitoring for Security Operations

**Establishing a Spectrum Baseline**

```bash
# Capture 24-hour baseline at all facilities
hackrf_sweep -f 24:6000 -l 40 -g 20 -w 500000 > baseline_$(date +%Y%m%d).csv

# Scheduled sweeps with cron
# /etc/cron.hourly/rf-survey
#!/bin/bash
hackrf_sweep -f 400:1000 -l 40 -g 20 -w 100000 -N 5   >> /var/log/rf-survey/$(date +%Y%m%d).csv

# Alert on anomalies - Python comparison script
python3 << 'EOF'
import csv

def load_sweep(filename):
    data = {}
    with open(filename) as f:
        for row in csv.reader(f):
            if len(row) >= 7:
                freq = float(row[2])
                power = float(row[6])
                data[freq] = power
    return data

baseline = load_sweep('baseline.csv')
current = load_sweep('current.csv')

threshold_db = 15  # Alert if 15 dB above baseline
for freq, power in current.items():
    if freq in baseline and (power - baseline[freq]) > threshold_db:
        print(f"ALERT: {freq/1e6:.3f} MHz is {power - baseline[freq]:.1f} dB above baseline")
EOF
```

**Rogue Access Point Detection with Kismet**
```bash
# Kismet WIDS configuration
alert=CRYPTODROP,5/min,1/sec        # Encryption downgrade
alert=APSPOOF,10/min,1/sec          # AP spoofing
alert=DEAUTHFLOOD,30/min,5/sec      # Deauth attack

# Send alerts to SIEM via MQTT
mqtt_server=192.168.1.10
mqtt_port=1883
mqtt_topic=kismet/alerts

# Rogue AP indicators:
# 1. Known SSID with unknown BSSID
# 2. Encryption downgrade (WPA2 -> WPA -> Open)
# 3. Client connecting to unfamiliar AP while known AP is present
# 4. KARMA/EVIL TWIN: AP responding to all probe requests
```

### IMSI Catcher Detection

**Software Tools**

```
Android: IMSI-Catcher Detector (AIMSICD)
  - Monitor cell tower LAC/CID changes
  - Alert on sudden 2G downgrade (3G/4G -> 2G)
  - Unusual signal strength spikes
  - Missing encryption indicators
  GitHub: https://github.com/CellularPrivacy/Android-IMSI-Catcher-Detector

SnoopSnitch (Android - rooted, Qualcomm chipset required)
  - Analyzes baseband signaling
  - Detects: silent SMS, IMSI catcher, LAC change, unusual paging

ESD America Overwatch / Cryptophone
  - Commercial IMSI catcher detection hardware
  - Used by high-value targets, government officials
```

**IMSI Catcher Indicators**
```
1. Signal Strength Anomaly: Tower appears much stronger than expected for location
2. Missing Neighbor Cells: Legitimate towers advertise neighbors; catchers often do not
3. Encryption Absence: System Information broadcasts missing A5/1 or A5/3 flags
4. 2G Downgrade: 3G/4G network forces device to 2G (unencrypted or weak encryption)
5. Location Update Loop: Repeated location update requests without movement
6. Silent SMS: Ping-type SMS not shown to user; triggers location update revealing position
7. TMSI Reuse: Temporary Mobile Subscriber Identity reuse patterns
```

**Mapping with kalibrate-rtl + gr-gsm**
```bash
# Build GSM cell map of area before investigation
kal -s GSM900 -g 40 2>&1 | tee gsm_cells.txt

# Cross-reference with OpenCelliD database
curl "https://opencellid.org/cell/get?key=API_KEY&radio=GSM&mcc=310&mnc=410&lac=1234&cellid=5678&format=json"

# Flag cells not in database - potential catchers
```

### RF Shielding

**Faraday Cage Construction**

| Material | Attenuation | Frequency Range | Notes |
|----------|------------|-----------------|-------|
| Copper mesh (200 mesh) | 60-80 dB | 1 MHz-10 GHz | Flexible; good ventilation |
| Solid copper sheet | 90-120 dB | DC-10 GHz | Excellent; heavy |
| MuMetal | 80 dB | Low frequency | Best for <1 MHz magnetic shielding |
| RF gasket tape | Variable | - | Sealing doors and seams |
| Carbon fiber | 30-50 dB | 1-10 GHz | Lightweight; structural |
| Window film (metallic) | 10-30 dB | 1-10 GHz | Retrofit option |

```bash
# Testing shielding effectiveness
# Inside cage: transmit at known power
# Outside cage: measure received power
# Attenuation (dB) = transmitted_power_dBm - received_power_dBm

# Quick test with HackRF (inside) + RTL-SDR (outside)
# Compare against free-space measurement at same distance
```

**RF Gasket and Sealing**
- All seams and penetrations reduce cage effectiveness
- Cable penetrations: use RF filters or waveguide-below-cutoff tubes
- Ventilation: copper honeycomb (EMC shielding panels)
- Door seams: beryllium copper finger stock or conductive foam gasket

### TEMPEST / EMSEC

**Van Eck Phreaking**
- Unintentional RF emissions from computer monitors, keyboards, CPUs
- Video signals from CRT monitors historically reconstructed at 100+ meters
- Modern LCD/LED: reduced but still measurable emanations
- Keyboard emanations: PS/2 and USB keyboards emit detectable RF per keystroke

**TEMPEST Standards**

| Standard | Type | Description |
|----------|------|-------------|
| NSTISSAM TEMPEST/1-92 | US | Three levels: A (most stringent), B, C |
| SDIP-27 | NATO | Levels A/B/C; equivalent to US TEMPEST |
| NSA CSS EPL | US | Evaluated Products List for TEMPEST equipment |
| CNSS Instruction 7000 | US | TEMPEST countermeasures policy |

**Practical EMSEC Countermeasures**
- Physical separation (RED/BLACK installation)
- Shielded enclosures for sensitive equipment
- Power line filtering (TEMPEST power conditioners)
- Fiber optic cables (no RF emissions vs. copper)
- Shielded cables with proper grounding
- Proximity controls limiting physical access

### Legal Framework (United States)

**Federal Statutes**
```
47 U.S.C. ss 333 - Willful or malicious interference with radio communications
  - Felony; up to $100,000 fine + 1 year imprisonment per violation
  - Applies to jamming, intentional interference, false distress signals

47 U.S.C. ss 705 - Unauthorized publication or use of communications
  - Radio communications not intended for public use may not be divulged
  - Exception: emergency, assistance in monitoring, or government authorized

18 U.S.C. ss 2511 - Electronic Communications Privacy Act (ECPA)
  - Prohibits intentional interception of wire, oral, or electronic communications
  - SDR interception of cellular may violate ECPA
  - Exception: public domain (police scanner, broadcast)

18 U.S.C. ss 1030 - Computer Fraud and Abuse Act (CFAA)
  - Applied to RF in cases involving computer network access via wireless RF
  - Unauthorized access to WiFi network via SDR injection -> CFAA applicable

State Wiretapping Laws
  - Many states have "all-party consent" laws for interception
  - CA Penal Code ss 631, IL 720 ILCS 5/14-2: stricter than federal
  - Active monitoring vs. passive reception distinction varies by jurisdiction
```

**Amateur Radio Testing Authorization (Part 97)**
- License holders may test transmitter performance on amateur frequencies
- Cannot test on cellular, satellite, public safety, or licensed commercial bands
- Must identify transmissions with callsign (47 C.F.R. ss 97.119)

**FCC Enforcement**
- Enforcement Bureau investigates complaints; issues Notice of Apparent Liability (NAL)
- Civil forfeiture penalties up to $100,000/day for continuing violations
- Criminal referral to DOJ for willful violations

### Responsible Disclosure for RF Vulnerabilities

```
1. Discovery: Document vulnerability with proof-of-concept (in controlled environment)
2. Scope Assessment: Determine affected systems, vendors, geographic impact
3. Vendor Contact: Use vendor PSIRT (Product Security Incident Response Team)
   - Motorola Solutions PSIRT: psirt@motorolasolutions.com
   - Qualcomm PSIRT: product-security@qualcomm.com
   - General: security@[vendor].com
4. Disclosure Timeline: Standard 90-day window (Google Project Zero policy)
5. Coordinated Disclosure: CISA (CERT/CC) coordinates multi-vendor issues
   - https://www.cisa.gov/coordinated-vulnerability-disclosure-process
6. Public Disclosure: Conference presentation (DEF CON, Black Hat, IEEE) + CVE

Bug Bounty Programs with RF Scope
- HackerOne: Several IoT/hardware programs include RF testing scope
- Bugcrowd: Automotive programs sometimes include TPMS/keyfob
- Responsible Disclosure: Many vendors will credit + patch without bounty
```

### CTF RF Challenges

```bash
# Hack-A-Sat (HAS) - satellite security CTF
# https://hackasat.com
# Involves satellite communication, orbital mechanics, SDR challenges

# DEF CON RF Village
# Annual CTF focused on RF challenges
# Common challenge types:
# - Decode mystery signal (identify modulation, decode message)
# - Replay attack to unlock flag
# - Find hidden transmission in spectrum
# - Direction finding challenge

# Signal Identification Wiki
# https://www.sigidwiki.com - reference for identifying unknown signals

# Tools for CTF RF challenges
# inspectrum    - IQ visualization with cursor-based measurement
# sox           - Audio file manipulation (convert to SDR-compatible formats)
# audacity      - Audio analysis; can open many IQ-like formats
# baudline       - Real-time signal analysis

# Common CTF RF challenge workflow:
# 1. Download IQ file (.wav, .complex, .iq, .cfile)
# 2. Open in inspectrum or GQRX (file source)
# 3. Identify modulation from waterfall (shape, bandwidth, pattern)
# 4. Demodulate in GNU Radio or SigDigger
# 5. Decode bits -> find encoding (Manchester, NRZ, etc.)
# 6. Interpret protocol -> extract flag
```

### Career Paths in RF Security

| Role | Skills Required | Typical Employer |
|------|----------------|-----------------|
| RF Penetration Tester | SDR, protocol analysis, wireless protocols | Security consultancies, Big 4 |
| Wireless Security Researcher | DSP, protocol reverse engineering, CVE writing | Academia, think tanks, vendors |
| Electronic Warfare Engineer | Advanced RF, SIGINT, military standards | Defense contractors, DoD |
| RF Forensics Analyst | Signal analysis, legal procedures, reporting | Law enforcement, government |
| IoT Security Engineer | RFID, Bluetooth, Zigbee, embedded firmware | IoT vendors, startups |
| Telecom Security Analyst | GSM/LTE/5G protocols, core network security | MNOs, telecom security firms |

**Certifications & Training**
- GIAC GAWN: Assessing and Auditing Wireless Networks
- Offensive Security OSWP: practical WiFi penetration testing
- GNU Radio Academy: online courses for GNU Radio DSP
- DEF CON RF Village: annual training workshops
- FCC Amateur Radio License: Technician -> General -> Extra (legal TX platform)

**Key Resources**
```
Books:
  - "Software Defined Radio using MATLAB & Simulink and the RTL-SDR" - Stewart
  - "Practical RF System Design" - Egan

Websites:
  - rtl-sdr.com       - tutorials, hardware reviews, project showcase
  - sigidwiki.com     - signal identification database
  - radioreference.com - US frequency database, P25 system info
  - openwebrx.de      - web-based SDR receiver platform

Communities:
  - r/RTLSDR (Reddit)
  - GNU Radio mailing list / Discourse
  - DEF CON RF Village Discord
  - SDR-Radio.com forum
```

---

*Last updated: 2026-05-04 | This document is for authorized security research and educational purposes only. Always obtain proper authorization before testing. Comply with all applicable laws and regulations.*
