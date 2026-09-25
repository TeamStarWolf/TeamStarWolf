# Command and Control — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Command and Control**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1001 — Data Obfuscation
<a id="t1001"></a>

**Detection strategy:** Detect Obfuscated C2 via Network Traffic Analysis (`DET0053`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1001](https://attack.mitre.org/techniques/T1001/) · [detail page](../../techniques/command-and-control.md#t1001)

- **`AN0144` Analytic 0144** · Windows
  Detects excessive outbound traffic to remote host over HTTP(S) from uncommon or previously unseen processes.
  - *Log sources:* `NSM:Flow` (HTTP )
  - *Tune:* `OutboundByteThreshold` — Defines threshold ratio of outbound to inbound bytes that signals possible obfuscation; `ProcessAllowlist` — List of known legitimate network clients to exclude from anomaly checks
- **`AN0145` Analytic 0145** · Linux
  Identifies custom or previously unseen userland processes initiating high-volume HTTP connections with low response volume.
  - *Log sources:* `auditd:SYSCALL` (connect)
  - *Tune:* `UserProcessBaseline` — Defines what is considered abnormal for a user-initiated process context
- **`AN0146` Analytic 0146** · macOS
  Flags unexpected user applications initiating long-lived HTTP(S) sessions with irregular traffic patterns.
  - *Log sources:* `macos:unifiedlog` (network flow); `macos:unifiedlog` (process)
  - *Tune:* `SessionDuration` — Session length that exceeds average per-user expectations

---

### T1001.001 — Junk Data
<a id="t1001001"></a>

**Detection strategy:** Detecting Junk Data in C2 Channels via Behavioral Analysis (`DET0011`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1001.001](https://attack.mitre.org/techniques/T1001/001/) · [detail page](../../techniques/command-and-control.md#t1001001)

- **`AN0030` Analytic 0030** · Windows
  Processes generating large outbound connections with disproportionate send/receive ratios, often to uncommon ports or hosts, potentially inserting meaningless data into protocol payloads.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=10); `NSM:Flow` (TCP/UDP)
  - *Tune:* `PayloadEntropyThreshold` — Tunable threshold for Shannon entropy of network payloads.; `TimeWindow` — Duration of outbound data transfer to evaluate disproportionate upload size.; `UserContext` — Filter based on user accounts allowed to generate outbound traffic.
- **`AN0031` Analytic 0031** · Linux
  Outbound traffic with anomalous payload sizes and patterns from non-networking processes, often observed via packet inspection or connection logs.
  - *Log sources:* `auditd:SYSCALL` (execve network tools); `NSM:Flow` (TCP session tracking)
  - *Tune:* `EntropyScore` — Adjust based on expected entropy of typical outbound data.; `ProcessWhitelist` — Exclude known good binaries that generate high network output.; `DataRatioThreshold` — Minimum ratio of bytes_sent to bytes_received.
- **`AN0032` Analytic 0032** · macOS
  Previously unseen applications generating outbound connections with atypical data flow characteristics, such as excessive data with no return response.
  - *Log sources:* `macos:unifiedlog` (connection attempts); `macos:osquery` (process_events); `NSM:Flow` (session behavior)
  - *Tune:* `ParentProcessCheck` — Allow filtering based on parent-child relationship for benign services.; `HostWhitelist` — Known legitimate C2-like patterns (e.g., Apple telemetry).
- **`AN0033` Analytic 0033** · ESXi
  Anomalous traffic from ESXi host management daemons (like hostd or vpxa) embedding non-standard payloads in management protocols (e.g., HTTPS) or beaconing behavior.
  - *Log sources:* `esxi:vmkernel` (Network activity); `esxi:hostd` (System service interactions)
  - *Tune:* `TLSFingerprintMismatch` — Detects mismatched TLS client behavior vs expected for hostd/vpxa.; `UnusualDestinationPorts` — Highlight traffic from ESXi hosts to uncommon ports outside vCenter ranges.

---

### T1001.002 — Steganography
<a id="t1001002"></a>

**Detection strategy:** Detecting Steganographic Command and Control via File + Network Correlation (`DET0235`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1001.002](https://attack.mitre.org/techniques/T1001/002/) · [detail page](../../techniques/command-and-control.md#t1001002)

- **`AN0651` Analytic 0651** · Windows
  Detect the creation or modification of common media file formats (e.g., .jpg, .png, .wav) following suspicious process activity like compression or encryption, especially when paired with lateral movement or exfiltration behavior.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (Session Transfer Content)
  - *Tune:* `FileExtensionFilter` — Allows tuning of monitored file types (e.g., .jpg, .png, .docx).; `PayloadEntropyThreshold` — Threshold for flagging potential hidden data in outbound payloads.; `ExecutionToExfilTimeWindow` — Time window between media creation and network transmission.
- **`AN0652` Analytic 0652** · Linux
  Unusual use of steganographic or media processing binaries (e.g., `steghide`, `ffmpeg`, `imagemagick`) followed by outbound communication to external IPs with high data output and media MIME types.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (Captured File Content); `NSM:Flow` (Observed File Transfers)
  - *Tune:* `ToolNameMatch` — Specify which binaries to monitor (e.g., steghide, outguess).; `OutboundTrafficPattern` — Adjust based on known normal file upload services.
- **`AN0653` Analytic 0653** · macOS
  Abnormal usage of Preview, ImageMagick, or binary editors to alter images/documents, followed by exfiltration or outbound connections with mismatched file MIME types or payload structure.
  - *Log sources:* `macos:unifiedlog` (File creation); `macos:osquery` (process_events); `NSM:Flow` (C2 exfiltration)
  - *Tune:* `ParentProcessBaseline` — Allow tuning based on expected apps calling image-editing tools.; `TimeDelta` — Gap between file manipulation and outbound connection.
- **`AN0654` Analytic 0654** · ESXi
  Suspicious modification of file artifacts (e.g., logs, ISO templates) on ESXi datastores, followed by beaconing or POST operations to external IPs potentially hiding payloads in file-like traffic.
  - *Log sources:* `esxi:vmkernel` (Storage access and file ops); `esxi:hostd` (Service initiated connections); `NSM:Flow` (Transferred file observations)
  - *Tune:* `FilenamePattern` — Tune for likely stego file names (e.g., wallpaper.jpg, template.iso).; `UnusualDestinationIP` — Destination outside vCenter management subnet.

---

### T1001.003 — Protocol or Service Impersonation
<a id="t1001003"></a>

**Detection strategy:** Detecting Protocol or Service Impersonation via Anomalous TLS, HTTP Header, and Port Mismatch Correlation (`DET0470`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1001.003](https://attack.mitre.org/techniques/T1001/003/) · [detail page](../../techniques/command-and-control.md#t1001003)

- **`AN1294` Analytic 1294** · Windows
  Untrusted processes creating outbound TLS/HTTPS connections with malformed certificates or header fields, often mismatched with target service behavior. Detects protocol impersonation attempts via traffic metadata analysis and host process lineage.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (SSL/TLS Handshake Analysis)
  - *Tune:* `IssuerOrgFilter` — Organizations in certificate issuer fields to allowlist or monitor.; `UserContext` — Restrict detection to non-system users or external-facing applications.; `HeaderSignatureMatch` — Specific HTTP header anomalies or patterns (e.g., missing User-Agent).
- **`AN1295` Analytic 1295** · Linux
  Detection of binaries spawning encrypted sessions using OpenSSL or curl to external services with mismatched ports/protocols. Identifies behavior where internal services simulate trusted cloud service traffic patterns.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (Network Capture TLS/HTTP)
  - *Tune:* `ProtocolMatchConfidence` — Threshold for header-field mismatch against expected service behavior.; `TimeWindow` — Correlation window between process spawn and encrypted session.
- **`AN1296` Analytic 1296** · macOS
  Unsigned or suspicious applications initiating network traffic claiming to be browser, mail, or cloud clients. Detects impersonation via TLS fingerprint and User-Agent string deviation.
  - *Log sources:* `macos:unifiedlog` (Outbound Traffic); `macos:osquery` (Process Execution + Hash); `NSM:Content` (HTTP Header Metadata)
  - *Tune:* `ParentProcessFilter` — Limit detections to children of suspicious binaries.; `HeaderAnomalyScore` — Threshold for deviation from expected headers (User-Agent, Host).
- **`AN1297` Analytic 1297** · ESXi
  ESXi hosts initiating connections from non-standard daemons mimicking HTTP/HTTPS or SNMP traffic, but with irregular payload formats or expired/unsigned TLS certificates.
  - *Log sources:* `esxi:hostd` (Service-Based Network Connection); `NSM:Content` (TLS Fingerprint and Certificate Analysis)
  - *Tune:* `TLSFingerprintMatch` — Allows matching against known-good or known-bad JA3/JA3S hashes.; `AllowedServicePorts` — Tune for expected network ports per ESXi role.

---

### T1008 — Fallback Channels
<a id="t1008"></a>

**Detection strategy:** Behavioral Detection of Fallback or Alternate C2 Channels (`DET0499`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1008](https://attack.mitre.org/techniques/T1008/) · [detail page](../../techniques/command-and-control.md#t1008)

- **`AN1376` Analytic 1376** · Windows
  Establishing network connections on uncommon ports or protocols following C2 disruption or blocking. Often executed by processes that typically exhibit no network activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (uncommon ports)
  - *Tune:* `DestinationPort` — Can be tuned to include unexpected or high-entropy ports not typically associated with the process.; `ProcessName` — Useful to filter benign applications vs suspicious fallback attempts.; `DataVolumeRatio` — Tunable ratio of sent/received bytes to indicate potential C2 beaconing or exfiltration.; `TimeWindow` — Adjust temporal window to match likely fallback C2 retries after primary channel fails.
- **`AN1377` Analytic 1377** · Linux
  Creation of outbound connections on alternate ports or using covert transport (e.g., ICMP, DNS) from non-network-intensive processes, following known disruption or blocked traffic.
  - *Log sources:* `auditd:SYSCALL` (outbound connections); `NSM:Flow` (alternate ports)
  - *Tune:* `ProtocolType` — Can filter for rare fallback channel types (e.g., ICMP, DNS over HTTP).; `UserContext` — Tuning by user (e.g., root vs. service account) helps suppress noise.
- **`AN1378` Analytic 1378** · macOS
  Outbound fallback traffic from low-profile or background launch agents using unusual protocols or destinations after primary channel inactivity.
  - *Log sources:* `macos:unifiedlog`; `NSM:Flow`
  - *Tune:* `LaunchAgentContext` — Used to suppress known legitimate agents.; `PayloadEntropy` — Can help isolate covert or encrypted fallback traffic.
- **`AN1379` Analytic 1379** · ESXi
  Outbound traffic from host management services or guest-to-host interactions over unusual interfaces (e.g., backdoor API endpoints or external VPN tunnels).
  - *Log sources:* `esxi:vmkernel`; `esxi:vpxd`
  - *Tune:* `InterfaceName` — May vary based on ESXi build and should be filtered to suppress known interfaces.; `FallbackIPRanges` — Environment-specific ranges to ignore (e.g., DR tunnels or out-of-band mgmt).

---

### T1071 — Application Layer Protocol
<a id="t1071"></a>

**Detection strategy:** Detection of Command and Control Over Application Layer Protocols (`DET0444`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1071](https://attack.mitre.org/techniques/T1071/) · [detail page](../../techniques/command-and-control.md#t1071)

- **`AN1225` Analytic 1225** · Windows
  Detects suspicious usage of common application-layer protocols (e.g., HTTP, HTTPS, DNS, SMB) by abnormal processes, with high outbound byte counts or irregular ports, possibly indicating command and control or data exfiltration.
  - *Log sources:* `NSM:Flow` (http, dns, smb, ssl logs); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `ProtocolList` — Limit detection to app-layer protocols of interest: HTTP, DNS, SSL, SMB, RDP; `DataVolumeThreshold` — Detects asymmetric communication volume (e.g., >90% outbound); `UnusualProcessList` — Track processes not normally associated with network activity
- **`AN1226` Analytic 1226** · Linux
  Detects suspicious curl, wget, or custom socket traffic that leverages DNS, HTTPS, or IRC-style protocols with unbalanced traffic or beacon-like intervals.
  - *Log sources:* `NSM:Flow` (dns, ssl, conn); `auditd:SYSCALL` (execve)
  - *Tune:* `KnownPortsToMonitor` — Uncommon ports for HTTPS, IRC, DNS (e.g., 8443, 5353); `BeaconTimingThreshold` — Detect intervals of outbound traffic within fixed timeframes
- **`AN1227` Analytic 1227** · macOS
  Detects applications using abnormal protocols or high volume traffic not previously associated with the process image, such as Automator or AppleScript invoking curl or python sockets.
  - *Log sources:* `macos:osquery` (socket_events); `macos:unifiedlog` (log stream)
  - *Tune:* `SocketParentProcessMatch` — Non-browser processes opening sockets to external IPs; `DataFlowImbalanceRatio` — High outbound/inbound ratio indicating C2 beacon
- **`AN1228` Analytic 1228** · Network Devices
  Detects application-layer tunneling or unauthorized app protocols like DNS-over-HTTPS, embedded C2 in TLS/HTTP headers, or misused SMB traffic crossing VLANs.
  - *Log sources:* `NSM:Flow` (conn.log, http.log, dns.log, ssl.log)
  - *Tune:* `AppProtocolAbusePattern` — Detects DNS tunneling, encrypted HTTP C2, or malformed headers; `NorthSouthEgressFilter` — Monitor internal hosts talking externally using internal protocols (e.g., SMB)

---

### T1071.001 — Web Protocols
<a id="t1071001"></a>

**Detection strategy:** Detection of Web Protocol-Based C2 Over HTTP, HTTPS, or WebSockets (`DET0027`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) · [detail page](../../techniques/command-and-control.md#t1071001)

- **`AN0075` Analytic 0075** · Windows
  Detects unexpected or high-volume HTTP/S/WebSocket communication from suspicious processes (e.g., PowerShell, rundll32) using uncommon user agents or mimicking browser traffic to unusual domains or IPs.
  - *Log sources:* `NSM:Flow` (http.log, ssl.log); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `ProcessNameExclusions` — Filter out legitimate browser/network utilities; `UserAgentAnomalies` — Detect non-browser user-agents or spoofed headers; `OutboundByteRatioThreshold` — Flag when outbound > inbound volume by 90%+
- **`AN0076` Analytic 0076** · Linux
  Detects curl, wget, Python requests, or custom HTTP clients communicating over non-standard ports, with repetitive or beacon-like patterns or POST-heavy behavior to rare domains.
  - *Log sources:* `NSM:Flow` (http.log, conn.log); `auditd:SYSCALL` (execve)
  - *Tune:* `CommandLinePatternMatch` — curl or wget in scripts with suspicious domains or silent flags; `BeaconIntervalWindow` — Fixed-timed HTTP callbacks with 60±5s jitter
- **`AN0077` Analytic 0077** · macOS
  Detects applications such as Automator, AppleScript, or LaunchDaemons invoking HTTP/S traffic to non-standard domains or using suspicious headers (e.g., Base64 in URIs or cookie fields).
  - *Log sources:* `macos:osquery` (socket_events); `macos:unifiedlog` (log stream --predicate)
  - *Tune:* `SuspiciousParentProcess` — Non-browser parent of web traffic (e.g., AppleScript, bash); `URIEntropyThreshold` — Unusually encoded data in GET/POST URIs
- **`AN0078` Analytic 0078** · ESXi
  Detects HTTP or HTTPS communication initiated by shell-based scripts or management daemons, especially those reaching public IPs over ports 80/443 using embedded curl or wget.
  - *Log sources:* `NSM:Flow` (SPAN or port-mirrored HTTP/S); `esxi:shell` (/root/.ash_history or /etc/init.d/*)
  - *Tune:* `ShellScriptMatch` — Match on commands like `wget https://*`, `curl -s`; `ExternalConnectionFilter` — Public IPs or external DNS hostnames
- **`AN0079` Analytic 0079** · Network Devices
  Detects Web protocol misuse such as encoded HTTP headers, WebSocket upgrade requests with abnormal payloads, or TLS handshake anomalies suggesting embedded C2 channels.
  - *Log sources:* `NSM:Flow` (http.log, ssl.log, websocket.log)
  - *Tune:* `HeaderEncodingPattern` — Base64, hex, or UTF-16 encoding in URI, cookie, or host; `TLSFingerprintMismatch` — JA3 hash deviation from known clients

---

### T1071.002 — File Transfer Protocols
<a id="t1071002"></a>

**Detection strategy:** Detection of File Transfer Protocol-Based C2 (FTP, FTPS, SMB, TFTP) (`DET0416`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1071.002](https://attack.mitre.org/techniques/T1071/002/) · [detail page](../../techniques/command-and-control.md#t1071002)

- **`AN1169` Analytic 1169** · Windows
  Detects FTP, SMB, or TFTP traffic initiated by suspicious processes like PowerShell, cmd.exe, or rundll32.exe—especially with large outbound file transfers or unbalanced traffic volume.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `NSM:Flow` (ftp.log, smb_files.log)
  - *Tune:* `ProcessImageFilter` — Limit to non-standard FTP clients or suspicious binaries (e.g., cmd, mshta); `DataFlowDirectionThreshold` — Ratio of outbound:inbound bytes; e.g., >90% outbound; `FilenamePattern` — Suspicious file extensions or naming (e.g., .zip, .rar, random hash names)
- **`AN1170` Analytic 1170** · Linux
  Detects usage of FTP, SCP, or TFTP by non-interactive shells or automation scripts transferring large data volumes to untrusted IPs.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (ftp.log, conn.log)
  - *Tune:* `TransferSizeThreshold` — Bytes sent in FTP upload or SCP push; `CommandLinePatternMatch` — e.g., scp -r /var/log/* or ftp upload scripts
- **`AN1171` Analytic 1171** · macOS
  Detects Automator, AppleScript, or Terminal executing curl, lftp, or TFTP for binary transfer to untrusted IPs or unusual ports.
  - *Log sources:* `macos:osquery` (socket_events); `macos:unifiedlog` (log stream --predicate)
  - *Tune:* `FilePathAccessed` — e.g., ~/Documents, ~/Library/logs/; `NetworkPortAnomaly` — Non-standard FTP/TFTP ports used (e.g., FTP over 443)
- **`AN1172` Analytic 1172** · ESXi
  Detects file movement or outbound TFTP/FTP transfers from ESXi host initiated via shell commands or injected scripts, particularly from scratch partitions or /tmp.
  - *Log sources:* `esxi:shell` (/root/.ash_history); `NSM:Flow` (mirror/SPAN port)
  - *Tune:* `TransferTargetDomainOrIP` — Public IPs or domains not belonging to known ESXi mgmt infra; `SourceDirectoryFilter` — Monitor transfers from /tmp/, /etc/, /vmfs/volumes/
- **`AN1173` Analytic 1173** · Network Devices
  Detects internal hosts generating large outbound FTP/TFTP/SMB sessions to external IPs, or file transfers using non-standard ports and application mismatches (e.g., FTP over port 80).
  - *Log sources:* `NSM:Flow` (ftp.log, conn.log, smb_files.log)
  - *Tune:* `AppLayerProtocolMatch` — e.g., FTP/SMB observed over uncommon ports; `OutboundDataRateThreshold` — Bytes transferred outside trusted subnets >100MB

---

### T1071.003 — Mail Protocols
<a id="t1071003"></a>

**Detection strategy:** Detection of Mail Protocol-Based C2 Activity (SMTP, IMAP, POP3) (`DET0135`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1071.003](https://attack.mitre.org/techniques/T1071/003/) · [detail page](../../techniques/command-and-control.md#t1071003)

- **`AN0379` Analytic 0379** · Windows
  Detects unauthorized use of SMTP/IMAP/POP3 by suspicious binaries (e.g., PowerShell, rundll32) to exfiltrate data or beacon via email, often bypassing proxy or content filters.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `NSM:Flow` (smtp.log)
  - *Tune:* `ProcessImageName` — Limit to uncommon clients (e.g., scripts or CLI tools using .NET SMTP libraries); `DestPortFilter` — Typically 25, 587, 993, 995, or 465 – flag anomalies; `AttachmentType` — Flag suspicious attachments (e.g., .zip, .7z, .bin)
- **`AN0380` Analytic 0380** · Linux
  Detects non-interactive or script-driven email transmission using tools like `sendmail`, `mailx`, or custom SMTP scripts by background processes, especially when sending attachments or large payloads.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (smtp.log, conn.log)
  - *Tune:* `TransferSizeThreshold` — Bytes transferred via SMTP session; `ScriptNameFilter` — e.g., base64 encoded mailer scripts or one-liners in cron
- **`AN0381` Analytic 0381** · macOS
  Detects email-sending behavior via Terminal, AppleScript, or Automator that interfaces with SMTP or IMAP, typically using curl or mail-related APIs in unsanctioned contexts.
  - *Log sources:* `macos:unifiedlog` (log stream --predicate 'processImagePath CONTAINS "curl" OR "osascript"'); `macos:osquery` (socket_events)
  - *Tune:* `UserContext` — Monitor non-mail client users initiating SMTP/IMAP; `TimeWindow` — Look for execution of mail commands during off-hours
- **`AN0382` Analytic 0382** · Network Devices
  Detects hosts transmitting large volumes of SMTP, IMAP, or POP3 traffic to external IPs or relays that aren't associated with the enterprise mail infrastructure.
  - *Log sources:* `NSM:Flow` (smtp.log, conn.log)
  - *Tune:* `ExternalMailRelayFilter` — Dest IPs not matching sanctioned SMTP/IMAP relays; `OutflowToInflowRatio` — Outbound email bytes vastly exceed response

---

### T1071.004 — DNS
<a id="t1071004"></a>

**Detection strategy:** Behavioral Detection of DNS Tunneling and Application Layer Abuse (`DET0400`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004/) · [detail page](../../techniques/command-and-control.md#t1071004)

- **`AN1121` Analytic 1121** · Windows
  Detects high-frequency or anomalous DNS queries initiated by non-browser, non-system processes (e.g., PowerShell, rundll32, python.exe) used to establish command and control via DNS tunneling.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (dns.log)
  - *Tune:* `QueryLengthThreshold` — Subdomain length for detecting base32/base64-encoded payloads; `ProcessImageFilter` — Flag non-standard executables making DNS queries; `TimeWindow` — Rate of queries in short interval per process
- **`AN1122` Analytic 1122** · Linux
  Detects local daemons or scripts generating outbound DNS queries with long or frequent subdomains, indicative of DNS tunneling via tools like `iodine`, `dnscat2`, or `dig` from cronjobs or reverse shells.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (dns.log)
  - *Tune:* `SubdomainEntropyScore` — Detects encoded payloads or randomness in DNS labels; `DaemonAllowList` — Allowlisted system daemons expected to perform frequent lookups
- **`AN1123` Analytic 1123** · macOS
  Detects scripting environments (AppleScript, osascript, curl) or non-native tools performing DNS queries with encoded subdomains, often used for data exfiltration or beaconing.
  - *Log sources:* `macos:unifiedlog` (log stream 'eventMessage contains "dns_request"')
  - *Tune:* `EntropyThreshold` — Tunable threshold for randomness in subdomain labels; `UncommonProcessContext` — Filters on user-launched or cron-based queries
- **`AN1124` Analytic 1124** · Network Devices
  Detects clients issuing DNS queries with high volume, long subdomain lengths, encoded payload patterns, or to known malicious infrastructure; indicative of DNS-based C2 channels.
  - *Log sources:* `NSM:Flow` (dns.log)
  - *Tune:* `DomainReputationFeed` — List of suspicious/malicious C2 domains; `QueryRatePerClient` — Tunable burst rate per IP per second
- **`AN1125` Analytic 1125** · ESXi
  Detects unusual outbound DNS traffic from ESXi hosts, often from shell scripts, custom daemons, or malicious VIBs interacting with external DNS infrastructure outside the management plane.
  - *Log sources:* `esxi:syslog` (/var/log/syslog.log); `NSM:FLow` (dns.log)
  - *Tune:* `OutboundDNSVolume` — Threshold for data volume and frequency from ESXi IPs; `KnownGoodVIBs` — Baseline known packages for allowlist comparison

---

### T1071.005 — Publish/Subscribe Protocols
<a id="t1071005"></a>

**Detection strategy:** Behavioral Detection of Publish/Subscribe Protocol Misuse for C2 (`DET0002`)  
**Platforms:** Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1071.005](https://attack.mitre.org/techniques/T1071/005/) · [detail page](../../techniques/command-and-control.md#t1071005)

- **`AN0002` Analytic 0002** · Windows
  Detects non-standard processes (e.g., PowerShell, python.exe, rundll32.exe) making outbound connections using publish/subscribe protocols (e.g., MQTT, AMQP) over non-browser, encrypted channels, often beaconing to message brokers.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (mqtt.log / xmpp.log (custom log feeds))
  - *Tune:* `UnusualProcessList` — Detect suspicious processes initiating outbound pub/sub connections; `TimeWindow` — Define beaconing interval used for temporal correlation; `ProtocolPortList` — Custom MQTT/XMPP port use in non-standard ranges (e.g., 1883, 5222, 5672)
- **`AN0003` Analytic 0003** · Linux
  Detects CLI tools (e.g., mosquitto_pub, nc, python scripts) interacting with pub/sub brokers using unusual topic names, high-frequency publication rates, or obfuscated payloads to non-standard hosts.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (mqtt.log or AMQP custom log)
  - *Tune:* `BrokerAllowList` — Known-good brokers used by approved apps and daemons; `TopicAnomalyScore` — Payload length, entropy, or topic name patterns
- **`AN0004` Analytic 0004** · macOS
  Detects osascript, curl, or custom binaries interacting with XMPP/MQTT brokers in unapproved destinations with encrypted payloads or frequent POST-like requests to broker URIs.
  - *Log sources:* `macos:unifiedlog` (log stream 'eventMessage contains pubsub or broker'); `macos:osquery` (socket_events)
  - *Tune:* `AppContextFilter` — Applications not known to use pub/sub protocols; `URIPathRegex` — Custom path patterns to message brokers over HTTPS
- **`AN0005` Analytic 0005** · Network Devices
  Detects pub/sub traffic over unusual ports, high-frequency topic publications, and connections to known-bad or dynamic broker endpoints outside allowlisted infrastructure.
  - *Log sources:* `NSM:Flow` (mqtt.log, xmpp.log, amqp.log)
  - *Tune:* `BrokerReputationList` — Dynamic blocklist or threat intel feed for C2 brokers; `PayloadLengthThreshold` — Exfil-style long topic messages vs telemetry-style short messages

---

### T1090 — Proxy
<a id="t1090"></a>

**Detection strategy:** Detection of Proxy Infrastructure Setup and Traffic Bridging (`DET0445`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1090](https://attack.mitre.org/techniques/T1090/) · [detail page](../../techniques/command-and-control.md#t1090)

- **`AN1229` Analytic 1229** · Windows
  Suspicious process spawning (e.g., `rundll32`, `svchost`, `powershell`, or `netsh`) followed by network connection creation to internal hosts or uncommon external endpoints on high or non-standard ports.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `NSM:Connections` (Outbound Connection)
  - *Tune:* `ParentProcessName` — Legitimate system processes that may rarely spawn network-capable child processes (e.g., `rundll32`, `svchost`).; `DestinationPort` — Watch for high-numbered ports or well-known proxy ports like 1080, 8080, 4444.; `TimeWindow` — Capture unusual spikes in outbound connections over a short period.
- **`AN1230` Analytic 1230** · Linux
  User-space tools (e.g., `socat`, `ncat`, `iptables`, `ssh`) used in non-standard ways to establish reverse shells, port-forwarding, or inter-host connections. Often chained with uncommon outbound destinations or SSH tunnels.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (Connection Tracking)
  - *Tune:* `CommandLinePattern` — Shell piping into tools like `socat`, `ncat`, or `openssl` for tunnel creation.; `OutboundPortRange` — Flag connections made from internal systems to uncommon high ports externally.; `ProcessUserContext` — Capture low-privilege or unexpected users executing system-level network tools.
- **`AN1231` Analytic 1231** · macOS
  AppleScript, LaunchAgents, or remote login services (`ssh`, `networksetup`) establishing proxy tunnels or dynamic port forwards to external IPs or alternate local hosts.
  - *Log sources:* `macos:unifiedlog`; `NSM:Firewall` (pf firewall logs); `NSM:Flow` (connection attempts)
  - *Tune:* `TargetDomain` — Identify suspicious domains often associated with CDN-routed or anonymized endpoints (e.g., Cloudflare, Fastly).; `AppleScriptUsage` — Alert when AppleScript or Automator tools are used for network tunneling tasks.; `LaunchAgentSource` — Monitor for LaunchAgents executing proxy tools or dynamic ports.
- **`AN1232` Analytic 1232** · ESXi
  Direct use of `nc`, `socat`, or reverse tunnel scripts initiated by abnormal user contexts or unauthorized VIBs initiating connections from hypervisor to external systems.
  - *Log sources:* `esxi:shell`; `esxi:vmkernel`; `NSM:Flow` (conn.log)
  - *Tune:* `CLICommand` — Custom proxy or port forwarding scripts executed from ESXi shell.; `DestinationIP` — Unusual outbound connections from ESXi host, particularly to internet.; `UserContext` — Root or elevated users initiating unexpected tunnels.
- **`AN1233` Analytic 1233** · Network Devices
  Dynamic or static port forwarding rules added to route traffic through an internal host, or configuration changes to proxy firewall rules not aligned with baselined policy.
  - *Log sources:* `NSM:Firewall` (Policy Change / Rule Update); `NSM:Flow` (Flow Creation (NetFlow/sFlow)); `networkdevice:cli` (Interface commands)
  - *Tune:* `RuleType` — Focus on new allow/permit rules with dynamic NAT or port forwarders.; `ChangeUser` — Flag any non-admins initiating proxy config changes.; `FlowVolumeDelta` — Detect sharp changes in bi-directional traffic patterns.

---

### T1090.001 — Internal Proxy
<a id="t1090001"></a>

**Detection strategy:** Internal Proxy Behavior via Lateral Host-to-Host C2 Relay (`DET0075`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1090.001](https://attack.mitre.org/techniques/T1090/001/) · [detail page](../../techniques/command-and-control.md#t1090001)

- **`AN0204` Analytic 0204** · Windows
  Anomalous process (e.g., `rundll32`, `svchost`, `cmd`) initiates connections to internal peer hosts not seen in typical communication baselines, used to proxy or forward traffic internally, often using SMB, RPC, or high ports.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `Windows Firewall Log` (SMB over high port)
  - *Tune:* `InternalConnectionPattern` — Tune based on known host-to-host communications that are rare (e.g., workstation-to-workstation).; `DestinationPort` — Focus on unusual internal traffic on ports like 1080, 8080, 4444, or SMB over non-standard ports.; `TimeWindow` — Correlate unusual traffic bursts with new process execution.
- **`AN0205` Analytic 0205** · Linux
  `socat`, `ssh`, `iptables`, or `ncat` invoked from user space or cron jobs to create port forwarding, reverse shells, or inter-host tunnels between compromised Linux systems. Behavior is typically paired with socket activity and high entropy traffic.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Connections` (Internal connection logging); `NSM:Flow` (conn.log)
  - *Tune:* `UserContext` — Alert on unexpected users executing inter-host relay tools (e.g., `www-data`, `backup`).; `PortRange` — Adjust to watch for commonly misused internal TCP/UDP ports.; `ProcessPattern` — Shell pipelines or wrapped invocations like `bash -c 'socat ...'`
- **`AN0206` Analytic 0206** · macOS
  Execution of AppleScript or Automator services launching `ssh -L`, `socat`, or `launchctl` items that dynamically reroute traffic from one Mac endpoint to another. LaunchAgents used to establish permanent internal tunnels.
  - *Log sources:* `macos:unifiedlog`; `NSM:Flow` (pf firewall logs); `macos:osquery` (Process Events and Launch Daemons)
  - *Tune:* `LaunchAgentPath` — Directory where proxying LaunchDaemons may be dropped, e.g., `/Library/LaunchDaemons/`.; `PortBindings` — Dynamic port forwards often use ephemeral or non-standard service ports.; `AppleScriptUsage` — May trigger on less common scripting interfaces for traffic redirection.
- **`AN0207` Analytic 0207** · ESXi
  ESXi shell execution of tools/scripts (`nc`, `socat`, `perl`) relaying network traffic to other internal hosts, especially when initiated by unauthorized users or VMs.
  - *Log sources:* `esxi:shell` (/var/log/shell.log); `esxi:vmkernel` (/var/log/vmkernel.log); `NSM:Flow` (conn.log)
  - *Tune:* `CLICommandPattern` — Watch for chained shell commands building local-to-local connections.; `VMInitiator` — Correlate to which VM initiated the traffic tunnel; unexpected VM behavior may be suspicious.; `ConnectionDirectionality` — Unusual east-west communication patterns among VMs.
- **`AN0208` Analytic 0208** · Network Devices
  Configuration of internal NAT or proxy rules that redirect traffic between client segments internally (e.g., site-to-site port forwarding). Often used to relay internal beaconing or move traffic laterally through trust zones.
  - *Log sources:* `Firewall Audit Logs` (Config Change); `NSM:Flow` (Inter-segment traffic); `networkdevice:cli` (Policy Update)
  - *Tune:* `ProxyTarget` — Internal subnets or endpoint roles allowed for port forwarding.; `ConfigChangeUser` — Detect changes made outside scheduled or authorized windows.; `FlowThreshold` — Volume of data relayed through proxy exceeds historical norms.

---

### T1090.002 — External Proxy
<a id="t1090002"></a>

**Detection strategy:** External Proxy Behavior via Outbound Relay to Intermediate Infrastructure (`DET0325`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1090.002](https://attack.mitre.org/techniques/T1090/002/) · [detail page](../../techniques/command-and-control.md#t1090002)

- **`AN0922` Analytic 0922** · Windows
  Unusual process (e.g., `rundll32`, `mshta`, `wscript`, or custom payloads) initiates network connection to external IPs/domains that proxy C2 traffic, often over uncommon ports or high entropy HTTP/S connections.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Microsoft-Windows-Windows Defender/Operational` (Unusual external domain access)
  - *Tune:* `DestinationASN` — Adjust for known benign but high-risk infrastructure (e.g., hosting providers like DigitalOcean, OVH, etc.).; `ParentProcess` — Detect suspicious lineage—proxy tools launched from script interpreters or LOLBins.; `EntropyThreshold` — Tune based on expected randomness in outbound request payloads.
- **`AN0923` Analytic 0923** · Linux
  `curl`, `wget`, `ncat`, `socat`, or custom binaries initiate outbound traffic to Internet-based proxies (e.g., via VPS or CDN). Behavior may include reverse shell constructs or persistent outbound beacons.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (conn.log or http.log); `NSM:Flow` (alert log)
  - *Tune:* `CommandLinePattern` — Regex or command substring matches indicative of dynamic proxy setup.; `ExternalIPList` — Tunable list of IPs or ASNs related to known proxy/VPS abuse.; `UserContext` — Unexpected users running networking tools (e.g., www-data, apache).
- **`AN0924` Analytic 0924** · macOS
  AppleScript or terminal sessions launch tools (`curl`, `nc`, `ssh`) to external IPs not commonly accessed. Outbound connections are made by LaunchAgents/LaunchDaemons, often masquerading as system services.
  - *Log sources:* `macos:unifiedlog` (process logs); `NSM:Flow` (pf firewall logs); `macos:osquery` (launchd or network_events)
  - *Tune:* `LaunchAgentPath` — Detect persistence used to restart proxy after reboot.; `ExternalPort` — Often high or non-standard ports, configurable for outbound proxy detection.; `ProcessReputation` — Flag unsigned or anomalous binaries making external connections.
- **`AN0925` Analytic 0925** · ESXi
  ESXi shell or guest VM tools initiate external connections via scripted traffic forwarding to Internet-based proxies. Detected by firewall or shell audit logs showing outbound connection spikes from hypervisor or guest VM to remote proxy nodes.
  - *Log sources:* `esxi:shell`; `esxi:vmkernel`; `NSM:Flow` (conn.log)
  - *Tune:* `VMOutboundPatterns` — Detect when VMs communicate with Internet IPs not in workload profiles.; `ProxyHostPattern` — Regex for proxy-related tools/scripts executed on the host.; `ConnectionDirectionality` — Outbound only connections from ESXi to new IPs.
- **`AN0926` Analytic 0926** · Network Devices
  Changes to NAT/firewall policies enabling outbound port forwarding from internal IPs to Internet-based proxy endpoints. Log spikes in outbound flows to CDN, VPS, or anomalous ASNs with few return packets.
  - *Log sources:* `Firewall Audit Logs` (Outbound NAT Rule Changes); `NSM:Flow` (Outbound flow records); `networkdevice:syslog` (Dynamic route changes)
  - *Tune:* `FlowThreshold` — Number of flows or bytes transferred per minute—flag surges to unrecognized ASNs.; `DestinationIPCategory` — Proxy destination categories: CDN, TOR exit node, anonymous hosting.; `ConfigChangeUser` — Track if unexpected user or automation changed NAT/forwarding rules.

---

### T1090.003 — Multi-hop Proxy
<a id="t1090003"></a>

**Detection strategy:** Multi-hop Proxy Behavior via Relay Node Chaining, Onion Routing, and Network Tunneling (`DET0359`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1090.003](https://attack.mitre.org/techniques/T1090/003/) · [detail page](../../techniques/command-and-control.md#t1090003)

- **`AN1020` Analytic 1020** · Windows
  Suspicious processes (e.g., Tor clients, relays, unknown binaries) launch with sustained encrypted outbound traffic to known anonymity infrastructure (e.g., Tor, I2P), and may relay to additional internal systems via reverse proxying, ICMP tunneling, or socket forwarding.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `dns:query` (Outbound resolution to hidden service domains (e.g., `.onion`))
  - *Tune:* `DomainCategory` — Can be tuned to `.onion`, I2P, or suspicious CDN domains.; `ProcessParent` — Detect known-good vs. abnormal launching binaries (e.g., mshta spawning Tor).; `ConnectionDuration` — Threshold for persistent connections over known relay ports (e.g., 9050).
- **`AN1021` Analytic 1021** · Linux
  Tools such as `tor`, `nglite`, `proxychains`, `chisel`, or custom daemons repeatedly initiate outbound sessions to multiple nodes before final destination. This behavior is abnormal for Linux services outside of VPN, monitoring, or CDN relay contexts.
  - *Log sources:* `auditd:SYSCALL` (execve for proxy tools); `NSM:Flow` (conn.log + ssl.log with Tor fingerprinting); `Netfilter/iptables` (Forwarded packets log)
  - *Tune:* `ExecutablePath` — Match known proxy tools, tuned for environment.; `RelayCount` — Detect outbound chaining behavior through >2 IPs in short succession.; `ProtocolType` — Allow filtering by ICMP, TCP/443, UDP for obfuscation channels.
- **`AN1022` Analytic 1022** · macOS
  LaunchAgents or LaunchDaemons initiate persistent Tor or relay processes that make encrypted outbound connections. May be paired with sandbox bypasses or unsigned executables communicating over SOCKS proxies.
  - *Log sources:* `macos:unifiedlog` (process, socket, and DNS logs); `macos:osquery` (process_events + launchd); `macos:unifiedlog` (forwarded encrypted traffic)
  - *Tune:* `LaunchdLabel` — Regex for masking patterns in LaunchAgents with proxy behavior.; `UnsignedBinary` — Allow for exceptions for known unsigned binaries.; `SOCKSPortUsage` — Monitor local 9050/9150 activity and rerouted system traffic.
- **`AN1023` Analytic 1023** · ESXi
  Outbound encrypted traffic initiated from hypervisor shell or via VM backdoor mechanisms to relays in VPS infrastructure, especially if traversing multiple nodes before reaching Internet destination. Packet captures or firewall logs show non-VM communication paths.
  - *Log sources:* `esxi:esxupdate` (/var/log/esxupdate.log or /var/log/vmksummary.log); `esxi:vmkernel` (/var/log/vmkernel.log); `NSM:Flow` (Relay patterns across IP hops)
  - *Tune:* `HopCount` — Threshold on number of IPs contacted in sequence without DNS resolution.; `ShellAccess` — Flag if relay communication initiated by ESXi shell or unknown VM agent.; `VPSIPRange` — Filter for known Tor/VPS egress networks.
- **`AN1024` Analytic 1024** · Network Devices
  Encrypted traffic or ICMP tunneling from border routers to internal routers or unknown external IPs. Forwarded traffic shows consistent hop-to-hop relaying without matching configured VPN or expected network topology.
  - *Log sources:* `NSM:Flow` (Relayed session pathing (multi-hop)); `NSM:Firewall` (Outbound encrypted traffic); `networkdevice:syslog` (Custom firmware or routing changes)
  - *Tune:* `VPNConfigWhitelist` — Define allowed internal router communication paths.; `ICMPPayloadEntropy` — High entropy ICMP payloads may indicate tunneling activity.; `RelayChainSignature` — Track known multi-hop pattern signatures or port hopping techniques.

---

### T1090.004 — Domain Fronting
<a id="t1090004"></a>

**Detection strategy:** Domain Fronting Behavior via Mismatched TLS SNI and HTTP Host Headers (`DET0196`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1090.004](https://attack.mitre.org/techniques/T1090/004/) · [detail page](../../techniques/command-and-control.md#t1090004)

- **`AN0564` Analytic 0564** · Windows
  Suspicious outbound HTTPS connections where the TLS Server Name Indication (SNI) does not match the HTTP Host header, indicating potential use of domain fronting to mask C2 traffic via CDNs.
  - *Log sources:* `NSM:Connections` (TLS handshake + HTTP headers); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `SNIHostMismatch` — Define acceptable mismatch ratio between SNI and HTTP Host fields based on legitimate domain usage patterns.; `CDNAllowList` — Whitelist of known safe CDN front-end domains (e.g., `cdn.company.com`).; `ProcessInitiator` — Filter for suspicious initiators of domain fronting, e.g., scripting engines, lolbins, unknown binaries.
- **`AN0565` Analytic 0565** · Linux
  Applications such as `curl`, `wget`, or custom binaries initiate HTTPS connections where the TLS SNI is mismatched or absent while HTTP Host targets CDN-available C2 endpoints.
  - *Log sources:* `NSM:Flow` (ssl.log + http.log); `auditd:SYSCALL` (execve)
  - *Tune:* `SNIFieldAbsent` — Detect TLS sessions where SNI is empty—'domainless' fronting.; `AllowedTools` — Environmental tuning for known binaries using alternate SNI for testing (e.g., API tests).; `ProcessContext` — Enrich command-line arguments or parent-child lineage to detect abuse.
- **`AN0566` Analytic 0566** · macOS
  Unsigned or user-space apps initiate TLS connections with one hostname and HTTP headers requesting a different domain, commonly abused in CDN-resident domain fronting techniques.
  - *Log sources:* `macos:unifiedlog` (network, socket, and http logs); `macos:osquery` (process_events)
  - *Tune:* `UnsignedBinary` — Helps tune detection when unsigned apps initiate fronted sessions.; `HostHeaderMatch` — Threshold to flag inconsistent domain targeting in encrypted sessions.; `SOCKSPortAnomaly` — Alert on unusual ports used in HTTPS+SOCKS activity patterns.
- **`AN0567` Analytic 0567** · ESXi
  Traffic originating from ESXi hosts or management interfaces displays SNI-to-Host mismatch behavior, particularly anomalous given typical infrastructure communication patterns.
  - *Log sources:* `NSM:Firewall` (TLS/HTTP inspection); `esxi:shell` (/var/log/vmkernel.log, /var/log/vmkwarning.log)
  - *Tune:* `AdminPortAccess` — ESXi hosts should rarely initiate external HTTPS—threshold to alert.; `TLSHandshakeOutliers` — Define entropy or timing anomalies for TLS handshake.; `DomainMismatchThreshold` — SNI/Host mismatch occurrence tolerance.

---

### T1092 — Communication Through Removable Media
<a id="t1092"></a>

**Detection strategy:** Cross-host C2 via Removable Media Relay (`DET0090`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1092](https://attack.mitre.org/techniques/T1092/) · [detail page](../../techniques/command-and-control.md#t1092)

- **`AN0247` Analytic 0247** · Windows
  Behavioral sequence where removable media is mounted, files are written/updated, and subsequently read/executed on a separate host, suggesting removable-media relay communication.
  - *Log sources:* `WinEventLog:System` (EventCode=1006); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `RemovableDriveLetter` — Adjust drive letters used in detection (e.g., E:, F:, G:) depending on enterprise usage.; `WriteToReadTimeWindow` — Tunable window for file write on one host followed by file read or execution on another (e.g., within 10 minutes).; `FileNamePattern` — Common naming schemes for payload, tasking, or exfil files (e.g., task.txt, beacon.log, data.bin).
- **`AN0248` Analytic 0248** · Linux
  Detection of file write-access to USB-mount directories (e.g., /media/, /run/media/) followed by same-file access or execution on another host.
  - *Log sources:* `auditd:SYSCALL` (write/open, FIM audit); `auditd:SYSCALL` (Removable media mount notification)
  - *Tune:* `MountPathPattern` — Typical mount paths to monitor (e.g., /media/usb*, /run/media/username/*).; `TimeWindowBetweenHosts` — Tunable detection window to correlate read/write between different hosts within a short interval (e.g., <15m).
- **`AN0249` Analytic 0249** · macOS
  Correlates removable volume mounts (disk arbitration) with file I/O events on that volume, followed by same file execution shortly after insert.
  - *Log sources:* `macos:unifiedlog` (com.apple.diskarbitration); `fs:fsusage` (open/write/exec calls)
  - *Tune:* `VolumeNameFilter` — Known suspicious USB volume labels or types (e.g., NO NAME, SECUREDATA).; `ProcessContext` — Unusual processes accessing USB drives (e.g., bash, Python, unsigned binaries).

---

### T1095 — Non-Application Layer Protocol
<a id="t1095"></a>

**Detection strategy:** Detection of Non-Application Layer Protocols for C2 (`DET0457`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1095](https://attack.mitre.org/techniques/T1095/) · [detail page](../../techniques/command-and-control.md#t1095)

- **`AN1254` Analytic 1254** · Windows
  Anomalous use of ICMP or UDP by non-network service processes for data exfiltration or remote control, especially if traffic bypasses proxy infrastructure or shows unusual flow patterns.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (ICMP/UDP traffic (Wireshark, Suricata, Zeek))
  - *Tune:* `ProcessContextAllowList` — Processes normally allowed to use ICMP/UDP (e.g., ping.exe, DNS resolver).; `ByteTransferAnomalyThreshold` — Suspicion if client sends much more data than it receives (e.g., >90%).; `ProtocolUsageBaseline` — Baseline which protocols are normal per host or segment (ICMP, UDP, etc.).
- **`AN1255` Analytic 1255** · Linux
  ICMP or raw socket traffic generated by user-mode processes like bash, Python, or nc, typically using `ping`, `hping3`, or crafted packets via libpcap or scapy.
  - *Log sources:* `auditd:SYSCALL` (sendto/connect); `NSM:Flow` (icmp.log, weird.log)
  - *Tune:* `RawSocketExecutionPath` — Uncommon programs using raw sockets (e.g., netcat, Python, nmap).; `TimeWindow` — Tunable window for correlating execution with network events (e.g., 2m).
- **`AN1256` Analytic 1256** · macOS
  Unsigned binaries or interpreted scripts initiating non-standard protocols (ICMP, UDP, SOCKS) outside of baseline network behavior.
  - *Log sources:* `macos:unifiedlog` (com.apple.network); `NSM:Flow` (ICMP/UDP monitoring (tcpdump, Wireshark, Zeek))
  - *Tune:* `UnsignedBinaryNetworkUsage` — Detection threshold for unsigned or transient binaries making ICMP/UDP calls.
- **`AN1257` Analytic 1257** · ESXi
  VMCI (Virtual Machine Communication Interface) traffic between guest and host, or between VMs, originating from non-management tools or unauthorized binaries.
  - *Log sources:* `esxi:vmkernel` (VMCI syslog entries)
  - *Tune:* `VMCIBackdoorProcess` — Monitor for non-vSphere or VMware-native processes using VMCI.; `GuestToHostCommPattern` — Baseline pattern of guest-to-host traffic vs anomaly (unexpected port, volume).
- **`AN1258` Analytic 1258** · Network Devices
  Non-standard port/protocol pairings or low-entropy ICMP traffic resembling tunneling patterns (e.g., fixed-size pings with delays).
  - *Log sources:* `NSM:Firewall` (ICMP/UDP protocol anomaly); `NSM:Flow` (conn.log, icmp.log)
  - *Tune:* `ProtocolEntropyThreshold` — ICMP/UDP packet content entropy filter to identify encoded payloads.; `SessionDurationThreshold` — Long ICMP/UDP sessions beyond expected limits (e.g., >5min).

---

### T1102 — Web Service
<a id="t1102"></a>

**Detection strategy:** Suspicious Use of Web Services for C2 (`DET0425`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1102](https://attack.mitre.org/techniques/T1102/) · [detail page](../../techniques/command-and-control.md#t1102)

- **`AN1189` Analytic 1189** · Windows
  Detects unusual outbound connections to web services from uncommon processes using SSL/TLS, particularly those exhibiting high outbound data volume or persistence.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (SSL/TLS Inspection or PCAP)
  - *Tune:* `ProcessName` — To tune for unexpected or uncommon executables initiating network connections; `DataTransferThreshold` — Volume of outbound data in short time window (e.g., >1MB in <5 min); `TimeWindow` — Look for connections persisting outside of normal business hours
- **`AN1190` Analytic 1190** · Linux
  Detects command-line tools, agents, or scripts making outbound HTTPS connections to popular web services like Discord, Slack, Dropbox, or Graph API in an unusual context.
  - *Log sources:* `auditd:SYSCALL` (connect/sendto); `NSM:Flow` (conn.log, ssl.log)
  - *Tune:* `ParentProcess` — Unusual parent-child process behavior initiating external comms (e.g., bash > curl); `HostnamePattern` — Destination hostnames (e.g., *.dropboxapi.com, *.graph.microsoft.com); `RequestFrequency` — Repeated requests at unusual intervals, suggesting beaconing
- **`AN1191` Analytic 1191** · macOS
  Detects user agents or background services making unauthorized or unscheduled web API calls to cloud/web services over HTTPS.
  - *Log sources:* `macos:unifiedlog` (process + network activity); `macos:osquery` (process_events, socket_events)
  - *Tune:* `ProcessSignature` — Unsigned or user-modified apps communicating with cloud services; `ConnectionInterval` — Beacon-like pattern of regular outbound communication
- **`AN1192` Analytic 1192** · ESXi
  Detects guest VMs or management agents issuing HTTP(S) traffic to external services without a valid patch management or backup justification.
  - *Log sources:* `esxi:vmkernel` (network activity); `vpxd.log` (API communication)
  - *Tune:* `RemoteIPRange` — Filter to detect only external/public destinations; `VMContext` — Exclude known backup or patch automation services

---

### T1102.001 — Dead Drop Resolver
<a id="t1102001"></a>

**Detection strategy:** Detection Strategy for Web Service: Dead Drop Resolver (`DET0058`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1102.001](https://attack.mitre.org/techniques/T1102/001/) · [detail page](../../techniques/command-and-control.md#t1102001)

- **`AN0158` Analytic 0158** · Windows
  Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `etw:Microsoft-Windows-NDIS-PacketCapture` (TLS Handshake/Network Flow)
  - *Tune:* `TargetDomain` — FQDN or IP for the hosting site of the dead drop (e.g., pastebin.com, twitter.com); `TimeWindow` — Defines how close in time the suspicious network and process behavior must occur; `UserContext` — Filter by user or system accounts to reduce noise
- **`AN0159` Analytic 0159** · Linux
  Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
  - *Log sources:* `auditd:SYSCALL` (connect); `NSM:Flow` (HTTP/TLS Logs)
  - *Tune:* `TargetDomain` — Dead drop hosting domain (e.g., GitHub, Google Docs); `PayloadEntropyThreshold` — Detects high entropy in payloads signaling obfuscation; `TimeWindow` — Causal proximity between access to resolver and follow-up connections
- **`AN0160` Analytic 0160** · macOS
  Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
  - *Log sources:* `macos:unifiedlog` (subsystem: com.apple.network); `macos:osquery` (process_events/socket_events)
  - *Tune:* `TargetService` — Known services abused for D2 (e.g., iCloud, Dropbox); `UserContext` — Useful to isolate rare users accessing web services for C2; `TimeWindow` — Max time gap between dead drop resolver fetch and follow-on traffic
- **`AN0161` Analytic 0161** · ESXi
  Detection of a process or script that accesses a common web service to retrieve content containing obfuscated indicators of a secondary C2 server (dead drop resolver behavior).
  - *Log sources:* `esxi:vobd` (Network Events); `NSM:Firewall` (Outbound Connections)
  - *Tune:* `DestinationIP` — Identifies unusual IP destinations embedded in traffic; `Protocol` — Used to detect uncommon protocols (e.g., DNS over HTTPS); `TimeWindow` — Used to correlate outbound web requests with process execution

---

### T1102.002 — Bidirectional Communication
<a id="t1102002"></a>

**Detection strategy:** Detect Bidirectional Web Service C2 Channels via Process & Network Correlation (`DET0035`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1102.002](https://attack.mitre.org/techniques/T1102/002/) · [detail page](../../techniques/command-and-control.md#t1102002)

- **`AN0100` Analytic 0100** · Windows
  Suspicious processes initiating encrypted HTTPS connections to common web service domains, followed by abnormal data upload behavior or automated posting behavior indicative of C2 bidirectional traffic.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `etw:Microsoft-Windows-WinINet` (HTTPS Inspection)
  - *Tune:* `TimeWindow` — Timeframe for evaluating multiple network connections tied to the same process; `DomainPattern` — Regex or string patterns used to identify common Web service infrastructure (e.g., *.googleapis.com); `PayloadSizeThreshold` — Minimum data upload size before flagging anomaly; `ProcessNameExclusionList` — Known benign updaters or service processes to reduce false positives
- **`AN0101` Analytic 0101** · Linux
  Non-interactive system processes making encrypted HTTPS connections to well-known web services followed by high outbound traffic volume or scripted upload patterns.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (conn.log); `NSM:Flow` (ssl.log)
  - *Tune:* `UploadDirectionality` — Bias detection toward sessions with larger upload vs download volume; `HostnameRegexList` — List of known public Web services used for dead drops or C2 (e.g., GitHub, Twitter); `ScriptParentName` — Shell interpreter or automated job parent used for filtering (e.g., /usr/bin/python)
- **`AN0102` Analytic 0102** · macOS
  Scripting engines (e.g., osascript, Python) initiating HTTPS requests to social media or content-sharing platforms, paired with automated response handling indicative of two-way communication.
  - *Log sources:* `macos:unifiedlog` (log stream --info --predicate 'subsystem == "com.apple.cfprefsd"'); `NSM:Connections` (web domain alerts)
  - *Tune:* `ScriptEngineList` — Scripting interpreters to monitor for unusual HTTP traffic (e.g., osascript, ruby, bash); `SocialMediaDomainPatterns` — Patterns or domains used for C2 dead drops and responses (e.g., pastebin.com, twitter.com); `BurstConnectionRate` — Threshold for number of short-lived HTTPS connections in a short window

---

### T1102.003 — One-Way Communication
<a id="t1102003"></a>

**Detection strategy:** Detect One-Way Web Service Command Channels (`DET0581`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1102.003](https://attack.mitre.org/techniques/T1102/003/) · [detail page](../../techniques/command-and-control.md#t1102003)

- **`AN1599` Analytic 1599** · Windows
  Suspicious process initiating outbound connections to web services without corresponding response or return traffic, indicative of one-way command channels.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `etw:Microsoft-Windows-WinINet` (WinINet API telemetry)
  - *Tune:* `DestinationDomain` — Can tune for popular web services (e.g., googleapis.com, github.com) based on threat actor tooling; `TimeWindow` — May adjust temporal window to catch beaconing patterns (e.g., every 10-30 mins); `ProcessName` — Environment-specific tuning to exclude expected update or telemetry tools
- **`AN1600` Analytic 1600** · Linux
  Curl, wget, or custom HTTP clients initiated by uncommon user accounts or cron jobs to popular web services, with no observed response parsing logic.
  - *Log sources:* `auditd:SYSCALL` (execve); `iptables:LOG` (OUTBOUND)
  - *Tune:* `ParentProcess` — May tune to detect unknown parents like custom scripts or reverse shells; `CommandLineArgs` — May adjust based on known curl/wget C2 behaviors
- **`AN1601` Analytic 1601** · macOS
  Process using URLSession or similar API to fetch from web services without any response handling, indicative of one-way C2 channels.
  - *Log sources:* `macos:unifiedlog` (process, network); `macos:endpointsecurity` (exec events)
  - *Tune:* `UserContext` — Flag unexpected outbound activity from non-admin or system users; `EntropyScore` — Optional if script-based obfuscation is seen in web requests
- **`AN1602` Analytic 1602** · ESXi
  ESXi shell or scheduled tasks initiating outbound HTTPS to known public services without inbound return or loggable response, used to fetch instructions.
  - *Log sources:* `esxi:hostd` (CLI network calls)
  - *Tune:* `ScheduledTaskName` — Can tune for task names used to execute curl-based outbound requests; `DestinationIP` — Scoped by environment to exclude known legitimate CDNs

---

### T1104 — Multi-Stage Channels
<a id="t1104"></a>

**Detection strategy:** Detect Multi-Stage Command and Control Channels (`DET0228`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1104](https://attack.mitre.org/techniques/T1104/) · [detail page](../../techniques/command-and-control.md#t1104)

- **`AN0637` Analytic 0637** · Windows
  Initial process initiates outbound connection to first-stage C2, receives payloads or commands, then spawns or injects into a second process that establishes a new outbound connection to an unrelated destination (second-stage C2).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `TimeWindow` — Correlate two-stage behavior occurring within a short window (e.g., 1-5 minutes); `ParentProcess` — Tune to exclude known legitimate updaters and management agents; `DestinationHostname` — May be customized to exclude known corporate domains and CDNs
- **`AN0638` Analytic 0638** · Linux
  Shell script or binary initiates curl/wget request to staging domain, writes output to disk or memory, and shortly afterward launches another process that establishes new outbound connection to a different IP or hostname.
  - *Log sources:* `auditd:SYSCALL` (execve, connect); `iptables:LOG` (OUTBOUND)
  - *Tune:* `BinaryPath` — Tune for suspicious binaries like curl, wget, python, netcat; `IPDistance` — Detect multiple different external IPs contacted within short timeframe
- **`AN0639` Analytic 0639** · macOS
  Initial process using NSURLSession or similar APIs reaches out to known staging domains, followed by creation of a reverse shell or RAT connecting to a second unrelated server.
  - *Log sources:* `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC); `macos:unifiedlog` (tcp/udp)
  - *Tune:* `UserContext` — Detect activity outside normal user behavior (e.g., automation or daemon context); `EntropyScore` — Optional for detecting encoded payloads delivered via stage 1
- **`AN0640` Analytic 0640** · ESXi
  CLI-based or API-based network call from the hypervisor to external staging host, shortly followed by a connection to a second external IP by a spawned process or scheduled task.
  - *Log sources:* `esxi:hostd` (CLI network calls); `esxi:cron` (process or cron activity)
  - *Tune:* `ScheduledTaskName` — Detect unknown or obfuscated task names launching follow-up stages; `DestinationIP` — Scope multiple IP destinations outside corporate ranges in short sequence

---

### T1105 — Ingress Tool Transfer
<a id="t1105"></a>

**Detection strategy:** Detect Ingress Tool Transfers via Behavioral Chain (`DET0060`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) · [detail page](../../techniques/command-and-control.md#t1105)

- **`AN0165` Analytic 0165** · Windows
  Unusual or uncommon processes initiate network connections to external destinations followed by file creation (tools downloaded).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `ParentProcessName` — Tune for known good updaters (e.g., ChromeUpdate, OneDrive); `DestinationIPCategory` — Allow filtering by internal vs external IP blocks; `FilePathRegex` — Focus on uncommon file drop paths (e.g., C:\Users\Public\)
- **`AN0166` Analytic 0166** · Linux
  Shell-based tools (curl, wget, scp) initiate connections to external domains followed by creation of executable files on disk.
  - *Log sources:* `auditd:SYSCALL` (connect, execve, write); `auditd:SYSCALL` (file creation/modification); `iptables:LOG` (TCP connections)
  - *Tune:* `ToolName` — Match on curl, wget, rsync, etc. based on environment; `DownloadExtension` — Tunable filter to limit to suspicious file types (.sh, .bin, .elf)
- **`AN0167` Analytic 0167** · macOS
  Process execution of curl or wget followed by a network connection and a file created in temporary or user-specific directories.
  - *Log sources:* `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC); `macos:unifiedlog` (file write/create); `macos:unifiedlog` (connection open)
  - *Tune:* `DirectoryTargeted` — Restrict to high-risk directories like /Users/Shared, /tmp/; `ProcessPath` — May tune based on custom tooling or MDM activity
- **`AN0168` Analytic 0168** · ESXi
  Command line interface or vCLI triggers remote transfer using wget or curl, writing files into datastore paths or local tmp directories.
  - *Log sources:* `esxi:hostd` (command execution); `esxi:vmkernel` (file write)
  - *Tune:* `ToolName` — Tune for wget, curl, netcat, and scripting languages in use; `DatastorePath` — Filter or prioritize specific paths (e.g., /vmfs/volumes/)
- **`AN0169` Analytic 0169** · Network Devices
  Network device logs show anomalous inbound file transfers or uncharacteristic flows with high payload volume to network devices with storage or automation hooks.
  - *Log sources:* `NSM:Flow` (connection metadata); `snmp:syslog` (firmware write/log event)
  - *Tune:* `PayloadVolumeThreshold` — Tune based on expected update size vs anomalous bulk data transfers; `ProtocolUsed` — Flag unexpected protocols like TFTP, FTP, HTTP

---

### T1132 — Data Encoding
<a id="t1132"></a>

**Detection strategy:** Detection Strategy for Data Encoding in C2 Channels (`DET0108`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1132](https://attack.mitre.org/techniques/T1132/) · [detail page](../../techniques/command-and-control.md#t1132)

- **`AN0302` Analytic 0302** · Windows
  Atypical processes (e.g., powershell.exe, regsvr32.exe) encode large outbound traffic using Base64 or other character encodings; this traffic is sent over uncommon ports or embedded in protocol fields (e.g., HTTP cookies or headers).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1); `NSM:Flow` (Unusual Base64-encoded content in URI, headers, or POST body)
  - *Tune:* `PayloadEntropyThreshold` — Adjust to accommodate legitimate compression or encryption patterns in normal web traffic; `ProcessAllowlist` — Define expected processes initiating outbound traffic to reduce false positives; `AnomalyScoreThreshold` — Set threshold for how far traffic deviates from baseline protocol structure or size
- **`AN0303` Analytic 0303** · Linux
  Custom scripts or processes encode outbound traffic using gzip, Base64, or hex prior to exfiltration via curl, wget, or custom sockets. Encoding typically occurs before or during outbound connections from non-network daemons.
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (Base64 strings or gzip in URI, headers, or POST body); `linux:syslog` (Unusual outbound transfers from CLI tools like base64, gzip, or netcat)
  - *Tune:* `TimeWindow` — Tune duration of multi-stage encoding + transfer operations to account for script variability; `UserContext` — Apply user allow/block list depending on which users normally perform CLI encoding
- **`AN0304` Analytic 0304** · macOS
  Processes use built-in encoding utilities (e.g., `base64`, `xxd`, or `plutil`) to encode file contents followed by HTTP/HTTPS transfer via curl or custom applications.
  - *Log sources:* `macos:unifiedlog` (base64 or curl processes chained within short execution window); `macos:unifiedlog` (HTTP POST with encoded content in user-agent or cookie field)
  - *Tune:* `EncodedCommandLengthThreshold` — Minimum byte size of encoded strings to treat as suspicious; `SuspiciousProcessChainDepth` — Number of chained processes within a short window to treat as a correlated behavior
- **`AN0305` Analytic 0305** · ESXi
  ESXi daemons (e.g., hostd, vpxa) are wrapped or impersonated to send large outbound traffic using gzip/Base64 encoding over SSH or HTTP. These actions follow suspicious logins or shell access.
  - *Log sources:* `esxi:shell` (base64 or gzip use within shell session); `esxi:vmkernel` (Outbound traffic using encoded payloads post-login); `ESXiLogs:authlog` (Unexpected login followed by encoding commands)
  - *Tune:* `AuthSourceTrustLevel` — Use to scope encoded traffic suspicion to accounts that should not initiate transfers; `ExfilBurstThreshold` — Threshold for bursty outbound traffic size deviation from baseline

---

### T1132.001 — Standard Encoding
<a id="t1132001"></a>

**Detection strategy:** Behavior-chain detection for T1132.001 Data Encoding: Standard Encoding (Base64/Hex/MIME) across Windows, Linux, macOS, ESXi (`DET0124`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1132.001](https://attack.mitre.org/techniques/T1132/001/) · [detail page](../../techniques/command-and-control.md#t1132001)

- **`AN0345` Analytic 0345** · Windows
  Process invokes a standard encoder (e.g., PowerShell -enc, certutil -encode, base64 via .NET/Invoke-Expression) or emits long Base64/hex literals → shortly followed by outbound network egress with high bytes_out:bytes_in ratio or HTTP headers/payloads containing Base64/MIME blocks.
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `M365Defender:DeviceNetworkEvents` (NetworkConnection: bytes_sent >> bytes_received anomaly)
  - *Tune:* `PayloadEntropyThreshold` — Shannon entropy cutoff to consider payload suspicious (e.g., > 4.5–5.0 for HTTP body).; `B64LengthThreshold` — Min continuous Base64 token length in command lines/script blocks to alert (e.g., > 100 chars).; `TimeWindow` — Correlation window between encoding event and egress (default 10m).; `KnownAdminTools` — Legitimate tools (e.g., backup agents) that routinely encode/compress data.; `BytesOutToInRatio` — Minimum ratio to treat flow as asymmetric (e.g., ≥ 4:1).
- **`AN0346` Analytic 0346** · Linux
  Shell/utility (base64, xxd -p, od, openssl enc -base64, python/perl base64 libraries) encodes data → subsequent outbound connections (curl/wget/bash TCP, socat, python requests) with high asymmetry or Base64/MIME blobs in HTTP/DNS payloads.
  - *Log sources:* `auditd:SYSCALL` (execve of base64|openssl|xxd|python|perl with arguments matching Base64 flags); `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (http: HTTP body or headers contain long Base64 sections; gzip/deflate + Base64)
  - *Tune:* `EncodingToolsAllowList` — Build/backup jobs that legitimately call base64/openssl.; `EntropyThreshold` — Shannon entropy for payloads (e.g., >4.5).; `TimeWindow` — Join window between exec and egress (default 10m).; `OutInRatio` — Bytes_out / bytes_in threshold (default 4).
- **`AN0347` Analytic 0347** · macOS
  Processes use base64/xxd/openssl/python Objective‑C APIs to encode data (seen in EndpointSecurity exec events or Unified Logs) → quick outbound connections with large bytes_out or HTTP POSTs carrying Base64/MIME bodies.
  - *Log sources:* `macos:unifiedlog` (process command line contains base64, -enc, openssl enc -base64); `PF:Logs` (outbound flows with bytes_out >> bytes_in); `NSM:Flow` (http: HTTP body contains long Base64 sections)
  - *Tune:* `AllowedDeveloperIDs` — Signed/allowed developer binaries routinely using encoding.; `EntropyThreshold` — Payload entropy cutoff.; `TimeWindow` — Exec → egress window.
- **`AN0348` Analytic 0348** · ESXi
  ESXi shell (BusyBox) or VMware utilities (openssl, python if present) used to Base64/hex encode data from datastore or config files → followed by abnormal egress from the host (NSX/flow logs) with asymmetric bytes_out or HTTPS posts to non-management endpoints.
  - *Log sources:* `esxi:shell` (commands containing base64, openssl enc -base64, xxd -p); `esxi:hostd` (unexpected script/command invocations via hostd); `NSX:FlowLogs` (network_flow: bytes_out >> bytes_in to external); `NSM:Flow` (http: Base64/MIME looking payloads from ESXi host IP)
  - *Tune:* `MgmtCIDRs` — CIDRs for legitimate vCenter/NSX/backup endpoints.; `BytesRatio` — Out:In ratio deemed suspicious (e.g., ≥3 on ESXi).; `TimeWindow` — Correlation window between shell command and egress.

---

### T1132.002 — Non-Standard Encoding
<a id="t1132002"></a>

**Detection strategy:** Behavior-chain detection for T1132.002 Data Encoding: Non-Standard Encoding across Windows, Linux, macOS, ESXi (`DET0326`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1132.002](https://attack.mitre.org/techniques/T1132/002/) · [detail page](../../techniques/command-and-control.md#t1132002)

- **`AN0927` Analytic 0927** · Windows
  A process/script constructs or references a custom/alphabet translation table (e.g., 64/85/32+ arbitrary chars, XOR/base-N loops) or emits long high-entropy strings that do NOT validate as standard Base64/Hex → shortly after, the same process (or its child) generates outbound traffic with asymmetric bytes_out:bytes_in, fixed-size beacons, or protocol/header mismatches (e.g., Content-Type says JSON but body fails JSON parse / contains non-standard alphabet).
  - *Log sources:* `WinEventLog:Security` (EventCode=4688); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:PowerShell` (EventCode=4103, 4104, 4105, 4106); `m365:defender` (NetworkConnection: high out:in ratio, periodic beacons, protocol mismatch)
  - *Tune:* `EntropyThreshold` — Minimum Shannon entropy for the suspected token/payload (e.g., >4.8).; `TokenLengthThreshold` — Minimum continuous token length to treat as potential non-standard payload (e.g., ≥120 chars).; `BytesOutToInRatio` — Out:In ratio considered suspicious (e.g., ≥4:1).; `FixedPacketStdDevThreshold` — Std. dev. threshold (size or interval) to mark packets as 'uniform' (beacon-like).; `TimeWindow` — Correlation window from encode routine to egress (default 10m).; `KnownLegitEncoders` — Legitimate in-house/custom encoders to suppress.
- **`AN0928` Analytic 0928** · Linux
  Shell scripts or binaries implement custom mapping tables (tr/sed/awk/golang/rust/python encode loops), or emit long high-entropy tokens that fail Base64/Hex validation → correlated with egress showing asymmetric flow, protocol-mismatch payloads, or DNS/HTTP bodies containing low-diversity-but-long custom alphabets.
  - *Log sources:* `auditd:SYSCALL` (execve of interpreters (python, perl), custom binaries, or shell utilities with long arguments containing non-standard tokens); `WinEventLog:Sysmon` (EventCode=3, 22); `NSM:Flow` (http: HTTP bodies/headers contain long tokens with non-standard alphabets or constant-size periodic POSTs)
  - *Tune:* `EntropyThreshold` — Payload entropy minimum.; `TokenLengthThreshold` — Length threshold for suspect tokens.; `BytesOutToInRatio` — Asymmetry cutoff for flows.; `TimeWindow` — Correlation join window.; `KnownEncoders` — Legitimate internal tools/agents.
- **`AN0929` Analytic 0929** · macOS
  EndpointSecurity/Unified Logs show processes generating custom alphabets or long high-entropy, non-standard tokens → network logs (PF/Zeek/EDR) show asymmetric beacons, protocol mismatches, or periodic fixed-size posts.
  - *Log sources:* `macos:endpointsecurity` (ES_EVENT_TYPE_NOTIFY_EXEC: arguments contain long, non-standard tokens / custom alphabets); `PF:Logs` (high out:in ratio or fixed-size periodic flows); `NSM:Flow` (http: suspicious long tokens with custom alphabets in body/headers)
  - *Tune:* `EntropyThreshold` — Payload entropy minimum.; `TokenLengthThreshold` — Minimum suspicious token length.; `BytesOutToInRatio` — Asymmetry threshold.; `TimeWindow` — Correlation window.; `AllowedSignedBinaries` — Signed binaries that legitimately implement custom encoders.
- **`AN0930` Analytic 0930** · ESXi
  ESXi shell or scripts produce long, high-entropy tokens (non-standard alphabets) in shell.log/hostd, followed by outbound flows (NSX/Zeek) with asymmetric ratios or protocol mismatches to non-management endpoints.
  - *Log sources:* `esxi:shell` (commands containing long non-standard tokens or custom lookup tables); `esxi:hostd` (unexpected script invocations producing long encoded strings); `NSM:Flow` (network_flow: bytes_out >> bytes_in, fixed packet sizes/intervals to non-approved CIDRs); `NSM:Flow` (http: HTTP bodies from ESXi host IPs containing long, non-standard tokens)
  - *Tune:* `MgmtCIDRs` — CIDRs allowed for normal ESXi mgmt/backup.; `BytesOutToInRatio` — Asymmetry cutoff (e.g., ≥3).; `TokenLengthThreshold` — Minimum token length.; `TimeWindow` — Correlation window.

---

### T1219 — Remote Access Tools
<a id="t1219"></a>

**Detection strategy:** Behavior-Chain Detection for Remote Access Tools (Tool-Agnostic) (`DET0496`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219/) · [detail page](../../techniques/command-and-control.md#t1219)

- **`AN1366` Analytic 1366** · Windows
  Chain of remote access tool behavior: (1) initial execution of remote-control/assist agent or GUI under user context; (2) persistence via service or autorun; (3) long-lived outbound connection/tunnel to external infrastructure; (4) interactive control signals such as shell or file-manager child processes spawned by the RAT parent.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:System` (EventCode=7045); `WinEventLog:Sysmon` (EventCode=12); `WinEventLog:Sysmon` (EventCode=13, 14); `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Correlation period binding start→persistence→egress→child (default 15m, adjust per environment).; `UserContext` — Differentiate help-desk/jump hosts and admin accounts from standard endpoints.; `ProcessAllowlist` — Known-good remote support tools; suppress expected events while still correlating anomalous sequences.; `InstallPathRegex` — Alert when services/agents execute from user-writable or temp paths.; `ExternalIPAllowlist` — Vendors’ support clouds/CDNs to reduce false positives on egress detection.; `ShellSpawnRegex` — Define which child shells from GUI parents are acceptable versus suspicious.; `EgressHeuristics` — Thresholds for session duration, connection counts, and bytes_out/bytes_in ratio.
- **`AN1367` Analytic 1367** · Linux
  Sequence of RAT agent execution, systemd persistence, and long-lived external egress; optional interactive shells spawned from the agent.
  - *Log sources:* `auditd:SYSCALL` (execve: Agent/headless flags (listen/connect/reverse/tunnel) or remote-control binaries spawning shells); `auditd:PATH` (WRITE: Drop of binaries/scripts in ~/.local, /tmp, or /opt tool dirs); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `TimeWindow` — Bind exec→service→egress events; extend for staged deployments.; `DaemonAllowlist` — Approved .service names/paths to avoid flagging corporate agents.; `SuspiciousChildProcesses` — Define shells/interpreters considered anomalous when spawned by GUI/agent parents.; `EgressHeuristics` — Flow heuristics for long-lived, client-heavy connections post-install.
- **`AN1368` Analytic 1368** · macOS
  Electron/GUI or headless RAT execution followed by LaunchAgent/Daemon persistence and persistent external connections; interactive children (osascript/sh/curl) spawned by parent.
  - *Log sources:* `macos:unifiedlog` (Process exec of remote-control apps or binaries with headless/connect flags); `macos:osquery` (CREATE/MODIFY: Creation of LaunchAgents/Daemons plists in user/system locations); `macos:osquery` (CONNECT: Long-lived connections from remote-control parents to external IPs/domains)
  - *Tune:* `AllowedAppBundlePaths` — Legitimate remote-support apps under /Applications.; `LaunchdAllowlist` — Known-good LaunchAgents/Daemons identifiers.; `TimeWindow` — Window for correlating exec→launchd→egress events.; `EgressHeuristics` — Duration/volume thresholds for persistent sessions.

---

### T1219.001 — IDE Tunneling
<a id="t1219001"></a>

**Detection strategy:** IDE Tunneling Detection via Process, File, and Network Behaviors (`DET0133`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1219.001](https://attack.mitre.org/techniques/T1219/001/) · [detail page](../../techniques/command-and-control.md#t1219001)

- **`AN0375` Analytic 0375** · Windows
  Detection of the creation of VSCode or JetBrains CLI tunneling profiles followed by persistent remote access via IDE-integrated tunnels, potentially authenticated via GitHub or JetBrains accounts.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=1); `WinEventLog:Sysmon` (EventCode=11); `NSM:Flow` (Outbound connection to *.tunnels.api.visualstudio.com or *.devtunnels.ms)
  - *Tune:* `TimeWindow` — Used to define the temporal proximity between tunnel profile creation and outbound connection.; `TunnelDomainPatterns` — Domain patterns for tunnel endpoints may change with IDE versions or organizations.; `AuthorizedUserList` — Helps filter tunnel usage from trusted developer accounts.
- **`AN0376` Analytic 0376** · Linux
  Creation of VSCode tunnel configuration file combined with interactive remote session via code CLI or ssh with JetBrains gateway.
  - *Log sources:* `auditd:SYSCALL` (execve on code or jetbrains-gateway with remote flags); `auditd:SYSCALL` (open: Write to ~/.vscode-cli/code_tunnel.json); `NSM:Flow` (Connections to *.devtunnels.ms or tunnels.api.visualstudio.com)
  - *Tune:* `PathRegex` — Regex patterns for user home directory file paths may vary by distro or user.; `TunnelCLIFlags` — Tunnel flags used by CLI tools can be customized or obfuscated by adversaries.; `Username` — The Linux user account associated with tunnel initiation; may vary across developer environments; `TunnelArtifactPath` — The filepath to the .vscode-cli/code_tunnel.json file may vary by distribution or IDE version; `CommandLineFlags` — Different IDEs or wrapper scripts may launch with different tunnel-related CLI options (e.g., --remote, --host)
- **`AN0377` Analytic 0377** · macOS
  Detection of JetBrains or VSCode tunnel profile creation followed by unusual persistent SSH or IDE-based tunnel communications to devtunnel APIs.
  - *Log sources:* `macos:unifiedlog` (process: code or jetbrains-gateway launching with --tunnel or --remote); `macos:unifiedlog` (creation of ~/.vscode-cli/code_tunnel.json); `NSM:Flow` (HTTPs connection to tunnels.api.visualstudio.com)
  - *Tune:* `ParentProcessName` — Helps scope tunnel launch context to non-interactive or suspicious parent processes.; `RemoteTunnelPersistence` — Allows tracking of tunnel re-establishment across reboots for persistence.; `RemoteFlag` — May include values like --remote, -R, or embedded ssh arguments passed by IDEs; `LaunchAgentPath` — If the IDE uses persistence via LaunchAgents, defenders may choose where to monitor for tunnel auto-launching; `TunnelReconnectInterval` — Frequency of retry attempts for tunnel reconnection can affect correlation window

---

### T1219.002 — Remote Desktop Software
<a id="t1219002"></a>

**Detection strategy:** Remote Desktop Software Execution and Beaconing Detection (`DET0259`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1219.002](https://attack.mitre.org/techniques/T1219/002/) · [detail page](../../techniques/command-and-control.md#t1219002)

- **`AN0714` Analytic 0714** · Windows
  Adversary installation or use of RMM software (e.g., TeamViewer, AnyDesk, ScreenConnect) followed by outbound beaconing or remote session establishment
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=11); `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` (new rule allowing inbound or outbound connections for remote desktop software)
  - *Tune:* `Image` — RMM software can vary; defenders should update rules to account for additional binaries (e.g., ConnectWise, Zoho Assist); `DestinationPort` — RMM software may use configurable or random high ports outside of standard (e.g., 7070, 5650); `ParentImage` — Expected parent process may vary in different enterprise contexts; `TimeWindow` — Correlation window for install-to-beacon or process-to-network event should match operational environment
- **`AN0715` Analytic 0715** · Linux
  Execution of known or custom VNC/remote desktop daemons or tunneling agents that initiate external communication after launch
  - *Log sources:* `auditd:SYSCALL` (execve); `NSM:Flow` (outbound connections to RMM services or to unusual destination ports)
  - *Tune:* `binary_name` — Custom-compiled or renamed VNC servers (e.g., x11vnc, tightvncserver) may require local tuning; `OutboundIPRange` — Destination IP or ASN may shift depending on geolocation of cloud-hosted RMM backends
- **`AN0716` Analytic 0716** · macOS
  Initiation of remote desktop sessions via AnyDesk, TeamViewer, or Chrome Remote Desktop accompanied by unexpected user logins or system modifications
  - *Log sources:* `macos:unifiedlog` (launch of remote desktop app or helper binary); `macos:unifiedlog` (network sessions initiated by remote desktop apps)
  - *Tune:* `process_signature` — App may be notarized and signed differently depending on distribution method (App Store vs .pkg); `sandbox_exception` — If the remote desktop tool circumvents sandbox, it may produce additional telemetry in local TCC logs

---

### T1219.003 — Remote Access Hardware
<a id="t1219003"></a>

**Detection strategy:** Detect Remote Access via USB Hardware (TinyPilot, PiKVM) (`DET0159`)  
**Platforms:** Linux, Windows, macOS  
**ATT&CK:** [T1219.003](https://attack.mitre.org/techniques/T1219/003/) · [detail page](../../techniques/command-and-control.md#t1219003)

- **`AN0446` Analytic 0446** · Windows
  Detection of USB-based remote access hardware (e.g., TinyPilot, PiKVM) attached to the host via drive or peripheral enumeration, triggering vendor identifiers or unusual EDID announcements.
  - *Log sources:* `WinEventLog:System` (EventCode=2003)
  - *Tune:* `VendorID` — Device vendor strings may need tuning to include additional remote hardware sources.; `SerialNumber` — Serial numbers for known implants can vary per campaign and may need expansion.; `TimeWindow` — Adjust the detection window for peripheral enumeration based on environment and operating hours.
- **`AN0447` Analytic 0447** · Linux
  Insertion of USB-based hardware proxies (e.g., PiKVM) which register under predictable names (e.g., tinypilot) or mount under known paths (e.g., /opt/tinypilot-privileged).
  - *Log sources:* `auditd:SYSCALL` (udev events or drive enumeration involving TinyPilot paths or device classes)
  - *Tune:* `FriendlyName` — Different hardware may present differently; names like 'TinyPilot' may need expanding to cover custom implants.; `MountPath` — Path matching (e.g., /opt/tinypilot) is mutable based on distro, customization, and staging.
- **`AN0448` Analytic 0448** · macOS
  Attachment of hardware-backed USB KVM devices (e.g., TinyPilot) that enumerate new HID or serial communication interfaces with identifiable metadata.
  - *Log sources:* `macos:unifiedlog` (Hardware enumeration events via IOKit or USBMuxd showing TinyPilot or unknown keyboard/mouse)
  - *Tune:* `DeviceClass` — Input or HID devices may be benign or malicious depending on context; tune based on environment (e.g., BYOD/dev stations).; `SerialCorrelationDepth` — Correlating serials across multiple device insertions may reduce noise but requires tuning.

---

### T1568 — Dynamic Resolution
<a id="t1568"></a>

**Detection strategy:** Detection Strategy for Dynamic Resolution across OS Platforms (`DET0039`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1568](https://attack.mitre.org/techniques/T1568/) · [detail page](../../techniques/command-and-control.md#t1568)

- **`AN0109` Analytic 0109** · Windows
  Correlate high-frequency or anomalous DNS query activity with processes that do not normally generate network requests (e.g., Office apps, system utilities). Detect pseudo-random or high-entropy domain lookups indicative of domain generation algorithms (DGAs).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `EntropyThreshold` — Adjust based on environment to differentiate DGAs from legitimate CDNs; `TimeWindow` — Interval for correlating bursts of DNS queries from the same process
- **`AN0110` Analytic 0110** · Linux
  Monitor /var/log/audit/audit.log and DNS resolver logs for repeated failed lookups or connections to high-entropy domain names. Correlate suspicious DNS queries with process lineage (e.g., Python, bash, or unusual system daemons).
  - *Log sources:* `auditd:SYSCALL` (socket/connect); `linux:syslog` (Query to suspicious domain with high entropy or low reputation)
  - *Tune:* `DomainReputationFeed` — Whitelist/blacklist tuned with external threat intel sources; `ProcessWhitelist` — Known safe daemons that frequently query domains
- **`AN0111` Analytic 0111** · macOS
  Inspect unified logs for anomalous DNS resolutions triggered by non-network applications. Flag repeated connections to newly registered or algorithmically generated domains. Correlate with endpoint process telemetry.
  - *Log sources:* `macos:unifiedlog` (DNS query with pseudo-random subdomain patterns); `macos:unifiedlog` (Unexpected applications generating outbound DNS queries)
  - *Tune:* `NewDomainThreshold` — Age of domain registration considered suspicious (e.g., < 30 days); `DNSQueryVolume` — Number of queries per process per time window
- **`AN0112` Analytic 0112** · ESXi
  Monitor esxcli and syslog records for DNS resolver changes or repeated queries to unusual external domains by management agents. Detect unauthorized changes to VM or host network settings that redirect DNS lookups.
  - *Log sources:* `esxi:syslog` (esxcli network vswitch or DNS resolver configuration updates)
  - *Tune:* `ResolverConfigPaths` — Expected resolvers or DNS forwarders in ESXi configurations; `ExternalDomainWhitelist` — Set of trusted external domains expected for ESXi host activity

---

### T1568.001 — Fast Flux DNS
<a id="t1568001"></a>

**Detection strategy:** Detection Strategy for Dynamic Resolution using Fast Flux DNS (`DET0485`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1568.001](https://attack.mitre.org/techniques/T1568/001/) · [detail page](../../techniques/command-and-control.md#t1568001)

- **`AN1331` Analytic 1331** · Windows
  Identify repeated DNS resolutions where the same domain name returns multiple IPs in short succession, combined with low TTL values and high query volume from unusual processes. Correlate with process lineage (e.g., Office apps spawning abnormal DNS lookups).
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Security` (EventCode=1)
  - *Tune:* `DNSQueryBurstThreshold` — Number of unique IPs returned per domain in a short window; `TimeWindow` — Adjust correlation timeframe for fast flux detection (e.g., 5–10 minutes)
- **`AN1332` Analytic 1332** · Linux
  Monitor resolver logs and auditd events for domains resolving to a rotating set of IPs within very short TTL intervals. Correlate high query rates from non-browser applications (e.g., python, curl).
  - *Log sources:* `auditd:SYSCALL` (socket/connect)
  - *Tune:* `TTLThreshold` — Minimum TTL value considered suspicious (e.g., < 60 seconds); `DomainReputationFeed` — External TI feed to exclude benign CDN or load balancer behavior
- **`AN1333` Analytic 1333** · macOS
  Use unified logs to identify processes issuing repeated DNS queries where the resolved IP addresses change frequently within very short TTL values. Correlate with outbound network traffic to validate C2-like patterns.
  - *Log sources:* `macos:unifiedlog` (Rapid domain-to-IP resolution changes for same domain); `macos:unifiedlog` (Unexpected apps generating frequent DNS queries)
  - *Tune:* `DNSRotationRate` — Rate of IP churn per domain to trigger detection; `NewDomainThreshold` — Flag if domain was registered recently (e.g., < 30 days)
- **`AN1334` Analytic 1334** · ESXi
  Monitor ESXi syslog and esxcli outputs for abnormal DNS resolver behavior, such as frequent domain-to-IP changes or unauthorized modifications of DNS settings used by management agents. Correlate domain lookups with short TTL values.
  - *Log sources:* `esxi:syslog` (Frequent DNS resolution of same domain with rotating IPs)
  - *Tune:* `ResolverConfigPaths` — Whitelist of expected DNS resolvers configured on ESXi; `ExternalDomainWhitelist` — Known trusted external domains for hypervisor services

---

### T1568.002 — Domain Generation Algorithms
<a id="t1568002"></a>

**Detection strategy:** Detection Strategy for Dynamic Resolution using Domain Generation Algorithms. (`DET0419`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1568.002](https://attack.mitre.org/techniques/T1568/002/) · [detail page](../../techniques/command-and-control.md#t1568002)

- **`AN1178` Analytic 1178** · Windows
  Correlate DNS queries that generate domains with high entropy or gibberish patterns, combined with short-lived connections from unusual processes. Monitor Sysmon DNS events and Windows Security logs for abnormal query rates and failed lookups.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Security` (EventCode=4688)
  - *Tune:* `EntropyThreshold` — Set threshold for randomness in queried domain strings (e.g., >4.0); `QueryFailureRate` — Failed resolution ratio above normal baseline (e.g., >30%); `TimeWindow` — Duration for aggregating suspicious DNS queries (e.g., 5–10 min)
- **`AN1179` Analytic 1179** · Linux
  Identify processes issuing repeated DNS queries to random-looking domains with abnormal entropy or word concatenations. Correlate resolver logs with high NXDOMAIN rates and auditd socket connections.
  - *Log sources:* `auditd:SYSCALL` (socket/connect); `linux:syslog` (Multiple NXDOMAIN responses and high entropy domains)
  - *Tune:* `NXDOMAINThreshold` — Ratio of failed queries triggering alert (e.g., >40%); `DomainAge` — Flag queries to domains registered in last 7–30 days
- **`AN1180` Analytic 1180** · macOS
  Monitor unified DNS logs for abnormal domain queries with low lexical similarity to known domains, repeated failed lookups, and random string structures. Cross-check with process logs to confirm unusual origins (non-browser apps).
  - *Log sources:* `macos:unifiedlog` (High entropy domain queries with multiple NXDOMAINs); `macos:unifiedlog` (Unexpected apps performing repeated DNS lookups)
  - *Tune:* `ReputationFeedWhitelist` — Exclude trusted CDN and cloud provider domains; `LexicalScoreThreshold` — Adjust score for word-based vs. letter-based DGAs
- **`AN1181` Analytic 1181** · ESXi
  Use ESXi syslogs to track abnormal DNS query patterns from management agents or VMs. Identify high-frequency, low-TTL, or unresolvable domains as suspicious. Correlate with unusual management plane process activity.
  - *Log sources:* `esxi:syslog` (Frequent DNS queries with high entropy names or NXDOMAIN results)
  - *Tune:* `ResolverConfigPaths` — Expected resolver settings for ESXi hosts; `DomainWhitelist` — Trusted external domains for hypervisor operations

---

### T1568.003 — DNS Calculation
<a id="t1568003"></a>

**Detection strategy:** Detection Strategy for Dynamic Resolution through DNS Calculation (`DET0262`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1568.003](https://attack.mitre.org/techniques/T1568/003/) · [detail page](../../techniques/command-and-control.md#t1568003)

- **`AN0728` Analytic 0728** · Windows
  Monitor DNS query results where subsequent connections use derived or unusual port numbers not explicitly resolved, especially when tied to suspicious processes. Correlate Sysmon DNS logs (Event ID 22) with process creation and socket activity.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `PortDeviationThreshold` — Deviation from common service ports (e.g., >1024 when DNS resolved service expects 80/443); `TimeWindow` — Correlation window between DNS response and network connection (e.g., 5 minutes)
- **`AN0729` Analytic 0729** · Linux
  Inspect resolver and audit logs for processes initiating outbound connections to ports calculated from DNS response IPs. Abnormal ephemeral port usage shortly after DNS queries can indicate DNS calculation behavior.
  - *Log sources:* `auditd:SYSCALL` (connect); `linux:syslog` (DNS response IPs followed by connections to non-standard calculated ports)
  - *Tune:* `EphemeralPortRange` — Configured ephemeral port ranges per environment to reduce false positives; `ResolverWhitelist` — Exclude trusted resolvers or internal services from analysis
- **`AN0730` Analytic 0730** · macOS
  Use unified logs to detect unusual DNS responses correlated with subsequent connections to calculated or non-standard ports. Monitor non-browser apps making repeated outbound connections that deviate from expected patterns.
  - *Log sources:* `macos:unifiedlog` (DNS responses followed by connections to ports outside standard ranges); `macos:unifiedlog` (Unexpected processes making network calls based on DNS-derived ports)
  - *Tune:* `ProcessAllowlist` — Expected processes allowed to open non-standard ports (e.g., developer tools); `ConnectionVolumeThreshold` — Volume of unusual connections needed before flagging as suspicious
- **`AN0731` Analytic 0731** · ESXi
  Analyze ESXi syslogs for management agents or VMs making outbound connections to dynamically calculated ports derived from DNS responses. Cross-check with VM traffic baselines to identify anomalies.
  - *Log sources:* `esxi:syslog` (DNS resolution events leading to outbound traffic on unexpected ports)
  - *Tune:* `ManagementPlaneIPs` — Known trusted ESXi management plane IPs to exclude from alerts; `DomainReputationFeed` — Integrate external feeds for reputation context on DNS-derived domains

---

### T1571 — Non-Standard Port
<a id="t1571"></a>

**Detection strategy:** Detection Strategy for Non-Standard Ports (`DET0227`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1571](https://attack.mitre.org/techniques/T1571/) · [detail page](../../techniques/command-and-control.md#t1571)

- **`AN0633` Analytic 0633** · Windows
  Processes initiating outbound connections on uncommon ports or using protocols inconsistent with the assigned port. Correlating process creation with subsequent network connections reveals anomalies such as svchost.exe or Office applications using high, atypical ports.
  - *Log sources:* `WinEventLog:Security` (EventCode=5156, 5157); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `PortThresholds` — Define what constitutes a 'non-standard port' based on organizational baselines (e.g., allow 443/80/22 but flag 8088/587/3389 changes).; `ProcessAllowList` — Processes normally allowed to use non-standard ports (e.g., custom apps).; `TimeWindow` — Correlate process creation and network activity within N seconds.
- **`AN0634` Analytic 0634** · Linux
  Unusual daemons or user processes binding/listening on ports outside of standard ranges, or initiating client connections using mismatched protocol/port pairings.
  - *Log sources:* `auditd:SYSCALL` (socket/connect syscalls); `linux:syslog` (processes binding to non-standard ports or sshd configured on unexpected port); `linux:osquery` (process listening or connecting on non-standard ports)
  - *Tune:* `AllowedServices` — Exclude ports intentionally configured for enterprise apps.; `PayloadEntropyThreshold` — Define thresholds for anomalous payload entropy to catch tunneled traffic.
- **`AN0635` Analytic 0635** · macOS
  Applications making outbound connections on non-standard ports or launchd services bound to ports inconsistent with system baselines.
  - *Log sources:* `macos:unifiedlog` (outbound TCP/UDP traffic over unexpected port); `macos:unifiedlog` (launchd services binding to non-standard ports)
  - *Tune:* `BaselinePortProfiles` — Define expected macOS service port usage (e.g., AirDrop, Bonjour).
- **`AN0636` Analytic 0636** · ESXi
  VM services or management daemons communicating on ports not defined by VMware defaults, such as vpxa or hostd processes initiating traffic over high-numbered or unexpected ports.
  - *Log sources:* `esxi:vpxd` (ESXi service connections on unexpected ports); `esxcli:network` (listening sockets bound to non-standard ports)
  - *Tune:* `ESXiAllowedPorts` — Default VMware service ports that should not be flagged.

---

### T1572 — Protocol Tunneling
<a id="t1572"></a>

**Detection strategy:** Detection Strategy for Protocol Tunneling accross OS platforms. (`DET0538`)  
**Platforms:** ESXi, Linux, Windows, macOS  
**ATT&CK:** [T1572](https://attack.mitre.org/techniques/T1572/) · [detail page](../../techniques/command-and-control.md#t1572)

- **`AN1483` Analytic 1483** · Windows
  Processes such as plink.exe, ssh.exe, or netsh.exe establishing outbound network connections where traffic patterns show encapsulated protocols (e.g., RDP over SSH). Defender observations include anomalous process-to-network relationships, large asymmetric data flows, and port usage mismatches.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=1)
  - *Tune:* `AllowedTools` — Whitelist legitimate tunneling tools (e.g., used by admins).; `DataAsymmetryThreshold` — Ratio of sent vs received bytes that indicates tunneling activity.; `TimeWindow` — Correlate process creation with network connection within N seconds.
- **`AN1484` Analytic 1484** · Linux
  sshd, socat, or custom binaries initiating port forwarding or encapsulating traffic (e.g., RDP, SMB) through SSH or HTTP. Defender sees abnormal connect/bind syscalls, encrypted traffic on ports typically used for non-encrypted services, and outlier traffic volume patterns.
  - *Log sources:* `auditd:SYSCALL` (socket/connect calls showing SSH processes forwarding arbitrary ports); `linux:syslog` (sshd sessions with unusual port forwarding parameters); `linux:osquery` (socat, ssh, or nc processes opening unexpected ports)
  - *Tune:* `ForwardingFlags` — Specific sshd config flags indicating port forwarding.; `ProtocolBaseline` — Define expected application protocols by port to catch tunneling mismatches.
- **`AN1485` Analytic 1485** · macOS
  launchd or user-invoked processes (ssh, socat) encapsulating traffic via SSH tunnels, VPN-style tooling, or DNS-over-HTTPS clients. Defender sees outbound TLS traffic with embedded DNS or RDP payloads.
  - *Log sources:* `macos:unifiedlog` (process execution of ssh with -L/-R forwarding flags); `macos:unifiedlog` (encrypted outbound traffic carrying unexpected application data)
  - *Tune:* `ExpectedDoHResolvers` — Known legitimate DoH resolvers used in environment.; `PayloadEntropyThreshold` — Flag excessive randomness in payloads on standard ports.
- **`AN1486` Analytic 1486** · ESXi
  VMware daemons or user processes encapsulating traffic (e.g., guest VMs tunneling via hostd). Defender sees network services inside ESXi creating flows inconsistent with management plane traffic, such as SSH forwarding or DNS-over-HTTPS from management interfaces.
  - *Log sources:* `esxi:vpxd` (ESXi processes relaying traffic via SSH or unexpected ports); `esxcli:network` (listening sockets bound with non-standard encapsulated protocols)
  - *Tune:* `ESXiServiceProfiles` — Baseline allowed services and expected ports for ESXi management.

---

### T1573 — Encrypted Channel
<a id="t1573"></a>

**Detection strategy:** Detection Strategy for Encrypted Channel across OS Platforms (`DET0273`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1573](https://attack.mitre.org/techniques/T1573/) · [detail page](../../techniques/command-and-control.md#t1573)

- **`AN0759` Analytic 0759** · Windows
  Processes that normally do not initiate network connections establishing outbound encrypted TLS/SSL sessions, especially with asymmetric traffic volumes (client sending more than receiving) or non-standard certificate chains. Defender observations correlate process creation with unexpected network encryption libraries being loaded.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=3, 22); `WinEventLog:Sysmon` (EventCode=7)
  - *Tune:* `AllowedEncryptedProcesses` — Whitelist processes expected to use TLS (e.g., browsers, mail clients).; `EntropyThreshold` — Payload randomness threshold to distinguish C2 encryption from legitimate traffic.; `TimeWindow` — Correlation window between process creation, module load, and encrypted connection.
- **`AN0760` Analytic 0760** · Linux
  Processes like curl, wget, python, socat, or custom binaries initiating TLS/SSL sessions to non-standard destinations. Defender sees abnormal syscalls for connect(), loading of libssl libraries, and persistent outbound encrypted traffic from daemons not normally communicating externally.
  - *Log sources:* `auditd:SYSCALL` (socket/connect with TLS context by unexpected process); `linux:syslog` (system daemons initiating TLS sessions outside expected services); `linux:osquery` (Processes linked with libssl or crypto libraries making outbound connections)
  - *Tune:* `WhitelistedDaemons` — Legitimate system services expected to use TLS (e.g., package updates).; `CertificateAuthorities` — Trusted CAs; flag self-signed or unrecognized certs.
- **`AN0761` Analytic 0761** · macOS
  Applications or launchd jobs initiating encrypted TLS traffic to rare external hosts. Defender observes unified logs showing ssl/TLS API calls by processes not baseline-approved, and payload entropy suggesting encrypted C2 sessions.
  - *Log sources:* `macos:unifiedlog` (Encrypted session initiation by unexpected binary); `macos:unifiedlog` (Process invoking SSL routines from Security framework)
  - *Tune:* `DoHResolvers` — Known legitimate DoH endpoints to reduce false positives.; `PayloadEntropyThreshold` — High-entropy traffic deviations used to detect concealed channels.
- **`AN0762` Analytic 0762** · ESXi
  VMware management daemons or guest processes initiating encrypted connections outside expected vCenter, update servers, or internal comms. Defender identifies hostd or vpxa initiating outbound TLS flows with uncommon destinations.
  - *Log sources:* `esxi:vpxd` (TLS session established by ESXi service to unapproved endpoint); `esxi:vmkernel` (Inspection of sockets showing encrypted sessions from non-baseline processes)
  - *Tune:* `AllowedMgmtHosts` — Baseline approved endpoints for vCenter or update services.
- **`AN0763` Analytic 0763** · Network Devices
  Unusual TLS tunnels through ports not normally encrypted (e.g., TLS on port 8080, 53). Defender sees NetFlow/IPFIX or packet inspection indicating high-entropy traffic volumes and asymmetric client/server exchange ratios.
  - *Log sources:* `NSM:Flow` (Session records with TLS-like byte patterns); `NSM:Connections` (Abnormal certificate chains or non-standard ports carrying TLS)
  - *Tune:* `PortProfiles` — Define expected TLS port usage to flag anomalies.; `TrafficAsymmetryRatio` — Sent/received byte thresholds to catch hidden C2.

---

### T1573.001 — Symmetric Cryptography
<a id="t1573001"></a>

**Detection strategy:** Detection Strategy for Encrypted Channel via Symmetric Cryptography across OS Platforms (`DET0143`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1573.001](https://attack.mitre.org/techniques/T1573/001/) · [detail page](../../techniques/command-and-control.md#t1573001)

- **`AN0400` Analytic 0400** · Windows
  Processes that typically do not perform cryptographic operations loading symmetric encryption libraries (e.g., bcryptprimitives.dll, aes.dll), then initiating outbound connections with high-entropy payloads. Defender correlates process creation, DLL load, and anomalous encrypted traffic patterns.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `AllowedCryptoProcesses` — Processes normally expected to use symmetric crypto (e.g., disk encryption, secure messaging).; `EntropyThreshold` — Minimum payload entropy score for flagging unusual encrypted sessions.; `TimeWindow` — Correlation window between module load and encrypted connection creation.
- **`AN0401` Analytic 0401** · Linux
  Unexpected processes (e.g., bash, python, custom binaries) dynamically loading libcrypto or performing AES/RC4 encryption operations, then initiating outbound sessions with abnormal byte entropy or asymmetric traffic patterns.
  - *Log sources:* `auditd:SYSCALL` (execve or socket/connect system calls from processes using crypto libraries); `linux:syslog` (System daemons initiating encrypted sessions with unexpected destinations); `linux:osquery` (Process linked with libcrypto.so making external connections)
  - *Tune:* `TrustedCryptoLibs` — Baseline expected crypto libraries to suppress false positives.; `TrafficAsymmetryRatio` — Ratio of sent/received bytes indicating possible hidden C2.
- **`AN0402` Analytic 0402** · macOS
  Launchd jobs or user processes invoking symmetric crypto APIs from the Security framework and generating outbound connections carrying randomized payloads inconsistent with normal TLS patterns.
  - *Log sources:* `macos:unifiedlog` (Process using AES/RC4 routines unexpectedly); `macos:unifiedlog` (Encrypted connection with anomalous payload entropy)
  - *Tune:* `DoHResolvers` — Legitimate DNS-over-HTTPS endpoints to avoid FP.; `PayloadEntropyThreshold` — Define entropy level at which traffic should be flagged.
- **`AN0403` Analytic 0403** · ESXi
  ESXi daemons (hostd, vpxa) unexpectedly using symmetric encryption routines for external connections. Defender identifies logs of service traffic with encrypted payloads inconsistent with VMware management baselines.
  - *Log sources:* `esxi:vpxd` (Symmetric crypto routines triggered for external session); `esxcli:network` (Socket sessions with randomized payloads inconsistent with TLS)
  - *Tune:* `AllowedMgmtHosts` — Baseline list of approved vCenter and update endpoints.
- **`AN0404` Analytic 0404** · Network Devices
  Flows showing encrypted payloads with high entropy not matching TLS handshake patterns, particularly when occurring on non-standard ports. Defender observes NetFlow/IPFIX byte distribution anomalies or IDS/IPS detecting symmetric encryption patterns without associated key exchange.
  - *Log sources:* `NSM:Flow` (Flow records with entropy signatures resembling symmetric encryption); `NSM:Connections` (Symmetric encryption detected without TLS handshake sequence)
  - *Tune:* `PortProfiles` — Baseline expected encryption by port/protocol.; `TrafficVolumeThreshold` — Volume thresholds for distinguishing benign VPN traffic from hidden C2.

---

### T1573.002 — Asymmetric Cryptography
<a id="t1573002"></a>

**Detection strategy:** Detection Strategy for Encrypted Channel via Asymmetric Cryptography across OS Platforms (`DET0543`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1573.002](https://attack.mitre.org/techniques/T1573/002/) · [detail page](../../techniques/command-and-control.md#t1573002)

- **`AN1496` Analytic 1496** · Windows
  Processes not typically associated with encryption loading asymmetric crypto libraries (e.g., rsaenh.dll, crypt32.dll) and subsequently initiating outbound TLS/SSL connections with abnormal certificate chains or handshakes. Defender correlates process creation, module load, and unusual encrypted sessions.
  - *Log sources:* `WinEventLog:Sysmon` (EventCode=7); `WinEventLog:Sysmon` (EventCode=3, 22)
  - *Tune:* `AllowedCryptoProcesses` — Whitelist browsers, mail clients, or apps expected to use asymmetric crypto.; `CertificateAuthorityList` — Baseline CA list for validating abnormal certs.; `HandshakeTimeout` — Detection of incomplete or malformed handshakes.
- **`AN1497` Analytic 1497** · Linux
  Processes (e.g., bash, python, custom binaries) dynamically linking libcrypto/libssl for RSA key exchange, then creating external connections with abnormal certificate validation or handshake anomalies. Defender observes syscall traces and outbound asymmetric key exchanges from non-SSL-native processes.
  - *Log sources:* `auditd:SYSCALL` (execve or socket/connect system calls for processes using RSA handshake); `linux:syslog` (Non-standard processes negotiating SSL/TLS key exchanges); `linux:osquery` (Processes linked with libssl/libcrypto performing network activity)
  - *Tune:* `ExpectedCryptoLibs` — Baseline libraries that normally handle asymmetric crypto.; `TrafficAsymmetryRatio` — Threshold for client-heavy data sending vs server.
- **`AN1498` Analytic 1498** · macOS
  Applications or launchd services invoking RSA or public-key routines from the Security framework, followed by outbound SSL/TLS sessions with unrecognized certs or anomalous handshakes. Defender observes unified logs of API calls and suspicious network entropy.
  - *Log sources:* `macos:unifiedlog` (Process invoking SecKeyCreateRandomKey or asymmetric crypto APIs); `macos:unifiedlog` (TLS connections with abnormal handshake sequence or self-signed cert)
  - *Tune:* `TrustedDoHEndpoints` — Known legitimate DoH/SSL endpoints.; `PayloadEntropyThreshold` — Entropy scoring for outbound payloads.
- **`AN1499` Analytic 1499** · ESXi
  VMware services (hostd, vpxa) unexpectedly negotiating asymmetric crypto sessions to external endpoints outside vCenter or update servers. Defender sees encrypted handshakes in logs inconsistent with baseline ESXi communication patterns.
  - *Log sources:* `esxi:vpxd` (ESXi process initiating asymmetric handshake with external host); `esxcli:network` (Socket inspection showing RSA key exchange outside baseline endpoints)
  - *Tune:* `BaselineMgmtHosts` — Expected external endpoints (vCenter, update repos).
- **`AN1500` Analytic 1500** · Network Devices
  Encrypted sessions detected with asymmetric key exchange anomalies on non-standard ports or with invalid/malformed certs. Defender correlates NetFlow/IPFIX with IDS/IPS detecting RSA exchanges outside expected TLS flows.
  - *Log sources:* `NSM:Flow` (Flow records with RSA key exchange on unexpected port); `IDS:TLSInspection` (Malformed certs, incomplete asymmetric handshakes, or invalid CAs)
  - *Tune:* `PortProfiles` — Define expected ports for asymmetric cryptography (e.g., 443, 993).; `CertValidationPolicy` — Thresholds for rejecting untrusted/self-signed certs.

---

### T1665 — Hide Infrastructure
<a id="t1665"></a>

**Detection strategy:** Detection Strategy for Hide Infrastructure (`DET0411`)  
**Platforms:** ESXi, Linux, Network Devices, Windows, macOS  
**ATT&CK:** [T1665](https://attack.mitre.org/techniques/T1665/) · [detail page](../../techniques/command-and-control.md#t1665)

- **`AN1148` Analytic 1148** · Windows
  Monitor DNS queries, proxy logs, and user-agent strings for anomalous patterns associated with adversary attempts to hide infrastructure. Defenders may observe DNS resolutions to short-lived domains, abnormal WHOIS registration data, or filtering of known defensive/responder IP addresses.
  - *Log sources:* `WinEventLog:Security` (EventCode=5156, 5157); `dns:query` (Excessive lookups for domains with suspicious WHOIS or short TTL values)
  - *Tune:* `SuspiciousDomains` — List of domains registered with privacy-protected or suspicious WHOIS metadata.; `ResponderIPs` — Known incident response or scanning infrastructure IP ranges.
- **`AN1149` Analytic 1149** · Linux
  Detect adversaries filtering traffic or modifying server responses to evade scanning. Monitor iptables, nftables, or proxy configurations that deny or redirect requests from known scanning agents or defensive tools.
  - *Log sources:* `auditd:SYSCALL` (execve: Execution of commands modifying iptables/nftables to block selective IPs); `NSM:Flow` (Altered response metadata or blocked content based on user-agent or geolocation)
  - *Tune:* `BlockedAgents` — User-agent strings or scanning tools to monitor for selective filtering.
- **`AN1150` Analytic 1150** · macOS
  Monitor unified logs for manipulation of proxy configurations, DNS resolution, or filtering rules. Adversaries may redirect responses or use trusted domains that later resolve to malicious C2 infrastructure.
  - *Log sources:* `macos:unifiedlog` (System process modifications altering DNS/proxy settings); `NSM:Flow` (Suspicious changes in TLS certificate responses or redirected domains)
  - *Tune:* `TrustedHostingProviders` — Known hosting/CDN providers often abused to hide malicious C2 infrastructure.
- **`AN1151` Analytic 1151** · Network Devices
  Inspect network telemetry for adversary attempts to blend malicious traffic with legitimate flows using VPNs, proxies, or geolocation spoofing. Defensive teams may observe anomalous tunnels, encrypted sessions to suspicious domains, or geo-mismatched IP activity.
  - *Log sources:* `NSM:Flow` (Encrypted tunnels or proxy traffic to non-standard destinations)
  - *Tune:* `GeoIPRanges` — Regions to monitor for unexpected or mismatched geolocation activity.
- **`AN1152` Analytic 1152** · ESXi
  Monitor VM-level DNS and network traffic logs for adversary-controlled domains or selective response behavior (e.g., dropped requests from security scanners).
  - *Log sources:* `esxi:vmkernel` (DNS lookups resolving to domains with rapid changes in registration metadata); `esxi:vmkernel` (Suspicious traffic filtered or redirected by VM networking stack)
  - *Tune:* `MonitoredVMs` — Targeted virtual machines where adversaries may attempt to hide C2 traffic.

---

