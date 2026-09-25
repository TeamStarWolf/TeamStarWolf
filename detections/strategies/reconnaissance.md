# Reconnaissance — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Reconnaissance**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1589 — Gather Victim Identity Information
<a id="t1589"></a>

**Detection strategy:** Detection of Gather Victim Identity Information (`DET0841`)  
**Platforms:** PRE  
**ATT&CK:** [T1589](https://attack.mitre.org/techniques/T1589/) · [detail page](../../techniques/reconnaissance.md#t1589)

- **`AN1973` Analytic 1973** · PRE
  Monitor for suspicious network traffic that could be indicative of probing for user information, such as large/iterative quantities of authentication requests originating from a single source (especially if the source is known to be associated with an adversary/botnet). Analyzing web metadata may also reveal artifacts that can be attributed to potentially malicious activity, such as referer or user-agent string HTTP/S fields.
  - *Log sources:* `Network Traffic`

---

### T1589.001 — Credentials
<a id="t1589001"></a>

**Detection strategy:** Detection of Credentials (`DET0813`)  
**Platforms:** PRE  
**ATT&CK:** [T1589.001](https://attack.mitre.org/techniques/T1589/001/) · [detail page](../../techniques/reconnaissance.md#t1589001)

- **`AN1945` Analytic 1945** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1589.002 — Email Addresses
<a id="t1589002"></a>

**Detection strategy:** Detection of Email Addresses (`DET0814`)  
**Platforms:** PRE  
**ATT&CK:** [T1589.002](https://attack.mitre.org/techniques/T1589/002/) · [detail page](../../techniques/reconnaissance.md#t1589002)

- **`AN1946` Analytic 1946** · PRE
  Monitor for suspicious network traffic that could be indicative of probing for email addresses and/or usernames, such as large/iterative quantities of authentication requests originating from a single source (especially if the source is known to be associated with an adversary/botnet). Analyzing web metadata may also reveal artifacts that can be attributed to potentially malicious activity, such as referer or user-agent string HTTP/S fields.
  - *Log sources:* `Network Traffic`

---

### T1589.003 — Employee Names
<a id="t1589003"></a>

**Detection strategy:** Detection of Employee Names (`DET0857`)  
**Platforms:** PRE  
**ATT&CK:** [T1589.003](https://attack.mitre.org/techniques/T1589/003/) · [detail page](../../techniques/reconnaissance.md#t1589003)

- **`AN1989` Analytic 1989** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1590 — Gather Victim Network Information
<a id="t1590"></a>

**Detection strategy:** Detection of Gather Victim Network Information (`DET0869`)  
**Platforms:** PRE  
**ATT&CK:** [T1590](https://attack.mitre.org/techniques/T1590/) · [detail page](../../techniques/reconnaissance.md#t1590)

- **`AN2001` Analytic 2001** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1590.001 — Domain Properties
<a id="t1590001"></a>

**Detection strategy:** Detection of Domain Properties (`DET0847`)  
**Platforms:** PRE  
**ATT&CK:** [T1590.001](https://attack.mitre.org/techniques/T1590/001/) · [detail page](../../techniques/reconnaissance.md#t1590001)

- **`AN1979` Analytic 1979** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1590.002 — DNS
<a id="t1590002"></a>

**Detection strategy:** Detection of DNS (`DET0843`)  
**Platforms:** PRE  
**ATT&CK:** [T1590.002](https://attack.mitre.org/techniques/T1590/002/) · [detail page](../../techniques/reconnaissance.md#t1590002)

- **`AN1975` Analytic 1975** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1590.003 — Network Trust Dependencies
<a id="t1590003"></a>

**Detection strategy:** Detection of Network Trust Dependencies (`DET0828`)  
**Platforms:** PRE  
**ATT&CK:** [T1590.003](https://attack.mitre.org/techniques/T1590/003/) · [detail page](../../techniques/reconnaissance.md#t1590003)

- **`AN1960` Analytic 1960** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1590.004 — Network Topology
<a id="t1590004"></a>

**Detection strategy:** Detection of Network Topology (`DET0819`)  
**Platforms:** PRE  
**ATT&CK:** [T1590.004](https://attack.mitre.org/techniques/T1590/004/) · [detail page](../../techniques/reconnaissance.md#t1590004)

- **`AN1951` Analytic 1951** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1590.005 — IP Addresses
<a id="t1590005"></a>

**Detection strategy:** Detection of IP Addresses (`DET0815`)  
**Platforms:** PRE  
**ATT&CK:** [T1590.005](https://attack.mitre.org/techniques/T1590/005/) · [detail page](../../techniques/reconnaissance.md#t1590005)

- **`AN1947` Analytic 1947** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1590.006 — Network Security Appliances
<a id="t1590006"></a>

**Detection strategy:** Detection of Network Security Appliances (`DET0889`)  
**Platforms:** PRE  
**ATT&CK:** [T1590.006](https://attack.mitre.org/techniques/T1590/006/) · [detail page](../../techniques/reconnaissance.md#t1590006)

- **`AN2021` Analytic 2021** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1591 — Gather Victim Org Information
<a id="t1591"></a>

**Detection strategy:** Detection of Gather Victim Org Information (`DET0890`)  
**Platforms:** PRE  
**ATT&CK:** [T1591](https://attack.mitre.org/techniques/T1591/) · [detail page](../../techniques/reconnaissance.md#t1591)

- **`AN2022` Analytic 2022** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1591.001 — Determine Physical Locations
<a id="t1591001"></a>

**Detection strategy:** Detection of Determine Physical Locations (`DET0806`)  
**Platforms:** PRE  
**ATT&CK:** [T1591.001](https://attack.mitre.org/techniques/T1591/001/) · [detail page](../../techniques/reconnaissance.md#t1591001)

- **`AN1938` Analytic 1938** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1591.002 — Business Relationships
<a id="t1591002"></a>

**Detection strategy:** Detection of Business Relationships (`DET0855`)  
**Platforms:** PRE  
**ATT&CK:** [T1591.002](https://attack.mitre.org/techniques/T1591/002/) · [detail page](../../techniques/reconnaissance.md#t1591002)

- **`AN1987` Analytic 1987** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1591.003 — Identify Business Tempo
<a id="t1591003"></a>

**Detection strategy:** Detection of Identify Business Tempo (`DET0849`)  
**Platforms:** PRE  
**ATT&CK:** [T1591.003](https://attack.mitre.org/techniques/T1591/003/) · [detail page](../../techniques/reconnaissance.md#t1591003)

- **`AN1981` Analytic 1981** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1591.004 — Identify Roles
<a id="t1591004"></a>

**Detection strategy:** Detection of Identify Roles (`DET0807`)  
**Platforms:** PRE  
**ATT&CK:** [T1591.004](https://attack.mitre.org/techniques/T1591/004/) · [detail page](../../techniques/reconnaissance.md#t1591004)

- **`AN1939` Analytic 1939** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1592 — Gather Victim Host Information
<a id="t1592"></a>

**Detection strategy:** Detection of Gather Victim Host Information (`DET0826`)  
**Platforms:** PRE  
**ATT&CK:** [T1592](https://attack.mitre.org/techniques/T1592/) · [detail page](../../techniques/reconnaissance.md#t1592)

- **`AN1958` Analytic 1958** · PRE
  Internet scanners may be used to look for patterns associated with malicious content designed to collect host information from visitors.
Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.
  - *Log sources:* `Internet Scan`

---

### T1592.001 — Hardware
<a id="t1592001"></a>

**Detection strategy:** Detection of Hardware (`DET0887`)  
**Platforms:** PRE  
**ATT&CK:** [T1592.001](https://attack.mitre.org/techniques/T1592/001/) · [detail page](../../techniques/reconnaissance.md#t1592001)

- **`AN2019` Analytic 2019** · PRE
  Internet scanners may be used to look for patterns associated with malicious content designed to collect host hardware information from visitors.
Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.
  - *Log sources:* `Internet Scan`

---

### T1592.002 — Software
<a id="t1592002"></a>

**Detection strategy:** Detection of Software (`DET0888`)  
**Platforms:** PRE  
**ATT&CK:** [T1592.002](https://attack.mitre.org/techniques/T1592/002/) · [detail page](../../techniques/reconnaissance.md#t1592002)

- **`AN2020` Analytic 2020** · PRE
  Internet scanners may be used to look for patterns associated with malicious content designed to collect host software information from visitors.
Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.
  - *Log sources:* `Internet Scan`

---

### T1592.003 — Firmware
<a id="t1592003"></a>

**Detection strategy:** Detection of Firmware (`DET0818`)  
**Platforms:** PRE  
**ATT&CK:** [T1592.003](https://attack.mitre.org/techniques/T1592/003/) · [detail page](../../techniques/reconnaissance.md#t1592003)

- **`AN1950` Analytic 1950** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1592.004 — Client Configurations
<a id="t1592004"></a>

**Detection strategy:** Detection of Client Configurations (`DET0820`)  
**Platforms:** PRE  
**ATT&CK:** [T1592.004](https://attack.mitre.org/techniques/T1592/004/) · [detail page](../../techniques/reconnaissance.md#t1592004)

- **`AN1952` Analytic 1952** · PRE
  Internet scanners may be used to look for patterns associated with malicious content designed to collect client configuration information from visitors.
Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.
  - *Log sources:* `Internet Scan`

---

### T1593 — Search Open Websites/Domains
<a id="t1593"></a>

**Detection strategy:** Detection of Search Open Websites/Domains (`DET0856`)  
**Platforms:** PRE  
**ATT&CK:** [T1593](https://attack.mitre.org/techniques/T1593/) · [detail page](../../techniques/reconnaissance.md#t1593)

- **`AN1988` Analytic 1988** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1593.001 — Social Media
<a id="t1593001"></a>

**Detection strategy:** Detection of Social Media (`DET0812`)  
**Platforms:** PRE  
**ATT&CK:** [T1593.001](https://attack.mitre.org/techniques/T1593/001/) · [detail page](../../techniques/reconnaissance.md#t1593001)

- **`AN1944` Analytic 1944** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1593.002 — Search Engines
<a id="t1593002"></a>

**Detection strategy:** Detection of Search Engines (`DET0811`)  
**Platforms:** PRE  
**ATT&CK:** [T1593.002](https://attack.mitre.org/techniques/T1593/002/) · [detail page](../../techniques/reconnaissance.md#t1593002)

- **`AN1943` Analytic 1943** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1593.003 — Code Repositories
<a id="t1593003"></a>

**Detection strategy:** Detection of Code Repositories (`DET0805`)  
**Platforms:** PRE  
**ATT&CK:** [T1593.003](https://attack.mitre.org/techniques/T1593/003/) · [detail page](../../techniques/reconnaissance.md#t1593003)

- **`AN1937` Analytic 1937** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders. 

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1594 — Search Victim-Owned Websites
<a id="t1594"></a>

**Detection strategy:** Detection of Search Victim-Owned Websites (`DET0810`)  
**Platforms:** PRE  
**ATT&CK:** [T1594](https://attack.mitre.org/techniques/T1594/) · [detail page](../../techniques/reconnaissance.md#t1594)

- **`AN1942` Analytic 1942** · PRE
  Monitor for suspicious network traffic that could be indicative of adversary reconnaissance, such as rapid successions of requests indicative of web crawling and/or large quantities of requests originating from a single source (especially if the source is known to be associated with an adversary). Analyzing web metadata may also reveal artifacts that can be attributed to potentially malicious activity, such as referer or user-agent string HTTP/S fields.
  - *Log sources:* `Application Log`

---

### T1595 — Active Scanning
<a id="t1595"></a>

**Detection strategy:** Detection of Active Scanning (`DET0830`)  
**Platforms:** PRE  
**ATT&CK:** [T1595](https://attack.mitre.org/techniques/T1595/) · [detail page](../../techniques/reconnaissance.md#t1595)

- **`AN1962` Analytic 1962** · PRE
  Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.
Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).
  - *Log sources:* `Network Traffic`; `Network Traffic`

---

### T1595.001 — Scanning IP Blocks
<a id="t1595001"></a>

**Detection strategy:** Detection of Scanning IP Blocks (`DET0817`)  
**Platforms:** PRE  
**ATT&CK:** [T1595.001](https://attack.mitre.org/techniques/T1595/001/) · [detail page](../../techniques/reconnaissance.md#t1595001)

- **`AN1949` Analytic 1949** · PRE
  Monitoring the content of network traffic can help detect patterns associated with active scanning activities. This can include identifying repeated connection attempts, unusual scanning behaviors, or probing activity targeting multiple IP addresses across a network.
Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.
  - *Log sources:* `Network Traffic`; `Network Traffic`

---

### T1595.002 — Vulnerability Scanning
<a id="t1595002"></a>

**Detection strategy:** Detection of Vulnerability Scanning (`DET0867`)  
**Platforms:** PRE  
**ATT&CK:** [T1595.002](https://attack.mitre.org/techniques/T1595/002/) · [detail page](../../techniques/reconnaissance.md#t1595002)

- **`AN1999` Analytic 1999** · PRE
  Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).
Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.
  - *Log sources:* `Network Traffic`; `Network Traffic`

---

### T1595.003 — Wordlist Scanning
<a id="t1595003"></a>

**Detection strategy:** Detection of Wordlist Scanning (`DET0868`)  
**Platforms:** PRE  
**ATT&CK:** [T1595.003](https://attack.mitre.org/techniques/T1595/003/) · [detail page](../../techniques/reconnaissance.md#t1595003)

- **`AN2000` Analytic 2000** · PRE
  Monitor for suspicious network traffic that could be indicative of scanning, such as large quantities originating from a single source (especially if the source is known to be associated with an adversary/botnet).
  - *Log sources:* `Network Traffic`

---

### T1596 — Search Open Technical Databases
<a id="t1596"></a>

**Detection strategy:** Detection of Search Open Technical Databases (`DET0860`)  
**Platforms:** PRE  
**ATT&CK:** [T1596](https://attack.mitre.org/techniques/T1596/) · [detail page](../../techniques/reconnaissance.md#t1596)

- **`AN1992` Analytic 1992** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1596.001 — DNS/Passive DNS
<a id="t1596001"></a>

**Detection strategy:** Detection of DNS/Passive DNS (`DET0877`)  
**Platforms:** PRE  
**ATT&CK:** [T1596.001](https://attack.mitre.org/techniques/T1596/001/) · [detail page](../../techniques/reconnaissance.md#t1596001)

- **`AN2009` Analytic 2009** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1596.002 — WHOIS
<a id="t1596002"></a>

**Detection strategy:** Detection of WHOIS (`DET0832`)  
**Platforms:** PRE  
**ATT&CK:** [T1596.002](https://attack.mitre.org/techniques/T1596/002/) · [detail page](../../techniques/reconnaissance.md#t1596002)

- **`AN1964` Analytic 1964** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1596.003 — Digital Certificates
<a id="t1596003"></a>

**Detection strategy:** Detection of Digital Certificates (`DET0831`)  
**Platforms:** PRE  
**ATT&CK:** [T1596.003](https://attack.mitre.org/techniques/T1596/003/) · [detail page](../../techniques/reconnaissance.md#t1596003)

- **`AN1963` Analytic 1963** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1596.004 — CDNs
<a id="t1596004"></a>

**Detection strategy:** Detection of CDNs (`DET0809`)  
**Platforms:** PRE  
**ATT&CK:** [T1596.004](https://attack.mitre.org/techniques/T1596/004/) · [detail page](../../techniques/reconnaissance.md#t1596004)

- **`AN1941` Analytic 1941** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1596.005 — Scan Databases
<a id="t1596005"></a>

**Detection strategy:** Detection of Scan Databases (`DET0858`)  
**Platforms:** PRE  
**ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/) · [detail page](../../techniques/reconnaissance.md#t1596005)

- **`AN1990` Analytic 1990** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1597 — Search Closed Sources
<a id="t1597"></a>

**Detection strategy:** Detection of Search Closed Sources (`DET0822`)  
**Platforms:** PRE  
**ATT&CK:** [T1597](https://attack.mitre.org/techniques/T1597/) · [detail page](../../techniques/reconnaissance.md#t1597)

- **`AN1954` Analytic 1954** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1597.001 — Threat Intel Vendors
<a id="t1597001"></a>

**Detection strategy:** Detection of Threat Intel Vendors (`DET0816`)  
**Platforms:** PRE  
**ATT&CK:** [T1597.001](https://attack.mitre.org/techniques/T1597/001/) · [detail page](../../techniques/reconnaissance.md#t1597001)

- **`AN1948` Analytic 1948** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1597.002 — Purchase Technical Data
<a id="t1597002"></a>

**Detection strategy:** Detection of Purchase Technical Data (`DET0880`)  
**Platforms:** PRE  
**ATT&CK:** [T1597.002](https://attack.mitre.org/techniques/T1597/002/) · [detail page](../../techniques/reconnaissance.md#t1597002)

- **`AN2012` Analytic 2012** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

### T1598 — Phishing for Information
<a id="t1598"></a>

**Detection strategy:** Detection of Phishing for Information (`DET0823`)  
**Platforms:** PRE  
**ATT&CK:** [T1598](https://attack.mitre.org/techniques/T1598/) · [detail page](../../techniques/reconnaissance.md#t1598)

- **`AN1955` Analytic 1955** · PRE
  Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).
Depending on the specific method of phishing, the detections can vary. Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header anal
  - *Log sources:* `Network Traffic`; `Application Log`; `Network Traffic`

---

### T1598.001 — Spearphishing Service
<a id="t1598001"></a>

**Detection strategy:** Detection of Spearphishing Service (`DET0821`)  
**Platforms:** PRE  
**ATT&CK:** [T1598.001](https://attack.mitre.org/techniques/T1598/001/) · [detail page](../../techniques/reconnaissance.md#t1598001)

- **`AN1953` Analytic 1953** · PRE
  Monitor social media traffic for suspicious activity, including messages requesting information as well as abnormal file or data transfers (especially those involving unknown, or otherwise suspicious accounts).
Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.
Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.
Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.
Monitor and analyze traffic patterns and packet inspection associated to protocol(s) th
  - *Log sources:* `Application Log`; `Network Traffic`; `Network Traffic`

---

### T1598.002 — Spearphishing Attachment
<a id="t1598002"></a>

**Detection strategy:** Detection of Spearphishing Attachment (`DET0865`)  
**Platforms:** PRE  
**ATT&CK:** [T1598.002](https://attack.mitre.org/techniques/T1598/002/) · [detail page](../../techniques/reconnaissance.md#t1598002)

- **`AN1997` Analytic 1997** · PRE
  Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.
Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed.
Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command 
  - *Log sources:* `Network Traffic`; `Application Log`; `Network Traffic`

---

### T1598.003 — Spearphishing Link
<a id="t1598003"></a>

**Detection strategy:** Detection of Spearphishing Link (`DET0878`)  
**Platforms:** PRE  
**ATT&CK:** [T1598.003](https://attack.mitre.org/techniques/T1598/003/) · [detail page](../../techniques/reconnaissance.md#t1598003)

- **`AN2010` Analytic 2010** · PRE
  Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed. Monitor for references to uncategorized or known-bad sites. URL inspection within email (including expanding shortened links and identifying obfuscated URLs) can also help detect links leading to known malicious sites.

Furthermore, monitor browser logs for homographs in ASCII and in internationalized domain names abusing different character sets (e.g. Cyrillic vs Latin versions of trusted sites).
Monitor network data for uncommon data flows. Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious.
Monitor
  - *Log sources:* `Application Log`; `Network Traffic`; `Network Traffic`

---

### T1598.004 — Spearphishing Voice
<a id="t1598004"></a>

**Detection strategy:** Detection of Spearphishing Voice (`DET0886`)  
**Platforms:** PRE  
**ATT&CK:** [T1598.004](https://attack.mitre.org/techniques/T1598/004/) · [detail page](../../techniques/reconnaissance.md#t1598004)

- **`AN2018` Analytic 2018** · PRE
  Monitor call logs from corporate devices to identify patterns of potential voice phishing, such as calls to/from known malicious phone numbers.
  - *Log sources:* `Application Log`

---

### T1681 — Search Threat Vendor Data
<a id="t1681"></a>

**Detection strategy:** Detection of Search Threat Vendor Data (`DET0866`)  
**Platforms:** PRE  
**ATT&CK:** [T1681](https://attack.mitre.org/techniques/T1681/) · [detail page](../../techniques/reconnaissance.md#t1681)

- **`AN1998` Analytic 1998** · PRE
  Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

---

