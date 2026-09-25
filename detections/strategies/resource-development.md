# Resource Development — Detection Strategies

> MITRE ATT&CK detection strategies and analytics (v18.1) for techniques whose primary tactic is **Resource Development**. Each analytic lists the **log sources / channels** it needs, the **detection logic**, and the **tunable elements** to adapt it to your environment. Authoritative source: the ATT&CK detection-strategy model in the Enterprise STIX.

See also: [all detection strategies index](/detections/strategies/README.md) · [Technique Detection Library](../TECHNIQUE_DETECTION_LIBRARY.md) (ready-to-run SIEM queries) · [Data Components & Log Sources](../../ATTACK_DATA_COMPONENTS.md) · [Technique Detail Pages](../../techniques/README.md)

---

### T1583 — Acquire Infrastructure
<a id="t1583"></a>

**Detection strategy:** Detection of Acquire Infrastructure (`DET0895`)  
**Platforms:** PRE  
**ATT&CK:** [T1583](https://attack.mitre.org/techniques/T1583/) · [detail page](../../techniques/resource-development.md#t1583)

- **`AN2027` Analytic 2027** · PRE
  Monitor for contextual data about an Internet-facing resource gathered from a scan, such as running services or ports that may buy, lease, or rent infrastructure that can be used during targeting. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Once adversaries have provisioned infrastructure (ex: a server for use in command and control), internet scans may help proactively discover adversary acquired infrastructure. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS negotiation features, or other response artifacts associated with adversary C2 software. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Monitor 
  - *Log sources:* `Internet Scan`; `Internet Scan`; `Domain Name`; `Domain Name`; `Domain Name`

---

### T1583.001 — Domains
<a id="t1583001"></a>

**Detection strategy:** Detection of Domains (`DET0892`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.001](https://attack.mitre.org/techniques/T1583/001/) · [detail page](../../techniques/resource-development.md#t1583001)

- **`AN2024` Analytic 2024** · PRE
  Monitor logged domain name system (DNS) data for purchased domains that can be used during targeting. Reputation/category-based detection may be difficult until the categorization is updated. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access and Command and Control. 
Domain registration information is, by design, captured in public registration logs. Consider use of services that may aid in tracking of newly acquired domains, such as WHOIS databases and/or passive DNS. In some cases it may be possible to pivot on known pieces of domain registration information to uncover other infrastructure purchased by the adversary. Consider monitoring for domains created with a similar structure to your own, including under a different TLD. Tho
  - *Log sources:* `Domain Name`; `Domain Name`; `Domain Name`

---

### T1583.002 — DNS Server
<a id="t1583002"></a>

**Detection strategy:** Detection of DNS Server (`DET0862`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.002](https://attack.mitre.org/techniques/T1583/002/) · [detail page](../../techniques/resource-development.md#t1583002)

- **`AN1994` Analytic 1994** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.

---

### T1583.003 — Virtual Private Server
<a id="t1583003"></a>

**Detection strategy:** Detection of Virtual Private Server (`DET0838`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.003](https://attack.mitre.org/techniques/T1583/003/) · [detail page](../../techniques/resource-development.md#t1583003)

- **`AN1970` Analytic 1970** · PRE
  Once adversaries have provisioned a VPS (ex: for use as a command and control server), internet scans may reveal servers that adversaries have acquired. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS negotiation features, or other response artifacts associated with adversary C2 software. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecyc
  - *Log sources:* `Internet Scan`; `Internet Scan`

---

### T1583.004 — Server
<a id="t1583004"></a>

**Detection strategy:** Detection of Server (`DET0871`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.004](https://attack.mitre.org/techniques/T1583/004/) · [detail page](../../techniques/resource-development.md#t1583004)

- **`AN2003` Analytic 2003** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Once adversaries have provisioned a server (ex: for use as a command and control server), internet scans may reveal servers that adversaries have acquired. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS negotiation features, or other response artifacts associated with adversary C2 software.
  - *Log sources:* `Internet Scan`; `Internet Scan`

---

### T1583.005 — Botnet
<a id="t1583005"></a>

**Detection strategy:** Detection of Botnet (`DET0837`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.005](https://attack.mitre.org/techniques/T1583/005/) · [detail page](../../techniques/resource-development.md#t1583005)

- **`AN1969` Analytic 1969** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Phishing, Endpoint Denial of Service, or Network Denial of Service.

---

### T1583.006 — Web Services
<a id="t1583006"></a>

**Detection strategy:** Detection of Web Services (`DET0896`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.006](https://attack.mitre.org/techniques/T1583/006/) · [detail page](../../techniques/resource-development.md#t1583006)

- **`AN2028` Analytic 2028** · PRE
  Once adversaries leverage the web service as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control (Web Service) or Exfiltration Over Web Service.
  - *Log sources:* `Internet Scan`

---

### T1583.007 — Serverless
<a id="t1583007"></a>

**Detection strategy:** Detection of Serverless (`DET0829`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.007](https://attack.mitre.org/techniques/T1583/007/) · [detail page](../../techniques/resource-development.md#t1583007)

- **`AN1961` Analytic 1961** · PRE
  Once adversaries leverage serverless functions as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle.
  - *Log sources:* `Internet Scan`

---

### T1583.008 — Malvertising
<a id="t1583008"></a>

**Detection strategy:** Detection of Malvertising (`DET0836`)  
**Platforms:** PRE  
**ATT&CK:** [T1583.008](https://attack.mitre.org/techniques/T1583/008/) · [detail page](../../techniques/resource-development.md#t1583008)

- **`AN1968` Analytic 1968** · PRE
  If infrastructure or patterns in the malicious web content related to malvertising have been previously identified, internet scanning may uncover when an adversary has staged malicious web content. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on other phases of the adversary lifecycle, such as Drive-by Compromise or Exploitation for Client Execution.
  - *Log sources:* `Internet Scan`

---

### T1584 — Compromise Infrastructure
<a id="t1584"></a>

**Detection strategy:** Detection of Compromise Infrastructure (`DET0885`)  
**Platforms:** PRE  
**ATT&CK:** [T1584](https://attack.mitre.org/techniques/T1584/) · [detail page](../../techniques/resource-development.md#t1584)

- **`AN2017` Analytic 2017** · PRE
  Once adversaries have provisioned compromised infrastructure (ex: a server for use in command and control), internet scans may help proactively discover compromised infrastructure. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS negotiation features, or other response artifacts associated with adversary C2 software.
Consider monitoring for anomalous changes to domain registrant information and/or domain resolution information that may indicate the compromise of a domain. Efforts may need to be tailored to specific domains of interest as benign registration and resolution changes are a common occurrence on the internet.
Monitor for queried domain name system (DNS) registry data that may compromise third-party infrastructure that can be use
  - *Log sources:* `Internet Scan`; `Domain Name`; `Domain Name`; `Domain Name`; `Internet Scan`

---

### T1584.001 — Domains
<a id="t1584001"></a>

**Detection strategy:** Detection of Domains (`DET0863`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.001](https://attack.mitre.org/techniques/T1584/001/) · [detail page](../../techniques/resource-development.md#t1584001)

- **`AN1995` Analytic 1995** · PRE
  Monitor for logged domain name system (DNS) registry data that may hijack domains and/or subdomains that can be used during targeting. In some cases, abnormal subdomain IP addresses (such as those originating in a different country from the root domain) may indicate a malicious subdomain. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Consider monitoring for anomalous changes to domain registrant information and/or domain resolution information that may indicate the compromise of a domain. Efforts may need to be tailored to specific domains of interest as benign registration and resolution c
  - *Log sources:* `Domain Name`; `Domain Name`; `Domain Name`

---

### T1584.002 — DNS Server
<a id="t1584002"></a>

**Detection strategy:** Detection of DNS Server (`DET0891`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.002](https://attack.mitre.org/techniques/T1584/002/) · [detail page](../../techniques/resource-development.md#t1584002)

- **`AN2023` Analytic 2023** · PRE
  Monitor for queried domain name system (DNS) registry data that may compromise third-party DNS servers that can be used during targeting. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
Monitor for logged domain name system (DNS) registry data that may compromise third-party DNS servers that can be used during targeting. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
  - *Log sources:* `Domain Name`; `Domain Name`

---

### T1584.003 — Virtual Private Server
<a id="t1584003"></a>

**Detection strategy:** Detection of Virtual Private Server (`DET0854`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.003](https://attack.mitre.org/techniques/T1584/003/) · [detail page](../../techniques/resource-development.md#t1584003)

- **`AN1986` Analytic 1986** · PRE
  Once adversaries have provisioned software on a compromised VPS (ex: for use as a command and control server), internet scans may reveal VPSs that adversaries have compromised. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS negotiation features, or other response artifacts associated with adversary C2 software.

Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
  - *Log sources:* `Internet Scan`; `Internet Scan`

---

### T1584.004 — Server
<a id="t1584004"></a>

**Detection strategy:** Detection of Server (`DET0874`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.004](https://attack.mitre.org/techniques/T1584/004/) · [detail page](../../techniques/resource-development.md#t1584004)

- **`AN2006` Analytic 2006** · PRE
  Once adversaries have provisioned software on a compromised server (ex: for use as a command and control server), internet scans may reveal servers that adversaries have compromised. Consider looking for identifiable patterns such as services listening, certificates in use, SSL/TLS negotiation features, or other response artifacts associated with adversary C2 software.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control.
  - *Log sources:* `Internet Scan`; `Internet Scan`

---

### T1584.005 — Botnet
<a id="t1584005"></a>

**Detection strategy:** Detection of Botnet (`DET0883`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.005](https://attack.mitre.org/techniques/T1584/005/) · [detail page](../../techniques/resource-development.md#t1584005)

- **`AN2015` Analytic 2015** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Phishing, Endpoint Denial of Service, or Network Denial of Service.

---

### T1584.006 — Web Services
<a id="t1584006"></a>

**Detection strategy:** Detection of Web Services (`DET0882`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.006](https://attack.mitre.org/techniques/T1584/006/) · [detail page](../../techniques/resource-development.md#t1584006)

- **`AN2014` Analytic 2014** · PRE
  Once adversaries leverage the abused web service as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control Web Service or Exfiltration Over Web Service .
  - *Log sources:* `Internet Scan`

---

### T1584.007 — Serverless
<a id="t1584007"></a>

**Detection strategy:** Detection of Serverless (`DET0864`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.007](https://attack.mitre.org/techniques/T1584/007/) · [detail page](../../techniques/resource-development.md#t1584007)

- **`AN1996` Analytic 1996** · PRE
  Once adversaries leverage serverless functions as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle.
  - *Log sources:* `Internet Scan`

---

### T1584.008 — Network Devices
<a id="t1584008"></a>

**Detection strategy:** Detection of Network Devices (`DET0859`)  
**Platforms:** PRE  
**ATT&CK:** [T1584.008](https://attack.mitre.org/techniques/T1584/008/) · [detail page](../../techniques/resource-development.md#t1584008)

- **`AN1991` Analytic 1991** · PRE
  Once adversaries leverage compromised network devices as infrastructure (ex: for command and control), it may be possible to look for unique characteristics associated with adversary software, if known. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle.
  - *Log sources:* `Internet Scan`

---

### T1585 — Establish Accounts
<a id="t1585"></a>

**Detection strategy:** Detection of Establish Accounts (`DET0873`)  
**Platforms:** PRE  
**ATT&CK:** [T1585](https://attack.mitre.org/techniques/T1585/) · [detail page](../../techniques/resource-development.md#t1585)

- **`AN2005` Analytic 2005** · PRE
  Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).
Consider monitoring social media activity related to your organization. Suspicious activity may include personas claiming to work for your organization or recently created/modified accounts making numerous connection requests to accoun
  - *Log sources:* `Network Traffic`; `Persona`

---

### T1585.001 — Social Media Accounts
<a id="t1585001"></a>

**Detection strategy:** Detection of Social Media Accounts (`DET0851`)  
**Platforms:** PRE  
**ATT&CK:** [T1585.001](https://attack.mitre.org/techniques/T1585/001/) · [detail page](../../techniques/resource-development.md#t1585001)

- **`AN1983` Analytic 1983** · PRE
  Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring and command line to detect anomalous processes execution and command line arguments associated to traffic patterns (e.g. monitor anomalies in use of files that do not normally initiate connections for respective protocol(s)).
Consider monitoring social media activity related to your organization. Suspicious activity may include personas claiming to work for your organization or recently created/modified accounts making numerous connection requests to accoun
  - *Log sources:* `Network Traffic`; `Persona`

---

### T1585.002 — Email Accounts
<a id="t1585002"></a>

**Detection strategy:** Detection of Email Accounts (`DET0835`)  
**Platforms:** PRE  
**ATT&CK:** [T1585.002](https://attack.mitre.org/techniques/T1585/002/) · [detail page](../../techniques/resource-development.md#t1585002)

- **`AN1967` Analytic 1967** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access (ex: Phishing).

---

### T1585.003 — Cloud Accounts
<a id="t1585003"></a>

**Detection strategy:** Detection of Cloud Accounts (`DET0846`)  
**Platforms:** PRE  
**ATT&CK:** [T1585.003](https://attack.mitre.org/techniques/T1585/003/) · [detail page](../../techniques/resource-development.md#t1585003)

- **`AN1978` Analytic 1978** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during exfiltration (ex: Transfer Data to Cloud Account).

---

### T1586 — Compromise Accounts
<a id="t1586"></a>

**Detection strategy:** Detection of Compromise Accounts (`DET0876`)  
**Platforms:** PRE  
**ATT&CK:** [T1586](https://attack.mitre.org/techniques/T1586/) · [detail page](../../techniques/resource-development.md#t1586)

- **`AN2008` Analytic 2008** · PRE
  Consider monitoring social media activity related to your organization. Suspicious activity may include personas claiming to work for your organization or recently modified accounts making numerous connection requests to accounts affiliated with your organization.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access (ex: Phishing).
Monitor and analyze traffic patterns and packet inspection associated to protocol(s) that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous synta
  - *Log sources:* `Persona`; `Network Traffic`

---

### T1586.001 — Social Media Accounts
<a id="t1586001"></a>

**Detection strategy:** Detection of Social Media Accounts (`DET0870`)  
**Platforms:** PRE  
**ATT&CK:** [T1586.001](https://attack.mitre.org/techniques/T1586/001/) · [detail page](../../techniques/resource-development.md#t1586001)

- **`AN2002` Analytic 2002** · PRE
  Consider monitoring social media activity related to your organization. Suspicious activity may include personas claiming to work for your organization or recently modified accounts making numerous connection requests to accounts affiliated with your organization.
Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access (ex: Spearphishing via Service).
Monitor and analyze traffic patterns and packet inspection associated to protocol(s), leveraging SSL/TLS inspection for encrypted traffic, that do not follow the expected protocol standards and traffic flows (e.g extraneous packets that do not belong to established flows, gratuitous or anomalous traffic patterns, anomalous syntax, or structure). Consider correlation with process monitoring 
  - *Log sources:* `Persona`; `Network Traffic`

---

### T1586.002 — Email Accounts
<a id="t1586002"></a>

**Detection strategy:** Detection of Email Accounts (`DET0861`)  
**Platforms:** PRE  
**ATT&CK:** [T1586.002](https://attack.mitre.org/techniques/T1586/002/) · [detail page](../../techniques/resource-development.md#t1586002)

- **`AN1993` Analytic 1993** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access (ex: Phishing).

---

### T1586.003 — Cloud Accounts
<a id="t1586003"></a>

**Detection strategy:** Detection of Cloud Accounts (`DET0879`)  
**Platforms:** PRE  
**ATT&CK:** [T1586.003](https://attack.mitre.org/techniques/T1586/003/) · [detail page](../../techniques/resource-development.md#t1586003)

- **`AN2011` Analytic 2011** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during exfiltration (ex: Transfer Data to Cloud Account).

---

### T1587 — Develop Capabilities
<a id="t1587"></a>

**Detection strategy:** Detection of Develop Capabilities (`DET0853`)  
**Platforms:** PRE  
**ATT&CK:** [T1587](https://attack.mitre.org/techniques/T1587/) · [detail page](../../techniques/resource-development.md#t1587)

- **`AN1985` Analytic 1985** · PRE
  Consider analyzing malware for features that may be associated with the adversary and/or their developers, such as compiler used, debugging artifacts, or code similarities. Malware repositories can also be used to identify additional samples associated with the adversary and identify development patterns over time. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Defense Evasion or Command and Control.
Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. Much of this activity will take place outside the
  - *Log sources:* `Malware Repository`; `Malware Repository`; `Internet Scan`

---

### T1587.001 — Malware
<a id="t1587001"></a>

**Detection strategy:** Detection of Malware (`DET0872`)  
**Platforms:** PRE  
**ATT&CK:** [T1587.001](https://attack.mitre.org/techniques/T1587/001/) · [detail page](../../techniques/resource-development.md#t1587001)

- **`AN2004` Analytic 2004** · PRE
  Consider analyzing malware for features that may be associated with the adversary and/or their developers, such as compiler used, debugging artifacts, or code similarities. Malware repositories can also be used to identify additional samples associated with the adversary and identify development patterns over time.
Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on post-compromise phases of the adversary lifecycle.
  - *Log sources:* `Malware Repository`; `Malware Repository`

---

### T1587.002 — Code Signing Certificates
<a id="t1587002"></a>

**Detection strategy:** Detection of Code Signing Certificates (`DET0833`)  
**Platforms:** PRE  
**ATT&CK:** [T1587.002](https://attack.mitre.org/techniques/T1587/002/) · [detail page](../../techniques/resource-development.md#t1587002)

- **`AN1965` Analytic 1965** · PRE
  Consider analyzing self-signed code signing certificates for features that may be associated with the adversary and/or their developers, such as the thumbprint, algorithm used, validity period, and common name. Malware repositories can also be used to identify additional samples associated with the adversary and identify patterns an adversary has used in crafting self-signed code signing certificates.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related follow-on behavior, such as Code Signing or Install Root Certificate.
  - *Log sources:* `Malware Repository`

---

### T1587.003 — Digital Certificates
<a id="t1587003"></a>

**Detection strategy:** Detection of Digital Certificates (`DET0844`)  
**Platforms:** PRE  
**ATT&CK:** [T1587.003](https://attack.mitre.org/techniques/T1587/003/) · [detail page](../../techniques/resource-development.md#t1587003)

- **`AN1976` Analytic 1976** · PRE
  Consider use of services that may aid in the tracking of certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure.
Detection efforts may be focused on related behaviors, such as Web Protocols , Asymmetric Cryptography , and/or Install Root Certificate .
  - *Log sources:* `Internet Scan`

---

### T1587.004 — Exploits
<a id="t1587004"></a>

**Detection strategy:** Detection of Exploits (`DET0894`)  
**Platforms:** PRE  
**ATT&CK:** [T1587.004](https://attack.mitre.org/techniques/T1587/004/) · [detail page](../../techniques/resource-development.md#t1587004)

- **`AN2026` Analytic 2026** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on behaviors relating to the use of exploits (i.e. Exploit Public-Facing Application, Exploitation for Client Execution, Exploitation for Privilege Escalation, Exploitation for Defense Evasion, Exploitation for Credential Access, Exploitation of Remote Services, and Application or System Exploitation).

---

### T1588 — Obtain Capabilities
<a id="t1588"></a>

**Detection strategy:** Detection of Obtain Capabilities (`DET0850`)  
**Platforms:** PRE  
**ATT&CK:** [T1588](https://attack.mitre.org/techniques/T1588/) · [detail page](../../techniques/resource-development.md#t1588)

- **`AN1982` Analytic 1982** · PRE
  Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure. Some server-side components of adversary tools may have default values set for SSL/TLS certificates. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Defense Evasion or Command and Control.
Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration informatio
  - *Log sources:* `Certificate`; `Malware Repository`; `Internet Scan`; `Malware Repository`

---

### T1588.001 — Malware
<a id="t1588001"></a>

**Detection strategy:** Detection of Malware (`DET0845`)  
**Platforms:** PRE  
**ATT&CK:** [T1588.001](https://attack.mitre.org/techniques/T1588/001/) · [detail page](../../techniques/resource-development.md#t1588001)

- **`AN1977` Analytic 1977** · PRE
  Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on post-compromise phases of the adversary lifecycle.
Consider analyzing malware for features that may be associated with malware providers, such as compiler used, debugging artifacts, code similarities, or even group identifiers associated with specific MaaS offerings. Malware repositories can also be used to identify additional samples associated with the developers and the adversary utilizing their services. Identifying overlaps in malware use by different adv
  - *Log sources:* `Malware Repository`; `Malware Repository`

---

### T1588.002 — Tool
<a id="t1588002"></a>

**Detection strategy:** Detection of Tool (`DET0852`)  
**Platforms:** PRE  
**ATT&CK:** [T1588.002](https://attack.mitre.org/techniques/T1588/002/) · [detail page](../../techniques/resource-development.md#t1588002)

- **`AN1984` Analytic 1984** · PRE
  Monitor for contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information. In some cases, malware repositories can also be used to identify features of tool use associated with an adversary, such as watermarks in Cobalt Strike payloads.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on post-compromise phases of the adversary lifecycle.
  - *Log sources:* `Malware Repository`

---

### T1588.003 — Code Signing Certificates
<a id="t1588003"></a>

**Detection strategy:** Detection of Code Signing Certificates (`DET0875`)  
**Platforms:** PRE  
**ATT&CK:** [T1588.003](https://attack.mitre.org/techniques/T1588/003/) · [detail page](../../techniques/resource-development.md#t1588003)

- **`AN2007` Analytic 2007** · PRE
  Consider analyzing code signing certificates for features that may be associated with the adversary and/or their developers, such as the thumbprint, algorithm used, validity period, common name, and certificate authority. Malware repositories can also be used to identify additional samples associated with the adversary and identify patterns an adversary has used in procuring code signing certificates.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related follow-on behavior, such as Code Signing or Install Root Certificate.
  - *Log sources:* `Malware Repository`

---

### T1588.004 — Digital Certificates
<a id="t1588004"></a>

**Detection strategy:** Detection of Digital Certificates (`DET0848`)  
**Platforms:** PRE  
**ATT&CK:** [T1588.004](https://attack.mitre.org/techniques/T1588/004/) · [detail page](../../techniques/resource-development.md#t1588004)

- **`AN1980` Analytic 1980** · PRE
  Consider use of services that may aid in the tracking of newly issued certificates and/or certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure. Some server-side components of adversary tools may have default values set for SSL/TLS certificates.
Monitor for logged network traffic in response to a scan showing both protocol header and body values that may buy and/or steal SSL/TLS certificates that can be used during targeting. Detection efforts may be focused on related behaviors, such as Web Protocols, Asymmetric Cryptography, and/or Install Root Certificate.
  - *Log sources:* `Certificate`; `Internet Scan`

---

### T1588.005 — Exploits
<a id="t1588005"></a>

**Detection strategy:** Detection of Exploits (`DET0827`)  
**Platforms:** PRE  
**ATT&CK:** [T1588.005](https://attack.mitre.org/techniques/T1588/005/) · [detail page](../../techniques/resource-development.md#t1588005)

- **`AN1959` Analytic 1959** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on behaviors relating to the use of exploits (i.e. Exploit Public-Facing Application, Exploitation for Client Execution, Exploitation for Privilege Escalation, Exploitation for Defense Evasion, Exploitation for Credential Access, Exploitation of Remote Services, and Application or System Exploitation).

---

### T1588.006 — Vulnerabilities
<a id="t1588006"></a>

**Detection strategy:** Detection of Vulnerabilities (`DET0808`)  
**Platforms:** PRE  
**ATT&CK:** [T1588.006](https://attack.mitre.org/techniques/T1588/006/) · [detail page](../../techniques/resource-development.md#t1588006)

- **`AN1940` Analytic 1940** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on behaviors relating to the potential use of exploits for vulnerabilities (i.e. Exploit Public-Facing Application, Exploitation for Client Execution, Exploitation for Privilege Escalation, Exploitation for Defense Evasion, Exploitation for Credential Access, Exploitation of Remote Services, and Application or System Exploitation).

---

### T1588.007 — Artificial Intelligence
<a id="t1588007"></a>

**Detection strategy:** Detection of Artificial Intelligence (`DET0842`)  
**Platforms:** PRE  
**ATT&CK:** [T1588.007](https://attack.mitre.org/techniques/T1588/007/) · [detail page](../../techniques/resource-development.md#t1588007)

- **`AN1974` Analytic 1974** · PRE
  Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on behaviors relating to the potential use of generative artificial intelligence (i.e. Phishing, Phishing for Information).

---

### T1608 — Stage Capabilities
<a id="t1608"></a>

**Detection strategy:** Detection of Stage Capabilities (`DET0839`)  
**Platforms:** PRE  
**ATT&CK:** [T1608](https://attack.mitre.org/techniques/T1608/) · [detail page](../../techniques/resource-development.md#t1608)

- **`AN1971` Analytic 1971** · PRE
  If infrastructure or patterns in malware, tooling, certificates, or malicious web content have been previously identified, internet scanning may uncover when an adversary has staged their capabilities.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as initial access and post-compromise behaviors.
  - *Log sources:* `Internet Scan`

---

### T1608.001 — Upload Malware
<a id="t1608001"></a>

**Detection strategy:** Detection of Upload Malware (`DET0824`)  
**Platforms:** PRE  
**ATT&CK:** [T1608.001](https://attack.mitre.org/techniques/T1608/001/) · [detail page](../../techniques/resource-development.md#t1608001)

- **`AN1956` Analytic 1956** · PRE
  If infrastructure or patterns in malware have been previously identified, internet scanning may uncover when an adversary has staged malware to make it accessible for targeting.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on post-compromise phases of the adversary lifecycle, such as User Execution or Ingress Tool Transfer .
  - *Log sources:* `Internet Scan`

---

### T1608.002 — Upload Tool
<a id="t1608002"></a>

**Detection strategy:** Detection of Upload Tool (`DET0834`)  
**Platforms:** PRE  
**ATT&CK:** [T1608.002](https://attack.mitre.org/techniques/T1608/002/) · [detail page](../../techniques/resource-development.md#t1608002)

- **`AN1966` Analytic 1966** · PRE
  If infrastructure or patterns in tooling have been previously identified, internet scanning may uncover when an adversary has staged tools to make them accessible for targeting.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on post-compromise phases of the adversary lifecycle, such as Ingress Tool Transfer.
  - *Log sources:* `Internet Scan`

---

### T1608.003 — Install Digital Certificate
<a id="t1608003"></a>

**Detection strategy:** Detection of Install Digital Certificate (`DET0840`)  
**Platforms:** PRE  
**ATT&CK:** [T1608.003](https://attack.mitre.org/techniques/T1608/003/) · [detail page](../../techniques/resource-development.md#t1608003)

- **`AN1972` Analytic 1972** · PRE
  Consider use of services that may aid in the tracking of certificates in use on sites across the Internet. In some cases it may be possible to pivot on known pieces of certificate information to uncover other adversary infrastructure.
Detection efforts may be focused on related behaviors, such as Web Protocols or Asymmetric Cryptography.
  - *Log sources:* `Internet Scan`

---

### T1608.004 — Drive-by Target
<a id="t1608004"></a>

**Detection strategy:** Detection of Drive-by Target (`DET0825`)  
**Platforms:** PRE  
**ATT&CK:** [T1608.004](https://attack.mitre.org/techniques/T1608/004/) · [detail page](../../techniques/resource-development.md#t1608004)

- **`AN1957` Analytic 1957** · PRE
  If infrastructure or patterns in the malicious web content utilized to deliver a Drive-by Compromise have been previously identified, internet scanning may uncover when an adversary has staged web content for use in a strategic web compromise.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on other phases of the adversary lifecycle, such as Drive-by Compromise or Exploitation for Client Execution.
  - *Log sources:* `Internet Scan`

---

### T1608.005 — Link Target
<a id="t1608005"></a>

**Detection strategy:** Detection of Link Target (`DET0893`)  
**Platforms:** PRE  
**ATT&CK:** [T1608.005](https://attack.mitre.org/techniques/T1608/005/) · [detail page](../../techniques/resource-development.md#t1608005)

- **`AN2025` Analytic 2025** · PRE
  If infrastructure or patterns in malicious web content have been previously identified, internet scanning may uncover when an adversary has staged web content to make it accessible for targeting.
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on other phases of the adversary lifecycle, such as during Spearphishing Link , Spearphishing Link , or Malicious Link .
  - *Log sources:* `Internet Scan`

---

### T1608.006 — SEO Poisoning
<a id="t1608006"></a>

**Detection strategy:** Detection of SEO Poisoning (`DET0881`)  
**Platforms:** PRE  
**ATT&CK:** [T1608.006](https://attack.mitre.org/techniques/T1608/006/) · [detail page](../../techniques/resource-development.md#t1608006)

- **`AN2013` Analytic 2013** · PRE
  If infrastructure or patterns in the malicious web content related to SEO poisoning or Drive-by Target have been previously identified, internet scanning may uncover when an adversary has staged web content supporting a strategic web compromise. Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on other phases of the adversary lifecycle, such as Drive-by Compromise or Exploitation for Client Execution.
  - *Log sources:* `Internet Scan`

---

### T1650 — Acquire Access
<a id="t1650"></a>

**Detection strategy:** Detection of Acquire Access (`DET0884`)  
**Platforms:** PRE  
**ATT&CK:** [T1650](https://attack.mitre.org/techniques/T1650/) · [detail page](../../techniques/resource-development.md#t1650)

- **`AN2016` Analytic 2016** · PRE
  Much of this takes place outside the visibility of the target organization, making detection difficult for defenders. 

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.

---

