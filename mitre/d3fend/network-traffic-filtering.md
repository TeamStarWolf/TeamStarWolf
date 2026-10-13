# D3FEND: Network Traffic Filtering

<a id="network-traffic-filtering"></a>

D3FEND tactic: Isolate  
Digital artifacts: Network Traffic, OT Protocol Message  

Restricting network traffic originating from any location.

## ATT&CK techniques countered (116)

- [T0800: Activate Firmware Update Mode](https://attack.mitre.org/techniques/T0800): filters
- [T0801: Monitor Process State](https://attack.mitre.org/techniques/T0801): filters
- [T0802: Automated Collection](https://attack.mitre.org/techniques/T0802): filters
- [T0806: Brute Force I/O](https://attack.mitre.org/techniques/T0806): filters
- [T0809: Data Destruction](https://attack.mitre.org/techniques/T0809): filters
- [T0811: Data from Information Repositories](https://attack.mitre.org/techniques/T0811): filters
- [T0814: Denial of Service](https://attack.mitre.org/techniques/T0814): filters
- [T0817: Drive-by Compromise](https://attack.mitre.org/techniques/T0817): filters
- [T0819: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T0819): filters
- [T0821: Modify Controller Tasking](https://attack.mitre.org/techniques/T0821): filters
- [T0822: External Remote Services](https://attack.mitre.org/techniques/T0822): filters
- [T0830: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T0830): filters
- [T0835: Manipulate I/O Image](https://attack.mitre.org/techniques/T0835): filters
- [T0836: Modify Parameter](https://attack.mitre.org/techniques/T0836): filters
- [T0838: Modify Alarm Settings](https://attack.mitre.org/techniques/T0838): filters
- [T0840: Network Connection Enumeration](https://attack.mitre.org/techniques/T0840): filters
- [T0842: Network Sniffing](https://attack.mitre.org/techniques/T0842): filters
- [T0843: Program Download](https://attack.mitre.org/techniques/T0843): filters
- [T0845: Program Upload](https://attack.mitre.org/techniques/T0845): filters
- [T0846: Remote System Discovery](https://attack.mitre.org/techniques/T0846): filters
- [T0848: Rogue Master](https://attack.mitre.org/techniques/T0848): filters
- [T0858: Change Operating Mode](https://attack.mitre.org/techniques/T0858): filters
- [T0861: Point & Tag Identification](https://attack.mitre.org/techniques/T0861): filters
- [T0865: Spearphishing Attachment](https://attack.mitre.org/techniques/T0865): filters
- [T0866: Exploitation of Remote Services](https://attack.mitre.org/techniques/T0866): filters
- [T0868: Detect Operating Mode](https://attack.mitre.org/techniques/T0868): filters
- [T0869: Standard Application Layer Protocol](https://attack.mitre.org/techniques/T0869): filters
- [T0873: Project File Infection](https://attack.mitre.org/techniques/T0873): filters
- [T0877: I/O Image](https://attack.mitre.org/techniques/T0877): filters
- [T0878: Alarm Suppression](https://attack.mitre.org/techniques/T0878): filters
- [T0884: Connection Proxy](https://attack.mitre.org/techniques/T0884): filters
- [T0885: Commonly Used Port](https://attack.mitre.org/techniques/T0885): filters
- [T0886: Remote Services](https://attack.mitre.org/techniques/T0886): filters
- [T0888: Remote System Information Discovery](https://attack.mitre.org/techniques/T0888): filters
- [T0889: Modify Program](https://attack.mitre.org/techniques/T0889): filters
- [T0893: Data from Local System](https://attack.mitre.org/techniques/T0893): filters
- [T0894: System Binary Proxy Execution](https://attack.mitre.org/techniques/T0894): filters
- [T0895: Autorun Image](https://attack.mitre.org/techniques/T0895): filters
- [T1001: Data Obfuscation](/mitre/techniques/T1001.md): filters. Adversaries may obfuscate command and control traffic to make it more difficult to detect.
- [T1003.006: DCSync](/mitre/techniques/T1003-006.md): filters. Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync.
- [T1008: Fallback Channels](/mitre/techniques/T1008.md): filters. Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.
- [T1011: Exfiltration Over Other Network Medium](/mitre/techniques/T1011.md): filters. Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel.
- [T1018: Remote System Discovery](/mitre/techniques/T1018.md): filters. Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.
- [T1020: Automated Exfiltration](/mitre/techniques/T1020.md): filters. Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.
- [T1021: Remote Services](/mitre/techniques/T1021.md): filters. Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service that accepts remote connections, such as telnet, SSH, and VNC.
- [T1021.001: Remote Desktop Protocol](/mitre/techniques/T1021-001.md): filters. Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP).
- [T1021.004: SSH](/mitre/techniques/T1021-004.md): filters. Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into remote machines using Secure Shell (SSH).
- [T1029: Scheduled Transfer](/mitre/techniques/T1029.md): filters. Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals.
- [T1030: Data Transfer Size Limits](/mitre/techniques/T1030.md): filters. An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds.
- [T1041: Exfiltration Over C2 Channel](/mitre/techniques/T1041.md): filters. Adversaries may steal data by exfiltrating it over an existing command and control channel.
- [T1047: Windows Management Instrumentation](/mitre/techniques/T1047.md): filters. Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.
- [T1048: Exfiltration Over Alternative Protocol](/mitre/techniques/T1048.md): filters. Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.
- [T1048.001: Exfiltration Over Symmetric Encrypted Non-C2 Protocol](/mitre/techniques/T1048-001.md): filters. Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel.
- [T1048.002: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol](/mitre/techniques/T1048-002.md): filters. Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel.
- [T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol](/mitre/techniques/T1048-003.md): filters. Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.
- [T1071: Application Layer Protocol](/mitre/techniques/T1071.md): filters. Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.
- [T1071.001: Web Protocols](/mitre/techniques/T1071-001.md): filters. Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- [T1071.002: File Transfer Protocols](/mitre/techniques/T1071-002.md): filters. Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic.
- [T1071.003: Mail Protocols](/mitre/techniques/T1071-003.md): filters. Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic.
- [T1071.004: DNS](/mitre/techniques/T1071-004.md): filters. Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic.
- [T1090.001: Internal Proxy](/mitre/techniques/T1090-001.md): filters. Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment.
- [T1090.002: External Proxy](/mitre/techniques/T1090-002.md): filters. Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure.
- [T1090.003: Multi-hop Proxy](/mitre/techniques/T1090-003.md): filters. Adversaries may chain together multiple proxies to disguise the source of malicious traffic.
- [T1090.004: Domain Fronting](/mitre/techniques/T1090-004.md): filters. Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS.
- [T1095: Non-Application Layer Protocol](/mitre/techniques/T1095.md): filters. Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network.
- [T1098.001: Additional Cloud Credentials](/mitre/techniques/T1098-001.md): filters. Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.
- [T1102: Web Service](/mitre/techniques/T1102.md): filters. Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system.
- [T1104: Multi-Stage Channels](/mitre/techniques/T1104.md): filters. Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions.
- [T1105: Ingress Tool Transfer](/mitre/techniques/T1105.md): filters. Adversaries may transfer tools or other files from an external system into a compromised environment.
- [T1110.003: Password Spraying](/mitre/techniques/T1110-003.md): filters. Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials.
- [T1110.004: Credential Stuffing](/mitre/techniques/T1110-004.md): filters. Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap.
- [T1132: Data Encoding](/mitre/techniques/T1132.md): filters. Adversaries may encode data to make the content of command and control traffic more difficult to detect.
- [T1185: Browser Session Hijacking](/mitre/techniques/T1185.md): filters. Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.
- [T1189: Drive-by Compromise](/mitre/techniques/T1189.md): filters. Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.
- [T1190: Exploit Public-Facing Application](/mitre/techniques/T1190.md): filters. Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.
- [T1197: BITS Jobs](/mitre/techniques/T1197.md): filters. Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks.
- [T1199: Trusted Relationship](/mitre/techniques/T1199.md): filters. Adversaries may breach or otherwise leverage organizations who have access to intended victims.
- [T1204.001: Malicious Link](/mitre/techniques/T1204-001.md): filters. An adversary may rely upon a user clicking a malicious link in order to gain execution.
- [T1205: Traffic Signaling](/mitre/techniques/T1205.md): filters. Adversaries may use traffic signaling to hide open ports or other malicious functionality used for persistence or command and control.
- [T1205.001: Port Knocking](/mitre/techniques/T1205-001.md): filters. Adversaries may use port knocking to hide open ports used for persistence or command and control.
- [T1207: Rogue Domain Controller](/mitre/techniques/T1207.md): filters. Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.
- [T1210: Exploitation of Remote Services](/mitre/techniques/T1210.md): filters. Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network.
- [T1218.003: CMSTP](/mitre/techniques/T1218-003.md): filters. Adversaries may abuse CMSTP to proxy execution of malicious code.
- [T1219: Remote Access Tools](/mitre/techniques/T1219.md): filters. An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network.
- [T1498.001: Direct Network Flood](/mitre/techniques/T1498-001.md): filters. Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.
- [T1498.002: Reflection Amplification](/mitre/techniques/T1498-002.md): filters. Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target.
- [T1499.002: Service Exhaustion Flood](/mitre/techniques/T1499-002.md): filters. Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).
- [T1542.005: TFTP Boot](/mitre/techniques/T1542-005.md): filters. Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server.
- [T1546.003: Windows Management Instrumentation Event Subscription](/mitre/techniques/T1546-003.md): filters. Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription.
- [T1546.008: Accessibility Features](/mitre/techniques/T1546-008.md): filters. Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features.
- [T1550.001: Application Access Token](/mitre/techniques/T1550-001.md): filters. Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems.
- [T1550.004: Web Session Cookie](/mitre/techniques/T1550-004.md): filters. Adversaries can use stolen session cookies to authenticate to web applications and services.
- [T1557: Adversary-in-the-Middle](/mitre/techniques/T1557.md): filters. Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or replay attacks ([Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)).
- [T1557.001: Name Resolution Poisoning and SMB Relay](/mitre/techniques/T1557-001.md): filters. By responding to LLMNR/NBT-NS/mDNS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system.
- [T1557.003: DHCP Spoofing](/mitre/techniques/T1557-003.md): filters. Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network.
- [T1558.003: Kerberoasting](/mitre/techniques/T1558-003.md): filters. Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110).
- [T1563: Remote Service Session Hijacking](/mitre/techniques/T1563.md): filters. Adversaries may take control of preexisting sessions with remote services to move laterally in an environment.
- [T1565.002: Transmitted Data Manipulation](/mitre/techniques/T1565-002.md): filters. Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data.
- [T1566.001: Spearphishing Attachment](/mitre/techniques/T1566-001.md): filters. Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.
- [T1566.002: Spearphishing Link](/mitre/techniques/T1566-002.md): filters. Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems.
- [T1567: Exfiltration Over Web Service](/mitre/techniques/T1567.md): filters. Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel.
- [T1567.001: Exfiltration to Code Repository](/mitre/techniques/T1567-001.md): filters. Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel.
- [T1567.002: Exfiltration to Cloud Storage](/mitre/techniques/T1567-002.md): filters. Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel.
- [T1568: Dynamic Resolution](/mitre/techniques/T1568.md): filters. Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.
- [T1570: Lateral Tool Transfer](/mitre/techniques/T1570.md): filters. Adversaries may transfer tools or other files between systems in a compromised environment.
- [T1571: Non-Standard Port](/mitre/techniques/T1571.md): filters. Adversaries may communicate using a protocol and port pairing that are typically not associated.
- [T1572: Protocol Tunneling](/mitre/techniques/T1572.md): filters. Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems.
- [T1573: Encrypted Channel](/mitre/techniques/T1573.md): filters. Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1573.001: Symmetric Cryptography](/mitre/techniques/T1573-001.md): filters. Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1573.002: Asymmetric Cryptography](/mitre/techniques/T1573-002.md): filters. Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol.
- [T1691.001: Command Message](https://attack.mitre.org/techniques/T1691/001): filters (D3FEND maps the revoked predecessor T0803)
- [T1692.001: Command Message](https://attack.mitre.org/techniques/T1692/001): filters (D3FEND maps the revoked predecessor T0855)
- [T1692.002: Reporting Message](https://attack.mitre.org/techniques/T1692/002): filters (D3FEND maps the revoked predecessor T0856)
- [T1693.001: System Firmware](https://attack.mitre.org/techniques/T1693/001): filters (D3FEND maps the revoked predecessor T0857)
- [T1693.002: Module Firmware](https://attack.mitre.org/techniques/T1693/002): filters (D3FEND maps the revoked predecessor T0839)
- [T1695.001: Serial COM](https://attack.mitre.org/techniques/T1695/001): filters (D3FEND maps the revoked predecessor T0805)

---

*Source: MITRE ATT&CK®, D3FEND™, CAPEC™, and ATLAS™, which are trademarks of The MITRE Corporation. Independent reference summary; consult the upstream projects for authoritative content.*
