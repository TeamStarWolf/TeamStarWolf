# Reconnaissance: Technique Detail

> Full detail pages for the 46 ATT&CK techniques whose primary tactic is [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1589: Gather Victim Identity Information
<a id="t1589"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1589)  

Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question responses, etc.) as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations. Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about users could also be enumerated via other active means (i.e. [Active Scanning](https://attack.mitre.org/techniques/T1595)) such as probing and analyzing responses from authentication services that may reveal valid usernames in a system or permitted MFA /methods associated with those usernames. Information about victims may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Gather Victim Identity Information  
Used by 10 threat groups: [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052), [G1055 VOID MANTICORE](https://attack.mitre.org/groups/G1055)  

---

### T1589.001: Credentials
<a id="t1589001"></a>

sub-technique of [T1589](/techniques/reconnaissance.md#t1589), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1589/001)  

Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts. Adversaries may gather credentials from potential victims in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then add malicious content designed to collect website authentication cookies from visitors. Where multi-factor authentication (MFA) based on out-of-band communications is in use, adversaries may compromise a service provider to gain access to MFA codes and one-time passwords (OTP). Credential information may also be exposed to adversaries via leaks to online or other accessible data sets (ex: [Search Engines](https://attack.mitre.org/techniques/T1593/002), breach dumps, code repositories, etc.). Adversaries may purchase credentials from dark web markets, such as Russian Market and 2easy, or through access to Telegram channels that distribute logs from infostealer malware. Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Credentials  
Used by 6 threat groups: [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1057 ShinyHunters](https://attack.mitre.org/groups/G1057)  

---

### T1589.002: Email Addresses
<a id="t1589002"></a>

sub-technique of [T1589](/techniques/reconnaissance.md#t1589), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1589/002)  

Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees. Adversaries may easily gather email addresses, since they may be readily available and exposed via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Email addresses could also be enumerated via more active means (i.e. [Active Scanning](https://attack.mitre.org/techniques/T1595)), such as probing and analyzing responses from authentication services that may reveal valid usernames in a system. For example, adversaries may be able to enumerate email addresses in Office 365 environments by querying a variety of publicly available API endpoints, such as autodiscover and GetCredentialType. Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Email Accounts](https://attack.mitre.org/techniques/T1586/002)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Brute Force](https://attack.mitre.org/techniques/T1110) via [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Email Addresses  
Used by 14 threat groups: [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036)  
Implemented by 1 software: [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1589.003: Employee Names
<a id="t1589003"></a>

sub-technique of [T1589](/techniques/reconnaissance.md#t1589), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1589/003)  

Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures. Adversaries may easily gather employee names, since they may be readily available and exposed via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Employee Names  
Used by 3 threat groups: [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122)  

---

### T1590: Gather Victim Network Information
<a id="t1590"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1590)  

Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations. Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about networks may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Gather Victim Network Information  
Used by 3 threat groups: [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1590.001: Domain Properties
<a id="t1590001"></a>

sub-technique of [T1590](/techniques/reconnaissance.md#t1590), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1590/001)  

Adversaries may gather information about the victim's network domain(s) that can be used during targeting. Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers. Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about victim domains and their properties may also be exposed to adversaries via online or other accessible data sets (ex: [WHOIS](https://attack.mitre.org/techniques/T1596/002)). Where third-party cloud providers are in use, this information may also be exposed through publicly available API endpoints, such as GetUserRealm and autodiscover in Office 365 environments. Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596), [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593), or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Domain Properties  
Used by 1 threat groups: [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034)  
Implemented by 1 software: [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1590.002: DNS
<a id="t1590002"></a>

sub-technique of [T1590](/techniques/reconnaissance.md#t1590), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1590/002)  

Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. DNS MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk. Adversaries may gather this information in various ways, such as querying or otherwise collecting details via [DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/001). DNS information may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596), [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593), or [Active Scanning](https://attack.mitre.org/techniques/T1595)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)). Adversaries may also use DNS zone transfer (DNS query type AXFR) to collect all records from a misconfigured DNS server.

ATT&CK mitigations (1): [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls (5): `AC-4`, `CM-6`, `CM-7`, `SC-32`, `SC-7`  
ATT&CK detection strategy: Detection of DNS  

---

### T1590.003: Network Trust Dependencies
<a id="t1590003"></a>

sub-technique of [T1590](/techniques/reconnaissance.md#t1590), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1590/003)  

Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about network trusts may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Network Trust Dependencies  

---

### T1590.004: Network Topology
<a id="t1590004"></a>

sub-technique of [T1590](/techniques/reconnaissance.md#t1590), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1590/004)  

Adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments. This information may also include specifics regarding network devices (gateways, routers, etc.) and other infrastructure. Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about network topologies may also be exposed to adversaries via online or other accessible data sets (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Network Topology  
Used by 4 threat groups: [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  

---

### T1590.005: IP Addresses
<a id="t1590005"></a>

sub-technique of [T1590](/techniques/reconnaissance.md#t1590), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1590/005)  

Adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety of details, such as which IP addresses are in use. IP addresses may also enable an adversary to derive other details about a victim, such as organizational size, physical location(s), Internet service provider, and or where/how their publicly-facing infrastructure is hosted. Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about assigned IP addresses may also be exposed to adversaries via online or other accessible data sets (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of IP Addresses  
Used by 3 threat groups: [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0138 Andariel](https://attack.mitre.org/groups/G0138)  

---

### T1590.006: Network Security Appliances
<a id="t1590006"></a>

sub-technique of [T1590](/techniques/reconnaissance.md#t1590), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1590/006)  

Adversaries may gather information about the victim's network security appliances that can be used during targeting. Information about network security appliances may include a variety of details, such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts. Adversaries may also target information about victim network-based intrusion detection systems (NIDS) or other appliances related to defensive cybersecurity operations. Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about network security appliances may also be exposed to adversaries via online or other accessible data sets (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Network Security Appliances  
Used by 1 threat groups: [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1591: Gather Victim Org Information
<a id="t1591"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1591)  

Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees. Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about an organization may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Gather Victim Org Information  
Used by 7 threat groups: [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1054 MirrorFace](https://attack.mitre.org/groups/G1054)  

---

### T1591.001: Determine Physical Locations
<a id="t1591001"></a>

sub-technique of [T1591](/techniques/reconnaissance.md#t1591), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1591/001)  

Adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within. Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Physical locations of a target organization may also be exposed to adversaries via online or other accessible data sets (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594) or [Social Media](https://attack.mitre.org/techniques/T1593/001)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566) or [Hardware Additions](https://attack.mitre.org/techniques/T1200)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Determine Physical Locations  
Used by 1 threat groups: [G0059 Magic Hound](https://attack.mitre.org/groups/G0059)  

---

### T1591.002: Business Relationships
<a id="t1591002"></a>

sub-technique of [T1591](/techniques/reconnaissance.md#t1591), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1591/002)  

Adversaries may gather information about the victim's business relationships that can be used during targeting. Information about an organization’s business relationships may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. This information may also reveal supply chains and shipment paths for the victim’s hardware and software resources. Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about business relationships may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195), [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Business Relationships  
Used by 3 threat groups: [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1591.003: Identify Business Tempo
<a id="t1591003"></a>

sub-technique of [T1591](/techniques/reconnaissance.md#t1591), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1591/003)  

Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim’s hardware and software resources. Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about business tempo may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199))

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Identify Business Tempo  

---

### T1591.004: Identify Roles
<a id="t1591004"></a>

sub-technique of [T1591](/techniques/reconnaissance.md#t1591), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1591/004)  

Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data/resources they have access to. Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about business roles may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Phishing](https://attack.mitre.org/techniques/T1566)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Identify Roles  
Used by 4 threat groups: [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1592: Gather Victim Host Information
<a id="t1592"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1592)  

Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.). Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors. Information about hosts may also be exposed to adversaries via online or other accessible data sets (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [External Remote Services](https://attack.mitre.org/techniques/T1133)). Adversaries may also gather victim host information via User-Agent HTTP headers, which are sent to a server to identify the application, operating system, vendor, and/or version of the requesting user agent. This can be used to inform the adversary’s follow-on action. For example, adversaries may check user agents for the requesting operating system, then only serve malware for target operating systems while ignoring others.

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Gather Victim Host Information  
Used by 1 threat groups: [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1592.001: Hardware
<a id="t1592001"></a>

sub-technique of [T1592](/techniques/reconnaissance.md#t1592), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1592/001)  

Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.). Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) (ex: hostnames, server banners, user agent strings) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors. Information about the hardware infrastructure may also be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Compromise Hardware Supply Chain](https://attack.mitre.org/techniques/T1195/003) or [Hardware Additions](https://attack.mitre.org/techniques/T1200)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Hardware  

---

### T1592.002: Software
<a id="t1592002"></a>

sub-technique of [T1592](/techniques/reconnaissance.md#t1592), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1592/002)  

Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: antivirus, SIEMs, etc.). Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) (ex: listening ports, server banners, user agent strings) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors. Information about the installed software may also be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Additionally, adversaries may analyze metadata from victim-owned files (e.g., PDFs, DOCs, images, and sound files hosted on victim-owned websites) to extract information about the software and hardware used to create or process those files. Metadata may reveal software versions, configurations, or timestamps that indicate outdated or vulnerable software. This information can be cross-referenced with known CVEs to identify potential vectors for exploitation in future operations. Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or for initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Software  
Used by 3 threat groups: [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0138 Andariel](https://attack.mitre.org/groups/G0138)  

---

### T1592.003: Firmware
<a id="t1592003"></a>

sub-technique of [T1592](/techniques/reconnaissance.md#t1592), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1592/003)  

Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment (ex: configuration, purpose, age/patch level, etc.). Adversaries may gather this information in various ways, such as direct elicitation via [Phishing for Information](https://attack.mitre.org/techniques/T1598). Information about host firmware may only be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Firmware  

---

### T1592.004: Client Configurations
<a id="t1592004"></a>

sub-technique of [T1592](/techniques/reconnaissance.md#t1592), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1592/004)  

Adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system/version, virtualization, architecture (ex: 32 or 64 bit), language, and/or time zone. Adversaries may gather this information in various ways, such as direct collection actions via [Active Scanning](https://attack.mitre.org/techniques/T1595) (ex: listening ports, server banners, user agent strings) or [Phishing for Information](https://attack.mitre.org/techniques/T1598). Adversaries may also compromise sites then include malicious content designed to collect host information from visitors. Information about the client configurations may also be exposed to adversaries via online or other accessible data sets (ex: job postings, network maps, assessment reports, resumes, or purchase invoices). Gathering this information may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) or [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Client Configurations  
Used by 1 threat groups: [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125)  

---

### T1593: Search Open Websites/Domains
<a id="t1593"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1593)  

Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts. Adversaries may search in different online sites depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Phishing](https://attack.mitre.org/techniques/T1566)).

ATT&CK mitigations (2): [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Search Open Websites/Domains  
Used by 6 threat groups: [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0099 APT-C-36](https://attack.mitre.org/groups/G0099), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1593.001: Social Media
<a id="t1593001"></a>

sub-technique of [T1593](/techniques/reconnaissance.md#t1593), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1593/001)  

Adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff. Adversaries may search in different social media sites depending on what information they seek to gather. Threat actors may passively harvest data from these sites, as well as use information gathered to create fake profiles/groups to elicit victim’s into revealing specific information (i.e. [Spearphishing Service](https://attack.mitre.org/techniques/T1598/001)). Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Social Media  
Used by 3 threat groups: [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1593.002: Search Engines
<a id="t1593002"></a>

sub-technique of [T1593](/techniques/reconnaissance.md#t1593), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1593/002)  

Adversaries may use search engines to collect information about victims that can be used during targeting. Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content (i.e. filetypes). Adversaries may craft various search engine queries depending on what information they seek to gather. Threat actors may use search engines to harvest general information about victims, as well as use specialized queries to look for spillages/leaks of sensitive information such as network details or credentials. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Valid Accounts](https://attack.mitre.org/techniques/T1078) or [Phishing](https://attack.mitre.org/techniques/T1566)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Search Engines  
Used by 1 threat groups: [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  

---

### T1593.003: Code Repositories
<a id="t1593003"></a>

sub-technique of [T1593](/techniques/reconnaissance.md#t1593), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1593/003)  

Adversaries may search public code repositories for information about victims that can be used during targeting. Victims may store code in repositories on various third-party websites such as GitHub, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git. Adversaries may search various public code repositories for various information about a victim. Public code repositories can often be a source of various general information about victims, such as commonly used programming languages and libraries as well as the names of employees. Adversaries may also identify more sensitive data, including accidentally leaked credentials or API keys. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Compromise Accounts](https://attack.mitre.org/techniques/T1586) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Valid Accounts](https://attack.mitre.org/techniques/T1078) or [Phishing](https://attack.mitre.org/techniques/T1566)). Note: This is distinct from [Code Repositories](https://attack.mitre.org/techniques/T1213/003), which focuses on [Collection](https://attack.mitre.org/tactics/TA0009) from private and internally hosted code repositories.

ATT&CK mitigations (2): [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
NIST 800-53 R5 controls (1): `CM-8`  
ATT&CK detection strategy: Detection of Code Repositories  
Used by 4 threat groups: [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052), [G1057 ShinyHunters](https://attack.mitre.org/groups/G1057)  
Implemented by 1 software: [S9008 Shai-Hulud](https://attack.mitre.org/software/S9008)  

---

### T1594: Search Victim-Owned Websites
<a id="t1594"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1594)  

Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: [Email Addresses](https://attack.mitre.org/techniques/T1589/002)). These sites may also have details highlighting business operations and relationships. Adversaries may search victim-owned websites to gather actionable information. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)), and/or initial access (ex: [Trusted Relationship](https://attack.mitre.org/techniques/T1199) or [Phishing](https://attack.mitre.org/techniques/T1566)). In addition to manually browsing the website, adversaries may attempt to identify hidden directories or files that could contain additional sensitive information or vulnerable functionality. They may do this through automated activities such as [Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003), as well as by leveraging files such as sitemap.xml and robots.txt.

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Search Victim-Owned Websites  
Used by 6 threat groups: [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1038 TA578](https://attack.mitre.org/groups/G1038)  

---

### T1595: Active Scanning
<a id="t1595"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1595)  

Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction. Adversaries may perform different forms of active scanning depending on what information they seek to gather. These scans can also be performed in various ways, including using native features of network protocols such as ICMP. Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Active Scanning  

---

### T1595.001: Scanning IP Blocks
<a id="t1595001"></a>

sub-technique of [T1595](/techniques/reconnaissance.md#t1595), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1595/001)  

Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Adversaries may scan IP blocks in order to [Gather Victim Network Information](https://attack.mitre.org/techniques/T1590), such as which IP addresses are actively in use as well as more detailed information about hosts assigned these addresses. Scans may range from simple pings (ICMP requests and responses) to more nuanced scans that may reveal host software/versions via server banners or other network artifacts. Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Scanning IP Blocks  
Used by 2 threat groups: [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  

---

### T1595.002: Vulnerability Scanning
<a id="t1595002"></a>

sub-technique of [T1595](/techniques/reconnaissance.md#t1595), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1595/002)  

Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific exploit the adversary may seek to use. These scans may also include more broad attempts to [Gather Victim Host Information](https://attack.mitre.org/techniques/T1592) that can be used to identify more commonly known, exploitable vulnerabilities. Vulnerability scans typically harvest running software and version numbers via server banners, listening ports, or other network artifacts. Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Vulnerability Scanning  
Used by 15 threat groups: [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1055 VOID MANTICORE](https://attack.mitre.org/groups/G1055), [G1057 ShinyHunters](https://attack.mitre.org/groups/G1057)  

---

### T1595.003: Wordlist Scanning
<a id="t1595003"></a>

sub-technique of [T1595](/techniques/reconnaissance.md#t1595), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1595/003)  

Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to [Brute Force](https://attack.mitre.org/techniques/T1110), its goal is the identification of content and infrastructure rather than the discovery of valid credentials. Wordlists used in these scans may contain generic, commonly used names and file extensions or terms specific to a particular software. Adversaries may also create custom, target-specific wordlists using data gathered from other Reconnaissance techniques (ex: [Gather Victim Org Information](https://attack.mitre.org/techniques/T1591), or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)). For example, adversaries may use web content discovery tools such as Dirb, DirBuster, and GoBuster and generic or custom wordlists to enumerate a website’s pages and directories. This can help them to discover old, vulnerable pages or hidden administrative portals that could become the target of further operations (ex: [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) or [Brute Force](https://attack.mitre.org/techniques/T1110)). As cloud storage solutions typically use globally unique names, adversaries may also use target-specific wordlists and tools such as s3recon and GCPBucketBrute to enumerate public and private buckets on cloud infrastructure. Once storage objects are discovered, adversaries may leverage [Data from Cloud Storage](https://attack.mitre.org/techniques/T1530) to access valuable information that can be exfiltrated or used to escalate privileges and move laterally.

ATT&CK mitigations (2): [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls (1): `SC-4`  
ATT&CK detection strategy: Detection of Wordlist Scanning  
Used by 2 threat groups: [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123)  

---

### T1596: Search Open Technical Databases
<a id="t1596"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1596)  

Adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans. Adversaries may search in different open databases depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Search Open Technical Databases  
Used by 2 threat groups: [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  

---

### T1596.001: DNS/Passive DNS
<a id="t1596001"></a>

sub-technique of [T1596](/techniques/reconnaissance.md#t1596), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1596/001)  

Adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts. Adversaries may search DNS data to gather actionable information. Threat actors can query nameservers for a target organization directly, or search through centralized repositories of logged DNS query responses (known as passive DNS). Adversaries may also seek and target DNS misconfigurations/leaks that reveal information about internal networks. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of DNS/Passive DNS  

---

### T1596.002: WHOIS
<a id="t1596002"></a>

sub-technique of [T1596](/techniques/reconnaissance.md#t1596), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1596/002)  

Adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names. Anyone can query WHOIS servers for information about a registered domain, such as assigned IP blocks, contact information, and DNS nameservers. Adversaries may search WHOIS data to gather actionable information. Threat actors can use online resources or command-line utilities to pillage through WHOIS data for information about potential victims. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of WHOIS  

---

### T1596.003: Digital Certificates
<a id="t1596003"></a>

sub-technique of [T1596](/techniques/reconnaissance.md#t1596), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1596/003)  

Adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content. These certificates, such as those used for encrypted web traffic (HTTPS SSL/TLS communications), contain information about the registered organization such as name and location. Adversaries may search digital certificate data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about certificates. Digital certificate data may also be available from artifacts signed by the organization (ex: certificates used from encrypted web traffic are served with content). Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Phishing for Information](https://attack.mitre.org/techniques/T1598)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Trusted Relationship](https://attack.mitre.org/techniques/T1199)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Digital Certificates  

---

### T1596.004: CDNs
<a id="t1596004"></a>

sub-technique of [T1596](/techniques/reconnaissance.md#t1596), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1596/004)  

Adversaries may search content delivery network (CDN) data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region. Adversaries may search CDN data to gather actionable information. Threat actors can use online resources and lookup tools to harvest information about content servers within a CDN. Adversaries may also seek and target CDN misconfigurations that leak sensitive information not intended to be hosted and/or do not have the same protection mechanisms (ex: login portals) as the content hosted on the organization’s website. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) or [Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)), and/or initial access (ex: [Drive-by Compromise](https://attack.mitre.org/techniques/T1189)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of CDNs  

---

### T1596.005: Scan Databases
<a id="t1596005"></a>

sub-technique of [T1596](/techniques/reconnaissance.md#t1596), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1596/005)  

Adversaries may search within public scan databases for information about victims that can be used during targeting. Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners. Adversaries may search scan databases to gather actionable information. Threat actors can use online resources and lookup tools to harvest information from these services. Adversaries may seek information about their already identified targets, or use these datasets to discover opportunities for successful breaches. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Active Scanning](https://attack.mitre.org/techniques/T1595) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Scan Databases  
Used by 2 threat groups: [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1597: Search Closed Sources
<a id="t1597"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1597)  

Adversaries may search and gather information about victims from closed (e.g., paid, private, or otherwise not freely available) sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical/threat intelligence data. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets. Adversaries may search in different closed databases depending on what information they seek to gather. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Search Closed Sources  
Used by 1 threat groups: [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011)  

---

### T1597.001: Threat Intel Vendors
<a id="t1597001"></a>

sub-technique of [T1597](/techniques/reconnaissance.md#t1597), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1597/001)  

Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures. Adversaries may search in private threat intelligence vendor data to gather actionable information. If a threat actor is searching for information on their own activities, that falls under [Search Threat Vendor Data](https://attack.mitre.org/techniques/T1681). Information reported by vendors may also reveal opportunities other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190) or [External Remote Services](https://attack.mitre.org/techniques/T1133)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Threat Intel Vendors  

---

### T1597.002: Purchase Technical Data
<a id="t1597002"></a>

sub-technique of [T1597](/techniques/reconnaissance.md#t1597), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1597/002)  

Adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan databases or other data aggregation services. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets. Adversaries may purchase information about their already identified targets, or use purchased data to discover opportunities for successful breaches. Threat actors may gather various technical details from purchased data, including but not limited to employee contact information, credentials, or specifics regarding a victim’s infrastructure. Information from these sources may reveal opportunities for other forms of reconnaissance (ex: [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [External Remote Services](https://attack.mitre.org/techniques/T1133) or [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Purchase Technical Data  
Used by 1 threat groups: [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1598: Phishing for Information
<a id="t1598"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1598)  

Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from [Phishing](https://attack.mitre.org/techniques/T1566) in that the objective is gathering data from the victim rather than executing malicious code. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass credential harvesting campaigns. Adversaries may also try to obtain information directly through the exchange of emails, instant messages, or other electronic conversation means. Victims may also receive phishing messages that direct them to call a phone number where the adversary attempts to collect confidential information. Phishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages. Another way to accomplish this is by [Email Spoofing](https://attack.mitre.org/techniques/T1684/002) the identity of the sender, which can be used to fool both the human recipient as well as automated security tools. Phishing for information may also involve evasive techniques, such as removing or manipulating emails or metadata/headers from compromised accounts being abused to send messages (e.g., [Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008)).

ATT&CK mitigations (2): [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls (11): `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
ATT&CK detection strategy: Detection of Phishing for Information  
Used by 6 threat groups: [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1057 ShinyHunters](https://attack.mitre.org/groups/G1057)  

---

### T1598.001: Spearphishing Service
<a id="t1598001"></a>

sub-technique of [T1598](/techniques/reconnaissance.md#t1598), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1598/001)  

Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries send messages through various social media services, personal webmail, and other non-enterprise controlled services. These services are more likely to have a less-strict security policy than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport with the target or get the target's interest in some way. Adversaries may create fake social media accounts and message employees for potential job opportunities. Doing so allows a plausible reason for asking about services, policies, and information about their environment. Adversaries may also use information from previous reconnaissance efforts (ex: [Social Media](https://attack.mitre.org/techniques/T1593/001) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to craft persuasive and believable lures.

ATT&CK mitigations (1): [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
NIST 800-53 R5 controls (7): `AC-4`, `CA-7`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
ATT&CK detection strategy: Detection of Spearphishing Service  

---

### T1598.002: Spearphishing Attachment
<a id="t1598002"></a>

sub-technique of [T1598](/techniques/reconnaissance.md#t1598), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1598/002)  

Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email. In some cases, they may rely upon the recipient populating information, then returning the file. The text of the spearphishing email usually tries to give a plausible reason why the file should be filled-in, such as a request for information from a business associate. In other cases, adversaries may leverage techniques such as [HTML Smuggling](https://attack.mitre.org/techniques/T1027/006) to harvest user credentials via fake login portals. Adversaries may also use information from previous reconnaissance efforts (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to craft persuasive and believable lures.

ATT&CK mitigations (2): [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls (11): `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
ATT&CK detection strategy: Detection of Spearphishing Attachment  
Used by 4 threat groups: [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033)  

---

### T1598.003: Spearphishing Link
<a id="t1598003"></a>

sub-technique of [T1598](/techniques/reconnaissance.md#t1598), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1598/003)  

Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, the malicious emails contain links generally accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. The given website may be a clone of a legitimate site (such as an online or corporate login portal) or may closely resemble a legitimate site in appearance and have a URL containing elements from the real site. URLs may also be obfuscated by taking advantage of quirks in the URL schema, such as the acceptance of integer- or hexadecimal-based hostname formats and the automatic discarding of text before an “@” symbol: for example, `hxxp://google.com@1157586937`. Adversaries may also embed “tracking pixels,” "web bugs," or "web beacons" within phishing messages to verify the receipt of an email, while also potentially profiling and tracking victim information such as IP address. These mechanisms often appear as small images (typically one pixel in size) or otherwise obfuscated objects and are typically delivered as HTML code containing a link to a remote server. Adversaries may also be able to spoof a complete website using what is known as a "browser-in-the-browser" (BitB) attack. By generating a fake browser popup window with an HTML-based address bar that appears to contain a legitimate URL (such as an authentication portal), they may be able to prompt users to enter their credentials while bypassing typical URL verification methods. Adversaries can use phishing kits such as `EvilProxy` and `Evilginx2` to perform adversary-in-the-middle phishing by proxying the connection between the victim and the legitimate website. On a successful login, the victim is redirected to the legitimate website, while the adversary captures their session cookie (i.e., [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539)) in addition to their username and password. This may enable the adversary to then bypass MFA via [Web Session Cookie](https://attack.mitre.org/techniques/T1550/004). Adversaries may also send a malicious link in the form of Quick Response (QR) Codes (also known as “quishing”). These links may direct a victim to a credential phishing page. By using a QR code, the URL may not be exposed in the email and may thus go undetected by most automated email security scans. These QR codes may be scanned by or delivered directly to a user’s mobile device (i.e., [Phishing](https://attack.mitre.org/techniques/T1660)), which may be less secure in several relevant ways. For example, mobile users may not be able to notice minor differences between genuine and credential harvesting websites due to mobile’s smaller form factor. From the fake website, information is gathered in web forms and sent to the adversary. Adversaries may also use information from previous reconnaissance efforts (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to craft persuasive and believable lures.

ATT&CK mitigations (2): [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
NIST 800-53 R5 controls (11): `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
ATT&CK detection strategy: Detection of Spearphishing Link  
Used by 16 threat groups: [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1057 ShinyHunters](https://attack.mitre.org/groups/G1057)  
Implemented by 3 software: [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S9003 evilginx2](https://attack.mitre.org/software/S9003)  

---

### T1598.004: Spearphishing Voice
<a id="t1598004"></a>

sub-technique of [T1598](/techniques/reconnaissance.md#t1598), Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1598/004)  

Adversaries may use voice communications to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Impersonation](https://attack.mitre.org/techniques/T1684/001)) and/or creating a sense of urgency or alarm for the recipient. All forms of phishing are electronically delivered social engineering. In this scenario, adversaries use phone calls to elicit sensitive information from victims. Known as voice phishing (or "vishing"), these communications can be manually executed by adversaries, hired call centers, or even automated via robocalls. Voice phishers may spoof their phone number while also posing as a trusted entity, such as a business partner or technical support staff. Victims may also receive phishing messages that direct them to call a phone number ("callback phishing") where the adversary attempts to collect confidential information. Adversaries may also use information from previous reconnaissance efforts (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to tailor pretexts to be even more persuasive and believable for the victim.

ATT&CK mitigations (1): [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Spearphishing Voice  
Used by 2 threat groups: [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1681: Search Threat Vendor Data
<a id="t1681"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1681)  

Threat actors may seek information/indicators from closed or open threat intelligence sources gathered about their own campaigns, as well as those conducted by other adversaries that may align with their target industries, capabilities/objectives, or other operational concerns. These reports may include descriptions of behavior, detailed breakdowns of attacks, atomic indicators such as malware hashes or IP addresses, timelines of a group’s activity, and more. Adversaries may change their behavior when planning their future operations. Adversaries have been observed replacing atomic indicators mentioned in blog posts in under a week. Adversaries have also been seen searching for their own domain names in threat vendor data and then taking them down, likely to avoid seizure or further investigation. This technique is distinct from [Threat Intel Vendors](https://attack.mitre.org/techniques/T1597/001) in that it describes threat actors performing reconnaissance on their own activity, not in search of victim information.

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
ATT&CK detection strategy: Detection of Search Threat Vendor Data  
Used by 2 threat groups: [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1682: Query Public AI Services
<a id="t1682"></a>

Tactics: Reconnaissance, Platforms: PRE, [ATT&CK](https://attack.mitre.org/techniques/T1682)  

Adversaries may query publicly accessible artificial intelligence (AI) services, such as large language models (LLMs), to support targeting and operations. In addition to searching websites or databases directly (i.e., Search Open Websites/Domains), adversaries may use AI services to synthesize, aggregate, and analyze publicly available information at scale. This may include identifying individuals or organizations to target, researching organizational structures and personnel, identifying technologies used by target organizations, researching business relationships to develop plausible pretexts for Social Engineering approaches, identifying contact information for use in Phishing or Phishing for Information, or gathering derogatory or sensitive information about individuals that may be used for extortion or coercion. Information gathered through AI services may be leveraged for other behaviors, such as establishing operational resources (i.e., Generate Content or Establish Accounts. For obtaining access to AI tools and services, see Artificial Intelligence.

ATT&CK mitigations (1): [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
NIST 800-53 R5 controls: none (*framework blind spot; rely on detection/design controls*)  
Used by 2 threat groups: [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1044 APT42](https://attack.mitre.org/groups/G1044)  

---
