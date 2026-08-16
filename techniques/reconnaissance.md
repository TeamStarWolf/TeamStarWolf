# Reconnaissance — Technique Detail

> Full detail pages for the **45 ATT&CK techniques** whose primary tactic is [Reconnaissance](https://attack.mitre.org/tactics/TA0043/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](README.md).

---

### T1589 — Gather Victim Identity Information
<a id="t1589"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1589)  

Adversaries may gather information about the victim's identity that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Gather Victim Identity Information  
**Used by 9 threat groups:** [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1589.001 — Credentials
<a id="t1589001"></a>

sub-technique of [T1589](reconnaissance.md#t1589) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1589/001)  

Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Credentials  
**Used by 5 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1589.002 — Email Addresses
<a id="t1589002"></a>

sub-technique of [T1589](reconnaissance.md#t1589) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1589/002)  

Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Email Addresses  
**Used by 14 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0127 TA551](https://attack.mitre.org/groups/G0127), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1589.003 — Employee Names
<a id="t1589003"></a>

sub-technique of [T1589](reconnaissance.md#t1589) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1589/003)  

Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Employee Names  
**Used by 3 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122)  

---

### T1590 — Gather Victim Network Information
<a id="t1590"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1590)  

Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Gather Victim Network Information  
**Used by 3 threat groups:** [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1590.001 — Domain Properties
<a id="t1590001"></a>

sub-technique of [T1590](reconnaissance.md#t1590) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1590/001)  

Adversaries may gather information about the victim's network domain(s) that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Domain Properties  
**Used by 1 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034)  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1590.002 — DNS
<a id="t1590002"></a>

sub-technique of [T1590](reconnaissance.md#t1590) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1590/002)  

Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts.

**ATT&CK mitigations (1):** [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (5):** `AC-4`, `CM-6`, `CM-7`, `SC-32`, `SC-7`  
**ATT&CK detection strategy:** Detection of DNS  

---

### T1590.003 — Network Trust Dependencies
<a id="t1590003"></a>

sub-technique of [T1590](reconnaissance.md#t1590) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1590/003)  

Adversaries may gather information about the victim's network trust dependencies that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Network Trust Dependencies  

---

### T1590.004 — Network Topology
<a id="t1590004"></a>

sub-technique of [T1590](reconnaissance.md#t1590) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1590/004)  

Adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Network Topology  
**Used by 3 threat groups:** [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  

---

### T1590.005 — IP Addresses
<a id="t1590005"></a>

sub-technique of [T1590](reconnaissance.md#t1590) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1590/005)  

Adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety of details, such as which IP addresses are in use.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of IP Addresses  
**Used by 3 threat groups:** [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0138 Andariel](https://attack.mitre.org/groups/G0138)  

---

### T1590.006 — Network Security Appliances
<a id="t1590006"></a>

sub-technique of [T1590](reconnaissance.md#t1590) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1590/006)  

Adversaries may gather information about the victim's network security appliances that can be used during targeting. Information about network security appliances may include a variety of details, such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Network Security Appliances  
**Used by 1 threat groups:** [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1591 — Gather Victim Org Information
<a id="t1591"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1591)  

Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Gather Victim Org Information  
**Used by 6 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036)  

---

### T1591.001 — Determine Physical Locations
<a id="t1591001"></a>

sub-technique of [T1591](reconnaissance.md#t1591) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1591/001)  

Adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Determine Physical Locations  
**Used by 1 threat groups:** [G0059 Magic Hound](https://attack.mitre.org/groups/G0059)  

---

### T1591.002 — Business Relationships
<a id="t1591002"></a>

sub-technique of [T1591](reconnaissance.md#t1591) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1591/002)  

Adversaries may gather information about the victim's business relationships that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Business Relationships  
**Used by 3 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1591.003 — Identify Business Tempo
<a id="t1591003"></a>

sub-technique of [T1591](reconnaissance.md#t1591) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1591/003)  

Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization’s business tempo may include a variety of details, including operational hours/days of the week.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Identify Business Tempo  

---

### T1591.004 — Identify Roles
<a id="t1591004"></a>

sub-technique of [T1591](reconnaissance.md#t1591) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1591/004)  

Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data/resources they have access to.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Identify Roles  
**Used by 4 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1592 — Gather Victim Host Information
<a id="t1592"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1592)  

Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Gather Victim Host Information  
**Used by 1 threat groups:** [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1592.001 — Hardware
<a id="t1592001"></a>

sub-technique of [T1592](reconnaissance.md#t1592) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1592/001)  

Adversaries may gather information about the victim's host hardware that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Hardware  

---

### T1592.002 — Software
<a id="t1592002"></a>

sub-technique of [T1592](reconnaissance.md#t1592) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1592/002)  

Adversaries may gather information about the victim's host software that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Software  
**Used by 3 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0138 Andariel](https://attack.mitre.org/groups/G0138)  

---

### T1592.003 — Firmware
<a id="t1592003"></a>

sub-technique of [T1592](reconnaissance.md#t1592) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1592/003)  

Adversaries may gather information about the victim's host firmware that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Firmware  

---

### T1592.004 — Client Configurations
<a id="t1592004"></a>

sub-technique of [T1592](reconnaissance.md#t1592) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1592/004)  

Adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system/version, virtualization, architecture (ex: 32 or 64 bit), language, and/or time zone.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Client Configurations  
**Used by 1 threat groups:** [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125)  

---

### T1593 — Search Open Websites/Domains
<a id="t1593"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1593)  

Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting.

**ATT&CK mitigations (2):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Search Open Websites/Domains  
**Used by 6 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1593.001 — Social Media
<a id="t1593001"></a>

sub-technique of [T1593](reconnaissance.md#t1593) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1593/001)  

Adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Social Media  
**Used by 3 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1593.002 — Search Engines
<a id="t1593002"></a>

sub-technique of [T1593](reconnaissance.md#t1593) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1593/002)  

Adversaries may use search engines to collect information about victims that can be used during targeting. Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content (i.e. filetypes).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Search Engines  
**Used by 1 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  

---

### T1593.003 — Code Repositories
<a id="t1593003"></a>

sub-technique of [T1593](reconnaissance.md#t1593) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1593/003)  

Adversaries may search public code repositories for information about victims that can be used during targeting. Victims may store code in repositories on various third-party websites such as GitHub, GitLab, SourceForge, and BitBucket.

**ATT&CK mitigations (2):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (1):** `CM-8`  
**ATT&CK detection strategy:** Detection of Code Repositories  
**Used by 3 threat groups:** [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1594 — Search Victim-Owned Websites
<a id="t1594"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1594)  

Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: Email Addresses).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Search Victim-Owned Websites  
**Used by 6 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1038 TA578](https://attack.mitre.org/groups/G1038)  

---

### T1595 — Active Scanning
<a id="t1595"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1595)  

Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Active Scanning  

---

### T1595.001 — Scanning IP Blocks
<a id="t1595001"></a>

sub-technique of [T1595](reconnaissance.md#t1595) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1595/001)  

Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Scanning IP Blocks  
**Used by 2 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  

---

### T1595.002 — Vulnerability Scanning
<a id="t1595002"></a>

sub-technique of [T1595](reconnaissance.md#t1595) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1595/002)  

Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific exploit the adversary may seek to use.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Vulnerability Scanning  
**Used by 13 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035)  

---

### T1595.003 — Wordlist Scanning
<a id="t1595003"></a>

sub-technique of [T1595](reconnaissance.md#t1595) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1595/003)  

Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to Brute Force, its goal is the identification of content and infrastructure rather than the discovery of valid credentials.

**ATT&CK mitigations (2):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls (1):** `SC-4`  
**ATT&CK detection strategy:** Detection of Wordlist Scanning  
**Used by 2 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0123 Volatile Cedar](https://attack.mitre.org/groups/G0123)  

---

### T1596 — Search Open Technical Databases
<a id="t1596"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1596)  

Adversaries may search freely available technical databases for information about victims that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Search Open Technical Databases  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094)  

---

### T1596.001 — DNS/Passive DNS
<a id="t1596001"></a>

sub-technique of [T1596](reconnaissance.md#t1596) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1596/001)  

Adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target’s subdomains, mail servers, and other hosts.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of DNS/Passive DNS  

---

### T1596.002 — WHOIS
<a id="t1596002"></a>

sub-technique of [T1596](reconnaissance.md#t1596) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1596/002)  

Adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of WHOIS  

---

### T1596.003 — Digital Certificates
<a id="t1596003"></a>

sub-technique of [T1596](reconnaissance.md#t1596) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1596/003)  

Adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Digital Certificates  

---

### T1596.004 — CDNs
<a id="t1596004"></a>

sub-technique of [T1596](reconnaissance.md#t1596) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1596/004)  

Adversaries may search content delivery network (CDN) data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor’s geographical region.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of CDNs  

---

### T1596.005 — Scan Databases
<a id="t1596005"></a>

sub-technique of [T1596](reconnaissance.md#t1596) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1596/005)  

Adversaries may search within public scan databases for information about victims that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Scan Databases  
**Used by 2 threat groups:** [G0096 APT41](https://attack.mitre.org/groups/G0096), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1597 — Search Closed Sources
<a id="t1597"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1597)  

Adversaries may search and gather information about victims from closed (e.g., paid, private, or otherwise not freely available) sources that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Search Closed Sources  
**Used by 1 threat groups:** [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011)  

---

### T1597.001 — Threat Intel Vendors
<a id="t1597001"></a>

sub-technique of [T1597](reconnaissance.md#t1597) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1597/001)  

Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Threat Intel Vendors  

---

### T1597.002 — Purchase Technical Data
<a id="t1597002"></a>

sub-technique of [T1597](reconnaissance.md#t1597) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1597/002)  

Adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan databases or other data aggregation services.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Purchase Technical Data  
**Used by 1 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1598 — Phishing for Information
<a id="t1598"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1598)  

Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detection of Phishing for Information  
**Used by 5 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036)  

---

### T1598.001 — Spearphishing Service
<a id="t1598001"></a>

sub-technique of [T1598](reconnaissance.md#t1598) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1598/001)  

Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information.

**ATT&CK mitigations (1):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
**NIST 800-53 R5 controls (7):** `AC-4`, `CA-7`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detection of Spearphishing Service  

---

### T1598.002 — Spearphishing Attachment
<a id="t1598002"></a>

sub-technique of [T1598](reconnaissance.md#t1598) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1598/002)  

Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detection of Spearphishing Attachment  
**Used by 4 threat groups:** [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033)  

---

### T1598.003 — Spearphishing Link
<a id="t1598003"></a>

sub-technique of [T1598](reconnaissance.md#t1598) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1598/003)  

Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (11):** `AC-4`, `CA-7`, `CM-2`, `CM-6`, `IA-9`, `SC-20`, `SC-44`, `SC-7`, `SI-3`, `SI-4`, `SI-8`  
**ATT&CK detection strategy:** Detection of Spearphishing Link  
**Used by 15 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0121 Sidewinder](https://attack.mitre.org/groups/G0121), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036)  
**Implemented by 2 software:** [S0649 SMOKEDHAM](https://attack.mitre.org/software/S0649), [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1598.004 — Spearphishing Voice
<a id="t1598004"></a>

sub-technique of [T1598](reconnaissance.md#t1598) · **Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1598/004)  

Adversaries may use voice communications to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information.

**ATT&CK mitigations (1):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Spearphishing Voice  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1681 — Search Threat Vendor Data
<a id="t1681"></a>

**Tactics:** Reconnaissance · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1681)  

Threat actors may seek information/indicators from closed or open threat intelligence sources gathered about their own campaigns, as well as those conducted by other adversaries that may align with their target industries, capabilities/objectives, or other operational concerns.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Search Threat Vendor Data  
**Used by 2 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

