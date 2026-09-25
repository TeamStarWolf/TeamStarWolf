# Resource Development — Technique Detail

> Full detail pages for the **47 ATT&CK techniques** whose primary tactic is [Resource Development](https://attack.mitre.org/tactics/TA0042/) (ATT&CK Enterprise v18.1). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1583 — Acquire Infrastructure
<a id="t1583"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583)  

Adversaries may buy, lease, rent, or obtain infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Acquire Infrastructure  
**Used by 8 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1583.001 — Domains
<a id="t1583001"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/001)  

Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Domains  
**Used by 40 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136), [G0137 Ferocious Kitten](https://attack.mitre.org/groups/G0137), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139) _(+16 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 3 software:** [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1207 XLoader](https://attack.mitre.org/software/S1207)  

---

### T1583.002 — DNS Server
<a id="t1583002"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/002)  

Adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: Application Layer Protocol).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of DNS Server  
**Used by 3 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  

---

### T1583.003 — Virtual Private Server
<a id="t1583003"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/003)  

Adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Virtual Private Server  
**Used by 14 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1583.004 — Server
<a id="t1583004"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/004)  

Adversaries may buy, lease, rent, or obtain physical servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Server  
**Used by 6 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  

---

### T1583.005 — Botnet
<a id="t1583005"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/005)  

Adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Botnet  
**Used by 3 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1023 APT5](https://attack.mitre.org/groups/G1023)  

---

### T1583.006 — Web Services
<a id="t1583006"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/006)  

Adversaries may register for web services that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Web Services  
**Used by 24 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0025 APT17](https://attack.mitre.org/groups/G0025), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1005 POLONIUM](https://attack.mitre.org/groups/G1005), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1038 TA578](https://attack.mitre.org/groups/G1038), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1583.007 — Serverless
<a id="t1583007"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/007)  

Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Serverless  

---

### T1583.008 — Malvertising
<a id="t1583008"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/008)  

Adversaries may purchase online advertisements that can be abused to distribute malware to victims. Ads can be purchased to plant as well as favorably position artifacts in specific locations online, such as prominently placed within search engine results.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Malvertising  
**Used by 1 threat groups:** [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  
**Implemented by 1 software:** [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130)  

---

### T1584 — Compromise Infrastructure
<a id="t1584"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584)  

Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, network devices, and third-party web and DNS services.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Compromise Infrastructure  

---

### T1584.001 — Domains
<a id="t1584001"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/001)  

Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant. Adversaries may gain access to an email account for the person listed as the owner of the domain.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Domains  
**Used by 6 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  
**Implemented by 1 software:** [S1138 Gootloader](https://attack.mitre.org/software/S1138)  

---

### T1584.002 — DNS Server
<a id="t1584002"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/002)  

Adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: Application Layer Protocol).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of DNS Server  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  

---

### T1584.003 — Virtual Private Server
<a id="t1584003"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/003)  

Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Virtual Private Server  
**Used by 2 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1584.004 — Server
<a id="t1584004"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/004)  

Adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Server  
**Used by 10 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0023 APT16](https://attack.mitre.org/groups/G0023), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  

---

### T1584.005 — Botnet
<a id="t1584005"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/005)  

Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Botnet  
**Used by 4 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1584.006 — Web Services
<a id="t1584006"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/006)  

Adversaries may compromise access to third-party web services that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, SendGrid, etc.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Web Services  
**Used by 4 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035)  
**Implemented by 1 software:** [S1138 Gootloader](https://attack.mitre.org/software/S1138)  

---

### T1584.007 — Serverless
<a id="t1584007"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/007)  

Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Serverless  

---

### T1584.008 — Network Devices
<a id="t1584008"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/008)  

Adversaries may compromise third-party network devices that can be used during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Network Devices  
**Used by 4 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1585 — Establish Accounts
<a id="t1585"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585)  

Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Establish Accounts  
**Used by 5 threat groups:** [G0025 APT17](https://attack.mitre.org/groups/G0025), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1585.001 — Social Media Accounts
<a id="t1585001"></a>

sub-technique of [T1585](/techniques/resource-development.md#t1585) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585/001)  

Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Social Media Accounts  
**Used by 17 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1050 Water Galura](https://attack.mitre.org/groups/G1050), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1585.002 — Email Accounts
<a id="t1585002"></a>

sub-technique of [T1585](/techniques/resource-development.md#t1585) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585/002)  

Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct Phishing for Information or Phishing.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Email Accounts  
**Used by 18 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1585.003 — Cloud Accounts
<a id="t1585003"></a>

sub-technique of [T1585](/techniques/resource-development.md#t1585) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585/003)  

Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Cloud Accounts  
**Used by 1 threat groups:** [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  

---

### T1586 — Compromise Accounts
<a id="t1586"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586)  

Adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. Establish Accounts), adversaries may compromise existing accounts.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Compromise Accounts  

---

### T1586.001 — Social Media Accounts
<a id="t1586001"></a>

sub-technique of [T1586](/techniques/resource-development.md#t1586) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586/001)  

Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Social Media Accounts  
**Used by 2 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0065 Leviathan](https://attack.mitre.org/groups/G0065)  

---

### T1586.002 — Email Accounts
<a id="t1586002"></a>

sub-technique of [T1586](/techniques/resource-development.md#t1586) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586/002)  

Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct Phishing for Information, Phishing, or large-scale spam email campaigns.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Email Accounts  
**Used by 12 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1037 TA577](https://attack.mitre.org/groups/G1037)  

---

### T1586.003 — Cloud Accounts
<a id="t1586003"></a>

sub-technique of [T1586](/techniques/resource-development.md#t1586) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586/003)  

Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Cloud Accounts  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  

---

### T1587 — Develop Capabilities
<a id="t1587"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587)  

Adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Develop Capabilities  
**Used by 3 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1587.001 — Malware
<a id="t1587001"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/001)  

Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Malware  
**Used by 22 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1587.002 — Code Signing Certificates
<a id="t1587002"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/002)  

Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Code Signing Certificates  
**Used by 3 threat groups:** [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  

---

### T1587.003 — Digital Certificates
<a id="t1587003"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/003)  

Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Digital Certificates  
**Used by 4 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1587.004 — Exploits
<a id="t1587004"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/004)  

Adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Exploits  
**Used by 3 threat groups:** [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1588 — Obtain Capabilities
<a id="t1588"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588)  

Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Obtain Capabilities  

---

### T1588.001 — Malware
<a id="t1588001"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/001)  

Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Malware  
**Used by 15 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0138 Andariel](https://attack.mitre.org/groups/G0138), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1013 Metador](https://attack.mitre.org/groups/G1013), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1588.002 — Tool
<a id="t1588002"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/002)  

Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: PsExec).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Tool  
**Used by 79 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0011 PittyTiger](https://attack.mitre.org/groups/G0011), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059) _(+55 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  
**Implemented by 1 software:** [S0681 Lizar](https://attack.mitre.org/software/S0681)  

---

### T1588.003 — Code Signing Certificates
<a id="t1588003"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/003)  

Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Code Signing Certificates  
**Used by 7 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 1 software:** [S0576 MegaCortex](https://attack.mitre.org/software/S0576)  

---

### T1588.004 — Digital Certificates
<a id="t1588004"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/004)  

Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Digital Certificates  
**Used by 7 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1588.005 — Exploits
<a id="t1588005"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/005)  

Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Exploits  
**Used by 2 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  

---

### T1588.006 — Vulnerabilities
<a id="t1588006"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/006)  

Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Vulnerabilities  
**Used by 3 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1588.007 — Artificial Intelligence
<a id="t1588007"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/007)  

Adversaries may obtain access to generative artificial intelligence tools, such as large language models (LLMs), to aid various techniques during targeting.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Artificial Intelligence  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1608 — Stage Capabilities
<a id="t1608"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608)  

Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed (Develop Capabilities) or obtained (Obtain Capabilities) and stage them on infrastructure under their control.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Stage Capabilities  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  

---

### T1608.001 — Upload Malware
<a id="t1608001"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/001)  

Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious content.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Upload Malware  
**Used by 25 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1044 APT42](https://attack.mitre.org/groups/G1044) _(+1 more — see [group→technique data](../data/attack/group_to_technique.jsonl))_  

---

### T1608.002 — Upload Tool
<a id="t1608002"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/002)  

Adversaries may upload tools to third-party or adversary controlled infrastructure to make it accessible during targeting. Tools can be open or closed source, free or commercial. Tools can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: PsExec).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Upload Tool  
**Used by 2 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  

---

### T1608.003 — Install Digital Certificate
<a id="t1608003"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/003)  

Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Install Digital Certificate  
**Used by 1 threat groups:** [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  

---

### T1608.004 — Drive-by Target
<a id="t1608004"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/004)  

Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in Drive-by Compromise.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Drive-by Target  
**Used by 8 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  

---

### T1608.005 — Link Target
<a id="t1608005"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/005)  

Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in Malicious Link.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Link Target  
**Used by 3 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014)  

---

### T1608.006 — SEO Poisoning
<a id="t1608006"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/006)  

Adversaries may poison mechanisms that influence search engine optimization (SEO) to further lure staged capabilities towards potential victims. Search engines typically display results to users based on purchased ads as well as the site’s ranking/score/reputation calculated by their web crawlers and algorithms.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of SEO Poisoning  
**Used by 1 threat groups:** [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  

---

### T1650 — Acquire Access
<a id="t1650"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1650)  

Adversaries may purchase or otherwise acquire an existing access to a target system or network. A variety of online services and initial access broker networks are available to sell access to previously compromised systems.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Acquire Access  
**Used by 1 threat groups:** [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  

---

