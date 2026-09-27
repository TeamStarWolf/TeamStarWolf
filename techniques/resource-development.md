# Resource Development — Technique Detail

> Full detail pages for the **50 ATT&CK techniques** whose primary tactic is [Resource Development](https://attack.mitre.org/tactics/TA0042/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1583 — Acquire Infrastructure
<a id="t1583"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583)  

Adversaries may buy, lease, rent, or obtain infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services. Some infrastructure providers offer free trial periods, enabling infrastructure acquisition at limited to no cost. Additionally, botnets are available for rent or purchase. Use of these infrastructure solutions allows adversaries to stage, launch, and execute operations. Solutions may help adversary operations blend in with traffic that is seen as normal, such as contacting third-party web services or acquiring infrastructure to support [Proxy](https://attack.mitre.org/techniques/T1090), including from residential proxy services. Depending on the implementation, adversaries may use infrastructure that makes it difficult to physically tie back to them as well as utilize infrastructure that can be rapidly provisioned, modified, and shut down.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Acquire Infrastructure  
**Used by 8 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1583.001 — Domains
<a id="t1583001"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/001)  

Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free. Adversaries may use acquired domains for a variety of purposes, including for [Phishing](https://attack.mitre.org/techniques/T1566), [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), and Command and Control. Adversaries may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different top-level domain (TLD). Typosquatting may be used to aid in delivery of payloads via [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). Adversaries may also use internationalized domain names (IDNs) and different character sets (e.g. Cyrillic, Greek, etc.) to execute "IDN homograph attacks," creating visually similar lookalike domains used to deliver malware to victim machines. Different URIs/URLs may also be dynamically generated to uniquely serve malicious content to victims (including one-time, single use domain names). Adversaries may also acquire and repurpose expired domains, which may be potentially already allowlisted/trusted by defenders based on an existing reputation/history. Domain registrars each maintain a publicly viewable database that displays contact information for every registered domain. Private WHOIS services display alternative information, such as their own company data, rather than the owner of the domain. Adversaries may use such private WHOIS services to obscure information about who owns a purchased domain. Adversaries may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars. In addition to legitimately purchasing a domain, an adversary may register a new domain in a compromised environment. For example, in AWS environments, adversaries may leverage the Route53 domain service to register a domain and create hosted zones pointing to resources of the threat actor’s choosing.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Domains  
**Used by 40 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0044 Winnti Group](https://attack.mitre.org/groups/G0044), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136), [G0137 Ferocious Kitten](https://attack.mitre.org/groups/G0137), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1042 RedEcho](https://attack.mitre.org/groups/G1042), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 3 software:** [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130), [S1207 XLoader](https://attack.mitre.org/software/S1207)  

---

### T1583.002 — DNS Server
<a id="t1583002"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/002)  

Adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of hijacking existing DNS servers, adversaries may opt to configure and run their own DNS servers in support of operations. By running their own DNS servers, adversaries can have more control over how they administer server-side DNS C2 traffic ([DNS](https://attack.mitre.org/techniques/T1071/004)). With control over a DNS server, adversaries can configure DNS applications to provide conditional responses to malware and, generally, have more flexibility in the structure of the DNS-based C2 channel.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of DNS Server  
**Used by 3 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  

---

### T1583.003 — Virtual Private Server
<a id="t1583003"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/003)  

Adversaries may rent Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them. The use of cloud infrastructure can also make it easier for adversaries to rapidly provision, modify, and shut down their infrastructure. Acquiring a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers. Adversaries may also acquire infrastructure from VPS service providers that are known for renting VPSs with minimal registration information, allowing for more anonymous acquisitions of infrastructure.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Virtual Private Server  
**Used by 14 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1583.004 — Server
<a id="t1583004"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/004)  

Adversaries may buy, lease, rent, or obtain physical servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, such as watering hole operations in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), enabling [Phishing](https://attack.mitre.org/techniques/T1566) operations, or facilitating [Command and Control](https://attack.mitre.org/tactics/TA0011). Instead of compromising a third-party [Server](https://attack.mitre.org/techniques/T1584/004) or renting a [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may opt to configure and run their own servers in support of operations. Free trial periods of cloud servers may also be abused. Adversaries may only need a lightweight setup if most of their activities will take place using online infrastructure. Or, they may need to build extensive infrastructure if they want to test, communicate, and control other aspects of their activities on their own systems.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Server  
**Used by 6 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  

---

### T1583.005 — Botnet
<a id="t1583005"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/005)  

Adversaries may buy, lease, or rent a network of compromised systems that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service. Internet-facing edge devices and related network appliances that are end-of-life (EOL) and unsupported by their manufacturers are commonly acquired for botnet activities. Adversaries may lease operational relay box (ORB) networks – consisting of virtual private servers (VPS), small office/home office (SOHO) routers, or Internet of Things (IoT) devices – to serve as a botnet. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS). Acquired botnets may also be used to support Command and Control activity, such as [Hide Infrastructure](https://attack.mitre.org/techniques/T1665) through an established [Proxy](https://attack.mitre.org/techniques/T1090) network.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Botnet  
**Used by 3 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1023 APT5](https://attack.mitre.org/groups/G1023)  

---

### T1583.006 — Web Services
<a id="t1583006"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/006)  

Adversaries may register for web services that can be used during targeting. A variety of popular websites exist for adversaries to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)), [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567), or [Phishing](https://attack.mitre.org/techniques/T1566). Using common services, such as those offered by Google, GitHub, or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, adversaries can make it difficult to physically tie back operations to them.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Web Services  
**Used by 24 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0025 APT17](https://attack.mitre.org/groups/G0025), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0142 Confucius](https://attack.mitre.org/groups/G0142), [G1005 POLONIUM](https://attack.mitre.org/groups/G1005), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1038 TA578](https://attack.mitre.org/groups/G1038), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1583.007 — Serverless
<a id="t1583007"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/007)  

Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them. Once acquired, the serverless runtime environment can be leveraged to either respond directly to infected machines or to [Proxy](https://attack.mitre.org/techniques/T1090) traffic to an adversary-owned command and control server. As traffic generated by these functions will appear to come from subdomains of common cloud providers, it may be difficult to distinguish from ordinary traffic to these providers - making it easier to [Hide Infrastructure](https://attack.mitre.org/techniques/T1665).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Serverless  

---

### T1583.008 — Malvertising
<a id="t1583008"></a>

sub-technique of [T1583](/techniques/resource-development.md#t1583) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1583/008)  

Adversaries may purchase online advertisements that can be abused to distribute malware to victims. Ads can be purchased to plant as well as favorably position artifacts in specific locations online, such as prominently placed within search engine results. These ads may make it more difficult for users to distinguish between actual search results and advertisements. Purchased ads may also target specific audiences using the advertising network’s capabilities, potentially further taking advantage of the trust inherently given to search engines and popular websites. Adversaries may purchase ads and other resources to help distribute artifacts containing malicious code to victims. Purchased ads may attempt to impersonate or spoof well-known brands. For example, these spoofed ads may trick victims into clicking the ad which could then send them to a malicious domain that may be a clone of official websites containing trojanized versions of the advertised software. Adversary’s efforts to create malicious domains and purchase advertisements may also be automated at scale to better resist cleanup efforts. Malvertising may be used to support [Drive-by Target](https://attack.mitre.org/techniques/T1608/004) and [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), potentially requiring limited interaction from the user if the ad contains code/exploits that infect the target system's web browser. Adversaries may also employ several techniques to evade detection by the advertising network. For example, adversaries may dynamically route ad clicks to send automated crawler/policy enforcer traffic to benign sites while validating potential targets then sending victims referred from real ad clicks to malicious pages. This infection vector may therefore remain hidden from the ad network as well as any visitor not reaching the malicious sites with a valid identifier from clicking on the advertisement. Other tricks, such as intentional typos to avoid brand reputation monitoring, may also be used to evade automated detection.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Malvertising  
**Used by 1 threat groups:** [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  
**Implemented by 1 software:** [S1130 Raspberry Robin](https://attack.mitre.org/software/S1130)  

---

### T1584 — Compromise Infrastructure
<a id="t1584"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584)  

Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, network devices, and third-party web and DNS services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle. Additionally, adversaries may compromise numerous machines to form a botnet they can leverage. Use of compromised infrastructure allows adversaries to stage, launch, and execute operations. Compromised infrastructure can help adversary operations blend in with traffic that is seen as normal, such as contact with high reputation or trusted sites. For example, adversaries may leverage compromised infrastructure (potentially also in conjunction with [Digital Certificates](https://attack.mitre.org/techniques/T1588/004)) to further blend in and support staged information gathering and/or [Phishing](https://attack.mitre.org/techniques/T1566) campaigns. Adversaries may also compromise numerous machines to support [Proxy](https://attack.mitre.org/techniques/T1090) and/or proxyware services or to form a botnet. Additionally, adversaries may compromise infrastructure residing in close proximity to a target in order to gain [Initial Access](https://attack.mitre.org/tactics/TA0001) via [Wi-Fi Networks](https://attack.mitre.org/techniques/T1669). By using compromised infrastructure, adversaries may enable follow-on malicious operations. Prior to targeting, adversaries may also compromise the infrastructure of other adversaries.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Compromise Infrastructure  

---

### T1584.001 — Domains
<a id="t1584001"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/001)  

Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant. Adversaries may gain access to an email account for the person listed as the owner of the domain. The adversary can then claim that they forgot their password in order to make changes to the domain registration. Other possibilities include social engineering a domain registration help desk to gain access to an account, taking advantage of renewal process gaps, or compromising a cloud service that enables managing domains (e.g., AWS Route53). Subdomain hijacking can occur when organizations have DNS entries that point to non-existent or deprovisioned resources. In such cases, an adversary may take control of a subdomain to conduct operations with the benefit of the trust associated with that domain. Adversaries who compromise a domain may also engage in domain shadowing by creating malicious subdomains under their control while keeping any existing DNS records. As service will not be disrupted, the malicious subdomains may go unnoticed for long periods of time.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Domains  
**Used by 6 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  
**Implemented by 1 software:** [S1138 Gootloader](https://attack.mitre.org/software/S1138)  

---

### T1584.002 — DNS Server
<a id="t1584002"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/002)  

Adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of setting up their own DNS servers, adversaries may compromise third-party DNS servers in support of operations. By compromising DNS servers, adversaries can alter DNS records. Such control can allow for redirection of an organization's traffic, facilitating Collection and Credential Access efforts for the adversary. Additionally, adversaries may leverage such control in conjunction with [Digital Certificates](https://attack.mitre.org/techniques/T1588/004) to redirect traffic to adversary-controlled infrastructure, mimicking normal trusted network communications. Alternatively, they may be able to prove ownership of a domain to a SaaS service in order to assert control of the service or create a new administrative [Cloud Account](https://attack.mitre.org/techniques/T1136/003). Adversaries may also be able to silently create subdomains pointed at malicious servers without tipping off the actual owner of the DNS server.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of DNS Server  
**Used by 2 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  

---

### T1584.003 — Virtual Private Server
<a id="t1584003"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/003)  

Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities. By compromising a VPS to use as infrastructure, adversaries can make it difficult to physically tie back operations to themselves. Compromising a VPS for use in later stages of the adversary lifecycle, such as Command and Control, can allow adversaries to benefit from the ubiquity and trust associated with higher reputation cloud service providers as well as that added by the compromised third-party.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Virtual Private Server  
**Used by 2 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1584.004 — Server
<a id="t1584004"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/004)  

Adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control. Instead of purchasing a [Server](https://attack.mitre.org/techniques/T1583/004) or [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may compromise third-party servers in support of operations. Adversaries may also compromise web servers to support watering hole operations, as in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), or email servers to support [Phishing](https://attack.mitre.org/techniques/T1566) operations.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Server  
**Used by 10 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0023 APT16](https://attack.mitre.org/groups/G0023), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  

---

### T1584.005 — Botnet
<a id="t1584005"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/005)  

Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks. Instead of purchasing/renting a botnet from a booter/stresser service, adversaries may build their own botnet by compromising numerous third-party systems. Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Botnet  
**Used by 4 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1584.006 — Web Services
<a id="t1584006"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/006)  

Adversaries may compromise access to third-party web services that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, SendGrid, etc. Adversaries may try to take ownership of a legitimate user's access to a web service and use that web service as infrastructure in support of cyber operations. Such web services can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)), [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567), or [Phishing](https://attack.mitre.org/techniques/T1566). Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, particularly when access is stolen from legitimate users, adversaries can make it difficult to physically tie back operations to them. Additionally, leveraging compromised web-based email services may allow adversaries to leverage the trust associated with legitimate domains.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Web Services  
**Used by 4 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1035 Winter Vivern](https://attack.mitre.org/groups/G1035)  
**Implemented by 1 software:** [S1138 Gootloader](https://attack.mitre.org/software/S1138)  

---

### T1584.007 — Serverless
<a id="t1584007"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/007)  

Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers, AWS Lambda functions, or Google Apps Scripts, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them. Once compromised, the serverless runtime environment can be leveraged to either respond directly to infected machines or to [Proxy](https://attack.mitre.org/techniques/T1090) traffic to an adversary-owned command and control server. As traffic generated by these functions will appear to come from subdomains of common cloud providers, it may be difficult to distinguish from ordinary traffic to these providers - making it easier to [Hide Infrastructure](https://attack.mitre.org/techniques/T1665).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Serverless  

---

### T1584.008 — Network Devices
<a id="t1584008"></a>

sub-technique of [T1584](/techniques/resource-development.md#t1584) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1584/008)  

Adversaries may compromise third-party network devices that can be used during targeting. Network devices, such as small office/home office (SOHO) routers, may be compromised where the adversary's ultimate goal is not [Initial Access](https://attack.mitre.org/tactics/TA0001) to that environment, but rather to leverage these devices to support additional targeting. Once an adversary has control, compromised network devices can be used to launch additional operations, such as hosting payloads for [Phishing](https://attack.mitre.org/techniques/T1566) campaigns (i.e., [Link Target](https://attack.mitre.org/techniques/T1608/005)) or enabling the required access to execute [Content Injection](https://attack.mitre.org/techniques/T1659) operations. Adversaries may also be able to harvest reusable credentials (i.e., [Valid Accounts](https://attack.mitre.org/techniques/T1078)) from compromised network devices. Adversaries often target Internet-facing edge devices and related network appliances that specifically do not support robust host-based defenses. Compromised network devices may be used to support subsequent [Command and Control](https://attack.mitre.org/tactics/TA0011) activity, such as [Hide Infrastructure](https://attack.mitre.org/techniques/T1665) through an established [Proxy](https://attack.mitre.org/techniques/T1090) and/or [Botnet](https://attack.mitre.org/techniques/T1584/005) network.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Network Devices  
**Used by 4 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  

---

### T1585 — Establish Accounts
<a id="t1585"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585)  

Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity. For operations incorporating social engineering, the utilization of an online persona may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, GitHub, Docker Hub, etc.). Establishing a persona may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos. Establishing accounts can also include the creation of accounts with email providers, which may be directly leveraged for [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566). In addition, establishing accounts may allow adversaries to abuse free services, such as registering for trial periods to [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) for malicious purposes.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Establish Accounts  
**Used by 5 threat groups:** [G0025 APT17](https://attack.mitre.org/groups/G0025), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1585.001 — Social Media Accounts
<a id="t1585001"></a>

sub-technique of [T1585](/techniques/resource-development.md#t1585) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585/001)  

Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. For operations incorporating social engineering, the utilization of a persona on social media may be important. These personas may be fictitious or impersonate real people. The persona may exist on a single social media site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Establishing a persona on social media may require development of additional documentation to make them seem real. This could include filling out profile information, developing social networks, or incorporating photos. Once a persona has been developed an adversary can use it to create connections to targets of interest. These connections may be direct or may include trying to connect through others. These accounts may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Social Media Accounts  
**Used by 17 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1050 Water Galura](https://attack.mitre.org/groups/G1050), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1585.002 — Email Accounts
<a id="t1585002"></a>

sub-technique of [T1585](/techniques/resource-development.md#t1585) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585/002)  

Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566). Establishing email accounts may also allow adversaries to abuse free services – such as trial periods – to [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) for follow-on purposes. Adversaries may also take steps to cultivate a persona around the email account, such as through use of [Social Media Accounts](https://attack.mitre.org/techniques/T1585/001), to increase the chance of success of follow-on behaviors. Created email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)). To decrease the chance of physically tying back operations to themselves, adversaries may make use of disposable email services.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Email Accounts  
**Used by 18 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1585.003 — Cloud Accounts
<a id="t1585003"></a>

sub-technique of [T1585](/techniques/resource-development.md#t1585) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1585/003)  

Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) or to [Upload Tool](https://attack.mitre.org/techniques/T1608/002)s. Cloud accounts can also be used in the acquisition of infrastructure, such as [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003)s or [Serverless](https://attack.mitre.org/techniques/T1583/007) infrastructure. Establishing cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers. Creating [Cloud Accounts](https://attack.mitre.org/techniques/T1585/003) may also require adversaries to establish [Email Accounts](https://attack.mitre.org/techniques/T1585/002) to register with the cloud provider.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Cloud Accounts  
**Used by 1 threat groups:** [G1046 Storm-1811](https://attack.mitre.org/groups/G1046)  

---

### T1586 — Compromise Accounts
<a id="t1586"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586)  

Adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. [Establish Accounts](https://attack.mitre.org/techniques/T1585)), adversaries may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. A variety of methods exist for compromising accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, brute forcing credentials (ex: password reuse from breach credential dumps), or paying employees, suppliers or business partners for access to credentials. Prior to compromising accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, Google, etc.). Compromised accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos. Adversaries may directly leverage compromised email accounts for [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Compromise Accounts  

---

### T1586.001 — Social Media Accounts
<a id="t1586001"></a>

sub-technique of [T1586](/techniques/resource-development.md#t1586) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586/001)  

Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. [Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. A variety of methods exist for compromising social media accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, or by brute forcing credentials (ex: password reuse from breach credential dumps). Prior to compromising social media accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Compromised social media accounts may require additional development, this could include filling out or modifying profile information, further developing social networks, or incorporating photos. Adversaries can use a compromised social media profile to create new, or hijack existing, connections to targets of interest. These connections may be direct or may include trying to connect through others. Compromised profiles may be leveraged during other phases of the adversary lifecycle, such as during Initial Access (ex: [Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Social Media Accounts  
**Used by 2 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0065 Leviathan](https://attack.mitre.org/groups/G0065)  

---

### T1586.002 — Email Accounts
<a id="t1586002"></a>

sub-technique of [T1586](/techniques/resource-development.md#t1586) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586/002)  

Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598), [Phishing](https://attack.mitre.org/techniques/T1566), or large-scale spam email campaigns. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship with, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)). A variety of methods exist for compromising email accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, brute forcing credentials (ex: password reuse from breach credential dumps), or paying employees, suppliers or business partners for access to credentials. Prior to compromising email accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Adversaries may target compromising well-known email accounts or domains from which malicious spam or [Phishing](https://attack.mitre.org/techniques/T1566) emails may evade reputation-based email filtering rules. Adversaries can use a compromised email account to hijack existing email threads with targets of interest.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Email Accounts  
**Used by 12 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1037 TA577](https://attack.mitre.org/groups/G1037)  

---

### T1586.003 — Cloud Accounts
<a id="t1586003"></a>

sub-technique of [T1586](/techniques/resource-development.md#t1586) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1586/003)  

Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buckets for [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) or to [Upload Tool](https://attack.mitre.org/techniques/T1608/002)s. Cloud accounts can also be used in the acquisition of infrastructure, such as [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003)s or [Serverless](https://attack.mitre.org/techniques/T1583/007) infrastructure. Additionally, cloud-based messaging services such as Twilio, SendGrid, AWS End User Messaging, AWS SNS (Simple Notification Service), or AWS SES (Simple Email Service) may be leveraged for spam or [Phishing](https://attack.mitre.org/techniques/T1566). Compromising cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers. A variety of methods exist for compromising cloud accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, conducting [Password Spraying](https://attack.mitre.org/techniques/T1110/003) attacks, or attempting to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s. Prior to compromising cloud accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. In some cases, adversaries may target privileged service provider accounts with the intent of leveraging a [Trusted Relationship](https://attack.mitre.org/techniques/T1199) between service providers and their customers.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Cloud Accounts  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  

---

### T1587 — Develop Capabilities
<a id="t1587"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587)  

Adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Adversaries may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle. As with legitimate development efforts, different skill sets may be required for developing capabilities. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the capability.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Develop Capabilities  
**Used by 3 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1587.001 — Malware
<a id="t1587001"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/001)  

Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Adversaries may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors. During malware development, adversaries may intentionally include indicators aligned with other known actors in order to mislead attribution by defenders. As with legitimate development efforts, different skill sets may be required for developing malware. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's malware development capabilities, provided the adversary plays a role in shaping requirements and maintains a degree of exclusivity to the malware. Some aspects of malware development, such as C2 protocol development, may require adversaries to obtain additional infrastructure. For example, malware developed that will communicate with Twitter for C2, may require use of [Web Services](https://attack.mitre.org/techniques/T1583/006).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Malware  
**Used by 22 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1587.002 — Code Signing Certificates
<a id="t1587002"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/002)  

Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is. Prior to [Code Signing](https://attack.mitre.org/techniques/T1553/002), adversaries may develop self-signed code signing certificates for use in operations.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Code Signing Certificates  
**Used by 3 threat groups:** [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  

---

### T1587.003 — Digital Certificates
<a id="t1587003"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/003)  

Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. In the case of self-signing, digital certificates will lack the element of trust associated with the signature of a third-party certificate authority (CA). Adversaries may create self-signed SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or even enabling [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) if added to the root of trust (i.e. [Install Root Certificate](https://attack.mitre.org/techniques/T1553/004)). After creating a digital certificate, an adversary may then install that certificate (see [Install Digital Certificate](https://attack.mitre.org/techniques/T1608/003)) on infrastructure under their control.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Digital Certificates  
**Used by 4 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0056 PROMETHIUM](https://attack.mitre.org/groups/G0056), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1587.004 — Exploits
<a id="t1587004"></a>

sub-technique of [T1587](/techniques/resource-development.md#t1587) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1587/004)  

Adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than finding/modifying exploits from online or purchasing them from exploit vendors, an adversary may develop their own exploits. Adversaries may use information acquired via [Vulnerabilities](https://attack.mitre.org/techniques/T1588/006) to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis. As with legitimate development efforts, different skill sets may be required for developing exploits. The skills needed may be located in-house, or may need to be contracted out. Use of a contractor may be considered an extension of that adversary's exploit development capabilities, provided the adversary plays a role in shaping requirements and maintains an initial degree of exclusivity to the exploit. Adversaries may use exploits during various phases of the adversary lifecycle (i.e. [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), [Exploitation for Stealth](https://attack.mitre.org/techniques/T1211), [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212), [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210), and [Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Exploits  
**Used by 3 threat groups:** [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1588 — Obtain Capabilities
<a id="t1588"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588)  

Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle. In addition to downloading free malware, software, and exploits from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware and exploits, criminal marketplaces, or from individuals. In addition to purchasing capabilities, adversaries may steal capabilities from third-party entities (including other adversaries). This can include stealing software licenses, malware, SSL/TLS and code-signing certificates, or raiding closed databases of vulnerabilities or exploits.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Obtain Capabilities  

---

### T1588.001 — Malware
<a id="t1588001"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/001)  

Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their operations, obtaining a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors. In addition to downloading free malware from the internet, adversaries may purchase these capabilities from third-party entities. Third-party entities can include technology companies that specialize in malware development, criminal marketplaces (including Malware-as-a-Service, or MaaS), or from individuals. In addition to purchasing malware, adversaries may steal and repurpose malware from third-party entities (including other adversaries).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Malware  
**Used by 15 threat groups:** [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0138 Andariel](https://attack.mitre.org/groups/G0138), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1013 Metador](https://attack.mitre.org/groups/G1013), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1588.002 — Tool
<a id="t1588002"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/002)  

Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Adversaries may obtain tools to support their operations, including to support execution of post-compromise behaviors. Tools may also be leveraged for testing – for example, evaluating malware against commercial antivirus or endpoint detection and response (EDR) applications. Tool acquisition may involve the procurement of commercial software licenses, including for red teaming tools such as Cobalt Strike. In addition to freely downloading or purchasing software, adversaries may steal software and/or software licenses from third-party entities (including other adversaries). Threat actors may also crack trial versions of software.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Tool  
**Used by 79 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0008 Carbanak](https://attack.mitre.org/groups/G0008), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0011 PittyTiger](https://attack.mitre.org/groups/G0011), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0051 FIN10](https://attack.mitre.org/groups/G0051), [G0052 CopyKittens](https://attack.mitre.org/groups/G0052), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0073 APT19](https://attack.mitre.org/groups/G0073), [G0076 Thrip](https://attack.mitre.org/groups/G0076), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0078 Gorgon Group](https://attack.mitre.org/groups/G0078), [G0079 DarkHydrus](https://attack.mitre.org/groups/G0079), [G0080 Cobalt Group](https://attack.mitre.org/groups/G0080), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0090 WIRTE](https://attack.mitre.org/groups/G0090), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0099 APT-C-36](https://attack.mitre.org/groups/G0099), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0107 Whitefly](https://attack.mitre.org/groups/G0107), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0135 BackdoorDiplomacy](https://attack.mitre.org/groups/G0135), [G0136 IndigoZebra](https://attack.mitre.org/groups/G0136), [G0137 Ferocious Kitten](https://attack.mitre.org/groups/G0137), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1005 POLONIUM](https://attack.mitre.org/groups/G1005), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1007 Aoqin Dragon](https://attack.mitre.org/groups/G1007), [G1009 Moses Staff](https://attack.mitre.org/groups/G1009), [G1013 Metador](https://attack.mitre.org/groups/G1013), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1021 Cinnamon Tempest](https://attack.mitre.org/groups/G1021), [G1032 INC Ransom](https://attack.mitre.org/groups/G1032), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1046 Storm-1811](https://attack.mitre.org/groups/G1046), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 1 software:** [S0681 Lizar](https://attack.mitre.org/software/S0681)  

---

### T1588.003 — Code Signing Certificates
<a id="t1588003"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/003)  

Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with. Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is. Prior to [Code Signing](https://attack.mitre.org/techniques/T1553/002), adversaries may purchase or steal code signing certificates for use in operations. The purchase of code signing certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal code signing materials directly from a compromised third-party.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Code Signing Certificates  
**Used by 7 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  
**Implemented by 1 software:** [S0576 MegaCortex](https://attack.mitre.org/software/S0576)  

---

### T1588.004 — Digital Certificates
<a id="t1588004"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/004)  

Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. Adversaries may purchase or steal SSL/TLS certificates to further their operations, such as encrypting C2 traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or even enabling [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) if the certificate is trusted or otherwise added to the root of trust (i.e. [Install Root Certificate](https://attack.mitre.org/techniques/T1553/004)). The purchase of digital certificates may be done using a front organization or using information stolen from a previously compromised entity that allows the adversary to validate to a certificate provider as that entity. Adversaries may also steal certificate materials directly from a compromised third-party, including from certificate authorities. Adversaries may register or hijack domains that they will later purchase an SSL/TLS certificate for. Certificate authorities exist that allow adversaries to acquire SSL/TLS certificates, such as domain validation certificates, for free. After obtaining a digital certificate, an adversary may then install that certificate (see [Install Digital Certificate](https://attack.mitre.org/techniques/T1608/003)) on infrastructure under their control.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Digital Certificates  
**Used by 7 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0098 BlackTech](https://attack.mitre.org/groups/G0098), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1588.005 — Exploits
<a id="t1588005"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/005)  

Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors. In addition to downloading free exploits from the internet, adversaries may purchase exploits from third-party entities. Third-party entities can include technology companies that specialize in exploit development, criminal marketplaces (including exploit kits), or from individuals. In addition to purchasing exploits, adversaries may steal and repurpose exploits from third-party entities (including other adversaries). An adversary may monitor exploit provider forums to understand the state of existing, as well as newly discovered, exploits. There is usually a delay between when an exploit is discovered and when it is made public. An adversary may target the systems of those known to conduct exploit research and development in order to gain that knowledge for use during a subsequent operation. Adversaries may use exploits during various phases of the adversary lifecycle (i.e. [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203), [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068), [Exploitation for Stealth](https://attack.mitre.org/techniques/T1211), [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212), [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210), and [Application or System Exploitation](https://attack.mitre.org/techniques/T1499/004)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Exploits  
**Used by 2 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  

---

### T1588.006 — Vulnerabilities
<a id="t1588006"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/006)  

Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur. Adversaries may find vulnerability information by searching open databases or gaining access to closed vulnerability databases. An adversary may monitor vulnerability disclosures/databases to understand the state of existing, as well as newly discovered, vulnerabilities. There is usually a delay between when a vulnerability is discovered and when it is made public. An adversary may target the systems of those known to conduct vulnerability research (including commercial vendors). Knowledge of a vulnerability may cause an adversary to search for an existing exploit (i.e. [Exploits](https://attack.mitre.org/techniques/T1588/005)) or to attempt to develop one themselves (i.e. [Exploits](https://attack.mitre.org/techniques/T1587/004)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Vulnerabilities  
**Used by 3 threat groups:** [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  

---

### T1588.007 — Artificial Intelligence
<a id="t1588007"></a>

sub-technique of [T1588](/techniques/resource-development.md#t1588) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1588/007)  

Adversaries may obtain access to generative artificial intelligence tools, such as large language models (LLMs), to aid various techniques during targeting. These tools may be used to inform, bolster, and enable a variety of malicious tasks, including conducting [Reconnaissance](https://attack.mitre.org/tactics/TA0043), creating basic scripts, assisting social engineering, and even developing payloads. For example, by utilizing a publicly available LLM an adversary is essentially outsourcing or automating certain tasks to the tool. Using AI, the adversary may draft and generate content in a variety of written languages to be used in [Phishing](https://attack.mitre.org/techniques/T1566)/[Phishing for Information](https://attack.mitre.org/techniques/T1598) campaigns. The same publicly available tool may further enable vulnerability or other offensive research supporting [Develop Capabilities](https://attack.mitre.org/techniques/T1587). AI tools may also automate technical tasks by generating, refining, or otherwise enhancing (e.g., [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)) malicious scripts and payloads. Finally, AI-generated text, images, audio, and video may be used for fraud, [Impersonation](https://attack.mitre.org/techniques/T1684/001), and other malicious activities.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Artificial Intelligence  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1608 — Stage Capabilities
<a id="t1608"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608)  

Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed ([Develop Capabilities](https://attack.mitre.org/techniques/T1587)) or obtained ([Obtain Capabilities](https://attack.mitre.org/techniques/T1588)) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or was otherwise compromised by them ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)). Capabilities may also be staged on web services, such as GitHub or Pastebin, or on Platform-as-a-Service (PaaS) offerings that enable users to easily provision applications. Staging of capabilities can aid the adversary in a number of initial access and post-compromise behaviors, including (but not limited to): * Staging web resources necessary to conduct [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) when a user browses to a site. * Staging web resources for a link target to be used with spearphishing. * Uploading malware or tools to a location accessible to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105). * Installing a previously acquired SSL/TLS certificate to use to encrypt command and control traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Stage Capabilities  
**Used by 1 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129)  

---

### T1608.001 — Upload Malware
<a id="t1608001"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/001)  

Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious content. Adversaries may upload malware to support their operations, such as making a payload available to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) by placing it on an Internet accessible web server. Malware may be placed on infrastructure that was previously purchased/rented by the adversary ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or was otherwise compromised by them ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)). Malware can also be staged on web services, such as GitHub or Pastebin; hosted on the InterPlanetary File System (IPFS), where decentralized content storage makes the removal of malicious files difficult; or saved on the blockchain as smart contracts, which are resilient against takedowns that would affect traditional infrastructure. Adversaries may upload backdoored files, such as software packages, application binaries, virtual machine images, or container images, to third-party software stores, package libraries, extension marketplaces, or repositories (ex: GitHub, CNET, AWS Community AMIs, Docker Hub, PyPi, NPM). By chance encounter, victims may directly download/install these backdoored files via [User Execution](https://attack.mitre.org/techniques/T1204). Masquerading, including typosquatting legitimate software, may increase the chance of users mistakenly executing these files.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Upload Malware  
**Used by 25 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0047 Gamaredon Group](https://attack.mitre.org/groups/G0047), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G0140 LazyScripter](https://attack.mitre.org/groups/G0140), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1002 BITTER](https://attack.mitre.org/groups/G1002), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1008 SideCopy](https://attack.mitre.org/groups/G1008), [G1011 EXOTIC LILY](https://attack.mitre.org/groups/G1011), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1018 TA2541](https://attack.mitre.org/groups/G1018), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020), [G1031 Saint Bear](https://attack.mitre.org/groups/G1031), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1044 APT42](https://attack.mitre.org/groups/G1044), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1608.002 — Upload Tool
<a id="t1608002"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/002)  

Adversaries may upload tools to third-party or adversary controlled infrastructure to make it accessible during targeting. Tools can be open or closed source, free or commercial. Tools can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) by placing it on an Internet accessible web server. Tools may be placed on infrastructure that was previously purchased/rented by the adversary ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or was otherwise compromised by them ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)). Tools can also be staged on web services, such as an adversary controlled GitHub repo, or on Platform-as-a-Service offerings that enable users to easily provision applications. Adversaries can avoid the need to upload a tool by having compromised victim machines download the tool directly from a third-party hosting location (ex: a non-adversary controlled GitHub repo), including the original hosting site of the tool.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Upload Tool  
**Used by 2 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  

---

### T1608.003 — Install Digital Certificate
<a id="t1608003"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/003)  

Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems. Digital certificates include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate securely with its owner. Certificates can be uploaded to a server, then the server can be configured to use the certificate to enable encrypted communication with it. Adversaries may install SSL/TLS certificates that can be used to further their operations, such as encrypting C2 traffic (ex: [Asymmetric Cryptography](https://attack.mitre.org/techniques/T1573/002) with [Web Protocols](https://attack.mitre.org/techniques/T1071/001)) or lending credibility to a credential harvesting site. Installation of digital certificates may take place for a number of server types, including web servers and email servers. Adversaries can obtain digital certificates (see [Digital Certificates](https://attack.mitre.org/techniques/T1588/004)) or create self-signed certificates (see [Digital Certificates](https://attack.mitre.org/techniques/T1587/003)). Digital certificates can then be installed on adversary controlled infrastructure that may have been acquired ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or previously compromised ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Install Digital Certificate  
**Used by 1 threat groups:** [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  

---

### T1608.004 — Drive-by Target
<a id="t1608004"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/004)  

Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). In such cases, the user's web browser is typically targeted for exploitation (often not requiring any extra user interaction once landing on the site), but adversaries may also set up websites for non-exploitation behavior such as [Application Access Token](https://attack.mitre.org/techniques/T1550/001). Prior to [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or previously compromised ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)). Adversaries may upload or inject malicious web content, such as [JavaScript](https://attack.mitre.org/techniques/T1059/007), into websites. This may be done in a number of ways, including: * Inserting malicious scripts into web pages or other user controllable web content such as forum posts * Modifying script files served to websites from publicly writeable cloud storage buckets * Crafting malicious web advertisements and purchasing ad space on a website through legitimate ad providers (i.e., [Malvertising](https://attack.mitre.org/techniques/T1583/008)) In addition to staging content to exploit a user's web browser, adversaries may also stage scripting content to profile the user's browser (as in [Gather Victim Host Information](https://attack.mitre.org/techniques/T1592)) to ensure it is vulnerable prior to attempting exploitation. Websites compromised by an adversary and used to stage a drive-by may be ones visited by a specific community, such as government, a particular industry, or region, where the goal is to compromise a specific user or set of users based on a shared interest. This kind of targeted campaign is referred to a strategic web compromise or watering hole attack. Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure ([Domains](https://attack.mitre.org/techniques/T1583/001)) to help facilitate [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Drive-by Target  
**Used by 8 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0134 Transparent Tribe](https://attack.mitre.org/groups/G0134), [G1012 CURIUM](https://attack.mitre.org/groups/G1012), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  

---

### T1608.005 — Link Target
<a id="t1608005"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/005)  

Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in [Malicious Link](https://attack.mitre.org/techniques/T1204/001). Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. Prior to a phish for information (as in [Spearphishing Link](https://attack.mitre.org/techniques/T1598/003)) or a phish to gain initial access to a system (as in [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)), an adversary must set up the resources for a link target for the spearphishing link. Typically, the resources for a link target will be an HTML page that may include some client-side script such as [JavaScript](https://attack.mitre.org/techniques/T1059/007) to decide what content to serve to the user. Adversaries may clone legitimate sites to serve as the link target, this can include cloning of login pages of legitimate web services or organization login pages in an effort to harvest credentials during [Spearphishing Link](https://attack.mitre.org/techniques/T1598/003). Adversaries may also [Upload Malware](https://attack.mitre.org/techniques/T1608/001) and have the link target point to malware for download/execution by the user. Adversaries may purchase domains similar to legitimate domains (ex: homoglyphs, typosquatting, different top-level domain, etc.) during acquisition of infrastructure ([Domains](https://attack.mitre.org/techniques/T1583/001)) to help facilitate [Malicious Link](https://attack.mitre.org/techniques/T1204/001). Links can be written by adversaries to mask the true destination in order to deceive victims by abusing the URL schema and increasing the effectiveness of phishing. Adversaries may also use free or paid accounts on link shortening services and Platform-as-a-Service providers to host link targets while taking advantage of the widely trusted domains of those providers to avoid being blocked while redirecting victims to malicious pages. In addition, adversaries may serve a variety of malicious links through uniquely generated URIs/URLs (including one-time, single use links). Finally, adversaries may take advantage of the decentralized nature of the InterPlanetary File System (IPFS) to host link targets that are difficult to remove.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Link Target  
**Used by 3 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014)  

---

### T1608.006 — SEO Poisoning
<a id="t1608006"></a>

sub-technique of [T1608](/techniques/resource-development.md#t1608) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1608/006)  

Adversaries may poison mechanisms that influence search engine optimization (SEO) to further lure staged capabilities towards potential victims. Search engines typically display results to users based on purchased ads as well as the site’s ranking/score/reputation calculated by their web crawlers and algorithms. To help facilitate [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), adversaries may stage content that explicitly manipulates SEO rankings in order to promote sites hosting their malicious payloads (such as [Drive-by Target](https://attack.mitre.org/techniques/T1608/004)) within search engines. Poisoning SEO rankings may involve various tricks, such as stuffing keywords (including in the form of hidden text) into compromised sites. These keywords could be related to the interests/browsing habits of the intended victim(s) as well as more broad, seasonably popular topics (e.g. elections, trending news). In addition to internet search engines (such as Google), adversaries may also aim to manipulate specific in-site searches for developer platforms (such as GitHub) to deceive users towards [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195) lures. In-site searches will rank search results according to their own algorithms and metrics such as popularity which may be targeted and gamed by malicious actors. Adversaries may also purchase or plant incoming links to staged capabilities in order to boost the site’s calculated relevance and reputation. SEO poisoning may also be combined with evasive redirects and other cloaking mechanisms (such as measuring mouse movements or serving content based on browser user agents, user language/localization settings, or HTTP headers) in order to feed SEO inputs while avoiding scrutiny from defenders.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of SEO Poisoning  
**Used by 1 threat groups:** [G1020 Mustard Tempest](https://attack.mitre.org/groups/G1020)  

---

### T1650 — Acquire Access
<a id="t1650"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1650)  

Adversaries may purchase or otherwise acquire an existing access to a target system or network. A variety of online services and initial access broker networks are available to sell access to previously compromised systems. In some cases, adversary groups may form partnerships to share compromised systems with each other. Footholds to compromised systems may take a variety of forms, such as access to planted backdoors (e.g., [Web Shell](https://attack.mitre.org/techniques/T1505/003)) or established access via [External Remote Services](https://attack.mitre.org/techniques/T1133). In some cases, access brokers will implant compromised systems with a “load” that can be used to install additional malware for paying customers. By leveraging existing access broker networks rather than developing or obtaining their own initial access capabilities, an adversary can potentially reduce the resources required to gain a foothold on a target network and focus their efforts on later stages of compromise. Adversaries may prioritize acquiring access to systems that have been determined to lack security monitoring or that have high privileges, or systems that belong to organizations in a particular sector. In some cases, purchasing access to an organization in sectors such as IT contracting, software development, or telecommunications may allow an adversary to compromise additional victims via a [Trusted Relationship](https://attack.mitre.org/techniques/T1199), [Multi-Factor Authentication Interception](https://attack.mitre.org/techniques/T1111), or even [Supply Chain Compromise](https://attack.mitre.org/techniques/T1195). **Note:** while this technique is distinct from other behaviors such as [Purchase Technical Data](https://attack.mitre.org/techniques/T1597/002) and [Credentials](https://attack.mitre.org/techniques/T1589/001), they may often be used in conjunction (especially where the acquired foothold requires [Valid Accounts](https://attack.mitre.org/techniques/T1078)).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detection of Acquire Access  
**Used by 1 threat groups:** [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  

---

### T1683 — Generate Content
<a id="t1683"></a>

**Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1683)  

Adversaries may create or generate content to support targeting and operations. This content may be used to establish personas, impersonate known individuals or organizations, and support Social Engineering, fraud, or influence activities. Written materials, audio, images, video, or other media may be developed and tailored to the target and objective. Content development may occur prior to or during an operation. Adversaries may develop or generate content in-house, source it through third parties, or produce it using AI-assisted tools. Adversaries may use AI to research targets, develop pretexts, and better understand the organizations and individuals they intend to target or deceive prior to generating content (i.e., Query Public AI Services); for obtaining access to AI tools used in content generation, see Artificial Intelligence. Content may be leveraged in support of techniques such as Phishing, Phishing for Information, Social Engineering, Financial Theft, or Establish Accounts. Generated or developed content does not include malicious code or scripts (i.e., Develop Capabilities and Artificial Intelligence).

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  

---

### T1683.001 — Written Content
<a id="t1683001"></a>

sub-technique of [T1683](/techniques/resource-development.md#t1683) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1683/001)  

Adversaries may create or tailor written materials to support targeting and malicious operations. Content may include phishing lures, fraudulent financial communications, fabricated job postings, fabricated employment credentials and documentation, decoy documents, social media persona content, and supporting narratives used to sustain fabricated personas over time. Content may be authored manually, commissioned through third parties, or produced using AI-assisted tools. Written materials may impersonate legitimate government correspondence, diplomatic communications, or internal organizational documents to support targeting efforts. AI-assisted tools may also be used to tailor content to specific targets, industries, or regions. For example, adversaries may leverage AI to translate content into a target's native language or mimic the communication style of trusted senders. Written content produced through these methods may be used in support of other techniques, such as Phishing, Spearphishing via Service, Phishing for Information, Internal Spearphishing, Social Engineering, Financial Theft, or Establish Accounts. Written content does not include malicious code or scripts; for development of malicious code and scripts, see Develop Capabilities.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**Used by 2 threat groups:** [G0099 APT-C-36](https://attack.mitre.org/groups/G0099), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---

### T1683.002 — Audio-Visual Content
<a id="t1683002"></a>

sub-technique of [T1683](/techniques/resource-development.md#t1683) · **Tactics:** Resource Development · **Platforms:** PRE · [ATT&CK ↗](https://attack.mitre.org/techniques/T1683/002)  

Adversaries may create or manipulate audio, image, and video content to support targeting and malicious operations. Adversaries may also use synthetic voice recordings, real-time altered audio or video during live interactions, fabricated profile photos and identity documents, or video content depicting fabricated or impersonated individuals. Content may be produced manually through editing tools, generated using AI-assisted tools, or produced using third-party synthetic services. AI-assisted tools have enabled adversaries to produce synthetic media at scale and generate content that is more difficult to identify as inauthentic. Audio-visual content produced through these methods may be used in support of other techniques, such as Phishing, Spearphishing via Service, Phishing for Information, Internal Spearphishing, Social Engineering, Financial Theft, or Establish Accounts.

**ATT&CK mitigations (1):** [M1056 Pre-compromise](../ATTACK_MITIGATIONS_REFERENCE.md#m1056)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**Used by 2 threat groups:** [G0099 APT-C-36](https://attack.mitre.org/groups/G0099), [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  

---
