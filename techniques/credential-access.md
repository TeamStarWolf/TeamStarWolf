# Credential Access — Technique Detail

> Full detail pages for the **52 ATT&CK techniques** whose primary tactic is [Credential Access](https://attack.mitre.org/tactics/TA0006/) (ATT&CK Enterprise v19.2). Each entry consolidates the ATT&CK description, mitigations, NIST 800-53 controls, detection guidance, and the threat groups and software that use it. See the [Technique Atlas](../ATTACK_TECHNIQUE_ATLAS.md) for the matrix view and [all techniques index](/techniques/README.md).

---

### T1003 — OS Credential Dumping
<a id="t1003"></a>

**Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003)  

Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures. Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information. Several of the tools mentioned in associated sub-techniques may be used by both adversaries and professional security testers. Additional custom tools likely exist as well.

**ATT&CK mitigations (9):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
**NIST 800-53 R5 controls (22):** `AC-16`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `CP-9`, `IA-2`, `IA-4`, `IA-5`, `SC-28`, `SC-39`, `SI-12`, `SI-2`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Credential Dumping via Sensitive Memory and Registry Access Correlation  
**Used by 13 threat groups:** [G0001 Axiom](https://attack.mitre.org/groups/G0001), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0033 Poseidon Group](https://attack.mitre.org/groups/G0033), [G0039 Suckfly](https://attack.mitre.org/groups/G0039), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0054 Sowbug](https://attack.mitre.org/groups/G0054), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0131 Tonto Team](https://attack.mitre.org/groups/G0131), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1043 BlackByte](https://attack.mitre.org/groups/G1043), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 7 software:** [S0030 Carbanak](https://attack.mitre.org/software/S0030), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0052 OnionDuke](https://attack.mitre.org/software/S0052), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0232 HOMEFRY](https://attack.mitre.org/software/S0232), [S0379 Revenge RAT](https://attack.mitre.org/software/S0379), [S1146 MgBot](https://attack.mitre.org/software/S1146)  

---

### T1003.001 — LSASS Memory
<a id="t1003001"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/001)  

Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550). As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system. For example, on the target host use procdump: * <code>procdump -ma lsass.exe lsass_dump</code> Locally, mimikatz can be run using: * <code>sekurlsa::Minidump lsassdump.dmp</code> * <code>sekurlsa::logonPasswords</code> Built-in Windows tools such as `comsvcs.dll` can also be used: * <code>rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID lsass.dmp full</code> Similar to [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012), the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`). Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called. The following SSPs can be used to access credentials: * Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package. * Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. * Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later. * CredSSP: Provides SSO and Network Level Authentication for Remote Desktop Services.

**ATT&CK mitigations (7):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1025 Privileged Process Integrity](../ATTACK_MITIGATIONS_REFERENCE.md#m1025), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1040 Behavior Prevention on Endpoint](../ATTACK_MITIGATIONS_REFERENCE.md#m1040), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043)  
**NIST 800-53 R5 controls (19):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-3`, `SC-39`, `SI-16`, `SI-2`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Credential Dumping from LSASS Memory via Access and Dump Sequence  
**Used by 42 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0006 APT1](https://attack.mitre.org/groups/G0006), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0050 APT32](https://attack.mitre.org/groups/G0050), [G0059 Magic Hound](https://attack.mitre.org/groups/G0059), [G0060 BRONZE BUTLER](https://attack.mitre.org/groups/G0060), [G0061 FIN8](https://attack.mitre.org/groups/G0061), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0065 Leviathan](https://attack.mitre.org/groups/G0065), [G0068 PLATINUM](https://attack.mitre.org/groups/G0068), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0091 Silence](https://attack.mitre.org/groups/G0091), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0107 Whitefly](https://attack.mitre.org/groups/G0107), [G0108 Blue Mockingbird](https://attack.mitre.org/groups/G0108), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G0143 Aquatic Panda](https://attack.mitre.org/groups/G0143), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1036 Moonstone Sleet](https://attack.mitre.org/groups/G1036), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1040 Play](https://attack.mitre.org/groups/G1040), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 26 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0005 Windows Credential Editor](https://attack.mitre.org/software/S0005), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0056 Net Crawler](https://attack.mitre.org/software/S0056), [S0121 Lslsass](https://attack.mitre.org/software/S0121), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0187 Daserf](https://attack.mitre.org/software/S0187), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0342 GreyEnergy](https://attack.mitre.org/software/S0342), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0368 NotPetya](https://attack.mitre.org/software/S0368), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0439 Okrum](https://attack.mitre.org/software/S0439), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1242 Qilin](https://attack.mitre.org/software/S1242)  

---

### T1003.002 — Security Account Manager
<a id="t1003002"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/002)  

Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the <code>net user</code> command. Enumerating the SAM database requires SYSTEM level access. A number of tools can be used to retrieve the SAM file through in-memory techniques: * pwdumpx.exe * [gsecdump](https://attack.mitre.org/software/S0008) * [Mimikatz](https://attack.mitre.org/software/S0002) * secretsdump.py Alternatively, the SAM can be extracted from the Registry with Reg: * <code>reg save HKLM\sam sam</code> * <code>reg save HKLM\system system</code> Creddump7 can then be used to process the SAM database locally to retrieve hashes. Notes: * RID 500 account is the local, built-in administrator. * RID 501 is the guest account. * User accounts start with a RID of 1,000+.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (15):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Credential Dumping from SAM via Registry Dump and Local File Access  
**Used by 13 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0093 GALLIUM](https://attack.mitre.org/groups/G0093), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1023 APT5](https://attack.mitre.org/groups/G1023), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1034 Daggerfly](https://attack.mitre.org/groups/G1034)  
**Implemented by 15 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0006 pwdump](https://attack.mitre.org/software/S0006), [S0008 gsecdump](https://attack.mitre.org/software/S0008), [S0046 CozyCar](https://attack.mitre.org/software/S0046), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0080 Mivast](https://attack.mitre.org/software/S0080), [S0120 Fgdump](https://attack.mitre.org/software/S0120), [S0125 Remsec](https://attack.mitre.org/software/S0125), [S0154 Cobalt Strike](https://attack.mitre.org/software/S0154), [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0371 POWERTON](https://attack.mitre.org/software/S0371), [S0376 HOPLIGHT](https://attack.mitre.org/software/S0376), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S1022 IceApple](https://attack.mitre.org/software/S1022)  

---

### T1003.003 — NTDS
<a id="t1003003"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/003)  

Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in <code>%SystemRoot%\NTDS\Ntds.dit</code> of a domain controller. In addition to looking for NTDS files on active Domain Controllers, adversaries may search for backups that contain the same or similar information. The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes. * Volume Shadow Copy * secretsdump.py * Using the in-built Windows tool, ntdsutil.exe * Invoke-NinjaCopy

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (18):** `AC-16`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CP-9`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection of NTDS.dit Credential Dumping from Domain Controllers  
**Used by 17 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1051 Medusa Group](https://attack.mitre.org/groups/G1051)  
**Implemented by 4 software:** [S0250 Koadic](https://attack.mitre.org/software/S0250), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0404 esentutl](https://attack.mitre.org/software/S0404), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488)  

---

### T1003.004 — LSA Secrets
<a id="t1003004"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/004)  

Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts. LSA secrets are stored in the registry at <code>HKEY_LOCAL_MACHINE\SECURITY\Policy\Secrets</code>. LSA secrets can also be dumped from memory. [Reg](https://attack.mitre.org/software/S0075) can be used to extract from the Registry. [Mimikatz](https://attack.mitre.org/software/S0002) can be used to extract secrets from memory.

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of LSA Secrets Dumping via Registry and Memory Extraction  
**Used by 10 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0045 menuPass](https://attack.mitre.org/groups/G0045), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003)  
**Implemented by 9 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0008 gsecdump](https://attack.mitre.org/software/S0008), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1022 IceApple](https://attack.mitre.org/software/S1022)  

---

### T1003.005 — Cached Domain Credentials
<a id="t1003005"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows, Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/005)  

Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable. On Windows Vista and newer, the hash format is DCC2 (Domain Cached Credentials version 2) hash, also known as MS-Cache v2 hash. The number of default cached credentials varies and can be altered per system. This hash does not allow pass-the-hash style attacks, and instead requires [Password Cracking](https://attack.mitre.org/techniques/T1110/002) to recover the plaintext password. On Linux systems, Active Directory credentials can be accessed through caches maintained by software like System Security Services Daemon (SSSD) or Quest Authentication Services (formerly VAS). Cached credential hashes are typically located at `/var/lib/sss/db/cache.[domain].ldb` for SSSD or `/var/opt/quest/vas/authcache/vas_auth.vdb` for Quest. Adversaries can use utilities, such as `tdbdump`, on these database files to dump the cached hashes and use [Password Cracking](https://attack.mitre.org/techniques/T1110/002) to obtain the plaintext password. With SYSTEM or sudo access, the tools/utilities such as [Mimikatz](https://attack.mitre.org/software/S0002), [Reg](https://attack.mitre.org/software/S0075), and secretsdump.py for Windows or Linikatz for Linux can be used to extract the cached credentials. Note: Cached credentials for Windows Vista are derived using PBKDF2.

**ATT&CK mitigations (5):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (17):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-4`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Cached Domain Credential Dumping via Local Hash Cache Access  
**Used by 4 threat groups:** [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077)  
**Implemented by 4 software:** [S0119 Cachedump](https://attack.mitre.org/software/S0119), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0439 Okrum](https://attack.mitre.org/software/S0439)  

---

### T1003.006 — DCSync
<a id="t1003006"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/006)  

Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API) to simulate the replication process from a remote domain controller using a technique called DCSync. Members of the Administrators, Domain Admins, and Enterprise Admin groups or computer accounts on the domain controller are able to run DCSync to pull password data from Active Directory, which may include current and historical hashes of potentially useful accounts such as KRBTGT and Administrators. The hashes can then in turn be used to create a [Golden Ticket](https://attack.mitre.org/techniques/T1558/001) for use in [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) or change an account's password as noted in [Account Manipulation](https://attack.mitre.org/techniques/T1098). DCSync functionality has been included in the "lsadump" module in [Mimikatz](https://attack.mitre.org/software/S0002). Lsadump also includes NetSync, which performs DCSync over a legacy replication protocol.

**ATT&CK mitigations (3):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (16):** `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-4`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Unauthorized DCSync Operations via Replication API Abuse  
**Used by 4 threat groups:** [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1006 Earth Lusca](https://attack.mitre.org/groups/G1006), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002)  

---

### T1003.007 — Proc Filesystem
<a id="t1003007"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/007)  

Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the `/proc/<PID>/maps` file shows how memory is mapped within the process’s virtual address space. And `/proc/<PID>/mem`, exposed for debugging purposes, provides access to the process’s virtual address space. When executing with root privileges, adversaries can search these memory locations for all processes on a system that contain patterns indicative of credentials. Adversaries may use regex patterns, such as <code>grep -E "^[0-9a-f-]* r" /proc/"$pid"/maps | cut -d' ' -f 1</code>, to look for fixed strings in memory structures or cached hashes. When running without privileged access, processes can still view their own virtual memory locations. Some services or programs may save credentials in clear text inside the process’s memory. If running as or with the permissions of a web browser, a process can search the `/maps` & `/mem` locations for common website credential patterns (that can also be used to find adjacent memory within the same structure) in which hashes or cleartext credentials may be located.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detecting OS Credential Dumping via /proc Filesystem Access on Linux  
**Implemented by 3 software:** [S0179 MimiPenguin](https://attack.mitre.org/software/S0179), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S1109 PACEMAKER](https://attack.mitre.org/software/S1109)  

---

### T1003.008 — /etc/passwd and /etc/shadow
<a id="t1003008"></a>

sub-technique of [T1003](/techniques/credential-access.md#t1003) · **Tactics:** Credential Access · **Platforms:** Linux · [ATT&CK ↗](https://attack.mitre.org/techniques/T1003/008)  

Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking. Most modern Linux operating systems use a combination of <code>/etc/passwd</code> and <code>/etc/shadow</code> to store user account information, including password hashes in <code>/etc/shadow</code>. By default, <code>/etc/shadow</code> is only readable by the root user. Linux stores user information such as user ID, group ID, home directory path, and login shell in <code>/etc/passwd</code>. A "user" on the system may belong to a person or a service. All password hashes are stored in <code>/etc/shadow</code> - including entries for users with no passwords and users with locked or disabled accounts. Adversaries may attempt to read or dump the <code>/etc/passwd</code> and <code>/etc/shadow</code> files on Linux systems via command line utilities such as the <code>cat</code> command. Additionally, the Linux utility <code>unshadow</code> can be used to combine the two files in a format suited for password cracking utilities such as John the Ripper - for example, via the command <code>/usr/bin/unshadow /etc/passwd /etc/shadow > /tmp/crack.password.db</code>. Since the user information stored in <code>/etc/passwd</code> are linked to the password hashes in <code>/etc/shadow</code>, an adversary would need to have access to both.

**ATT&CK mitigations (2):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-28`, `SC-39`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Credential Access via /etc/passwd and /etc/shadow Parsing  
**Implemented by 1 software:** [S0349 LaZagne](https://attack.mitre.org/software/S0349)  

---

### T1040 — Network Sniffing
<a id="t1040"></a>

**Tactics:** Credential Access, Discovery · **Platforms:** Linux, macOS, Windows, Network Devices, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1040)  

Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [Name Resolution Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary. Network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and/or [Stealth](https://attack.mitre.org/tactics/TA0005) activities. Adversaries may likely also utilize network sniffing during [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) (AiTM) to passively gain additional knowledge about the environment. In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to. Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic. The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic. On network devices, adversaries may perform network captures using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `monitor capture`.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (12):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `CM-7`, `IA-2`, `IA-5`, `SC-4`, `SC-8`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Network Sniffing Across Platforms  
**Used by 8 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045), [G1047 Velvet Ant](https://attack.mitre.org/groups/G1047), [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  
**Implemented by 16 software:** [S0019 Regin](https://attack.mitre.org/software/S0019), [S0174 Responder](https://attack.mitre.org/software/S0174), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0443 MESSAGETAP](https://attack.mitre.org/software/S0443), [S0587 Penquin](https://attack.mitre.org/software/S0587), [S0590 NBTscan](https://attack.mitre.org/software/S0590), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S1154 VersaMem](https://attack.mitre.org/software/S1154), [S1186 Line Dancer](https://attack.mitre.org/software/S1186), [S1203 J-magic](https://attack.mitre.org/software/S1203), [S1204 cd00r](https://attack.mitre.org/software/S1204), [S1206 JumbledPath](https://attack.mitre.org/software/S1206), [S1224 CASTLETAP](https://attack.mitre.org/software/S1224)  

---

### T1110 — Brute Force
<a id="t1110"></a>

**Tactics:** Credential Access · **Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, macOS, Network Devices, Office Suite, SaaS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110)  

Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism. Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes. Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), [Account Discovery](https://attack.mitre.org/techniques/T1087), or [Password Policy Discovery](https://attack.mitre.org/techniques/T1201). Adversaries may also combine brute forcing activity with behaviors such as [External Remote Services](https://attack.mitre.org/techniques/T1133) as part of Initial Access. If an adversary guesses the correct password but fails to login to a compromised account due to location-based conditional access policies, they may change their infrastructure until they match the victim’s location and therefore bypass those policies.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Brute Force Authentication Failures with Multi-Platform Log Correlation  
**Used by 14 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0053 FIN5](https://attack.mitre.org/groups/G0053), [G0082 APT38](https://attack.mitre.org/groups/G0082), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0105 DarkVishnya](https://attack.mitre.org/groups/G0105), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1030 Agrius](https://attack.mitre.org/groups/G1030), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 7 software:** [S0220 Chaos](https://attack.mitre.org/software/S0220), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0572 Caterpillar WebShell](https://attack.mitre.org/software/S0572), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0650 QakBot](https://attack.mitre.org/software/S0650)  

---

### T1110.001 — Password Guessing
<a id="t1110001"></a>

sub-technique of [T1110](/techniques/credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Containers, Network Devices, Office Suite, Identity Provider, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/001)  

Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts. Guessing passwords can be a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. Typically, management services over commonly used ports are used when guessing passwords. Commonly targeted services include the following: * SSH (22/TCP) * Telnet (23/TCP) * FTP (21/TCP) * NetBIOS / SMB / Samba (139/TCP & 445/TCP) * LDAP (389/TCP) * Kerberos (88/TCP) * RDP / Terminal Services (3389/TCP) * HTTP/HTTP Management Services (80/TCP & 443/TCP) * MSSQL (1433/TCP) * Oracle (1521/TCP) * MySQL (3306/TCP) * VNC (5900/TCP) * SNMP (161/UDP and 162/TCP/UDP) In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.. Further, adversaries may abuse network device interfaces (such as `wlanAPI`) to brute force accessible wifi-router(s) via wireless authentication protocols. In default environments, LDAP and Kerberos connection attempts are less likely to trigger events over SMB, which creates Windows "logon failure" event ID 4625.

**ATT&CK mitigations (4):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Password Guessing via Multi-Source Authentication Failure Correlation  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 9 software:** [S0020 China Chopper](https://attack.mitre.org/software/S0020), [S0341 Xbash](https://attack.mitre.org/software/S0341), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0374 SpeakUp](https://attack.mitre.org/software/S0374), [S0453 Pony](https://attack.mitre.org/software/S0453), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0532 Lucifer](https://attack.mitre.org/software/S0532), [S0598 P.A.S. Webshell](https://attack.mitre.org/software/S0598), [S0698 HermeticWizard](https://attack.mitre.org/software/S0698)  

---

### T1110.002 — Password Cracking
<a id="t1110002"></a>

sub-technique of [T1110](/techniques/credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows, Network Devices, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/002)  

Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) can be used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option. Further, adversaries may leverage [Data from Configuration Repository](https://attack.mitre.org/techniques/T1602) in order to obtain hashed credentials for network devices. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network. The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access.

**ATT&CK mitigations (2):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Post-Credential Dump Password Cracking Detection via Suspicious File Access and Hash Analysis Tools  
**Used by 4 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G1045 Salt Typhoon](https://attack.mitre.org/groups/G1045)  
**Implemented by 1 software:** [S0056 Net Crawler](https://attack.mitre.org/software/S0056)  

---

### T1110.003 — Password Spraying
<a id="t1110003"></a>

sub-technique of [T1110](/techniques/credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Containers, ESXi, IaaS, Identity Provider, Linux, Network Devices, Office Suite, SaaS, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/003)  

Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. Typically, management services over commonly used ports are used when password spraying. Commonly targeted services include the following: * SSH (22/TCP) * Telnet (23/TCP) * FTP (21/TCP) * NetBIOS / SMB / Samba (139/TCP & 445/TCP) * LDAP (389/TCP) * Kerberos (88/TCP) * RDP / Terminal Services (3389/TCP) * HTTP/HTTP Management Services (80/TCP & 443/TCP) * MSSQL (1433/TCP) * Oracle (1521/TCP) * MySQL (3306/TCP) * VNC (5900/TCP) In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365. In order to avoid detection thresholds, adversaries may deliberately throttle password spraying attempts to avoid triggering security alerting. Additionally, adversaries may leverage LDAP and Kerberos authentication attempts, which are less likely to trigger high-visibility events such as Windows "logon failure" event ID 4625 that is commonly triggered by failed SMB connection attempts.

**ATT&CK mitigations (3):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Distributed Password Spraying via Authentication Failures Across Multiple Accounts  
**Used by 11 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016), [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G0122 Silent Librarian](https://attack.mitre.org/groups/G0122), [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1030 Agrius](https://attack.mitre.org/groups/G1030)  
**Implemented by 4 software:** [S0362 Linux Rabbit](https://attack.mitre.org/software/S0362), [S0413 MailSniper](https://attack.mitre.org/software/S0413), [S0488 CrackMapExec](https://attack.mitre.org/software/S0488), [S0606 Bad Rabbit](https://attack.mitre.org/software/S0606)  

---

### T1110.004 — Credential Stuffing
<a id="t1110004"></a>

sub-technique of [T1110](/techniques/credential-access.md#t1110) · **Tactics:** Credential Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Containers, Network Devices, Office Suite, Identity Provider, ESXi · [ATT&CK ↗](https://attack.mitre.org/techniques/T1110/004)  

Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts. Credential stuffing is a risky option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies. Typically, management services over commonly used ports are used when stuffing credentials. Commonly targeted services include the following: * SSH (22/TCP) * Telnet (23/TCP) * FTP (21/TCP) * NetBIOS / SMB / Samba (139/TCP & 445/TCP) * LDAP (389/TCP) * Kerberos (88/TCP) * RDP / Terminal Services (3389/TCP) * HTTP/HTTP Management Services (80/TCP & 443/TCP) * MSSQL (1433/TCP) * Oracle (1521/TCP) * MySQL (3306/TCP) * VNC (5900/TCP) In addition to management services, adversaries may "target single sign-on (SSO) and cloud-based applications utilizing federated authentication protocols," as well as externally facing email applications, such as Office 365.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (14):** `AC-2`, `AC-20`, `AC-3`, `AC-5`, `AC-6`, `AC-7`, `CA-7`, `CM-2`, `CM-6`, `IA-11`, `IA-2`, `IA-4`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Credential Stuffing Detection via Reused Breached Credentials Across Services  
**Used by 1 threat groups:** [G0114 Chimera](https://attack.mitre.org/groups/G0114)  
**Implemented by 1 software:** [S0266 TrickBot](https://attack.mitre.org/software/S0266)  

---

### T1111 — Multi-Factor Authentication Interception
<a id="t1111"></a>

**Tactics:** Credential Access · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1111)  

Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms. If a smart card is used for multi-factor authentication, then a keylogger will need to be used to obtain the password associated with a smart card during normal use. With both an inserted card and access to the smart card password, an adversary can connect to a network resource using the infected system to proxy the authentication with the inserted hardware token. Adversaries may also employ a keylogger to similarly target other hardware tokens, such as RSA SecurID. Capturing token input (including a user's personal identification code) may provide temporary access (i.e. replay the one-time passcode until the next value rollover) as well as possibly enabling adversaries to reliably predict future authentication values (given access to both the algorithm and any seed values used to generate appended temporary codes). Other methods of MFA may be intercepted and used by an adversary to authenticate. It is common for one-time codes to be sent via out-of-band communications (email, SMS). If the device and/or service is not secured, then it may be vulnerable to interception. Service providers can also be targeted: for example, an adversary may compromise an SMS messaging service in order to steal MFA codes sent to users’ phones.

**ATT&CK mitigations (1):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017)  
**NIST 800-53 R5 controls (9):** `AC-20`, `CA-7`, `CM-2`, `CM-6`, `IA-13`, `IA-2`, `IA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for MFA Interception via Input Capture and Smart Card Proxying  
**Used by 4 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0114 Chimera](https://attack.mitre.org/groups/G0114), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 2 software:** [S0018 Sykipot](https://attack.mitre.org/software/S0018), [S1104 SLOWPULSE](https://attack.mitre.org/software/S1104)  

---

### T1187 — Forced Authentication
<a id="t1187"></a>

**Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1187)  

Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept. The Server Message Block (SMB) protocol is commonly used in Windows networks for authentication and communication between systems for access to resources and file sharing. When a Windows system attempts to connect to an SMB resource it will automatically attempt to authenticate and send credential information for the current user to the remote system. This behavior is typical in enterprise environments so that users do not need to enter credentials to access network resources. Web Distributed Authoring and Versioning (WebDAV) is also typically used by Windows systems as a backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will typically operate over TCP ports 80 and 443. Adversaries may take advantage of this behavior to gain access to user account hashes through forced SMB/WebDAV authentication. An adversary can send an attachment to a user through spearphishing that contains a resource link to an external server controlled by the adversary (i.e. [Template Injection](https://attack.mitre.org/techniques/T1221)), or place a specially crafted file on navigation path for privileged accounts (e.g..SCF file placed on desktop) or on a publicly accessible share to be accessed by victim(s). When the user's system accesses the untrusted resource, it will attempt authentication and send information, including the user's hashed credentials, over SMB to the adversary-controlled server. With access to the credential hash, an adversary can perform off-line [Brute Force](https://attack.mitre.org/techniques/T1110) cracking to gain access to plaintext credentials. There are several different ways this can occur. Some specifics from in-the-wild use include: * A spearphishing attachment containing a document with a resource that is automatically loaded when the document is opened (i.e. [Template Injection](https://attack.mitre.org/techniques/T1221)). The document can include, for example, a request similar to <code>file[:]//[remote address]/Normal.dotm</code> to trigger the SMB request. * A modified.LNK or.SCF file with the icon filename pointing to an external reference such as <code>\\[remote address]\pic.png</code> that will force the system to load the resource when the icon is rendered to repeatedly gather credentials. Alternatively, by leveraging the <code>EfsRpcOpenFileRaw</code> function, an adversary can send SMB requests to a remote system's MS-EFSRPC interface and force the victim computer to initiate an authentication procedure and share its authentication details. The Encrypting File System Remote Protocol (EFSRPC) is a protocol used in Windows networks for maintenance and management operations on encrypted data that is stored remotely to be accessed over a network. Utilization of <code>EfsRpcOpenFileRaw</code> function in EFSRPC is used to open an encrypted object on the server for backup or restore. Adversaries can collect this data and abuse it as part of a NTLM relay attack to gain access to remote systems on the same internal network.

**ATT&CK mitigations (2):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (10):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detect Forced SMB/WebDAV Authentication via lure files and outbound NTLM  
**Used by 2 threat groups:** [G0035 Dragonfly](https://attack.mitre.org/groups/G0035), [G0079 DarkHydrus](https://attack.mitre.org/groups/G0079)  
**Implemented by 1 software:** [S0634 EnvyScout](https://attack.mitre.org/software/S0634)  

---

### T1212 — Exploitation for Credential Access
<a id="t1212"></a>

**Tactics:** Credential Access · **Platforms:** Linux, Windows, macOS, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1212)  

Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Credentialing and authentication mechanisms may be targeted for exploitation by adversaries as a means to gain access to useful credentials or circumvent the process to gain authenticated access to systems. One example of this is `MS14-068`, which targets Kerberos and can be used to forge Kerberos tickets using domain user permissions. Another example of this is replay attacks, in which the adversary intercepts data packets sent between parties and then later replays these packets. If services don't properly validate authentication requests, these replayed packets may allow an adversary to impersonate one of the parties and gain unauthorized access or privileges. Such exploitation has been demonstrated in cloud environments as well. For example, adversaries have exploited vulnerabilities in public cloud infrastructure that allowed for unintended authentication token creation and renewal. Exploitation for credential access may also result in Privilege Escalation depending on the process targeted or credentials obtained.

**ATT&CK mitigations (5):** [M1013 Application Developer Guidance](../ATTACK_MITIGATIONS_REFERENCE.md#m1013), [M1019 Threat Intelligence Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1019), [M1048 Application Isolation and Sandboxing](../ATTACK_MITIGATIONS_REFERENCE.md#m1048), [M1050 Exploit Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1050), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (24):** `AC-2`, `AC-4`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `CM-8`, `IA-2`, `IA-5`, `RA-10`, `RA-5`, `SC-18`, `SC-2`, `SC-26`, `SC-3`, `SC-30`, `SC-35`, `SC-39`, `SC-7`, `SI-2`, `SI-3`, `SI-4`, `SI-5`, `SI-7`  
**ATT&CK detection strategy:** Detection Strategy for Exploitation for Credential Access  
**Used by 1 threat groups:** [G1048 UNC3886](https://attack.mitre.org/groups/G1048)  

---

### T1528 — Steal Application Access Token
<a id="t1528"></a>

**Tactics:** Credential Access · **Platforms:** SaaS, Containers, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1528)  

Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources. Application access tokens are used to make authorized API requests on behalf of a user or service and are commonly used as a way to access resources in cloud and container-based applications and software-as-a-service (SaaS). Adversaries who steal account API tokens in cloud and containerized environments may be able to access data and perform actions with the permissions of these accounts, which can lead to privilege escalation and further compromise of the environment. For example, in Kubernetes environments, processes running inside a container may communicate with the Kubernetes API server using service account tokens. If a container is compromised, an adversary may be able to steal the container’s token and thereby gain access to Kubernetes API commands. Similarly, instances within continuous-development / continuous-integration (CI/CD) pipelines will often use API tokens to authenticate to other services for testing and deployment. If these pipelines are compromised, adversaries may be able to steal these tokens and leverage their privileges. In Azure, an adversary who compromises a resource with an attached Managed Identity, such as an Azure VM, can request short-lived tokens through the Azure Instance Metadata Service (IMDS). These tokens can then facilitate unauthorized actions or further access to other Azure services, bypassing typical credential-based authentication. Token theft can also occur through social engineering, in which case user action may be required to grant access. OAuth is one commonly implemented framework that issues tokens to users for access to systems. An application desiring access to cloud-based services or protected APIs can gain entry using OAuth 2.0 through a variety of authorization protocols. An example commonly-used sequence is Microsoft's Authorization Code Grant flow. An OAuth access token enables a third-party application to interact with resources containing user data in the ways requested by the application without obtaining user credentials. Adversaries can leverage OAuth authorization by constructing a malicious application designed to be granted access to resources with the target user's OAuth token. The adversary will need to complete registration of their application with the authorization server, for example Microsoft Identity Platform using Azure Portal, the Visual Studio IDE, the command-line interface, PowerShell, or REST API calls. Then, they can send a [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002) to the target user to entice them to grant access to the application. Once the OAuth access token is granted, the application can gain potentially long-term access to features of the user account through [Application Access Token](https://attack.mitre.org/techniques/T1550/001). Application access tokens may function within a limited lifetime, limiting how long an adversary can utilize the stolen token. However, in some cases, adversaries can also steal application refresh tokens, allowing them to obtain new access tokens without prompting the user.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (19):** `AC-10`, `AC-2`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-13`, `IA-2`, `IA-4`, `IA-5`, `IA-8`, `RA-5`, `SA-11`, `SA-15`, `SI-4`  
**ATT&CK detection strategy:** Detection Strategy for T1528 - Steal Application Access Token  
**Used by 2 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007), [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 2 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1539 — Steal Web Session Cookie
<a id="t1539"></a>

**Tactics:** Credential Access · **Platforms:** Linux, Office Suite, SaaS, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1539)  

An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website. Cookies are often valid for an extended period of time, even if the web application is not actively used. Cookies can be found on disk, in the process memory of the browser, and in network traffic to remote systems. Additionally, other applications on the targets machine might store sensitive authentication cookies in memory (e.g. apps which authenticate to cloud services). Session cookies can be used to bypasses some multi-factor authentication protocols. There are several examples of malware targeting cookies from web browsers on the local system. Adversaries may also steal cookies by injecting malicious JavaScript content into websites or relying on [User Execution](https://attack.mitre.org/techniques/T1204) by tricking victims into running malicious JavaScript in their browser. There are also open source frameworks such as `Evilginx2` and `Muraena` that can gather session cookies through a malicious proxy (e.g., [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557)) that can be set up by an adversary and used in phishing campaigns. After an adversary acquires a valid cookie, they can then perform a [Web Session Cookie](https://attack.mitre.org/techniques/T1550/004) technique to login to the corresponding web application.

**ATT&CK mitigations (6):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (10):** `AC-20`, `AC-3`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detection of Web Session Cookie Theft via File, Memory, and Network Artifacts  
**Used by 8 threat groups:** [G0030 Lotus Blossom](https://attack.mitre.org/groups/G0030), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1033 Star Blizzard](https://attack.mitre.org/groups/G1033), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 16 software:** [S0467 TajMahal](https://attack.mitre.org/software/S0467), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0568 EVILNUM](https://attack.mitre.org/software/S0568), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0657 BLUELIGHT](https://attack.mitre.org/software/S0657), [S0658 XCSSET](https://attack.mitre.org/software/S0658), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1140 Spica](https://attack.mitre.org/software/S1140), [S1146 MgBot](https://attack.mitre.org/software/S1146), [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240)  

---

### T1552 — Unsecured Credentials
<a id="t1552"></a>

**Tactics:** Credential Access · **Platforms:** Windows, SaaS, IaaS, Linux, macOS, Containers, Network Devices, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552)  

Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Shell History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)), or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).

**ATT&CK mitigations (11):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (32):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-20`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `IA-3`, `IA-4`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SC-7`, `SI-10`, `SI-12`, `SI-15`, `SI-2`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Access or Search for Unsecured Credentials Across Platforms  
**Used by 1 threat groups:** [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017)  
**Implemented by 4 software:** [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S1091 Pacu](https://attack.mitre.org/software/S1091), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1131 NPPSPY](https://attack.mitre.org/software/S1131)  

---

### T1552.001 — Credentials In Files
<a id="t1552001"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Containers, IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/001)  

Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords. It is possible to extract passwords from backups or saved virtual machines through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. In cloud and/or containerized environments, authenticated user and service account credentials are often stored in local configuration and credential files. They may also be found as parameters to deployment commands in container logs. In some cases, these files can be copied and reused on another machine or the contents can be read and then used to authenticate without needing to copy any files.

**ATT&CK mitigations (4):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (17):** `AC-2`, `AC-4`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SC-7`, `SI-4`  
**ATT&CK detection strategy:** Detect Access to Unsecured Credential Files Across Platforms  
**Used by 14 threat groups:** [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1003 Ember Bear](https://attack.mitre.org/groups/G1003), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1016 FIN13](https://attack.mitre.org/groups/G1016), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 18 software:** [S0067 pngdowner](https://attack.mitre.org/software/S0067), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0117 XTunnel](https://attack.mitre.org/software/S0117), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0344 Azorult](https://attack.mitre.org/software/S0344), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0583 Pysa](https://attack.mitre.org/software/S0583), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183)  

---

### T1552.002 — Credentials in Registry
<a id="t1552002"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/002)  

Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons. Example commands to find Registry keys related to password information: * Local Machine Hive: <code>reg query HKLM /f password /t REG_SZ /s</code> * Current User Hive: <code>reg query HKCU /f password /t REG_SZ /s</code>

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (18):** `AC-17`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SI-4`  
**ATT&CK detection strategy:** Detect Credential Discovery via Windows Registry Enumeration  
**Used by 2 threat groups:** [G0050 APT32](https://attack.mitre.org/groups/G0050), [G1039 RedCurl](https://attack.mitre.org/groups/G1039)  
**Implemented by 7 software:** [S0075 Reg](https://attack.mitre.org/software/S0075), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0476 Valak](https://attack.mitre.org/software/S0476), [S1022 IceApple](https://attack.mitre.org/software/S1022), [S1183 StrelaStealer](https://attack.mitre.org/software/S1183)  

---

### T1552.003 — Shell History
<a id="t1552003"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/003)  

Adversaries may search the command history on compromised systems for insecurely stored credentials. On Linux and macOS systems, shells such as Bash and Zsh keep track of the commands users type on the command-line with the "history" utility. Once a user logs out, the history is flushed to the user's history file. For each user, this file resides at the same location: for example, `~/.bash_history` or `~/.zsh_history`. Typically, these files keeps track of the user's last 1000 commands. On Windows, PowerShell has both a command history that is wiped after the session ends, and one that contains commands used in all sessions and is persistent. The default location for persistent history can be found in `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`, but command history can also be accessed with `Get-History`. Command Prompt (CMD) on Windows does not have persistent history. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Adversaries can abuse this by looking through the file for potential credentials.

**ATT&CK mitigations (1):** [M1028 Operating System Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1028)  
**NIST 800-53 R5 controls (4):** `CM-6`, `CM-7`, `SC-28`, `SI-4`  
**ATT&CK detection strategy:** Detect Access and Parsing of .bash_history Files for Credential Harvesting  
**Implemented by 1 software:** [S0599 Kinsing](https://attack.mitre.org/software/S0599)  

---

### T1552.004 — Private Keys
<a id="t1552004"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/004)  

Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures. Common key and certificate file extensions include:.key,.pgp,.gpg,.ppk.,.p12,.pem,.pfx,.cer,.p7b,.asc. Adversaries may also look in common key directories, such as <code>~/.ssh</code> for SSH keys on * nix-based systems or <code>C:&#92;Users&#92;(username)&#92;.ssh&#92;</code> on Windows. Adversary tools may also search compromised systems for file extensions relating to cryptographic keys and certificates. When a device is registered to Entra ID, a device key and a transport key are generated and used to verify the device’s identity. An adversary with access to the device may be able to export the keys in order to impersonate the device. On network devices, private keys may be exported via [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `crypto pki export`. Some private keys require a password or passphrase for operation, so an adversary may also use [Input Capture](https://attack.mitre.org/techniques/T1056) for keylogging or attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase off-line. These private keys can be used to authenticate to [Remote Services](https://attack.mitre.org/techniques/T1021) like SSH or for use in decrypting other collected files such as email.

**ATT&CK mitigations (4):** [M1022 Restrict File and Directory Permissions](../ATTACK_MITIGATIONS_REFERENCE.md#m1022), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (21):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-20`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-12`, `SC-28`, `SC-4`, `SC-7`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Suspicious Access to Private Key Files and Export Attempts Across Platforms  
**Used by 5 threat groups:** [G0106 Rocke](https://attack.mitre.org/groups/G0106), [G0139 TeamTNT](https://attack.mitre.org/groups/G0139), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 11 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0377 Ebury](https://attack.mitre.org/software/S0377), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0599 Kinsing](https://attack.mitre.org/software/S0599), [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0661 FoggyWeb](https://attack.mitre.org/software/S0661), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1060 Mafalda](https://attack.mitre.org/software/S1060), [S1196 Troll Stealer](https://attack.mitre.org/software/S1196)  

---

### T1552.005 — Cloud Instance Metadata API
<a id="t1552005"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/005)  

Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data. Most cloud service providers support a Cloud Instance Metadata API which is a service provided to running virtual instances that allows applications to access information about the running virtual instance. Available information generally includes name, security group, and additional metadata including sensitive data such as credentials and UserData scripts that may contain additional secrets. The Instance Metadata API is provided as a convenience to assist in managing applications and is accessible by anyone who can access the instance. A cloud metadata API has been used in at least one high profile compromise. If adversaries have a presence on the running virtual instance, they may query the Instance Metadata API directly to identify credentials that grant access to additional resources. Additionally, adversaries may exploit a Server-Side Request Forgery (SSRF) vulnerability in a public facing web proxy that allows them to gain access to the sensitive information via a request to the Instance Metadata API. The de facto standard across cloud service providers is to host the Instance Metadata API at <code>http[:]//169.254.169.254</code>.

**ATT&CK mitigations (3):** [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (14):** `AC-16`, `AC-17`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-6`, `CM-7`, `IA-3`, `IA-4`, `SC-7`, `SI-10`, `SI-15`, `SI-4`  
**ATT&CK detection strategy:** Detect Access to Cloud Instance Metadata API (IaaS)  
**Used by 1 threat groups:** [G0139 TeamTNT](https://attack.mitre.org/groups/G0139)  
**Implemented by 2 software:** [S0601 Hildegard](https://attack.mitre.org/software/S0601), [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1552.006 — Group Policy Preferences
<a id="t1552006"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/006)  

Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts. These group policies are stored in SYSVOL on a domain controller. This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public). The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files: * Metasploit’s post exploitation module: <code>post/windows/gather/credentials/gpp</code> * Get-GPPPassword * gpprefdecrypt.py On the SYSVOL share, adversaries may use the following command to enumerate potential GPP XML files: <code>dir /s *.xml</code>

**ATT&CK mitigations (3):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (12):** `AC-2`, `AC-5`, `AC-6`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detect Access and Decryption of Group Policy Preference (GPP) Credentials in SYSVOL  
**Used by 2 threat groups:** [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 2 software:** [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1552.007 — Container API
<a id="t1552007"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** Containers · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/007)  

Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components. An adversary may access the Docker API to collect logs that contain credentials to cloud, container, and various other resources in the environment. An adversary with sufficient permissions, such as via a pod's service account, may also use the Kubernetes API to retrieve credentials from the Kubernetes API server. These credentials may include those needed for Docker API authentication or secrets from Kubernetes cluster components.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035)  
**NIST 800-53 R5 controls (14):** `AC-17`, `AC-2`, `AC-23`, `AC-3`, `AC-4`, `AC-5`, `AC-6`, `CM-5`, `CM-6`, `CM-7`, `IA-2`, `SC-46`, `SC-7`, `SC-8`  
**ATT&CK detection strategy:** Detect Abuse of Container APIs for Credential Access  
**Implemented by 1 software:** [S0683 Peirates](https://attack.mitre.org/software/S0683)  

---

### T1552.008 — Chat Messages
<a id="t1552008"></a>

sub-technique of [T1552](/techniques/credential-access.md#t1552) · **Tactics:** Credential Access · **Platforms:** SaaS, Office Suite · [ATT&CK ↗](https://attack.mitre.org/techniques/T1552/008)  

Adversaries may directly collect unsecured credentials stored or passed through user communication services. Credentials may be sent and stored in user chat communication applications such as email, chat services like Slack or Teams, collaboration tools like Jira or Trello, and any other services that support user communication. Users may share various forms of credentials (such as usernames and passwords, API keys, or authentication tokens) on private or public corporate internal communications channels. Rather than accessing the stored chat logs (i.e., [Credentials In Files](https://attack.mitre.org/techniques/T1552/001)), adversaries may directly access credentials within these services on the user endpoint, through servers hosting the services, or through administrator portals for cloud hosted services. Adversaries may also compromise integration tools like Slack Workflows to automatically search through messages to extract user credentials. These credentials may then be abused to perform follow-on activities such as lateral movement or privilege escalation.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (2):** `AC-4`, `SI-4`  
**ATT&CK detection strategy:** Detect Unsecured Credentials Shared in Chat Messages  
**Used by 1 threat groups:** [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004)  

---

### T1555 — Credentials from Password Stores
<a id="t1555"></a>

**Tactics:** Credential Access · **Platforms:** IaaS, Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555)  

Adversaries may search for common password storage locations to obtain user credentials. Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls (8):** `AC-20`, `AC-3`, `AC-6`, `CA-7`, `CM-3`, `IA-5`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detect Credentials Access from Password Stores  
**Used by 12 threat groups:** [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0087 APT39](https://attack.mitre.org/groups/G0087), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0120 Evilnum](https://attack.mitre.org/groups/G0120), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1026 Malteiro](https://attack.mitre.org/groups/G1026)  
**Implemented by 24 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0138 OLDBAIT](https://attack.mitre.org/software/S0138), [S0167 Matryoshka](https://attack.mitre.org/software/S0167), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0373 Astaroth](https://attack.mitre.org/software/S0373), [S0378 PoshC2](https://attack.mitre.org/software/S0378), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S1111 DarkGate](https://attack.mitre.org/software/S1111), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1146 MgBot](https://attack.mitre.org/software/S1146), [S1156 Manjusaka](https://attack.mitre.org/software/S1156), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1555.001 — Keychain
<a id="t1555001"></a>

sub-technique of [T1555](/techniques/credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/001)  

Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes. There are three types of Keychains: Login Keychain, System Keychain, and Local Items (iCloud) Keychain. The default Keychain is the Login Keychain, which stores user passwords and information. The System Keychain stores items accessed by the operating system, such as items shared among users on a host. The Local Items (iCloud) Keychain is used for items synced with Apple’s iCloud service. Keychains can be viewed and edited through the Keychain Access application or using the command-line utility <code>security</code>. Keychain files are located in <code>~/Library/Keychains/</code>, <code>/Library/Keychains/</code>, and <code>/Network/Library/Keychains/</code>. Adversaries may gather user credentials from Keychain storage/memory. For example, the command <code>security dump-keychain –d</code> will dump all Login Keychain credentials from <code>~/Library/Keychains/login.keychain-db</code>. Adversaries may also directly read Login Keychain credentials from the <code>~/Library/Keychains/login.keychain</code> file. Both methods require a password, where the default password for the Login Keychain is the current user’s password to login to the macOS host.

**ATT&CK mitigations (1):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027)  
**NIST 800-53 R5 controls (3):** `CA-7`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detect Access to macOS Keychain for Credential Theft  
**Used by 1 threat groups:** [G1052 Contagious Interview](https://attack.mitre.org/groups/G1052)  
**Implemented by 10 software:** [S0274 Calisto](https://attack.mitre.org/software/S0274), [S0278 iKitten](https://attack.mitre.org/software/S0278), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0690 Green Lambert](https://attack.mitre.org/software/S0690), [S1016 MacMa](https://attack.mitre.org/software/S1016), [S1153 Cuckoo Stealer](https://attack.mitre.org/software/S1153), [S1185 LightSpy](https://attack.mitre.org/software/S1185), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1555.002 — Securityd Memory
<a id="t1555002"></a>

sub-technique of [T1555](/techniques/credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/002)  

An adversary with root access may gather credentials by reading `securityd`’s memory. `securityd` is a service/daemon responsible for implementing security protocols such as encryption and authorization. A privileged adversary may be able to scan through `securityd`'s memory to find the correct sequence of keys to decrypt the user’s logon keychain. This may provide the adversary with various plaintext passwords, such as those for users, WiFi, mail, browsers, certificates, secure notes, etc. In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple’s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords. Apple’s `securityd` utility takes the user’s logon password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a set of keys and algorithms to encrypt the user’s password, but once the master key is found, an adversary need only iterate over the other values to unlock the final password.

**ATT&CK mitigations:** none mapped  
**NIST 800-53 R5 controls (5):** `AC-3`, `AC-6`, `CA-7`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detect Suspicious Access to securityd Memory for Credential Extraction  
**Implemented by 1 software:** [S0276 Keydnap](https://attack.mitre.org/software/S0276)  

---

### T1555.003 — Credentials from Web Browsers
<a id="t1555003"></a>

sub-technique of [T1555](/techniques/credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/003)  

Adversaries may acquire credentials from web browsers by reading files specific to the target browser. Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers. For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, <code>AppData\Local\Google\Chrome\User Data\Default\Login Data</code> and executing a SQL query: <code>SELECT action_url, username_value, password_value FROM logins;</code>. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function <code>CryptUnprotectData</code>, which uses the victim’s cached logon credentials as the decryption key. Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc. Windows stores Internet Explorer and Microsoft Edge credentials in Credential Lockers managed by the [Windows Credential Manager](https://attack.mitre.org/techniques/T1555/004). Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials. After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1021 Restrict Web-Based Content](../ATTACK_MITIGATIONS_REFERENCE.md#m1021), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051)  
**NIST 800-53 R5 controls:** none — *framework blind spot; rely on detection/design controls*  
**ATT&CK detection strategy:** Detect Suspicious Access to Browser Credential Stores  
**Used by 23 threat groups:** [G0021 Molerats](https://attack.mitre.org/groups/G0021), [G0022 APT3](https://attack.mitre.org/groups/G0022), [G0034 Sandworm Team](https://attack.mitre.org/groups/G0034), [G0037 FIN6](https://attack.mitre.org/groups/G0037), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0040 Patchwork](https://attack.mitre.org/groups/G0040), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0064 APT33](https://attack.mitre.org/groups/G0064), [G0067 APT37](https://attack.mitre.org/groups/G0067), [G0069 MuddyWater](https://attack.mitre.org/groups/G0069), [G0077 Leafminer](https://attack.mitre.org/groups/G0077), [G0092 TA505](https://attack.mitre.org/groups/G0092), [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0096 APT41](https://attack.mitre.org/groups/G0096), [G0100 Inception](https://attack.mitre.org/groups/G0100), [G0128 ZIRCONIUM](https://attack.mitre.org/groups/G0128), [G0130 Ajax Security Team](https://attack.mitre.org/groups/G0130), [G1001 HEXANE](https://attack.mitre.org/groups/G1001), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1017 Volt Typhoon](https://attack.mitre.org/groups/G1017), [G1026 Malteiro](https://attack.mitre.org/groups/G1026), [G1039 RedCurl](https://attack.mitre.org/groups/G1039), [G1044 APT42](https://attack.mitre.org/groups/G1044)  
**Implemented by 62 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0048 PinchDuke](https://attack.mitre.org/software/S0048), [S0050 CosmicDuke](https://attack.mitre.org/software/S0050), [S0089 BlackEnergy](https://attack.mitre.org/software/S0089), [S0093 Backdoor.Oldrea](https://attack.mitre.org/software/S0093), [S0094 Trojan.Karagany](https://attack.mitre.org/software/S0094), [S0113 Prikormka](https://attack.mitre.org/software/S0113), [S0115 Crimson](https://attack.mitre.org/software/S0115), [S0130 Unknown Logger](https://attack.mitre.org/software/S0130), [S0132 H1N1](https://attack.mitre.org/software/S0132), [S0138 OLDBAIT](https://attack.mitre.org/software/S0138), [S0144 ChChes](https://attack.mitre.org/software/S0144), [S0153 RedLeaves](https://attack.mitre.org/software/S0153), [S0161 XAgentOSX](https://attack.mitre.org/software/S0161), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0198 NETWIRE](https://attack.mitre.org/software/S0198), [S0226 Smoke Loader](https://attack.mitre.org/software/S0226), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0251 Zebrocy](https://attack.mitre.org/software/S0251), [S0262 QuasarRAT](https://attack.mitre.org/software/S0262), [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0283 jRAT](https://attack.mitre.org/software/S0283), [S0331 Agent Tesla](https://attack.mitre.org/software/S0331), [S0344 Azorult](https://attack.mitre.org/software/S0344), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0356 KONNI](https://attack.mitre.org/software/S0356), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0365 Olympic Destroyer](https://attack.mitre.org/software/S0365), [S0367 Emotet](https://attack.mitre.org/software/S0367), [S0385 njRAT](https://attack.mitre.org/software/S0385), [S0387 KeyBoy](https://attack.mitre.org/software/S0387), [S0409 Machete](https://attack.mitre.org/software/S0409), [S0428 PoetRAT](https://attack.mitre.org/software/S0428), [S0434 Imminent Monitor](https://attack.mitre.org/software/S0434), [S0435 PLEAD](https://attack.mitre.org/software/S0435), [S0436 TSCookie](https://attack.mitre.org/software/S0436), [S0447 Lokibot](https://attack.mitre.org/software/S0447), [S0484 Carberp](https://attack.mitre.org/software/S0484), [S0492 CookieMiner](https://attack.mitre.org/software/S0492), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S0528 Javali](https://attack.mitre.org/software/S0528), [S0530 Melcoz](https://attack.mitre.org/software/S0530), [S0531 Grandoreiro](https://attack.mitre.org/software/S0531), [S0629 RainyDay](https://attack.mitre.org/software/S0629), [S0631 Chaes](https://attack.mitre.org/software/S0631), [S0650 QakBot](https://attack.mitre.org/software/S0650), [S0657 BLUELIGHT](https://attack.mitre.org/software/S0657), [S0670 WarzoneRAT](https://attack.mitre.org/software/S0670), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1042 SUGARDUMP](https://attack.mitre.org/software/S1042), [S1122 Mispadu](https://attack.mitre.org/software/S1122), [S1146 MgBot](https://attack.mitre.org/software/S1146), [S1148 Raccoon Stealer](https://attack.mitre.org/software/S1148), [S1156 Manjusaka](https://attack.mitre.org/software/S1156), [S1201 TRANSLATEXT](https://attack.mitre.org/software/S1201), [S1207 XLoader](https://attack.mitre.org/software/S1207), [S1213 Lumma Stealer](https://attack.mitre.org/software/S1213), [S1240 RedLine Stealer](https://attack.mitre.org/software/S1240), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245), [S1246 BeaverTail](https://attack.mitre.org/software/S1246)  

---

### T1555.004 — Windows Credential Manager
<a id="t1555004"></a>

sub-technique of [T1555](/techniques/credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/004)  

Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (previously known as Windows Vaults). The Windows Credential Manager separates website credentials from application or network credentials in two lockers. As part of [Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003), Internet Explorer and Microsoft Edge website credentials are managed by the Credential Manager and are stored in the Web Credentials locker. Application and network credentials are stored in the Windows Credentials locker. Credential Lockers store credentials in encrypted `.vcrd` files, located under `%Systemdrive%\Users\\[Username]\AppData\Local\Microsoft\\[Vault/Credentials]\`. The encryption key can be found in a file named <code>Policy.vpol</code>, typically located in the same folder as the credentials. Adversaries may list credentials managed by the Windows Credential Manager through several mechanisms. <code>vaultcmd.exe</code> is a native Windows executable that can be used to enumerate credentials stored in the Credential Locker through a command-line interface. Adversaries may also gather credentials by directly reading files located inside of the Credential Lockers. Windows APIs, such as <code>CredEnumerateA</code>, may also be absued to list credentials managed by the Credential Manager. Adversaries may also obtain credentials from credential backups. Credential backups and restorations may be performed by running <code>rundll32.exe keymgr.dll KRShowKeyMgr</code> then selecting the “Back up...” button on the “Stored User Names and Passwords” GUI. Password recovery tools may also obtain plain text passwords from the Credential Manager.

**ATT&CK mitigations (1):** [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (5):** `CM-2`, `CM-6`, `CM-7`, `IA-5`, `SI-4`  
**ATT&CK detection strategy:** Detect Suspicious Access to Windows Credential Manager  
**Used by 4 threat groups:** [G0010 Turla](https://attack.mitre.org/groups/G0010), [G0038 Stealth Falcon](https://attack.mitre.org/groups/G0038), [G0049 OilRig](https://attack.mitre.org/groups/G0049), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 9 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0240 ROKRAT](https://attack.mitre.org/software/S0240), [S0349 LaZagne](https://attack.mitre.org/software/S0349), [S0476 Valak](https://attack.mitre.org/software/S0476), [S0526 KGH_SPY](https://attack.mitre.org/software/S0526), [S0629 RainyDay](https://attack.mitre.org/software/S0629), [S0681 Lizar](https://attack.mitre.org/software/S0681), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692)  

---

### T1555.005 — Password Managers
<a id="t1555005"></a>

sub-technique of [T1555](/techniques/credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/005)  

Adversaries may acquire user credentials from third-party password managers. Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database. After the database is unlocked, these credentials may be copied to memory. These databases can be stored as files on disk. Adversaries may acquire user credentials from password managers by extracting the master password and/or plain-text credentials from memory. Adversaries may extract credentials from memory via [Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212). Adversaries may also try brute forcing via [Password Guessing](https://attack.mitre.org/techniques/T1110/001) to obtain the master password of a password manager.

**ATT&CK mitigations (5):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1051 Update Software](../ATTACK_MITIGATIONS_REFERENCE.md#m1051), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (8):** `AC-2`, `AC-3`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `SI-2`, `SI-4`  
**ATT&CK detection strategy:** Detect Unauthorized Access to Password Managers  
**Used by 7 threat groups:** [G0027 Threat Group-3390](https://attack.mitre.org/groups/G0027), [G0117 Fox Kitten](https://attack.mitre.org/groups/G0117), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015), [G1048 UNC3886](https://attack.mitre.org/groups/G1048), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 4 software:** [S0266 TrickBot](https://attack.mitre.org/software/S0266), [S0279 Proton](https://attack.mitre.org/software/S0279), [S0652 MarkiRAT](https://attack.mitre.org/software/S0652), [S1245 InvisibleFerret](https://attack.mitre.org/software/S1245)  

---

### T1555.006 — Cloud Secrets Management Stores
<a id="t1555006"></a>

sub-technique of [T1555](/techniques/credential-access.md#t1555) · **Tactics:** Credential Access · **Platforms:** IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1555/006)  

Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault. Secrets managers support the secure centralized management of passwords, API keys, and other credential material. Where secrets managers are in use, cloud services can dynamically acquire credentials via API requests rather than accessing secrets insecurely stored in plain text files or environment variables. If an adversary is able to gain sufficient privileges in a cloud environment – for example, by obtaining the credentials of high-privileged [Cloud Accounts](https://attack.mitre.org/techniques/T1078/004) or compromising a service that has permission to retrieve secrets – they may be able to request secrets from the secrets manager. This can be accomplished via commands such as `get-secret-value` in AWS, `gcloud secrets describe` in GCP, and `az key vault secret show` in Azure. **Note:** this technique is distinct from [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005) in that the credentials are being directly requested from the cloud secrets manager, rather than through the medium of the instance metadata API.

**ATT&CK mitigations (1):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `CM-7`  
**ATT&CK detection strategy:** Detect Unauthorized Access to Cloud Secrets Management Stores  
**Used by 2 threat groups:** [G0125 HAFNIUM](https://attack.mitre.org/groups/G0125), [G1053 Storm-0501](https://attack.mitre.org/groups/G1053)  
**Implemented by 1 software:** [S1091 Pacu](https://attack.mitre.org/software/S1091)  

---

### T1557 — Adversary-in-the-Middle
<a id="t1557"></a>

**Tactics:** Credential Access, Collection · **Platforms:** Linux, macOS, Network Devices, Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557)  

Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or replay attacks ([Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions. For example, adversaries may manipulate victim DNS settings to enable other malicious activities such as preventing/redirecting users from accessing legitimate sites and/or pushing additional malware. Adversaries may also manipulate DNS and leverage their position in order to intercept user credentials, including access tokens ([Steal Application Access Token](https://attack.mitre.org/techniques/T1528)) and session cookies ([Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539)). [Downgrade Attack](https://attack.mitre.org/techniques/T1689)s can also be used to establish an AiTM position, such as by negotiating a less secure, deprecated, or weaker version of communication protocol (SSL/TLS) or encryption algorithm. Adversaries may also leverage the AiTM position to attempt to monitor and/or modify traffic, such as in [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). Adversaries can setup a position similar to AiTM to prevent traffic from flowing to the appropriate destination, potentially to impair defenses and/or in support of a [Network Denial of Service](https://attack.mitre.org/techniques/T1498).

**ATT&CK mitigations (7):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (24):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `RA-5`, `SC-23`, `SC-4`, `SC-46`, `SC-7`, `SC-8`, `SI-10`, `SI-12`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Adversary-in-the-Middle via Network and Configuration Anomalies  
**Used by 3 threat groups:** [G0094 Kimsuky](https://attack.mitre.org/groups/G0094), [G0129 Mustang Panda](https://attack.mitre.org/groups/G0129), [G1041 Sea Turtle](https://attack.mitre.org/groups/G1041)  
**Implemented by 3 software:** [S0281 Dok](https://attack.mitre.org/software/S0281), [S1131 NPPSPY](https://attack.mitre.org/software/S1131), [S1188 Line Runner](https://attack.mitre.org/software/S1188)  

---

### T1557.001 — Name Resolution Poisoning and SMB Relay
<a id="t1557001"></a>

sub-technique of [T1557](/techniques/credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/001)  

By responding to LLMNR/NBT-NS/mDNS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials. Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. Multicast Domain Name System(mDNS) is a zero-configuration service used to resolve hostnames to IP addresses with “.local” as a top-level domain. MDNS is based upon Domain Name System (DNS) format and allows hosts on the same network segment to perform name resolution for other hosts, using multicast. Adversaries can spoof an authoritative source for name resolution on a victim network by responding to LLMNR (UDP 5355)/NBT-NS (UDP 137)/mDNS (UDP 5353) traffic as if they know the identity of the requested host, effectively poisoning the service so that the victims will communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will then be sent to the adversary controlled system. The adversary can then collect the hash information sent over the wire through tools that monitor the ports for traffic or through [Network Sniffing](https://attack.mitre.org/techniques/T1040) and crack the hashes offline through [Brute Force](https://attack.mitre.org/techniques/T1110) to obtain the plaintext passwords. In some cases where an adversary has access to a system that is in the authentication path between systems or when automated scans that use credentials attempt to authenticate to an adversary controlled system, the NTLMv1/v2 hashes can be intercepted and relayed to access and execute code against a target system. The relay step can happen in conjunction with poisoning but may also be independent of it. Additionally, adversaries may encapsulate the NTLMv1/v2 hashes into various other protocols, such as LDAP, MSSQL and HTTP, to expand and use multiple services with the valid NTLM response. Several tools may be used to poison name services within local networks such as NBNSpoof, Metasploit, and [Responder](https://attack.mitre.org/software/S0174).

**ATT&CK mitigations (4):** [M1030 Network Segmentation](../ATTACK_MITIGATIONS_REFERENCE.md#m1030), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (15):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-23`, `SC-46`, `SC-7`, `SC-8`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect LLMNR/NBT-NS Poisoning and SMB Relay on Windows  
**Used by 2 threat groups:** [G0032 Lazarus Group](https://attack.mitre.org/groups/G0032), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102)  
**Implemented by 5 software:** [S0174 Responder](https://attack.mitre.org/software/S0174), [S0192 Pupy](https://attack.mitre.org/software/S0192), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0378 PoshC2](https://attack.mitre.org/software/S0378)  

---

### T1557.002 — ARP Cache Poisoning
<a id="t1557002"></a>

sub-technique of [T1557](/techniques/credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/002)  

Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). The ARP protocol is used to resolve IPv4 addresses to link layer addresses, such as a media access control (MAC) address. Devices in a local network segment communicate with each other by using link layer addresses. If a networked device does not have the link layer address of a particular networked device, it may send out a broadcast ARP request to the local network to translate the IP address to a MAC address. The device with the associated IP address directly replies with its MAC address. The networked device that made the ARP request will then use as well as store that information in its ARP cache. An adversary may passively wait for an ARP request to poison the ARP cache of the requesting device. The adversary may reply with their MAC address, thus deceiving the victim by making them believe that they are communicating with the intended networked device. For the adversary to poison the ARP cache, their reply must be faster than the one made by the legitimate IP address owner. Adversaries may also send a gratuitous ARP reply that maliciously announces the ownership of a particular IP address to all the devices in the local network segment. The ARP protocol is stateless and does not require authentication. Therefore, devices may wrongly add or update the MAC address of the IP address in their ARP cache. Adversaries may use ARP cache poisoning as a means to intercept network traffic. This activity may be used to collect and/or relay data such as credentials, especially those sent over an insecure, unencrypted protocol.

**ATT&CK mitigations (6):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1035 Limit Access to Resource Over Network](../ATTACK_MITIGATIONS_REFERENCE.md#m1035), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042)  
**NIST 800-53 R5 controls (22):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-20`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-23`, `SC-4`, `SC-7`, `SC-8`, `SI-10`, `SI-12`, `SI-15`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect ARP Cache Poisoning Across Linux, Windows, and macOS  
**Used by 2 threat groups:** [G0003 Cleaver](https://attack.mitre.org/groups/G0003), [G1014 LuminousMoth](https://attack.mitre.org/groups/G1014)  

---

### T1557.003 — DHCP Spoofing
<a id="t1557003"></a>

sub-technique of [T1557](/techniques/credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Linux, Windows, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/003)  

Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). DHCP is based on a client-server model and has two functionalities: a protocol for providing network configuration settings from a DHCP server to a client and a mechanism for allocating network addresses to clients. The typical server-client interaction is as follows: 1. The client broadcasts a `DISCOVER` message. 2. The server responds with an `OFFER` message, which includes an available network address. 3. The client broadcasts a `REQUEST` message, which includes the network address offered. 4. The server acknowledges with an `ACK` message and the client receives the network configuration parameters. Adversaries may spoof as a rogue DHCP server on the victim network, from which legitimate hosts may receive malicious network configurations. For example, malware can act as a DHCP server and provide adversary-owned DNS servers to the victimized computers. Through the malicious network configurations, an adversary may achieve the AiTM position, route client traffic through adversary-controlled systems, and collect information from the client network. DHCPv6 clients can receive network configuration information without being assigned an IP address by sending a <code>INFORMATION-REQUEST (code 11)</code> message to the <code>All_DHCP_Relay_Agents_and_Servers</code> multicast address. Adversaries may use their rogue DHCP server to respond to this request message with malicious network configurations. Rather than establishing an AiTM position, adversaries may also abuse DHCP spoofing to perform a DHCP exhaustion attack (i.e, [Service Exhaustion Flood](https://attack.mitre.org/techniques/T1499/002)) by generating many broadcast DISCOVER messages to exhaust a network’s DHCP allocation pool.

**ATT&CK mitigations (2):** [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031), [M1037 Filter Network Traffic](../ATTACK_MITIGATIONS_REFERENCE.md#m1037)  
**NIST 800-53 R5 controls (15):** `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `CM-7`, `CM-8`, `SC-23`, `SC-46`, `SC-7`, `SC-8`, `SI-10`, `SI-15`, `SI-3`, `SI-4`  
**ATT&CK detection strategy:** Detect DHCP Spoofing Across Linux, Windows, and macOS  

---

### T1557.004 — Evil Twin
<a id="t1557004"></a>

sub-technique of [T1557](/techniques/credential-access.md#t1557) · **Tactics:** Credential Access, Collection · **Platforms:** Network Devices · [ATT&CK ↗](https://attack.mitre.org/techniques/T1557/004)  

Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or [Input Capture](https://attack.mitre.org/techniques/T1056). By using a Service Set Identifier (SSID) of a legitimate Wi-Fi network, fraudulent Wi-Fi access points may trick devices or users into connecting to malicious Wi-Fi networks. Adversaries may provide a stronger signal strength or block access to Wi-Fi access points to coerce or entice victim devices into connecting to malicious networks. A Wi-Fi Pineapple – a network security auditing and penetration testing tool – may be deployed in Evil Twin attacks for ease of use and broader range. Custom certificates may be used in an attempt to intercept HTTPS traffic. Similarly, adversaries may also listen for client devices sending probe requests for known or previously connected networks (Preferred Network Lists or PNLs). When a malicious access point receives a probe request, adversaries can respond with the same SSID to imitate the trusted, known network. Victim devices are led to believe the responding access point is from their PNL and initiate a connection to the fraudulent network. Upon logging into the malicious Wi-Fi access point, a user may be directed to a fake login page or captive portal webpage to capture the victim’s credentials. Once a user is logged into the fraudulent Wi-Fi network, the adversary may able to monitor network activity, manipulate data, or steal additional credentials. Locations with high concentrations of public Wi-Fi access, such as airports, coffee shops, or libraries, may be targets for adversaries to set up illegitimate Wi-Fi access points.

**ATT&CK mitigations (2):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1031 Network Intrusion Prevention](../ATTACK_MITIGATIONS_REFERENCE.md#m1031)  
**NIST 800-53 R5 controls (16):** `AC-18`, `AC-19`, `AC-3`, `AC-4`, `CA-7`, `CM-2`, `CM-6`, `SC-13`, `SC-23`, `SC-40`, `SC-46`, `SC-7`, `SC-8`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Evil Twin Wi-Fi Access Points on Network Devices  
**Used by 1 threat groups:** [G0007 APT28](https://attack.mitre.org/groups/G0007)  

---

### T1558 — Steal or Forge Kerberos Tickets
<a id="t1558"></a>

**Tactics:** Credential Access · **Platforms:** Windows, Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558)  

Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as “realms”, there are three basic participants: client, service, and Key Distribution Center (KDC). Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting. Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access. On Windows, the built-in <code>klist</code> utility can be used to list and analyze cached Kerberos tickets.

**ATT&CK mitigations (6):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Kerberos Ticket Theft or Forgery (T1558)  
**Used by 1 threat groups:** [G1024 Akira](https://attack.mitre.org/groups/G1024)  

---

### T1558.001 — Golden Ticket
<a id="t1558001"></a>

sub-technique of [T1558](/techniques/credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/001)  

Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket. Golden tickets enable adversaries to generate authentication material for any account in Active Directory. Using a golden ticket, adversaries are then able to request ticket granting service (TGS) tickets, which enable access to specific resources. Golden tickets require adversaries to interact with the Key Distribution Center (KDC) in order to obtain TGS. The KDC service runs all on domain controllers that are part of an Active Directory domain. KRBTGT is the Kerberos Key Distribution Center (KDC) service account and is responsible for encrypting and signing all Kerberos tickets. The KRBTGT password hash may be obtained using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) and privileged access to a domain controller.

**ATT&CK mitigations (2):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026)  
**NIST 800-53 R5 controls (9):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`  
**ATT&CK detection strategy:** Detect Forged Kerberos Golden Tickets (T1558.001)  
**Used by 1 threat groups:** [G0004 Ke3chang](https://attack.mitre.org/groups/G0004)  
**Implemented by 4 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0633 Sliver](https://attack.mitre.org/software/S0633), [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.002 — Silver Ticket
<a id="t1558002"></a>

sub-technique of [T1558](/techniques/credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/002)  

Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets. Silver tickets are more limited in scope in than golden tickets in that they only enable adversaries to access a particular resource (e.g. MSSQL) and the system that hosts the resource; however, unlike golden tickets, adversaries with the ability to forge silver tickets are able to create TGS tickets without interacting with the Key Distribution Center (KDC), potentially making detection more difficult. Password hashes for target services may be obtained using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) or [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Forged Kerberos Silver Tickets (T1558.002)  
**Implemented by 4 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0677 AADInternals](https://attack.mitre.org/software/S0677), [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.003 — Kerberoasting
<a id="t1558003"></a>

sub-technique of [T1558](/techniques/credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/003)  

Adversaries may abuse a valid Kerberos ticket-granting ticket (TGT) or sniff network traffic to obtain a ticket-granting service (TGS) ticket that may be vulnerable to [Brute Force](https://attack.mitre.org/techniques/T1110). Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service). Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC). Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline [Brute Force](https://attack.mitre.org/techniques/T1110) attacks that may expose plaintext credentials. This same behavior could be executed using service tickets captured from network traffic. Cracked hashes may enable [Persistence](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), and [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078).

**ATT&CK mitigations (3):** [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `AC-5`, `AC-6`, `CA-7`, `CM-2`, `CM-5`, `CM-6`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Kerberoasting Attempts (T1558.003)  
**Used by 3 threat groups:** [G0046 FIN7](https://attack.mitre.org/groups/G0046), [G0102 Wizard Spider](https://attack.mitre.org/groups/G0102), [G0119 Indrik Spider](https://attack.mitre.org/groups/G0119)  
**Implemented by 6 software:** [S0194 PowerSploit](https://attack.mitre.org/software/S0194), [S0357 Impacket](https://attack.mitre.org/software/S0357), [S0363 Empire](https://attack.mitre.org/software/S0363), [S0692 SILENTTRINITY](https://attack.mitre.org/software/S0692), [S1063 Brute Ratel C4](https://attack.mitre.org/software/S1063), [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.004 — AS-REP Roasting
<a id="t1558004"></a>

sub-technique of [T1558](/techniques/credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Windows · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/004)  

Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by [Password Cracking](https://attack.mitre.org/techniques/T1110/002) Kerberos messages. Preauthentication offers protection against offline [Password Cracking](https://attack.mitre.org/techniques/T1110/002). When enabled, a user requesting access to a resource initiates communication with the Domain Controller (DC) by sending an Authentication Server Request (AS-REQ) message with a timestamp that is encrypted with the hash of their password. If and only if the DC is able to successfully decrypt the timestamp with the hash of the user’s password, it will then send an Authentication Server Response (AS-REP) message that contains the Ticket Granting Ticket (TGT) to the user. Part of the AS-REP message is signed with the user’s password. For each account found without preauthentication, an adversary may send an AS-REQ message without the encrypted timestamp and receive an AS-REP message with TGT data which may be encrypted with an insecure algorithm such as RC4. The recovered encrypted data may be vulnerable to offline [Password Cracking](https://attack.mitre.org/techniques/T1110/002) attacks similarly to [Kerberoasting](https://attack.mitre.org/techniques/T1558/003) and expose plaintext credentials. An account registered to a domain, with or without special privileges, can be abused to list all domain accounts that have preauthentication disabled by utilizing Windows tools like [PowerShell](https://attack.mitre.org/techniques/T1059/001) with an LDAP filter. Alternatively, the adversary may send an AS-REQ message for each user. If the DC responds without errors, the account does not require preauthentication and the AS-REP message will already contain the encrypted data. Cracked hashes may enable [Persistence](https://attack.mitre.org/tactics/TA0003), [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), and [Lateral Movement](https://attack.mitre.org/tactics/TA0008) via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078).

**ATT&CK mitigations (3):** [M1027 Password Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1027), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (19):** `AC-16`, `AC-17`, `AC-18`, `AC-19`, `AC-2`, `AC-3`, `CA-7`, `CM-2`, `CM-6`, `IA-2`, `IA-5`, `RA-5`, `SA-11`, `SA-15`, `SC-4`, `SI-12`, `SI-3`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect AS-REP Roasting Attempts (T1558.004)  
**Implemented by 1 software:** [S1071 Rubeus](https://attack.mitre.org/software/S1071)  

---

### T1558.005 — Ccache Files
<a id="t1558005"></a>

sub-technique of [T1558](/techniques/credential-access.md#t1558) · **Tactics:** Credential Access · **Platforms:** Linux, macOS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1558/005)  

Adversaries may attempt to steal Kerberos tickets stored in credential cache files (or ccache). These files are used for short term storage of a user's active session credentials. The ccache file is created upon user authentication and allows for access to multiple services without the user having to re-enter credentials. The <code>/etc/krb5.conf</code> configuration file and the <code>KRB5CCNAME</code> environment variable are used to set the storage location for ccache entries. On Linux, credentials are typically stored in the `/tmp` directory with a naming format of `krb5cc_%UID%` or `krb5.ccache`. On macOS, ccache entries are stored by default in memory with an `API:{uuid}` naming scheme. Typically, users interact with ticket storage using <code>kinit</code>, which obtains a Ticket-Granting-Ticket (TGT) for the principal; <code>klist</code>, which lists obtained tickets currently held in the credentials cache; and other built-in binaries. Adversaries can collect tickets from ccache files stored on disk and authenticate as the current user without their password to perform [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) attacks. Adversaries can also use these tickets to impersonate legitimate users with elevated privileges to perform [Privilege Escalation](https://attack.mitre.org/tactics/TA0004). Tools like Kekeo can also be used by adversaries to convert ccache files to Windows format for further [Lateral Movement](https://attack.mitre.org/tactics/TA0008). On macOS, adversaries may use open-source tools or the Kerberos framework to interact with ccache files and extract TGTs or Service Tickets via lower-level APIs.

**ATT&CK mitigations (2):** [M1043 Credential Access Protection](../ATTACK_MITIGATIONS_REFERENCE.md#m1043), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (10):** `AC-2`, `AC-3`, `AC-6`, `CA-7`, `IA-2`, `IA-5`, `SC-4`, `SI-12`, `SI-4`, `SI-7`  
**ATT&CK detection strategy:** Detect Kerberos Ccache File Theft or Abuse (T1558.005)  
**Implemented by 1 software:** [S0357 Impacket](https://attack.mitre.org/software/S0357)  

---

### T1606 — Forge Web Credentials
<a id="t1606"></a>

**Tactics:** Credential Access · **Platforms:** SaaS, Windows, macOS, Linux, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1606)  

Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access. Adversaries may generate these credential materials in order to gain access to web resources. This differs from [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539), [Steal Application Access Token](https://attack.mitre.org/techniques/T1528), and other similar behaviors in that the credentials are new and forged by the adversary, rather than stolen or intercepted from legitimate users. The generation of web credentials often requires secret values, such as passwords, [Private Keys](https://attack.mitre.org/techniques/T1552/004), or other cryptographic seed values. Adversaries may also forge tokens by taking advantage of features such as the `AssumeRole` and `GetFederationToken` APIs in AWS, which allow users to request temporary security credentials (i.e., [Temporary Elevated Cloud Access](https://attack.mitre.org/techniques/T1548/005)), or the `zmprov gdpak` command in Zimbra, which generates a pre-authentication key that can be used to generate tokens for any user in the domain. Once forged, adversaries may use these web credentials to access resources (ex: [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)), which may bypass multi-factor and other authentication protection mechanisms.

**ATT&CK mitigations (4):** [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-3`, `AC-5`, `AC-6`, `IA-13`, `SC-17`, `SI-2`  
**ATT&CK detection strategy:** Detection Strategy for Forged Web Credentials  

---

### T1606.001 — Web Cookies
<a id="t1606001"></a>

sub-technique of [T1606](/techniques/credential-access.md#t1606) · **Tactics:** Credential Access · **Platforms:** Linux, macOS, Windows, SaaS, IaaS · [ATT&CK ↗](https://attack.mitre.org/techniques/T1606/001)  

Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access. Adversaries may generate these cookies in order to gain access to web resources. This differs from [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539) and other similar behaviors in that the cookies are new and forged by the adversary, rather than stolen or intercepted from legitimate users. Most common web applications have standardized and documented cookie values that can be generated using provided tools or interfaces. The generation of web cookies often requires secret values, such as passwords, [Private Keys](https://attack.mitre.org/techniques/T1552/004), or other cryptographic seed values. Once forged, adversaries may use these web cookies to access resources ([Web Session Cookie](https://attack.mitre.org/techniques/T1550/004)), which may bypass multi-factor and other authentication protection mechanisms.

**ATT&CK mitigations (2):** [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047), [M1054 Software Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1054)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `SI-2`  
**ATT&CK detection strategy:** Detection Strategy for Forged Web Cookies  

---

### T1606.002 — SAML Tokens
<a id="t1606002"></a>

sub-technique of [T1606](/techniques/credential-access.md#t1606) · **Tactics:** Credential Access · **Platforms:** SaaS, Windows, IaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1606/002)  

An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate. The default lifetime of a SAML token is one hour, but the validity period can be specified in the <code>NotOnOrAfter</code> value of the <code>conditions...</code> element in a token. This value can be changed using the <code>AccessTokenLifetime</code> in a <code>LifetimeTokenPolicy</code>. Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO (single sign-on) mechanism. An adversary may utilize [Private Keys](https://attack.mitre.org/techniques/T1552/004) to compromise an organization's token-signing certificate to create forged SAML tokens. If the adversary has sufficient permissions to establish a new federation trust with their own Active Directory Federation Services (AD FS) server, they may instead generate their own trusted token-signing certificate. This differs from [Steal Application Access Token](https://attack.mitre.org/techniques/T1528) and other similar behaviors in that the tokens are new and forged by the adversary, rather than stolen or intercepted from legitimate users. An adversary may gain administrative Entra ID privileges if a SAML token is forged which claims to represent a highly privileged account. This may lead to [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550), which may bypass multi-factor and other authentication protection mechanisms.

**ATT&CK mitigations (4):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1018 User Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1018), [M1026 Privileged Account Management](../ATTACK_MITIGATIONS_REFERENCE.md#m1026), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (4):** `AC-2`, `AC-3`, `AC-6`, `IA-13`  
**ATT&CK detection strategy:** Detection Strategy for Forged SAML Tokens  
**Implemented by 1 software:** [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---

### T1621 — Multi-Factor Authentication Request Generation
<a id="t1621"></a>

**Tactics:** Credential Access · **Platforms:** Windows, Linux, macOS, IaaS, SaaS, Office Suite, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1621)  

Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users. Adversaries in possession of credentials to [Valid Accounts](https://attack.mitre.org/techniques/T1078) may be unable to complete the login process if they lack access to the 2FA or MFA mechanisms required as an additional credential and security control. To circumvent this, adversaries may abuse the automatic generation of push notifications to MFA services such as Duo Push, Microsoft Authenticator, Okta, or similar services to have the user grant access to their account. If adversaries lack credentials to victim accounts, they may also abuse automatic push notification generation when this option is configured for self-service password reset (SSPR). In some cases, adversaries may continuously repeat login attempts in order to bombard users with MFA push notifications, SMS messages, and phone calls, potentially resulting in the user finally accepting the authentication request in response to “MFA fatigue.”

**ATT&CK mitigations (3):** [M1017 User Training](../ATTACK_MITIGATIONS_REFERENCE.md#m1017), [M1032 Multi-factor Authentication](../ATTACK_MITIGATIONS_REFERENCE.md#m1032), [M1036 Account Use Policies](../ATTACK_MITIGATIONS_REFERENCE.md#m1036)  
**NIST 800-53 R5 controls (7):** `AC-2`, `AC-6`, `CM-5`, `IA-13`, `IA-2`, `IA-3`, `IA-5`  
**ATT&CK detection strategy:** Detection Strategy for Multi-Factor Authentication Request Generation (T1621)  
**Used by 3 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016), [G1004 LAPSUS$](https://attack.mitre.org/groups/G1004), [G1015 Scattered Spider](https://attack.mitre.org/groups/G1015)  

---

### T1649 — Steal or Forge Authentication Certificates
<a id="t1649"></a>

**Tactics:** Credential Access · **Platforms:** Windows, Linux, macOS, Identity Provider · [ATT&CK ↗](https://attack.mitre.org/techniques/T1649)  

Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For example, Entra ID device certificates and Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts. Authentication certificates can be both stolen and forged. For example, AD CS certificates can be stolen from encrypted storage (in the Registry or files), misplaced certificate files (i.e. [Unsecured Credentials](https://attack.mitre.org/techniques/T1552)), or directly from the Windows certificate store via various crypto APIs. With appropriate enrollment rights, users and/or machines within a domain can also request and/or manually renew certificates from enterprise certificate authorities (CA). This enrollment process defines various settings and permissions associated with the certificate. Of note, the certificate’s extended key usage (EKU) values define signing, encryption, and authentication use cases, while the certificate’s subject alternative name (SAN) values define the certificate owner’s alternate names. Abusing certificates for authentication credentials may enable other behaviors such as [Lateral Movement](https://attack.mitre.org/tactics/TA0008). Certificate-related misconfigurations may also enable opportunities for [Privilege Escalation](https://attack.mitre.org/tactics/TA0004), by way of allowing users to impersonate or assume privileged accounts or permissions via the identities (SANs) associated with a certificate. These abuses may also enable [Persistence](https://attack.mitre.org/tactics/TA0003) via stealing or forging certificates that can be used as [Valid Accounts](https://attack.mitre.org/techniques/T1078) for the duration of the certificate's validity, despite user password resets. Authentication certificates can also be stolen and forged for machine accounts. Adversaries who have access to root (or subordinate) CA certificate private keys (or mechanisms protecting/managing these keys) may also establish [Persistence](https://attack.mitre.org/tactics/TA0003) by forging arbitrary authentication certificates for the victim domain (known as “golden” certificates). Adversaries may also target certificates and related services in order to access other forms of credentials, such as [Golden Ticket](https://attack.mitre.org/techniques/T1558/001) ticket-granting tickets (TGT) or NTLM plaintext.

**ATT&CK mitigations (4):** [M1015 Active Directory Configuration](../ATTACK_MITIGATIONS_REFERENCE.md#m1015), [M1041 Encrypt Sensitive Information](../ATTACK_MITIGATIONS_REFERENCE.md#m1041), [M1042 Disable or Remove Feature or Program](../ATTACK_MITIGATIONS_REFERENCE.md#m1042), [M1047 Audit](../ATTACK_MITIGATIONS_REFERENCE.md#m1047)  
**NIST 800-53 R5 controls (3):** `IA-13`, `IA-2`, `IA-5`  
**ATT&CK detection strategy:** Detection Strategy for Steal or Forge Authentication Certificates  
**Used by 1 threat groups:** [G0016 APT29](https://attack.mitre.org/groups/G0016)  
**Implemented by 2 software:** [S0002 Mimikatz](https://attack.mitre.org/software/S0002), [S0677 AADInternals](https://attack.mitre.org/software/S0677)  

---
