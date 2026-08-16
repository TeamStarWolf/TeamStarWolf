# ATT&CK Data Components & Log Sources

> The **106 MITRE ATT&CK data components** (v18.1) — the telemetry categories that feed detection — each with the concrete **log sources and channels** that populate it and the number of techniques its analytics help detect. Use this to plan logging coverage: if a data component is dark in your environment, every technique that depends on it is a blind spot.

Machine-readable: [`data/attack/data_components.jsonl`](data/attack/data_components.jsonl). See also: [Detection Strategies](detections/strategies/README.md) · [Technique Detection Library](detections/TECHNIQUE_DETECTION_LIBRARY.md).

| Data Component | Data Source | Techniques | Example log sources |
|---|---|--:|---|
| Process Creation | — | 452 | `Process`, `auditd:SYSCALL`, `macos:unifiedlog`, `WinEventLog:Sysmon` +316 |
| Command Execution | — | 209 | `Command`, `auditd:SYSCALL`, `macos:unifiedlog`, `EDR:AMSI` +279 |
| File Creation | — | 174 | `File`, `WinEventLog:Sysmon`, `auditd:SYSCALL`, `macos:unifiedlog` +85 |
| Network Connection Creation | — | 151 | `Network Traffic`, `AWS:VPCFlowLogs`, `macos:unifiedlog`, `esxi:hostd` +91 |
| Network Traffic Content | — | 139 | `Network Traffic`, `ebpf:syscalls`, `WebProxy:AccessLogs`, `NSM:Flow` +235 |
| File Modification | — | 115 | `File`, `auditd:SYSCALL`, `macos:unifiedlog`, `fs:fileevents` +140 |
| Module Load | — | 109 | `Module`, `WinEventLog:Sysmon`, `ETW:LoadImage`, `auditd:SYSCALL` +35 |
| Application Log Content | — | 98 | `Application Log`, `WinEventLog:Application`, `m365:unified`, `saas:okta` +202 |
| Network Traffic Flow | — | 92 | `Network Traffic`, `macos:osquery`, `NSM:Flow`, `snmp:config` +151 |
| File Access | — | 91 | `File`, `m365:unified`, `auditd:SYSCALL`, `macos:unifiedlog` +98 |
| Windows Registry Key Modification | — | 86 | `Windows Registry`, `WinEventLog:Security`, `WinEventLog:Security`, `WinEventLog:Sysmon` +6 |
| Process Access | — | 77 | `WinEventLog:Sysmon`, `linux:osquery`, `auditd:SYSCALL`, `macos:unifiedlog` +18 |
| File Metadata | — | 64 | `File`, `linux:osquery`, `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational`, `journald:package` +85 |
| Logon Session Creation | — | 56 | `Logon Session`, `macos:unifiedlog`, `AWS:CloudTrail`, `azure:signin` +63 |
| OS API Execution | — | 54 | `Process`, `etw:Microsoft-Windows-Kernel-Base`, `AWS:CloudTrail`, `macos:osquery` +65 |
| User Account Authentication | — | 53 | `User Account`, `NSM:Flow`, `WinEventLog:Security`, `saas:okta` +102 |
| Logon Session Metadata | — | 30 | `Logon Session`, `WinEventLog:Security`, `macos:unifiedlog`, `WinEventLog:Security` +30 |
| Process Metadata | — | 30 | `Process`, `macos:unifiedlog`, `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational`, `linux:syslog` +40 |
| Response Content | — | 28 | `Internet Scan`, `NSM:Flow` |
| Service Creation | — | 28 | `Service`, `WinEventLog:System`, `auditd:CONFIG_CHANGE`, `macos:osquery` +11 |
| Script Execution | — | 28 | `Script`, `m365:office`, `macos:unifiedlog`, `linux:syslog` +28 |
| Process Modification | — | 24 | `auditd:SYSCALL`, `auditd:SYSCALL`, `macos:endpointsecurity`, `auditd:SYSCALL` +15 |
| User Account Modification | — | 21 | `azure:audit`, `linux:syslog`, `WinEventLog:Security`, `auditd:SYSCALL` +37 |
| User Account Metadata | — | 20 | `WinEventLog:Security`, `WinEventLog:Security`, `AWS:CloudTrail`, `auditd:SYSCALL` +24 |
| Cloud Service Modification | — | 18 | `AWS:CloudTrail`, `m365:unified`, `AWS:CloudTrail`, `AWS:CloudTrail` +27 |
| Active Directory Object Modification | — | 17 | `azure:activity`, `esxi:vpxa`, `WinEventLog:Security`, `WinEventLog:Security` +7 |
| Scheduled Job Creation | — | 15 | `Scheduled Job`, `WinEventLog:Security`, `linux:syslog`, `WinEventLog:TaskScheduler` +12 |
| Driver Load | — | 14 | `WinEventLog:Sysmon`, `linux:syslog`, `linux:syslog` |
| Host Status | — | 14 | `Sensor Health`, `macos:osquery`, `Windows:perfmon`, `macos:unifiedlog` +35 |
| Service Metadata | — | 13 | `Service`, `WinEventLog:Sysmon`, `linux:syslog`, `macos:unifiedlog` +17 |
| Firewall Rule Modification | — | 12 | `WinEventLog:Security`, `Firewall Audit Logs`, `esxi:hostd`, `networkdevice:cli` +10 |
| File Deletion | — | 12 | `File`, `auditd:SYSCALL`, `auditd:SYSCALL`, `macos:osquery` +18 |
| Cloud Storage Access | — | 11 | `AWS:CloudTrail`, `AWS:CloudTrail`, `m365:unified`, `m365:unified` +4 |
| Windows Registry Key Creation | — | 11 | `WinEventLog:Sysmon` |
| Instance Start | — | 11 | `AWS:CloudTrail`, `AWS:CloudTrail` |
| Firmware Modification | — | 10 | `Firmware`, `networkdevice:syslog`, `networkdevice:config`, `WinEventLog:Microsoft-Windows-Kernel-Boot` +15 |
| Active Directory Credential Request | — | 9 | `WinEventLog:Security`, `WinEventLog:Security`, `WinEventLog:Kerberos`, `WinEventLog:Security` +1 |
| Process Termination | — | 9 | `Process`, `WinEventLog:Sysmon`, `linux:syslog`, `macos:osquery` +9 |
| Cloud Service Metadata | — | 9 | `AWS:CloudTrail`, `AWS:CloudTrail`, `saas:github`, `AWS:CloudWatch` +6 |
| Network Share Access | — | 9 | `Network Share`, `WinEventLog:Microsoft-Windows-SMBClient/Security`, `WinEventLog:Security`, `WinEventLog:Security` +3 |
| Drive Creation | — | 8 | `Drive`, `WinEventLog:System`, `auditd:SYSCALL`, `macos:unifiedlog` +18 |
| Drive Access | — | 8 | `WinEventLog:Sysmon`, `auditd:SYSCALL`, `auditd:SYSCALL`, `auditd:SYSCALL` +4 |
| Container Creation | — | 8 | `kubernetes:apiserver`, `kubernetes:events`, `docker:daemon`, `kubernetes:audit` +4 |
| WMI Creation | — | 7 | `WinEventLog:WMI`, `WinEventLog:WMI`, `WinEventLog:Application` |
| Response Metadata | — | 7 | `Internet Scan`, `NSM:Flow` |
| Malware Metadata | — | 7 | `Malware Repository` |
| Drive Modification | — | 6 | `Drive`, `networkdevice:runtime`, `WinEventLog:Sysmon`, `macos:unifiedlog` +6 |
| Active Directory Object Access | — | 6 | `WinEventLog:Security`, `WinEventLog:Security` |
| Cloud Service Enumeration | — | 6 | `AWS:CloudTrail`, `gcp:secrets`, `azure:ad`, `AWS:CloudTrail` +7 |
| User Account Creation | — | 6 | `WinEventLog:Security`, `azure:audit`, `AWS:CloudTrail`, `saas:zoom` +7 |
| Windows Registry Key Access | — | 6 | `WinEventLog:Security`, `WinEventLog:Security`, `EDR:hunting`, `Autoruns:RegistryScan` |
| Web Credential Usage | — | 6 | `AWS:CloudTrail`, `m365:unified`, `AWS:CloudTrail`, `saas:access` +16 |
| Active DNS | — | 5 | `Domain Name` |
| Passive DNS | — | 5 | `Domain Name` |
| Domain Registration | — | 5 | `Domain Name`, `dns:query`, `esxi:vmkernel` |
| Instance Stop | — | 4 | `AWS:CloudTrail`, `AWS:CloudTrail` |
| Malware Content | — | 4 | `Malware Repository` |
| Snapshot Creation | — | 4 | `esxi:vmkernel`, `AWS:CloudTrail`, `azure:activity` |
| Container Start | — | 4 | `docker:events`, `kubernetes:events`, `containerd:runtime`, `docker:events` |
| Social Media | — | 4 | `Persona` |
| Named Pipe Metadata | — | 4 | `WinEventLog:Sysmon`, `macos:unifiedlog` |
| Active Directory Object Creation | — | 3 | `azure:audit`, `WinEventLog:Security`, `WinEventLog:Security`, `AWS:CloudTrail` |
| Cloud Storage Modification | — | 3 | `AWS:CloudTrail`, `AWS:CloudTrail`, `AWS:CloudTrail`, `m365:unified` +1 |
| Instance Metadata | — | 3 | `AWS:CloudTrail` |
| Scheduled Job Metadata | — | 3 | `Scheduled Job`, `linux:cron`, `fs:fileevents`, `WinEventLog:TaskScheduler` +4 |
| Image Creation | — | 3 | `containerd:events`, `docker:daemon`, `kubernetes:audit`, `AWS:CloudTrail` +2 |
| Image Metadata | — | 3 | `docker:events`, `esxi:vmkernel`, `kubernetes:apiserver` |
| Instance Creation | — | 3 | `azure:activity`, `gcp:audit`, `azure:activity`, `gcp:audit` +1 |
| Scheduled Job Modification | — | 3 | `Scheduled Job`, `auditd:CONFIG_CHANGE`, `m365:exchange`, `WinEventLog:Security` |
| Cloud Storage Enumeration | — | 3 | `AWS:CloudTrail`, `AWS:CloudTrail`, `azure:activity`, `gcp:storage` |
| Snapshot Deletion | — | 2 | `AWS:CloudTrail`, `esxi:hostd` |
| Certificate Registration | — | 2 | `Certificate` |
| Kernel Module Load | — | 2 | `esxi:vmkernel`, `macos:osquery` |
| Instance Enumeration | — | 2 | `AWS:CloudTrail`, `azure:activity`, `gcp:audit`, `AWS:CloudTrail` +1 |
| Volume Deletion | — | 2 | `esxi:vmkernel`, `AWS:CloudTrail` |
| Cloud Storage Deletion | — | 2 | `AWS:CloudTrail` |
| Pod Creation | — | 2 | `AWS:CloudTrail`, `kubernetes:audit` |
| Web Credential Creation | — | 2 | `WinEventLog:ADFS`, `AWS:CloudTrail`, `azure:signinlogs`, `m365:unified` +1 |
| Service Modification | — | 2 | `Service`, `WinEventLog:Microsoft-IIS-Configuration`, `WinEventLog:System` |
| Snapshot Metadata | — | 2 | `AWS:CloudTrail`, `gcp:audit`, `AWS:CloudTrail` |
| Container Enumeration | — | 2 | `docker:daemon`, `AWS:CloudTrail`, `containerd:runtime` |
| Firewall Disable | — | 2 | `esxi:vmkernel`, `AWS:CloudTrail` |
| Volume Modification | — | 2 | `kubernetes:apiserver`, `AWS:CloudTrail` |
| User Account Deletion | — | 2 | `WinEventLog:Security`, `esxi:hostd`, `m365:unified` |
| Volume Creation | — | 2 | `AWS:CloudTrail`, `WinEventLog:Microsoft-Windows-VSS` |
| Cloud Storage Metadata | — | 2 | `AWS:CloudTrail`, `m365:unified`, `saas:box`, `saas:dropbox` |
| Cloud Service Disable | — | 2 | `AWS:CloudTrail`, `AWS:CloudTrail`, `azure:activity`, `saas:audit` +1 |
| Snapshot Modification | — | 2 | `AWS:CloudTrail` |
| Group Modification | — | 1 | `m365:unified` |
| Image Modification | — | 1 | `docker:registry`, `AWS:CloudTrail` |
| Pod Enumeration | — | 1 | `kubernetes:apiserver` |
| Instance Modification | — | 1 | `AWS:CloudTrail`, `azure:activity`, `gcp:audit` |
| Cloud Storage Creation | — | 1 | `AWS:CloudTrail` |
| Instance Deletion | — | 1 | `azure:activity`, `gcp:audit` |
| Group Metadata | — | 1 | `m365:sharepoint` |
| Group Enumeration | — | 1 | `AWS:CloudTrail`, `azure:audit`, `gcp:audit`, `saas:salesforce` +1 |
| Active Directory Object Deletion | — | 1 | `WinEventLog:Security` |
| Volume Metadata | — | 0 | `Metadata` |
| Windows Registry Key Deletion | — | 0 | `Windows Registry` |
| Pod Modification | — | 0 |  |
| Firewall Metadata | — | 0 |  |
| Image Deletion | — | 0 |  |
| Firewall Enumeration | — | 0 |  |
| Volume Enumeration | — | 0 |  |
| Driver Metadata | — | 0 |  |
| Snapshot Enumeration | — | 0 |  |

---

## Detail

### Process Creation
**Feeds detection for 452 techniques.**  
Refers to the event in which a new process (executable) is initialized by an operating system. This can involve parent-child process relationships, process arguments, and environmental variables. Monitoring process creation is crucial for detecting malicious behaviors, such as execution of unauthorized binaries, scripting abuse, or privilege escalation attempts..  

| Log source | Channel |
|---|---|
| `Process` |  |
| `auditd:SYSCALL` | execve |
| `macos:unifiedlog` | log stream 'eventMessage contains pubsub or broker' |
| `WinEventLog:Sysmon` | EventCode=1 |
| `linux:osquery` | Execution of binary resolved from $PATH not located in /usr/bin or /bin |
| `macos:unifiedlog` | Process execution path inconsistent with baseline PATH directories |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC |
| `WinEventLog:Security` | EventCode=4688 |
| `linux:osquery` | process_events |
| `macos:endpointsecurity` | exec |
| `macos:osquery` | processes |
| `macos:unifiedlog` | Execution of launchctl with suspicious arguments |
| `auditd:SYSCALL` | execve network tools |
| `macos:osquery` | process_events |
| `auditd:SYSCALL` | execve calls to soffice.bin with suspicious macro execution flags |
| `macos:unifiedlog` | Process execution of Microsoft Word, Excel, PowerPoint with macro execution attempts |
| `macos:osquery` | process reading browser configuration paths |
| `macos:unifiedlog` | exec logs |
| `auditd:EXECVE` | execve: Processes launched with LD_PRELOAD/LD_LIBRARY_PATH pointing to non-system dirs |
| `macos:endpointsecurity` | exec: Process execution context for loaders calling dlopen/dlsym |
| `auditd:EXECVE` | EXECVE |
| `auditd:EXECVE` | execution of unexpected binaries during user shell startup |
| `macos:unifiedlog` | launch of Terminal.app or shell with non-standard environment setup |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC with unusual parent-child process relationships from zsh |
| `auditd:SYSCALL` | execve of systemctl or service stop |
| `auditd:SYSCALL` | execve of launchctl or pkill |
| `macos:unifiedlog` | process::exec |
| `auditd:SYSCALL` | execve: Execution of klist, kinit, or tools interacting with ccache outside normal user context |
| `macos:osquery` | Execution of non-standard binaries accessing Kerberos APIs |
| `auditd:SYSCALL` | execve: Electron-based binary spawning shell or script interpreter |
| `macos:unifiedlog` | Electron app spawning unexpected child process |
| `esxi:shell` | /root/.ash_history or /etc/init.d/* |
| `auditd:SYSCALL` | execve calls with high-frequency or known bandwidth-intensive tools |
| `macos:unifiedlog` | exec or spawn calls to proxy tools or torrent clients |
| `containers:osquery` | bandwidth-intensive command execution from within a container namespace |
| `macos:unifiedlog` | process launch |
| `macos:unifiedlog` | log stream --info --predicate 'subsystem == "com.apple.cfprefsd"' |
| `macos:unifiedlog` | execution of security, sqlite3, or unauthorized binaries |
| `macos:unifiedlog` | Unexpected applications generating outbound DNS queries |
| `linux:Sysmon` | EventCode=1 |
| `macos:osquery` | execve |
| `macos:unifiedlog` | Unexpected child process of Safari or Chrome |
| `auditd:SYSCALL` | execve or syscall invoking vm artifact check commands (e.g., dmidecode, lspci, dmesg) |
| `macos:unifiedlog` | execution of system_profiler, ioreg, kextstat with argument patterns related to VM/sandbox checks |
| `macos:unifiedlog` | process writes or modifies files in excluded paths |
| `macos:unifiedlog` | process |
| `macos:unifiedlog` | com.apple.mail.* exec.* |
| `macos:unifiedlog` | execution of memory inspection tools (lldb, gdb, osqueryi) |
| `esxi:vobd` | /var/log/vobd.log |
| `kubernetes:apiserver` | kubectl exec or kubelet API calls targeting running pods |
| `docker:audit` | Process execution events within container namespace context |
| `auditd:SYSCALL` | process persists beyond parent shell termination |
| `macos:unifiedlog` | background process persists beyond user logout |
| `auditd:SYSCALL` | execve: Execution of scripts or binaries sourced from mail directories (/var/mail, ~/Maildir) |
| `macos:unifiedlog` | Preview.app, Safari.app, or Mail.app spawning new processes outside normal patterns |
| `esxi:hostd` | process execution across cloud VM |
| `auditd:EXECVE` | systemctl spawning managed processes |
| `macos:unifiedlog` |  |
| `esxi:shell` | /var/log/shell.log |
| `macos:unifiedlog` | Execution of processes linked to hijacked sessions (e.g., anomalous parent-child process lineage) |
| `macos:unifiedlog` | exec events where web process starts a shell/tooling |
| `docker:events` | Docker/Kubernetes audit of exec/attach (kubectl exec) or unexpected child processes inside container |
| `macos:unifiedlog` | exec of osascript, bash, curl with suspicious parameters |
| `auditd:SYSCALL` | execve: Execution of container management CLIs (docker, crictl, kubectl) or interpreted shells (sh, bash, python) within container context |
| `macos:endpointsecurity` | es_event_exec |
| `auditd:SYSCALL` | execve: Execution of discovery commands targeting backup binaries, processes, or config paths |
| `macos:unifiedlog` | Process execution logs showing discovery commands like mdfind, system_profiler, or launchctl list |
| `macos:osquery` | process_events OR launchd |
| `auditd:EXECVE` | execve |
| `macos:osquery` | launchd or process_events |
| `macos:unifiedlog` | process and file events via log stream |
| `auditd:SYSCALL` | execve: Execution of scripts or binaries spawned from browser processes |
| `macos:unifiedlog` | Browser processes launching unexpected interpreters (osascript, bash) |
| `macos:unifiedlog` | exec: Execution of defaults, plutil, or common editors (vim/nano) targeting plist files |
| `auditd:SYSCALL` | EXECVE |
| `macos:unifiedlog` | process:exec |
| `auditd:SYSCALL` | execve: Execution of bash, python, or perl processes spawned by browser/email client |
| `macos:unifiedlog` | Execution of osascript, bash, or Terminal initiated from Mail.app or Safari |
| `auditd:SYSCALL` | execve of /bin/sh,/bin/bash,/usr/bin/curl,/usr/bin/python by service accounts (e.g., apache, mysql, nobody) immediately after inbound network activity. |
| `macos:osquery` | parent_name in ('sshd','httpd','screensharingd') spawning shells or scripting runtimes. |
| `macos:unifiedlog` | process activity stream |
| `auditd:SYSCALL` | SYSCALL record where exe contains passwd/userdel/chage and auid != root |
| `macos:unifiedlog` | Post-login execution of unrecognized child process from launchd or loginwindow |
| `auditd:SYSCALL` | execve of base64|openssl|xxd|python|perl with arguments matching Base64 flags |
| `macos:unifiedlog` | process command line contains base64, -enc, openssl enc -base64 |
| `macos:endpointsecurity` | exec: arguments contain Base64-like strings |
| `esxi:shell` | commands containing base64, openssl enc -base64, xxd -p |
| `macos:unifiedlog` | Execution of process launched via loginwindow session restore |
| `macos:unifiedlog` | process: exec + filewrite: ~/.ssh/authorized_keys |
| `containerd:runtime` | /var/log/containers/*.log |
| `macos:unifiedlog` | Execution of Java apps or other processes with hidden window attributes |
| `macos:unifiedlog` | Process Execution |
| `auditd:SYSCALL` | execve on code or jetbrains-gateway with remote flags |
| `macos:unifiedlog` | process: code or jetbrains-gateway launching with --tunnel or --remote |
| `macos:unifiedlog` | log stream --predicate 'processImagePath CONTAINS "curl" OR "osascript"' |
| `auditd:EXECVE` | Execution of dd, shred, wipe targeting block devices |
| `auditd:SYSCALL` | execve of sleep or ping command within script interpreted by bash/python |
| `auditd:SYSCALL` | execve or socket/connect system calls from processes using crypto libraries |
| `macos:unifiedlog` | Process using AES/RC4 routines unexpectedly |
| `linux:osquery` | execution of known firewall binaries |
| `auditd:SYSCALL` | type=EXECVE or SYSCALL for /bin/date, /usr/bin/timedatectl, /sbin/hwclock, /bin/cat /etc/timezone, /bin/cat /proc/uptime |
| `linux:osquery` | execve: command like 'date', 'timedatectl', 'hwclock', 'cat /etc/timezone' |
| `macos:unifiedlog` | process exec events of systemsetup, date, ioreg with command_line parameters indicating time discovery |
| `macos:endpointsecurity` | exec: binary == "/usr/sbin/systemsetup" and args contains "-gettimezone" |
| `macos:osquery` | execve: command LIKE '%systemsetup -gettimezone%' OR '%date%' |
| `macos:unifiedlog` | execution of osascript, curl, or unexpected automation |
| `macos:unifiedlog` | exec /usr/bin/pwpolicy |
| `auditd:SYSCALL` | socket(AF_PACKET|AF_INET, SOCK_RAW, *), setsockopt(… SO_ATTACH_FILTER|SO_ATTACH_BPF …), bpf(cmd=BPF_PROG_LOAD), open/openat path="/dev/bpf*" (BSD/macOS-like) or setcap cap_net_raw. |
| `linux:syslog` | KERN messages about eBPF program load/verify or LSM denials related to bpf. |
| `OpenBSM:AuditTrail` | open/openat of /dev/bpf*; ioctl BIOCSETF-like operations. |
| `macos:unifiedlog` | Exec of tcpdump, rvictl, custom tools linked to libpcap.A.dylib; sysextd/systemextensionsctl events for NetworkExtension content filters. |
| `auditd:EXECVE` | /usr/sbin/postfix, /usr/sbin/exim, /usr/sbin/sendmail |
| `auditd:SYSCALL` | execution of known flash tools (e.g., flashrom, fwupd) |
| `macos:unifiedlog` | com.apple.firmwareupdater activity or update-firmware binary invoked |
| `auditd:SYSCALL` | execve of system tools like dmidecode, lspci, lscpu, dmesg, systemd-detect-virt |
| `macos:unifiedlog` | exec or spawn of 'system_profiler', 'ioreg', 'kextstat', 'sysctl', or calls to sysctl API |
| `macos:endpointSecurity` | ES_EVENT_TYPE_NOTIFY_EXEC |
| `auditd:SYSCALL` | execve: Suspicious binaries or scripts interacting with authentication binaries (sshd, gdm, login) |
| `macos:osquery` | execve: Processes unexpectedly invoking Keychain or authentication APIs |
| `auditd:SYSCALL` | execve: execve calls where a browser/webview process is parent and child is interpreter (python, sh, ruby) or downloader (curl, wget) |
| `macos:unifiedlog` | process_create: Process creation where parent is Safari/Google Chrome and child is script interpreter or signed-but-unusual helper binary |
| `auditd:EXECVE` |  |
| `macos:unifiedlog` | process:launch |
| `auditd:EXECVE` | Shell commands invoked by SQL process such as postgres, mysqld, or mariadbd |
| `auditd:SYSCALL` | execve of smbclient, smbmap, rpcclient, nmblookup, crackmapexec smb |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC: Process execution of "sharing -l", "smbutil view", "mount_smbfs" |
| `macos:unifiedlog` | Execution of scp, rsync, curl with remote destination |
| `macos:unifiedlog` | logMessage contains pbpaste or osascript |
| `auditd:SYSCALL` | execve call with argv matching known disk enumeration commands (lsblk, parted, fdisk) |
| `macos:unifiedlog` | process launch of diskutil or system_profiler with SPStorageDataType |
| `esxi:hostd` | execution of esxcli with args matching 'storage', 'filesystem', 'core device list' |
| `macos:unifiedlog` | Mail.app executing with parameters updating rules state |
| `esxi:shell` | /var/log/vmkernel.log, /var/log/vmkwarning.log |
| `macos:endpointsecurity` | exec: Exec of ffmpeg, avfoundation-based binaries, or custom signed apps accessing camera |
| `kubernetes:apiserver` | exec into pod followed by secret retrieval via API |
| `macos:unifiedlog` | process_name IN ("VBoxManage", "prlctl") AND command CONTAINS ("list", "show") |
| `macos:unifiedlog` | exec srm|exec openssl|exec gpg |
| `linux:osquery` | Process execution with LD_PRELOAD or modified library path |
| `macos:unifiedlog` | Execution of process with DYLD_INSERT_LIBRARIES set |
| `linux:Sysmon` | process creation events linked to container namespaces executing host-level binaries |
| `macos:unifiedlog` | process and signing chain events |
| `macos:unifiedlog` | launchservices events for misleading extensions |
| `fs:fsusage` | Execution of disguised binaries |
| `linux:osquery` | process listening or connecting on non-standard ports |
| `macos:unifiedlog` | launchd services binding to non-standard ports |
| `auditd:SYSCALL` | execve, connect |
| `esxi:cron` | process or cron activity |
| `macos:unifiedlog` | Execution of binaries with unsigned or anomalously signed certificates |
| `auditd:SYSCALL` | execve logging for /usr/bin/systemctl and systemd-run |
| `macos:osquery` | Invocation of osascript or dylib injection |
| `auditd:SYSCALL` | execve: Execution of files saved in mail or download directories |
| `macos:unifiedlog` | Execution of Terminal, osascript, or other interpreters originating from Mail or Preview |
| `macos:unifiedlog` | process events |
| `linux:syslog` | Unauthorized sudo or shell access, especially leading to file changes in /var/www or /srv/http |
| `macos:unifiedlog` | Execution of unexpected terminal or web scripts modifying /Library/WebServer/Documents |
| `auditd:SYSCALL` | execve: Execution of CLI tools like psql, mysql, mongo, sqlite3 |
| `macos:unifiedlog` | Process start of Java or native DB client tools |
| `macos:unifiedlog` | loginwindow or tccd-related entries |
| `macos:osquery` | query: process_events, launchd, and tcc.db access |
| `ebpf:syscalls` | process execution or network connect from just-created container PID namespace |
| `auditd:SYSCALL` | execve: Execution of pip, npm, gem, or similar package managers |
| `macos:unifiedlog` | Command line invocation of pip3, brew install, npm install from interactive Terminal |
| `auditd:SYSCALL` | fork/exec of service via PID 1 (systemd) |
| `auditd:EXECVE` | Execution of ssh/scp/sftp without corresponding authentication log |
| `macos:unifiedlog` | Execution of ssh or sftp without corresponding login event |
| `auditd:SYSCALL` | execve: execve where exe=/usr/bin/python3 or similar interpreter |
| `macos:unifiedlog` | launch of remote desktop app or helper binary |
| `macos:unifiedlog` | Unexpected processes making network calls based on DNS-derived ports |
| `macos:unifiedlog` | launchctl spawning new processes |
| `macos:unifiedlog` | launchctl activity and process creation |
| `containerd:events` | New container with suspicious image name or high resource usage |
| `macos:unifiedlog` | Execution of Python, Swift, or other binaries invoking archiving libraries |
| `linux:osquery` | Processes linked with libssl or crypto libraries making outbound connections |
| `macos:unifiedlog` | Process invoking SSL routines from Security framework |
| `auditd:SYSCALL` | Execution of binaries located in /etc/init.d/ or systemd service paths |
| `macos:unifiedlog` | Execution of binary listed in newly modified LaunchAgent plist |
| `macos:unifiedlog` | Execution of bless or nvram modifying boot parameters |
| `macos:unifiedlog` | Unexpected processes registered with launchd |
| `macos:unifiedlog` | Process launch |
| `macos:unifiedlog` | execution of curl, osascript, or unexpected Office processes |
| `macos:osquery` | exec |
| `macos:unifiedlog` | Trust validation failures or bypass attempts during notarization and code signing checks |
| `esxi:vmkernel` | spawned shell or execution environment activity |
| `macos:unifiedlog` | process_exec: image in {/bin/bash,/bin/zsh,/usr/bin/osascript,/usr/bin/python*,/usr/bin/curl,/usr/bin/ssh,/usr/bin/open} AND parent in {Preview, TextEdit, Microsoft Word, Microsoft Excel, AdobeReader, Archive Utility, Finder} |
| `auditd:SYSCALL` | execve: exe in {/bin/bash,/bin/sh,/usr/bin/python*,/usr/bin/perl,/usr/bin/php,/usr/bin/node,/usr/bin/curl,/usr/bin/wget,/usr/bin/xdg-open,/usr/bin/ssh,/usr/bin/rundll32 (wine)} AND ppid process is a document viewer/browser |
| `auditd:EXECVE` | Execution of dd/sgdisk with arguments writing to sector 0 or partition table |
| `macos:unifiedlog` | Execution of zip, ditto, hdiutil, or openssl by processes not normally associated with archiving |
| `macos:unifiedlog` | process execution events for chmod, chown, chflags with unusual parameters or targets |
| `m365:defender` | AdvancedHunting(DeviceEvents, ProcessCreate, ImageLoad, AMSI/ETW derived signals) |
| `macos:unifiedlog` | execve or dylib load from memory without backing file |
| `auditd:SYSCALL` | execve: Commands that alter firewall or start listeners: iptables|nft|ufw|firewall-cmd|pfctl|systemctl start sshd/telnet/dropbear; raw-socket/libpcap tools (tcpdump, tshark, nmap --raw). |
| `macos:unifiedlog` | exec: Execution of pfctl, socketfilterfw, launchctl start ssh/telnet, libpcap consumers. |
| `esxi:shell` | Shell Execution |
| `macos:unifiedlog` | Unusual child process tree indicating attempted recovery after crash |
| `auditd:SYSCALL` | execve: Execution of binaries/scripts presenting false health messages for security daemons |
| `macos:unifiedlog` | Execution of processes mimicking Apple Security & Privacy GUIs |
| `auditd:SYSCALL` | execve, setifflags |
| `macos:osquery` | process_events where path like '%tcpdump%' |
| `auditd:EXECVE` | Execution of dd, shred, or wipe with arguments targeting block devices |
| `auditd:EXECVE` | systemctl stop auditd, kill -9 <pid>, or modifications to /etc/selinux/config |
| `macos:unifiedlog` | execution of curl, git, or Office processes with network connections |
| `macos:unifiedlog` | log stream - process subsystem |
| `auditd:SYSCALL` | execve calls for qemu-system*, kvm, or VBoxHeadless |
| `macos:unifiedlog` | Process execution for VBoxHeadless, prl_vm_app, vmware-vmx |
| `macos:unifiedlog` | process logs |
| `esxi:shell` |  |
| `auditd:SYSCALL` | execve of interpreters (python, perl), custom binaries, or shell utilities with long arguments containing non-standard tokens |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC: arguments contain long, non-standard tokens / custom alphabets |
| `macos:unifiedlog` | command line or log output shows non-standard encoding routines |
| `esxi:shell` | commands containing long non-standard tokens or custom lookup tables |
| `macos:unifiedlog` | Execution of /usr/sbin/installer spawning child process from within /private/tmp or package contents |
| `auditd:SYSCALL` | Execution of dpkg or rpm followed by fork/execve from within postinst, prerm, etc. |
| `macos:unifiedlog` | execve: Helper tools invoked through XPC executing unexpected binaries |
| `macos:unifiedlog` | execution of modified binary without valid signature |
| `auditd:SYSCALL` | execve: exe in (/usr/bin/bash,/usr/bin/sh,/usr/bin/zsh,/usr/bin/python*) AND cmdline matches '(curl|wget).*(\||\|\s*sh|bash)|base64\s*-d|python\s*-c' |
| `macos:unifiedlog` | exec: ParentImage in (Terminal, iTerm2) AND Image in (/bin/zsh,/bin/bash,/usr/bin/python*) AND CommandLine matches '(curl|wget).*(\||\|\s*sh|bash)|base64 -D|python -c' |
| `macos:unifiedlog` | process created with repeated ICMP or UDP flood behavior |
| `fs:fsusage` | binary execution of security_authtrampoline |
| `macos:unifiedlog` | process: exec |
| `esxi:vmkernel` | Exec |
| `macos:unifiedlog` | Child processes of Safari, Chrome, or Firefox executing scripting interpreters |
| `macos:unifiedlog` | Execution of older or non-standard interpreters |
| `linux:osquery` | process execution events for permission modification utilities with command-line analysis |
| `macos:unifiedlog` | process execution events for chmod, chown, chflags with parameter analysis and target path examination |
| `macos:osquery` | process execution monitoring for permission modification utilities with command-line argument analysis |
| `auditd:SYSCALL` | Invocation of packet generation tools (e.g., hping3, nping) or fork bombs |
| `macos:osquery` | Execution of flooding tools or compiled packet generators |
| `esxi:hostd` | process |
| `auditd:SYSCALL` | execve for proxy tools |
| `macos:unifiedlog` | process, socket, and DNS logs |
| `macos:osquery` | process_events table |
| `macos:unifiedlog` | Command line containing `trap` or `echo 'trap` written to login shell files |
| `macos:unifiedlog` | log collect --predicate |
| `auditd:SYSCALL` | execve or nanosleep with no stdout/stderr I/O |
| `macos:unifiedlog` | launchd or osascript spawns process with delay command |
| `linux:syslog` | systemd-udevd spawning user-defined action from RUN+= |
| `ebpf:syscalls` | execve |
| `macos:unifiedlog` | process:spawn |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "exec"' |
| `auditd:EXECVE` | cat|less|grep accessing .bash_history from a non-shell process |
| `auditd:EXECVE` | Process execution via .desktop Exec path from /etc/xdg/autostart or ~/.config/autostart |
| `auditd:SYSCALL` | Execution of dpkg, rpm, or other package manager with list flag |
| `macos:unifiedlog` | Execution of system_profiler or osascript invoking enumeration |
| `auditd:SYSCALL` | apache2 or nginx spawning sh, bash, or python interpreter |
| `macos:unifiedlog` | httpd spawning bash, zsh, python, or osascript |
| `macos:unifiedlog` | Execution of /usr/libexec/security_authtrampoline or child processes originating from non-trusted binaries triggering credential prompts |
| `macos:unifiedlog` | execution of security or osascript |
| `macos:unifiedlog` | launchd spawning processes tied to new or modified LaunchDaemon .plist entries |
| `macos:unifiedlog` | Execution of ping, nping, or crafted network packets via bash or python to reflection services |
| `auditd:SYSCALL` | execve: Execution of commands modifying iptables/nftables to block selective IPs |
| `macos:unifiedlog` | System process modifications altering DNS/proxy settings |
| `containerd:Events` | unusual process spawned from container image context |
| `macos:osquery` | curl, python scripts, rsync with internal share URLs |
| `macos:unifiedlog` | process: spawn, exec |
| `macos:osquery` | Rapid spawning of resource-heavy applications (e.g., Preview, Safari, Office) |
| `macos:unifiedlog` | Process creation events where command line = pmset with arguments affecting sleep, hibernatemode, displaysleep |
| `macos:unifiedlog` | Unexpected apps performing repeated DNS lookups |
| `macos:unifiedlog` | launchservices or loginwindow events |
| `auditd:SYSCALL` | execve with LD_PRELOAD or linker-related environment variables set |
| `macos:unifiedlog` | execution of process with DYLD_INSERT_LIBRARIES set |
| `macos:unifiedlog` | Suspicious Swift/Objective-C or scripting processes writing archive-like outputs |
| `auditd:SYSCALL` | execve of re-parented process |
| `linux:osquery` | Anomalous parent PID change |
| `macos:unifiedlog` | Process creation with parent PID of 1 (launchd) |
| `linux:osquery` | child process invoking dynamic linker post-ptrace |
| `macos:osquery` | Processes executing kextload, spctl, or modifying kernel extension directories |
| `macos:osquery` | Unsigned or ad-hoc signed process executions in user contexts |
| `macos:unifiedlog` | Execution of diskutil or hdiutil attaching hidden partitions |
| `macos:unifiedlog` | process execution events for discovery utilities (system_profiler, sw_vers, dscl, networksetup) with command-line parameter analysis |
| `macos:osquery` | process event monitoring with focus on discovery utilities and cryptographic framework usage correlation |
| `macos:unifiedlog` | Unexpected apps generating frequent DNS queries |
| `macos:unifiedlog` | process exec |
| `auditd:SYSCALL` | socket: Suspicious creation of AF_UNIX sockets outside expected daemons |
| `macos:unifiedlog` | Non-standard processes invoking financial applications or payment APIs |
| `auditd:SYSCALL` | execve: Agent/headless flags (listen/connect/reverse/tunnel) or remote-control binaries spawning shells |
| `auditd:SYSCALL` | systemctl enable/start: Creation/enablement of custom .service units in /etc/systemd/system |
| `macos:unifiedlog` | Process exec of remote-control apps or binaries with headless/connect flags |
| `auditd:SYSCALL` | execve: systemctl stop, service stop, or kill -9 on security daemons (e.g., falcon-sensor, auditd) |
| `macos:unifiedlog` | Execution of launchctl unload, kill, or removal of security agent daemons |
| `macos:unifiedlog` | process activity, exec events |
| `macos:unifiedlog` | log stream process subsystem |
| `macos:unifiedlog` | process:exec and kext load events |
| `macos:unifiedlog` | log stream --info --predicate 'eventMessage CONTAINS "exec"' |
| `WinEventLog:Microsoft-Windows-DotNETRuntime` | Unexpected AppDomain creation events or anomalous AppDomainManager assembly load behavior |
| `auditd:SYSCALL` | Execution of network stress tools or anomalies in socket/syscall behavior |
| `macos:unifiedlog` | Unsigned binary execution following SIP change |
| `auditd:SYSCALL` | execve: Commands altering firewall or enabling listeners (iptables, nft, ufw, firewall-cmd, systemctl start *ssh*/*telnet*, ip route add, tcpdump, tshark) |
| `macos:unifiedlog` | exec: Execution of /sbin/pfctl, /usr/libexec/ApplicationFirewall/socketfilterfw, ifconfig, tcpdump, npcap/libpcap consumers |
| `macos:unifiedlog` | Execution of zip, ditto, hdiutil, or openssl by non-terminal parent processes |
| `macos:unifiedlog` | Execution of binaries with TCC protected access under unexpected parent processes such as Finder.app, SystemUIServer, or nsurlsessiond |
| `WinEventLog:AppLocker` | EventCode=8003, 8004 |
| `auditd:SYSCALL` | execve, unlink |
| `macos:osquery` | launchd, processes |
| `linux:osquery` | socat, ssh, or nc processes opening unexpected ports |
| `macos:unifiedlog` | process execution of ssh with -L/-R forwarding flags |
| `macos:unifiedlog` | launchd or cron spawning mining binaries |
| `auditd:SYSCALL` | execve or socket/connect system calls for processes using RSA handshake |
| `macos:unifiedlog` | Process invoking SecKeyCreateRandomKey or asymmetric crypto APIs |
| `azure:vmguest` | Unexpected execution of cloud agent processes (e.g., WindowsAzureGuestAgent.exe, ssm-agent) followed by arbitrary script or binary execution |
| `macos:unifiedlog` | Script interpreter invoked by nginx/apache worker process |
| `macos:unifiedlog` | execution of Office binaries with network activity |
| `macos:unifiedlog` | launch of bash/zsh/python/osascript targeting key file locations |
| `macos:unifiedlog` | execution of /sbin/emond with child processes launched |
| `etw:Microsoft-Windows-Kernel-Process` | provider: ETW CreateProcess events linking msbuild.exe to suspicious children where standard logs are incomplete |
| `macos:unifiedlog` | shutdown -h now or reboot |
| `macos:unifiedlog` | Execution of Code.app, idea, JetBrainsToolbox, eclipse with install/extension flags |
| `macos:unifiedlog` | process execution events for system discovery utilities (system_profiler, sysctl, networksetup, ioreg) with parameter analysis |
| `OpenBSM:AuditTrail` | BSM audit events for process execution and system call monitoring during reconnaissance |
| `esxi:hostd` | host daemon events related to VM operations and configuration queries during reconnaissance |
| `esxi:vmkernel` | VMware kernel events for hardware and system configuration access during environmental validation |
| `linux:osquery` | processes modifying environment variables related to history logging |
| `auditd:SYSCALL` | execve: parent process is usb/hid device handler, child process bash/python invoked |
| `macos:unifiedlog` | execution of curl, rclone, or Office apps invoking network sessions |
| `macos:unifiedlog` | exec: Execution of kextstat, kextfind, or ioreg targeting driver information |
| `macos:endpointsecurity` | exec events |
| `macos:unifiedlog` | Process creation involving binaries interacting with resource fork data |
| `macos:unifiedlog` | process event |
| `auditd:SYSCALL` | execve: Execution of suspicious exploit binaries targeting security daemons |
| `macos:osquery` | execve: Unsigned or unnotarized processes launched with high privileges |
| `macos:unifiedlog` | security OR injection attempts into 1Password OR LastPass |

---

### Command Execution
**Feeds detection for 209 techniques.**  
Command Execution involves monitoring and capturing the execution of textual commands (including shell commands, cmdlets, and scripts) within an operating system or application. These commands may include arguments or parameters and are typically executed through interpreters such as `cmd.exe`, `bash`, `zsh`, `PowerShell`, or programmatic execution. Examples: 

- Windows Command Prompt
 - dir – Lists directory contents.
 - net user – Queries or manipulates user accounts.
 - tasklist – Lists runn  

| Log source | Channel |
|---|---|
| `Command` |  |
| `auditd:SYSCALL` | execution of realmd, samba-tool, or ldapmodify with user-related arguments |
| `macos:unifiedlog` | dsconfigad or dscl with create or append options for AD-bound users |
| `EDR:AMSI` |  |
| `linux:syslog` | cron activity |
| `WinEventLog:PowerShell` | Get-ADTrust|GetAllTrustRelationships |
| `gcp:audit` |  |
| `auditd:SYSCALL` | Execution of script interpreters by systemd timer (ExecStart) |
| `AWS:CloudTrail` | InvokeFunction |
| `m365:unified` | Automated forwarding or file sync initiated by a logic app |
| `WinEventLog:PowerShell` | EventCode=4103, 4104, 4105, 4106 |
| `linux:syslog` | Suspicious script or command execution targeting browser folders |
| `esxi:shell` | snapshot create/copy, esxcli |
| `auditd:SYSCALL` | execve: Commands like systemctl stop <service>, service <service> stop, or kill -9 <pid> |
| `macos:unifiedlog` | launchctl unload, kill, or pkill commands affecting daemons or background services |
| `macos:unifiedlog` | execution of security-agent detection or enumeration commands |
| `macos:unifiedlog` | log stream --predicate |
| `WinEventLog:PowerShell` | Execution of Microsoft script to enumerate custom forms in Outlook mailbox |
| `m365:messagetrace` | Inbound email triggers execution of mailbox-stored custom form |
| `auditd:EXECVE` | Use of mv or cp to rename files with '.' prefix |
| `macos:unifiedlog` | Execution of chflags hidden or SetFile -a V |
| `esxi:shell` | interactive shell |
| `networkdevice:cli` | CLI command |
| `macos:unifiedlog` | log stream |
| `esxi:vmkernel` | /var/log/vmkernel.log |
| `auditd:SYSCALL` | execve calls to locale, timedatectl, or cat /etc/timezone |
| `macos:unifiedlog` | defaults read -g AppleLocale, systemsetup -gettimezone |
| `macos:unifiedlog` | profiles install -type=configuration |
| `auditd:SYSCALL` | sleep function usage or loops (nanosleep, usleep) in scripts |
| `m365:unified` | Search-Mailbox, Get-MessageTrace, eDiscovery requests |
| `EDR:cli` | Command Line Telemetry |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "loginwindow" or "pfctl"' |
| `networkdevice:syslog` | Command Audit / Configuration Change |
| `WinEventLog:Microsoft-Office/OutlookAddinMonitor` | Outlook loading add-in via unexpected load path or non-default profile context |
| `macos:unifiedlog` | exec or sudo usage with NOPASSWD context or echo modifying sudoers |
| `WinEventLog:Security` | EventCode=4103, 4104, 4105, 4106 |
| `auditd:EXECVE` | execve: Execution of update-ca-certificates or trust anchor modification commands |
| `macos:unifiedlog` | Execution of /usr/bin/security add-trusted-cert or keychain modifications to System.keychain |
| `auditd:EXECVE` | gcore, gdb, strings, hexdump execution |
| `auditd:SYSCALL` | connect, execve, write |
| `esxi:hostd` | command execution |
| `auditd:EXECVE` | Execution of auditctl, systemctl stop auditd, or kill -9 auditd |
| `macos:syslog` | system.log |
| `esxi:hostd` | /var/log/hostd.log |
| `esxi:shell` | /var/log/shell.log |
| `docker:daemon` | docker exec or docker run with unexpected command/entrypoint |
| `auditd:SYSCALL` | execve call including 'nohup' or trailing '&' |
| `macos:unifiedlog` | nohup, disown, or osascript execution patterns |
| `WinEventLog:PowerShell` | CommandLine=copy-item or robocopy from UNC path |
| `esxi:shell` | invoked remote scripts (esxcli) |
| `auditd:EXECVE` | execution of systemctl with subcommands start, stop, enable, disable |
| `networkdevice:cli` | Policy Update |
| `auditd:SYSCALL` |  |
| `AWS:CloudTrail` | eventName: RunInstances, CreateUser, PutRolePolicy, InvokeCommand |
| `gcp:audit` | methodName: setIamPolicy, startInstance, createServiceAccount |
| `auditd:SYSCALL` | execve: Commands executed within an SSH session where no matching logon/authentication event exists |
| `esxi:hostd` | modification of config files or shell command execution |
| `kubernetes:audit` | Shell process (e.g., /bin/sh, /bin/bash) spawned in a container without an interactive session attached (i.e., automation anomaly) |
| `macos:unifiedlog` | Execution of 'profiles install -type=configuration' |
| `macos:unifiedlog` | subsystem:com.apple.Terminal |
| `networkdevice:syslog` | eventlog |
| `esxi:hostd` | shell access or job registration |
| `WinEventLog:PowerShell` | PowerShell launched from outlook.exe or triggered without user invocation |
| `m365:messagetrace` | Inbound email matches crafted rule trigger pattern tied to persistence logic |
| `linus:syslog` |  |
| `linux:syslog` | Unusual outbound transfers from CLI tools like base64, gzip, or netcat |
| `macos:unifiedlog` | base64 or curl processes chained within short execution window |
| `esxi:shell` | base64 or gzip use within shell session |
| `macos:unifiedlog` | exec: Invocation of /usr/bin/defaults write or /usr/bin/plutil modifying plist keys |
| `auditd:SYSCALL` | chmod, execve |
| `macos:unifiedlog` | chmod command with arguments including '+s', 'u+s', or numeric values 4000–6777 |
| `macos:unifiedlog` | command includes dscl . delete or sysadminctl --deleteUser |
| `fs:fsusage` | file system activity monitor |
| `networkdevice:cli` | ip ssh pubkey-chain |
| `esxi:shell` | scripts or binaries with misleading names |
| `auditd:EXECVE` | Execution of GUI-related binaries with suppressed window/display flags |
| `linuxsyslog` | nslcd or winbind logs |
| `macos:unifiedlog` | DS daemon log entries |
| `esxi:hostd` | logline inspection |
| `macos:unifiedlog` | diskutil eraseDisk / asr restore with destructive flags |
| `networkdevice:cli` | erase flash:, erase startup-config, format disk |
| `networkdevice:syslog` | command_exec |
| `auditd:SYSCALL` | execve: iptables, nft, firewall-cmd modifications |
| `macos:unifiedlog` | pfctl -d, socketfilterfw --setglobalstate off, or modifications to com.apple.alf |
| `esxi:hostd` | esxcli network firewall set commands |
| `docker:events` | container exec rm|container stop --force |
| `esxi:hostd` | event stream |
| `networkdevice:cli` | CLI command logs |
| `esxi:shell` | /var/log/shell.log entries containing "esxcli system clock get" |
| `networkdevice:syslog` | command-exec: CLI commands containing "show clock", "show clock detail", "show timezone" executed by suspicious user/source |
| `networkdevice:cli` | cmd: cmd=show clock detail |
| `auditd:EXECVE` | curl -X POST, wget --post-data |
| `linux:syslog` | sudo chage|grep pam_pwquality|cat /etc/login.defs |
| `macos:unifiedlog` | pwpolicy|PasswordPolicy |
| `networkdevice:syslog` | cmd='show aaa*' OR 'show running-config | include password|aaa' OR 'show aaa common-criteria policy all' |
| `networkdevice:syslog` | CLI command audit |
| `networkdevice:cli` | Execution of commands to load, copy, or replace system images (e.g., 'copy tftp flash', 'boot system') |
| `WinEventLog:PowerShell` | Execution of PowerShell script to enumerate or remove malicious Home Page folder config |
| `m365:messagetrace` | Inbound email triggering Outlook to auto-access folder tied to malicious Home Page |
| `macos:unifiedlog` | Command line contains smbutil view //, mount_smbfs // |
| `auditd:SYSCALL` | execve: Invocation of scp, rsync, curl, or sftp |
| `esxi:hostd` | scp/ssh used to move file across hosts |
| `auditd:EXECVE` | command line arguments containing lsblk, fdisk, parted |
| `macos:unifiedlog` | log messages related to disk enumeration context or Terminal session |
| `auditd:SYSCALL` | execve calls modifying local mail filter configuration files |
| `esxi:hostd` |  |
| `esxi:shell` |  |
| `networkdevice:cli` |  |
| `linux:syslog` | sudo execution of ffmpeg/gst-launch/v4l2-ctl by non-standard user |
| `docker:api` | docker logs access or container inspect commands from non-administrative users |
| `esxi:shell` | command IN ("esxcli vm process list", "vim-cmd vmsvc/getallvms") |
| `auditd:SYSCALL` | execve: process_name IN ("virsh", "VBoxManage", "qemu-img") AND command IN ("list", "info") |
| `esxi:shell` | openssl|tar|dd |
| `AWS:CloudTrail` | SSM RunCommand |
| `azure:activity` | Intune PowerShell Scripts |
| `m365:exchange` | Cmdlet: Get-GlobalAddressList, Get-Recipient |
| `networkdevice:cli` | Execution of commands like 'show running-config', 'copy running-config', or 'export config' |
| `esxi:syslog` | boot logs |
| `networkdevice:syslog` | system boot logs |
| `auditd:SYSCALL` | execve: service stop syslog, systemctl stop rsyslog, kill -9 syslog |
| `macos:unifiedlog` | defaults write com.apple.system.logging or logd manipulation |
| `esxi:hostd` | esxcli system syslog config set or reload |
| `auditd:SYSCALL` | execve: openssl pkcs12, certutil, keytool |
| `macos:unifiedlog` | process calling security find-certificate, export, or import |
| `networkdevice:cli` | Execution of CLI commands altering crypto parameters (e.g., 'crypto key generate rsa modulus 512') |
| `auditd:SYSCALL` | execve: Process in container namespace executes curl|wget|bash|sh|python|nc with outbound args |
| `m365:exchange` | Get-RoleGroup, Get-DistributionGroup |
| `auditd:SYSCALL` | execution of systemctl or service with enable/start parameters |
| `auditd:SYSCALL` | execve: Execution of cat, less, grep, journalctl targeting log directories (/var/log/) |
| `macos:unifiedlog` | Execution of log show, fs_usage, or cat targeting system.log |
| `AWS:CloudTrail` | GetLogEvents: High frequency log exports from CloudWatch or equivalent services |
| `esxi:shell` | Execution of cat, tail, grep targeting /var/log/vmkernel.log or /var/log/hostd.log |
| `esxi:shell` | CLI usage logs |
| `macos:syslog` | /var/log/system.log |
| `macos:unifiedlog` | execution of launchctl load/unload/start commands |
| `WinEventLog:PowerShell` | Exchange Cmdlets |
| `auditd:SYSCALL` | execve: Execution of python, perl, or custom binaries invoking compression libraries |
| `auditd:SYSCALL` | execve, USER_CMD |
| `auditd:USER_CMD` | USER_CMD |
| `esxi:shell` | Command execution trace |
| `auditd:SYSCALL` | bash/zsh of base64, tar, gzip, or openssl immediately after file write |
| `linux:osquery` | Command-line includes base64 -d or openssl enc -d |
| `macos:unifiedlog` | base64 -d or osascript invoked on staged file |
| `auditd:EXECVE` | exec: Execution of dd, efibootmgr, or flashrom modifying firmware/boot partitions |
| `auditd:EXECVE` | curl -d, wget --post-data |
| `auditd:SYSCALL` | execve: Processes executing sendmail/postfix with forged headers |
| `macos:unifiedlog` | diskutil partitionDisk or eraseVolume with partition scheme modifications |
| `networkdevice:cli` | format flash:, format disk, reformat commands |
| `auditd:SYSCALL` | execve: Execution of tar, gzip, bzip2, xz, zip, or openssl with compression/encryption arguments |
| `auditd:PROCTITLE` | proctitle contains chmod, chown, setfacl, or attr commands with suspicious parameters |
| `esxi:shell` | shell command execution for chmod, chown, or file permission modification on VMFS or system files |
| `networkdevice:Firewall` | Audit trail or CLI/API access indicating commands like no access-list, delete rule-set, clear config |
| `auditd:EXECVE` | grep/cat/awk on files with password fields |
| `macos:unifiedlog` | grep/cat on files matching credential patterns |
| `kubernetes:audit` | process execution involving curl, grep, or awk on secrets |
| `AWS:CloudTrail` | command-line execution invoking credential enumeration |
| `auditd:SYSCALL` | promiscuous mode transitions (ioctl or ifconfig) |
| `fs:fsusage` | access to BPF devices or interface IOCTLs |
| `networkdevice:syslog` | exec command='monitor capture' |
| `WinEventLog:Microsoft-Office-Alerts` | Unexpected DLL or component loaded at Office startup |
| `m365:office` | Startup execution includes non-default component |
| `macos:unifiedlog` | diskutil eraseDisk/zeroDisk or asr restore with destructive flags |
| `networkdevice:cli` | erase flash:, erase nvram:, format disk |
| `macos:unifiedlog` | spctl --master-disable, csrutil disable, or defaults write to disable Gatekeeper |
| `esxi:shell` | esxcli system syslog config set --loghost='' or stopping hostd service |
| `networkdevice:syslog` | no logging buffered, no aaa new-model, disable firewall |
| `auditd:EXECVE` | git push, curl -X POST |
| `linux:cli` | command logging |
| `esxi:hostd` | command log |
| `networkdevice:cli` | command logs |
| `networkdevice:syslog` | interactive shell logging |
| `esxi:hostd` | Execution of '/bin/vmx' or modifications to '/etc/rc.local.d/local.sh' |
| `auditd:SYSCALL` | chattr, rm, shred, dd run on recovery directories or partitions |
| `networkdevice:syslog` | command sequence: erase → format → reload |
| `macos:unifiedlog` | process: at, job runner |
| `macos:osquery` | Interpreter exec with suspicious arguments as above |
| `auditd:SYSCALL` | execve: Execution of curl or wget writing files to /tmp/* followed by chmod or execution |
| `auditd:SYSCALL` | execve: Execution of downgraded interpreters such as python2 or forced fallback commands |
| `auditd:PROCTITLE` | proctitle contains chmod, chown, chgrp, setfacl, or attr with suspicious parameters (777, 755, +x, -R) |
| `auditd:EXECVE` | Execution of gsettings set org.gnome.login-screen disable-user-list true |
| `macos:unifiedlog` | Execution of dscl . create with IsHidden=1 |
| `linux:syslog` | sshd logs |
| `esxi:shell` | Shell Access/Command Execution |
| `networkdevice:syslog` | CLI Command Logging |
| `auditd:CONFIG_CHANGE` | udev rule reload or trigger command executed |
| `linux:cli` | Shell history logs |
| `macos:unifiedlog` | log stream --predicate 'processImagePath contains "zip" OR "base64"' |
| `networkdevice:cli` | command logging |
| `esxi:hostd` | Command Execution |
| `macos:osquery` | launchd + process_events |
| `esxi:vmkernel` | DCUI shell start, BusyBox activity |
| `esxi:hostd` | remote CLI + vim-cmd logging |
| `networkdevice:syslog` | CLI Command Audit |
| `m365:defender` | Activity Log: Command Invocation |
| `WinEventLog:PowerShell` | CmdletName: Get-Recipient, Get-User |
| `WinEventLog:PowerShell` | Execution of 'Get-WmiObject Win32_Product' or similar PowerShell cmdlets |
| `linux:shell` | Manual invocation of software enumeration commands via interactive shell |
| `auditd:SYSCALL` | Command line arguments including SPApplicationsDataType |
| `AWS:CloudTrail` | ssm:GetCommandInvocation |
| `esxi:shell` | esxcli software vib list |
| `auditd:EXECVE` | execution of setfattr or getfattr commands |
| `macos:unifiedlog` | xattr utility execution with -w or -p flags |
| `auditd:SYSCALL` | Execution of spoofing tools (e.g., hping3, nping, scapy) sending UDP packets to known amplifier ports |
| `auditd:SYSCALL` | execution of tools like cat, grep, or awk on credential files |
| `macos:unifiedlog` | execution of 'security', 'cat', or 'grep' commands accessing credential storage |
| `linux:syslog` | CLI access to 'show running-config', 'show password', or 'cat config.txt' |
| `auditd:SYSCALL` | execve of curl, rsync, wget with internal knowledge base or IPs |
| `esxi:shell` | /root/.ash_history |
| `auditd:SYSCALL` | execve: Execution of systemctl, loginctl, or systemd-inhibit commands related to sleep/hibernate |
| `auditd:SYSCALL` | Execution of xev, xdotool, or input activity emulators |
| `macos:unifiedlog` | launchctl load or boot-time plist registration |
| `auditd:SYSCALL` | execve: Execution of interpreters creating archive-like outputs without calling tar/gzip |
| `networkdevice:syslog` | command audit |
| `networkdevice:cli` | Interface commands |
| `macos:unifiedlog` | dscl -create |
| `esxi:vmkernel` | esxcli system account add |
| `ebpf:syscalls` | useradd or /etc/passwd modified inside container |
| `auditd:SYSCALL` | Execution of insmod, modprobe, or rmmod commands by non-standard users or outside expected timeframes |
| `macos:unifiedlog` | kextload execution from Terminal or suspicious paths |
| `WinEventLog:PowerShell` | Execution of PowerShell without -NoProfile flag |
| `auditd:EXECVE` | Process execution of update-ca-certificates or openssl with suspicious arguments |
| `macos:unifiedlog` | xattr -d com.apple.quarantine or similar removal commands |
| `azure:signinlogs` | OperationName=SetDomainAuthentication OR Update-MsolFederatedDomain |
| `linux:syslog` | Sudo or root escalation followed by filesystem mount commands |
| `WinEventLog:PowerShell` | EventCode=4101 |
| `networkdevice:cli` | Execution of privileged commands such as 'copy tftp flash', 'boot system', or 'debug memory' |
| `auditd:SYSCALL` | execve syscalls for discovery commands (uname, hostname, id, whoami, ps, netstat, mount) with command-line parameter analysis |
| `auditd:PROCTITLE` | process title records containing discovery command sequences and environmental assessment patterns |
| `macos:unifiedlog` | Security framework operations including keychain access, cryptographic operations, and certificate validation |
| `m365:unified` | Set-Mailbox, New-InboxRule |
| `macos:unifiedlog` |  |
| `networkdevice:cli` | Execution of commands disabling crypto hardware acceleration (e.g., 'no crypto engine enable') |
| `auditd:SYSCALL` | execve: Execution of curl, wget, or custom scripts accessing financial endpoints |
| `auditd:EXECVE` | Execution of chattr to set +i or +a attributes |
| `macos:unifiedlog` | Execution of chflags hidden or setfile -a V |
| `esxi:shell` | mv, rename, or chmod commands moving VM files into hidden directories |
| `esxi:hostd` | execution + payload hints |
| `linux:osquery` | process_events.command_line |
| `macos:unifiedlog` | process:spawn, process:exec |
| `esxi:vobd` | shell session start |
| `networkdevice:cli` | shell command |
| `WinEventLog:Microsoft-Office-Alerts` | Office application warning or alert on macro execution from template |
| `m365:unified` | Set-Mailbox, Set-MailboxPolicy, Set-TrustedLocation |
| `m365:office` | Execution of unsigned macro from template |
| `linux:cli` | Terminal Command History |
| `macos:unifiedlog` | csrutil disable |
| `macos:unifiedlog` | log show --predicate 'process == <utility>' |
| `networkdevice:syslog` | Privilege-level command execution |
| `auditd:SYSCALL` | execve: Execution of tar, gzip, bzip2, or openssl with output redirection |
| `saas:PRMetadata` | Commit message or branch name contains encoded strings or payload indicators |
| `macos:unifiedlog` | Execution of launchctl with setenv or bootout targeting TCC.db or AppleScript under Finder context |
| `esxi:shell` | `esxcli software vib install` with `--force` or `--no-sig-check` from shell history or `shell.log` |
| `AWS:CloudTrail` | SendCommand, StartSession, ExecuteCommand: Unexpected AWS Systems Manager command execution targeting EC2 instances |
| `esxi:vmkernel` | Unexpected restarts of management agents or shell access |
| `auditd:EXECVE` | curl or wget with POST/PUT options |
| `networkdevice:syslog` | Detected CLI command to export key material |
| `networkdevice:config` | PKI export or certificate manipulation commands |
| `macos:unifiedlog` | command execution triggered by emond (e.g., shell, curl, python) |
| `esxi:vmkernel` | esxcli, vim-cmd invocation |
| `esxi:shell` | CLI session activity |
| `auditd:SYSCALL` | execve=/sbin/shutdown or /sbin/reboot |
| `esxi:shell` | esxcli system shutdown or reboot invoked |
| `networkdevice:syslog` | reload command issued |
| `auditd:PROCTITLE` | command-line execution patterns for system discovery utilities (uname, hostname, ifconfig, netstat, lsof, ps, mount) |
| `esxi:shell` | shell command execution for system discovery (vim-cmd, esxcli, vmware-cmd) targeting VM inventory and host configuration |
| `vpxd.log` | VM inventory queries and configuration enumeration through vCenter API calls |
| `auditd:SYSCALL` | execve calls modifying HISTFILE or HISTCONTROL via unset/export |
| `macos:unifiedlog` | Set or unset HIST* variables in shell environment |
| `esxi:shell` | unset HISTFILE or HISTFILESIZE modifications |
| `networkdevice:cli` | Commands like 'no logging' or equivalents that disable session history |
| `auditd:SYSCALL` | execve calls to /usr/bin/locale or shell execution of $LANG |
| `macos:unifiedlog` | defaults read -g AppleLocale or systemsetup -gettimezone |
| `networkdevice:cli` | Execution of commands such as 'copy tftp flash', 'boot system <image>', 'reload' |
| `auditd:EXECVE` | curl -T, rclone copy |
| `auditd:SYSCALL` | execution of systemctl or service with enable/start/modify |
| `macos:unifiedlog` | launchctl load/unload or plist file modification |
| `networkdevice:syslog` | syslog facility LOCAL7 or trap messages |
| `linux:cli` | /home/*/.bash_history |
| `auditd:SYSCALL` | execve: Execution of lsmod, modinfo, or cat /proc/modules |
| `networkdevice:config` | Configuration changes referencing 'boot system tftp' or modification of startup-config pointing to external TFTP servers |
| `macos:unifiedlog` | dscl . -create |
| `macos:unifiedlog` | Execution of commands like `ls -l@`, `xattr -l`, or custom tools interacting with resource forks |
| `esxi:vpxd` | vCenter Management |

---

### File Creation
**Feeds detection for 174 techniques.**  
A new file is created on a system or network storage. This action often signifies an operation such as saving a document, writing data, or deploying a file. Logging these events helps identify legitimate or potentially malicious file creation activities. Examples include logging file creation events (e.g., Sysmon Event ID 11 or Linux auditd logs).  

| Log source | Channel |
|---|---|
| `File` |  |
| `WinEventLog:Sysmon` | EventCode=11 |
| `auditd:SYSCALL` | creat |
| `macos:unifiedlog` | file write |
| `macos:osquery` | CREATE/MODIFY: Modification of app.asar inside .app bundle |
| `auditd:FILE` | File creation with name starting with '.' |
| `macos:unifiedlog` | Creation or modification of browser extension .plist files |
| `auditd:SYSCALL` | open or creat syscalls targeting excluded paths |
| `macos:unifiedlog` | file creation in AV exclusion directories |
| `auditd:SYSCALL` | file creation/modification |
| `macos:unifiedlog` | file write/create |
| `esxi:vmkernel` | file write |
| `snmp:syslog` | firmware write/log event |
| `auditd:SYSCALL` | open,creat,rename: Writes in $HOME/Downloads, /tmp, ~/.cache with exe/script/archive/office extensions |
| `fs:fsevents` | Create in /Users/*/Downloads or /private/var/folders/* with quarantine attribute |
| `macos:unifiedlog` | file events |
| `esxi:vmkernel` | VMFS file creation |
| `auditd:SYSCALL` | write/open, FIM audit |
| `fs:fsusage` | open/write/exec calls |
| `macos:unifiedlog` | Creation of .plist under /Library/Managed Preferences/ |
| `fs:fileevents` | creat |
| `fs:fsusage` | disk activity on /Library/LaunchAgents or LaunchDaemons |
| `macos:osquery` | file_events |
| `auditd:SYSCALL` | open: Write to ~/.vscode-cli/code_tunnel.json |
| `macos:unifiedlog` | creation of ~/.vscode-cli/code_tunnel.json |
| `macos:unifiedlog` | create/modify dylib files in monitored directories |
| `auditd:SYSCALL` | write |
| `linux:Sysmon` | New files in /tmp, /var/tmp, $HOME/.cache, executed within TimeWindow after browser HTTP fetch |
| `macos:unifiedlog` | New files written to /var/folders, /tmp, ~/Library/Caches, or ~/Downloads by browser context or its children |
| `auditd:FILE` | create: New file created in system binaries or temp directories |
| `macos:unifiedlog` | File created in ~/Library/LaunchAgents or executable directories |
| `auditd:SYSCALL` | open, unlink, rename: File creation or deletion involving critical stored data |
| `macos:unifiedlog` | Process wrote large .mov/.mp4 in user temp/hidden dirs |
| `macos:unifiedlog` | logd:file write |
| `fs:fsusage` | File IO |
| `auditd:SYSCALL` | creat, open, write on /etc/systemd/system and /usr/lib/systemd/system |
| `macos:unifiedlog` | File creation |
| `macos:unifiedlog` | Attachment files written to ~/Downloads or temporary folders |
| `fs:fsusage` | file activity |
| `CloudTrail:PutObject` | PutObject |
| `auditd:PATH` | Creation of files with extensions .sql, .csv, .sqlite, especially in user directories |
| `macos:unifiedlog` | Writes of .sql/.csv/.xlsx files to user documents/downloads |
| `auditd:PATH` | New .py/.js/.sh files written to ~/.local/, ~/.cache/, or /tmp/ within 5 min of package install |
| `auditd:SYSCALL` | write, open, or rename to /etc/systemd/system/*.service |
| `auditd:FILE` | create: Creation of .zip, .gz, .bz2 files in /tmp, /var/tmp, or /home directories |
| `macos:unifiedlog` | Creation of .zip, .gz, .dmg archives in /Users, /tmp, or application directories |
| `fs:fsusage` | file open/write |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_CREATE: path under /Users/*/(Downloads|Desktop|Library/*/Containers|Library/Group Containers) AND extension in SuspiciousExtensions |
| `auditd:SYSCALL` | open/create/rename: name in (/home/*/Downloads/*|/tmp/*|/run/user/*|/media/*) AND ext in SuspiciousExtensions |
| `auditd:FILE` | create: Creation of archive files in /tmp, /var/tmp, or user home directories |
| `macos:unifiedlog` | Creation of .zip, .dmg, .tar.gz files in /Users, /tmp, or application directories |
| `linux:osquery` | file_events |
| `macos:unifiedlog` | File Events |
| `auditd:SYSCALL` | File creations of *.qcow2, *.vdi, *.vmdk outside standard VM directories |
| `macos:unifiedlog` | Creation or modification of postinstall scripts within .pkg or .mpkg contents |
| `auditd:SYSCALL` | open: File creation under /tmp, /var/tmp, ~/.cache with executable bit or shell shebang |
| `macos:unifiedlog` | create: New files in /tmp or ~/Library/Application Support/* with executable or script extensions |
| `auditd:SYSCALL` | open, write, unlink |
| `WinEventLog:Sysmon` | File creation of suspicious scripts/binaries in temporary directories |
| `macos:unifiedlog` | File creation of unsigned binaries/scripts in user cache or download directories |
| `auditd:SYSCALL` | File creation events in /var/mail or /var/spool/mail exceeding baseline thresholds |
| `fs:fsusage` | create: Attachment file creation in ~/Library/Mail directories |
| `WinEventLog:Microsoft-Windows-Shell-Core` | New startup folder shortcut or binary placed in Startup directory |
| `auditd:SYSCALL` | write or create file after .bash_history access |
| `auditd:SYSCALL` | new file created in /var/www/html, /srv/http, or similar web root |
| `fs:launchdaemons` | file_create |
| `auditd:PATH` | mount target path within /proc/* |
| `macos:fsevents` | /Library/StartupItems/, ~/Library/LaunchAgents/ |
| `fs:fsusage` | write or chmod to ~/Library/LaunchAgents/*.plist |
| `auditd:PATH` | creation of .so files in non-standard directories (e.g., /tmp, /home/*) |
| `auditd:FILE` | create: Creation of files with anomalous headers and entropy levels in /tmp or user directories |
| `macos:unifiedlog` | Creation of files with anomalous headers and entropy values |
| `auditd:SYSCALL` | Access or modification to /lib/modules or creation of .ko files |
| `fs:fsevents` | Directory events (kFSEventStreamEventFlagItemCreated) |
| `gcp:workspaceaudit` | drive.activity logs |
| `fs:fileevents` | create/write/rename in user-writable paths |
| `auditd:PATH` | WRITE: Drop of binaries/scripts in ~/.local, /tmp, or /opt tool dirs |
| `macos:osquery` | CREATE/MODIFY: Creation of LaunchAgents/Daemons plists in user/system locations |
| `auditd:SYSCALL` | open,create |
| `auditd:FILE` | Creation of hidden files (.*) in sensitive directories (/etc, /var, /usr/bin) |
| `macos:unifiedlog` | Creation of LaunchAgents/LaunchDaemons in hidden or non-standard directories |
| `auditd:FILE` | create: Creation of files ending in .tar, .gz, .bz2, .zip in /tmp or /var/tmp |
| `macos:unifiedlog` | Creation of .zip or .dmg files in user-accessible or temporary directories |
| `fs:fsusage` | file write |
| `macos:endpointsecurity` | es_event_open |
| `macos:unifiedlog` | file create or modify in /etc/emond.d/rules or /private/var/db/emondClients |
| `auditd:SYSCALL` | open,creat,rename,write |
| `macos:unifiedlog` | Writes under ~/Library/Application Support/Code*/extensions or JetBrains plugins |
| `AWS:CloudTrail` | PutObject |

---

### Network Connection Creation
**Feeds detection for 151 techniques.**  
The initial establishment of a network session, where a system or process initiates a connection to a local or remote endpoint. This typically involves capturing socket information (source/destination IP, ports, protocol) and tracking session metadata. Monitoring these events helps detect lateral movement, exfiltration, and command-and-control (C2) activities.

*Data Collection Measures:*

- Windows:
 - Event ID 5156 – Filtering Platform Connection - Logs network connections permitted by Windows  

| Log source | Channel |
|---|---|
| `Network Traffic` |  |
| `AWS:VPCFlowLogs` | Outbound connection to 169.254.169.254 from EC2 workload |
| `macos:unifiedlog` | connection attempts |
| `esxi:hostd` | System service interactions |
| `WinEventLog:Sysmon` | EventCode=3, 22 |
| `NSM:Connections` | web domain alerts |
| `auditd:SYSCALL` | connect |
| `macos:osquery` | process_events/socket_events |
| `NSM:Firewall` | Outbound Connections |
| `macos:unifiedlog` | connection open |
| `auditd:SYSCALL` | execve: Execs of chromium, google-chrome, firefox, libreoffice with http(s) in cmdline |
| `NSM:Flow` | New TCP/443 or TCP/80 to domain not previously seen for the user/host |
| `NSM:Connections` | New outbound connection from Safari/Chrome/Firefox/Word |
| `NSM:Flow` | conn.log |
| `macos:osquery` | execution of trusted tools interacting with external endpoints |
| `linux:Sysmon` | EventCode=3, 22 |
| `WinEventLog:Microsoft-Windows-Bits-Client/Operational` | BITS job lifecycle events such as job create/modify/transfer/complete and URL/remote name fields |
| `NSM:Firewall` | proxy or TLS inspection logs |
| `macos:unifiedlog` | network connection events |
| `esxi:vmkernel` | protocol egress |
| `NSM:Flow` | Outbound connection to *.tunnels.api.visualstudio.com or *.devtunnels.ms |
| `NSM:Flow` | Connections to *.devtunnels.ms or tunnels.api.visualstudio.com |
| `NSM:Flow` | HTTPs connection to tunnels.api.visualstudio.com |
| `WinEventLog:Security` | EventCode=5156, 5157 |
| `linux:osquery` | family=AF_PACKET or protocol raw; process name not in allowlist. |
| `macos:unifiedlog` | First outbound connection from the same PID/user shortly after an inbound trigger. |
| `NSM:Flow` | Outbound or inbound TFTP file transfers of ROMMON or firmware binaries |
| `NSM:Connections` | Outbound connections from newly spawned child processes or from the browser to uncommon endpoints or on anomalous ports |
| `NSM:Flow` | connection: TCP connections to ports 139/445 to multiple hosts |
| `NSM:Flow` | connection: SMB connections to multiple internal hosts |
| `auditd:SYSCALL` | connect/sendto |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_CONNECT |
| `snmp:access` | GETBULK/GETNEXT requests for OIDs associated with configuration parameters |
| `esxi:hostd` | Service initiated connections |
| `AWS:VPCFlowLogs` | Large transfer volume (>20MB) from RDS IP range to external public IPs |
| `AWS:VPCFlowLogs` | High outbound traffic from new region resource |
| `NSM:Flow` | Outbound HTTP/S initiated by newly installed interpreter process |
| `auditd:SYSCALL` | open or connect syscalls on /tmp/ssh-* or $SSH_AUTH_SOCK |
| `NSM:Flow` | outbound connections to RMM services or to unusual destination ports |
| `macos:unifiedlog` | network sessions initiated by remote desktop apps |
| `AWS:VPCFlowLogs` | Outbound connections to port 22, 3389 |
| `auditd:SYSCALL` | socket/connect with TLS context by unexpected process |
| `NSM:Flow` | Multiple failed connections (conn_state=REJ/S0 or history has 'R') across distinct ports from the same src_ip followed by success to a specific port. |
| `auditd:SYSCALL` | socket/bind: New bind() to a previously closed port shortly after the sequence. |
| `NSM:Flow` | Sequence of REJ/S0 then SF success from same src_ip within TimeWindow. |
| `NSM:Flow` | Series of denied/closed flows to distinct ports then success to mgmt port from same src_ip within TimeWindow. |
| `NSM:Flow` | Outbound traffic spike through formerly blocked ports/subnets following config change |
| `cni:netflow` | outbound connection to internal or external APIs |
| `macos:osquery` | launchd or network_events |
| `networkdevice:syslog` | Dynamic route changes |
| `NSM:Flow` | New egress to Internet by the same UID/host shortly after terminal exec |
| `NSM:Flow` | connection: Inbound connections to SSH or VPN ports |
| `macos:unifiedlog` | Inbound connections to VNC/SSH ports |
| `NSM:Flow` | External access to container ports (2375, 6443) |
| `linux:syslog` | network |
| `macos:osquery` | process_events + launchd |
| `esxi:esxupdate` | /var/log/esxupdate.log or /var/log/vmksummary.log |
| `ebpf:syscalls` | socket connect |
| `NSM:Flow` | remote access |
| `NSM:Flow` | Outbound Connections |
| `macos:unifiedlog` | network |
| `AWS:VPCFlowLogs` | Traffic observed on mirror destination instance |
| `networkdevice:Flow` | Traffic from mirrored interface to mirror target IP |
| `macos:osquery` | process_events, socket_events |
| `esxi:vmkernel` | network activity |
| `NSM:Flow` | connection attempts |
| `NSM:Flow` | High-volume or repeated SNMP GETBULK/GETNEXT queries from untrusted or external IPs |
| `auditd:SYSCALL` | sendto/connect |
| `NSM:Flow` | outbound connections from host during or immediately after image build |
| `macos:unifiedlog` | Outbound Traffic |
| `esxi:hostd` | Service-Based Network Connection |
| `linux:syslog` | postfix/smtpd |
| `NSM:Flow` | new outbound connection from browser/office lineage |
| `NSM:Flow` | new outbound connection from exploited lineage |
| `macos:osquery` | CONNECT: Long-lived connections from remote-control parents to external IPs/domains |
| `auditd:SYSCALL` | outbound connections |
| `macos:unifiedlog` |  |
| `esxi:vmkernel` |  |
| `macos:unifiedlog` | networkd or socket |
| `macos:unifiedlog` | log stream network activity |
| `NSM:Flow` | Multiple failed connections to closed ports (history contains 'R' or conn_state in {REJ, S0}) followed by a successful handshake to a new port from same src within TimeWindowKnock |
| `auditd:SYSCALL` | socket/bind: Process binds to a new local port shortly after knock |
| `NSM:Flow` | Closed-port hits followed by success from same src_ip |
| `NSM:Flow` | Port-knock pattern from one src to device unicast,broadcast,network addresses on same port within TimeWindowKnock |
| `WinEventLog:Microsoft-Windows-WLAN-AutoConfig` | EventCode=8001, 8002, 8003 |
| `linux:syslog` | New Wi-Fi connection established or repeated association failures |
| `macos:unifiedlog` | Association and authentication events including failures and new SSIDs |
| `auditd:SYSCALL` | socket/connect calls showing SSH processes forwarding arbitrary ports |
| `esxi:vmkernel` | network session initiation with external HTTPS services |
| `WinEventLog:System` | EventCode=8001 |
| `linux:syslog` |  |
| `macos:osquery` |  |
| `auditd:SYSCALL` | openat,connect -k discovery |
| `NSM:Flow` | Unexpected inbound/outbound TFTP traffic for device image files |
| `NSM:Flow` | Unexpected or unauthorized inbound connections to SNMP, NETCONF, or RESTCONF services |

---

### Network Traffic Content
**Feeds detection for 139 techniques.**  
The full packet capture (PCAP) or session data that logs both protocol headers and payload content. This allows analysts to inspect command and control (C2) traffic, exfiltration, and other suspicious activity within network communications. Unlike metadata-based logs, full content analysis enables deeper protocol inspection, payload decoding, and forensic investigations.

*Data Collection Measures:*

- Network Packet Capture (Full Content Logging)
 - Wireshark / tcpdump / tshark
 - Full packet c  

| Log source | Channel |
|---|---|
| `Network Traffic` |  |
| `ebpf:syscalls` | Process within container accesses link-local address 169.254.169.254 |
| `WebProxy:AccessLogs` | SSRF-like patterns accessing metadata endpoint through proxy (e.g., Host: 169.254.169.254) |
| `NSM:Flow` | mqtt.log / xmpp.log (custom log feeds) |
| `NSM:Flow` | mqtt.log or AMQP custom log |
| `NSM:Flow` | mqtt.log, xmpp.log, amqp.log |
| `networkdevice:syslog` | ACL/Firewall rule modification or new route injection |
| `m365:office` | External HTTP/DNS connection from Office binary shortly after macro trigger |
| `NSM:Flow` | TCP/UDP |
| `NSM:Flow` | TCP session tracking |
| `NSM:Flow` | Captured packet payloads |
| `NSM:Flow` | session behavior |
| `esxi:vmkernel` | Network activity |
| `NSM:Flow` | External C2 channel over TLS |
| `NSM:Flow` | http/file-xfer: Inbound/outbound transfer of ELF shared objects |
| `NSM:Flow` | http.log, files.log |
| `NSM:Flow` | unexpected network activity initiated shortly after shell session starts |
| `NSM:Flow` | HTTP/WebDAV requests that contain NTLMSSP or PROPFIND/MOVE/OPTIONS with Authorization: NTLM |
| `NSM:Flow` | http.log, ssl.log |
| `NSM:Flow` | http.log, conn.log |
| `NSM:Flow` | SPAN or port-mirrored HTTP/S |
| `NSM:Flow` | http.log, ssl.log, websocket.log |
| `macos:unifiedlog` | process + network metrics correlation for bandwidth saturation |
| `docker:stats` | unusual network TX/RX byte deltas |
| `etw:Microsoft-Windows-WinINet` | HTTPS Inspection |
| `NSM:Flow` | ssl.log |
| `linux:syslog` | Query to suspicious domain with high entropy or low reputation |
| `macos:unifiedlog` | DNS query with pseudo-random subdomain patterns |
| `azure:vpcflow` | HTTP requests to 169.254.169.254 or Azure Metadata endpoints |
| `NSM:Flow` | Browser connections to known C2 or dynamic DNS domains |
| `NSM:Flow` | Session History Reset |
| `NSM:Flow` | HTTP  |
| `macos:unifiedlog` | network flow |
| `linux:syslog` | curl|wget|python .*http |
| `macos:unifiedlog` | curl|osascript.*open location |
| `NSM:Flow` | query: High-volume LDAP traffic with filters targeting groupPolicyContainer attributes |
| `etw:Microsoft-Windows-NDIS-PacketCapture` | TLS Handshake/Network Flow |
| `NSM:Flow` | HTTP/TLS Logs |
| `macos:unifiedlog` | subsystem: com.apple.network |
| `linux:syslog` | Unexpected SQL or application log entries showing tampered or malformed data |
| `EDR:hunting` | Advanced Hunting: DeviceProcessEvents + DeviceNetworkEvents |
| `NSM:Flow` | Suspicious URL patterns, uncommon TLDs, short-lived domains, URL shorteners; HTTP method GET/POST |
| `NSM:Flow` | Suspicious URL patterns, uncommon TLDs, URL shorteners |
| `macos:unifiedlog` | open URL|clicked link|LSQuarantineAttach |
| `NSM:Flow` | Suspicious GET/POST; downloader patterns |
| `NSM:Flow` | SSH logins or scp activity |
| `NSM:Flow` | remote login and transfer |
| `esxi:vob` | NFS/remote access logs |
| `AWS:VPCFlowLogs` | Traffic between instances |
| `NSM:Flow` | conn.log |
| `WinEventLog:System` | EventCode=5005 (WLAN), EventCode=302 (Bluetooth) |
| `macos:unifiedlog` |  |
| `NSM:Flow` | Suspicious long-lived or reattached remote desktop sessions from unexpected IPs |
| `NSM:Flow` | HTTP payloads with SQLi/LFI/JNDI/deserialization indicators |
| `NSM:Flow` | outbound egress from web host after suspicious request |
| `NSM:Flow` | Requests towards cloud metadata or command & control from pod IPs |
| `ALB:HTTPLogs` | AWS ALB/ELB/GCP/Azure Application Gateway HTTP logs with unusual methods, long URIs, serialized payloads, 4xx/5xx bursts |
| `NSM:Flow` | Connections to TCP 427 (SLP) or vCenter web services from untrusted sources |
| `NSM:Flow` | NetFlow/sFlow for odd egress to Internet from mgmt plane |
| `NSM:Flow` | packet capture or DPI logs |
| `NSM:Flow` | http.log |
| `NSM:Flow` | SMB2_LOGOFF/SMB_TREE_DISCONNECT |
| `macos:unifiedlog` | Connections to suspicious domains with mismatched certificate or unusual patterns |
| `NSM:Flow` | Unusual Base64-encoded content in URI, headers, or POST body |
| `NSM:Flow` | Base64 strings or gzip in URI, headers, or POST body |
| `macos:unifiedlog` | HTTP POST with encoded content in user-agent or cookie field |
| `esxi:vmkernel` | Outbound traffic using encoded payloads post-login |
| `macos:unifiedlog` | Suspicious outbound HTTPS requests to domains flagged as newly registered or untrusted after spearphishing message interaction |
| `NSM:Flow` | Inbound connections to 445, 3389, 5985-5986 with high error/connection-reset rate, followed by new outbound sessions from the same host to internal assets within short interval. |
| `NSM:Flow` | Inbound connections to monitored service ports from external or unusual internal sources; rapid follow-on lateral connections from the same host. |
| `NSM:Flow` | Inbound to tcp/427 (OpenSLP), tcp/443 (vSphere APIs), tcp/902, tcp/5989 followed by new unexpected outbound sessions from the ESXi/vCenter host. |
| `NSM:Flow` | Inbound to 22/5900/8080 and follow-on internal connections. |
| `NSM:Flow` | http: HTTP body or headers contain long Base64 sections; gzip/deflate + Base64 |
| `NSM:Flow` | http: HTTP body contains long Base64 sections |
| `NSM:Flow` | http: Base64/MIME looking payloads from ESXi host IP |
| `NSM:Flow` | LDAP Bind/Search |
| `NSM:Flow` | LDAP Query |
| `macos:unifiedlog` | log stream (subsystem: com.apple.system.networking) |
| `NSM:Flow` | smtp.log |
| `NSM:Flow` | smtp.log, conn.log |
| `NSM:Flow` | remote CLI session detection |
| `macos:unifiedlog` | Encrypted connection with anomalous payload entropy |
| `esxcli:network` | Socket sessions with randomized payloads inconsistent with TLS |
| `NSM:Connections` | Symmetric encryption detected without TLS handshake sequence |
| `NSM:Flow` | http.log, ftp.log |
| `NSM:Flow` | PCAP inspection |
| `NSM:Flow` | large HTTPS POST requests to webhook endpoints |
| `esxi:vmkernel` | HTTPS POST connections to webhook endpoints |
| `NSM:Flow` | Single, low-volume inbound packet (REJ/S0/OTH or uncommon dport/protocol) from src_ip followed by outbound SF connection to src_ip. |
| `NSM:Flow` | Rare inbound packet characteristics (ICMP/UDP/TCP to uncommon port) from src_ip followed ≤TimeWindow by outbound SF from same host to src_ip. |
| `NSM:Flow` | Inbound one-off packet to uncommon port → outbound SF to same src_ip within TimeWindow. |
| `networkdevice:config` | NAT table modification (add/update/delete rule) |
| `NSM:Flow` | large upload to firmware interface port or path |
| `macos:unifiedlog` | Rapid incoming TLS handshakes or HTTP requests in quick succession |
| `NSM:Flow` | http.request: HTTP requests and responses for specific script resources, unexpected content-types (application/octet-stream for script URLs), suspicious referrers, or obfuscated javascript resources |
| `NSM:Flow` | http::response: HTTP responses with suspicious content-type for scripts, long obfuscated javascript bodies, or redirects to exploit kit domains |
| `NSM:Flow` | HTTP/HTTPS requests for script resources flagged by content inspection (excessive obfuscation, eval usage, unusual redirects) |
| `NSM:Connections` | TLS handshake + HTTP headers |
| `NSM:Flow` | ssl.log + http.log |
| `macos:unifiedlog` | network, socket, and http logs |
| `NSM:Firewall` | TLS/HTTP inspection |
| `NSM:Flow` | http/file-xfer: Outbound transfer of large video-like MIME types soon after capture |
| `container:proxy` | outbound/inbound network activity from spawned pods |
| `esxcli:network` | listening sockets bound to non-standard ports |
| `NSM:Flow` | Outbound SCP, TFTP, or FTP sessions carrying configuration file content |
| `NSM:Flow` | Session Transfer Content |
| `NSM:Flow` | Captured File Content |
| `NSM:Flow` | C2 exfiltration |
| `NSM:Flow` | Transferred file observations |
| `apache:access_log` | Unusual HTTP POST or PUT requests to paths such as '/uploads/', '/admin/', or CMS plugin folders |
| `NSM:Flow` | http::post: Outbound HTTP POST from host shortly after DB export activity |
| `NSM:Flow` | HTTPS API requests to Dropbox, iCloud, Google Drive, OneDrive shortly after DB tool usage |
| `NSM:Flow` | Observed downgrade in negotiated cipher suites or TLS/SSH versions across sessions |
| `NSM:Flow` | New egress from container IP/namespace to Internet or non-approved CIDRs/ASNs |
| `NSM:Flow` | New VM egress to crypto-mining pools or non-approved Internet ranges within minutes of boot |
| `docker:events` | remote API calls to /containers/create or /containers/{id}/start |
| `NSM:Flow` | http::request: Network connection to package registry or C2 from interpreter shortly after install |
| `linux:syslog` | Integrity mismatch warnings or malformed packets detected |
| `NSM:Flow` | http::request: Outbound HTTP initiated by Python interpreter |
| `WinEventLog:Sysmon` | Outbound requests with forged tokens/cookies in headers |
| `linux:syslog` | DNS response IPs followed by connections to non-standard calculated ports |
| `macos:unifiedlog` | DNS responses followed by connections to ports outside standard ranges |
| `macos:unifiedlog` | Persistent outbound traffic to mining domains |
| `macos:unifiedlog` | Encrypted session initiation by unexpected binary |
| `esxi:vmkernel` | Inspection of sockets showing encrypted sessions from non-baseline processes |
| `NSM:Connections` | Abnormal certificate chains or non-standard ports carrying TLS |
| `NSM:Flow` | DrsAddEntry, DrsReplicaAdd, GetNCChanges calls between non-DC and DCs. |
| `NSM:Flow` | large HTTPS POST requests to text storage domains |
| `esxi:vmkernel` | HTTPS POST connections to pastebin-like domains |
| `NSM:Flow` | Unexpected ARP replies or DNS responses inconsistent with authoritative servers |
| `NSM:Flow` | TLS downgrade or inconsistent DNS answers |
| `NSM:Flow` | Unusual request pattern leading up to service crash (e.g., malformed or oversized payload) |
| `AWS:VPCFlowLogs` | Large volume of malformed or synthetic payloads to application endpoints prior to failure |
| `networkconfig ` | interface flag PROMISC, netstat | ip link | ethtool |
| `macos:unifiedlog` | eventMessage = 'promiscuous' |
| `networkdevice:syslog` | config change (e.g., logging buffered, pcap buffers) |
| `macos:unifiedlog` | outbound HTTPS connections to code repository APIs |
| `azure:activity` | networkInsightsLogs |
| `gcp:audit` | network.query* |
| `WinEventLog:Microsoft-Windows-Windows Defender/Operational` | Unusual external domain access |
| `NSM:Flow` | conn.log or http.log |
| `NSM:Flow` | http: HTTP bodies/headers contain long tokens with non-standard alphabets or constant-size periodic POSTs |
| `NSM:Flow` | dns: DNS labels with excessive length and restricted custom alphabets (e.g., base36 only) repeated frequently |
| `NSM:Flow` | http: suspicious long tokens with custom alphabets in body/headers |
| `NSM:Flow` | http: HTTP bodies from ESXi host IPs containing long, non-standard tokens |
| `NSM:Flow` | Traffic patterns showing downgrade from strong encryption (AES-256) to weaker or plaintext protocols |
| `NSM:Flow` | HTTP(S) requests with User-Agents typical of PowerShell or curl from desktop; or URIs matching paste-inspired payload hosts |
| `NSM:Flow` | Egress to non-approved networks from host after terminal exec |
| `NSM:Flow` | Flow/PCAP analysis for outbound payloads |
| `NSM:Flow` | conn.log + files.log + ssl.log |
| `macos:unifiedlog` | eventMessage = 'open', 'sendto', 'connect' |
| `NSM:Flow` | HTTPS or custom protocol traffic with large payloads |
| `esxi:vmkernel` | network stack module logs |
| `NSM:Flow` | Unexpected script or binary content returned in HTTP response body |
| `NSM:Flow` | Injected content responses with unexpected script/malware signatures |
| `NSM:Flow` | Content injection observed in HTTPS responses with mismatched certificates or altered payloads |
| `NSM:Firewall` | High rate of inbound TCP SYN or ACK packets with missing 3-way handshake completion |
| `NSM:Firewall` | Anomalous TCP SYN or ACK spikes from specific source or interface |
| `saas:confluence` | REST API access from non-browser agents |
| `Netfilter/iptables` | Forwarded packets log |
| `NSM:Flow` | Relay patterns across IP hops |
| `NSM:Firewall` | Outbound encrypted traffic |
| `NSM:Flow` | ldap.log |
| `macos:unifiedlog` | dns-sd, mDNSResponder, socket activity |
| `networkdevice:IDS` | content inspection / PCAP / HTTP body |
| `NSM:Flow` | Probe responses from unauthorized APs responding to client probe requests |
| `auditd:SYSCALL` | setsockopt, ioctl modifying ARP entries |
| `NSM:Flow` | Excessive gratuitous ARP replies on local subnet |
| `NSM:Flow` | Inbound HTTP POST with suspicious payload size or user-agent |
| `NSM:Flow` | POST requests to .php, .jsp, .aspx files with high entropy body |
| `NSM:Flow` | dns.log |
| `NSM:FLow` | dns.log |
| `NSM:Flow` | Encrypted tunnels or proxy traffic to non-standard destinations |
| `esxi:vmkernel` | Suspicious traffic filtered or redirected by VM networking stack |
| `NSM:Flow` | large transfer from management IPs to unauthorized host |
| `NSM:Flow` | Sustained abnormal inbound request rate targeting application ports (e.g., 80/443/25) |
| `NSM:Flow` | ftp.log, smb_files.log |
| `NSM:Flow` | ftp.log, conn.log |
| `NSM:Flow` | mirror/SPAN port |
| `NSM:Flow` | ftp.log, conn.log, smb_files.log |
| `linux:syslog` | Multiple NXDOMAIN responses and high entropy domains |
| `NSM:Flow` | SSL/TLS Inspection or PCAP |
| `NSM:Flow` | conn.log, ssl.log |
| `macos:unifiedlog` | process + network activity |
| `NSM:Flow` | http, dns, smb, ssl logs |
| `NSM:Flow` | dns, ssl, conn |
| `NSM:Flow` | conn.log, http.log, dns.log, ssl.log |
| `networkdevice:syslog` | Authentication failures, unexpected community string usage, or unauthorized SNMPv1/v2 requests |
| `NSM:Flow` | ICMP/UDP traffic (Wireshark, Suricata, Zeek) |
| `NSM:Flow` | icmp.log, weird.log |
| `NSM:Flow` | ICMP/UDP monitoring (tcpdump, Wireshark, Zeek) |
| `esxi:vmkernel` | VMCI syslog entries |
| `NSM:Firewall` | ICMP/UDP protocol anomaly |
| `NSM:Flow` | Unusual responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from unauthorized hosts |
| `NSM:Flow` | DHCP OFFER or ACK with unauthorized DNS/gateway parameters |
| `NSM:Flow` | Multiple DHCP OFFER responses for a single DISCOVER |
| `NSM:Flow` | SSL/TLS Handshake Analysis |
| `NSM:Flow` | HTTP Header Metadata |
| `NSM:Flow` | Network Capture TLS/HTTP |
| `NSM:Content` | SSL Certificate Metadata |
| `NSM:Content` | HTTP Header Metadata |
| `NSM:Content` | TLS Fingerprint and Certificate Analysis |
| `NSM:Flow` | container egress to unknown IPs/domains |
| `gcp:vpcflow` | first 5m egress to unknown ASNs |
| `NSM:Flow` | HTTP Request Logging |
| `WinEventLog:iis` | IIS Logs |
| `macos:unifiedlog` | subsystem=com.apple.WebKit |
| `AWS:VPCFlowLogs` | Unusual volume of data transferred from S3 storage endpoints to non-corporate IPs |
| `NSM:Flow` | ssh connections originating from third-party CIDRs |
| `NSM:Flow` | ssh/smb connections to internal resources from third-party devices |
| `NSM:Flow` | Degraded encryption throughput or switch to weaker cipher suites compared to historical baselines |
| `NSM:Flow` | ssl.log (for TLS handshake analysis), dns.log (tunneling indicators) |
| `NSM:Flow` | host switch egress data |
| `NSM:Flow` | Outbound HTTP/S |
| `macos:unifiedlog` | subsystem: com.apple.WebKit or com.apple.WebKit.Networking |
| `NSM:Flow` | ssl.log - Certificate Analysis |
| `NSM:Flow` | ssl.log, conn.log |
| `NSM:Flow` | ssl.log, x509.log |
| `NSM:Flow` | Packets with unusual flags or payloads outside established flows (e.g., WoL magic FF×6 + 16×MAC) |
| `WIDS:AssociationLogs` | Unauthorized AP or anomalous MAC address connection attempts |
| `macos:unifiedlog` | encrypted outbound traffic carrying unexpected application data |
| `esxcli:network` | listening sockets bound with non-standard encapsulated protocols |
| `macos:unifiedlog` | Persistent outbound connections with consistent periodicity |
| `macos:unifiedlog` | TLS connections with abnormal handshake sequence or self-signed cert |
| `esxcli:network` | Socket inspection showing RSA key exchange outside baseline endpoints |
| `IDS:TLSInspection` | Malformed certs, incomplete asymmetric handshakes, or invalid CAs |
| `macos:unifiedlog` | Web server process initiating outbound TCP connections not tied to normal server traffic |
| `macos:unifiedlog` | outbound TLS connections to cloud storage providers |
| `saas:box` | API calls exceeding baseline thresholds |
| `macos:unifiedlog` | outbound HTTPS connections to cloud storage APIs |
| `AWS:VPCFlowLogs` | High volume internal-to-internal IP transfer or cross-account cloud transfer |
| `etw:Microsoft-Windows-WinINet` | WinINet API telemetry |
| `macos:unifiedlog` | process, network |
| `NSM:Connections` | Unusual POST requests to admin or upload endpoints |
| `NSM:Flow` | Suspicious POSTs to upload endpoints |
| `networkdevice:syslog` | Authentication failures or unusual community string usage in SNMP queries |
| `API:ConfigRepoAudit` | Access to configuration repository endpoints, unusual enumeration requests or mass downloads |
| `NSM:Content` | Traffic on RPC DRSUAPI |
| `macos:unifiedlog` | process = 'ssh' OR eventMessage CONTAINS 'ssh' |

---

### File Modification
**Feeds detection for 115 techniques.**  
Changes made to a file, including updates to its contents, metadata, access permissions, or attributes. These modifications may indicate legitimate activity (e.g., software updates) or unauthorized changes (e.g., tampering, ransomware, or adversarial modifications). Examples: 

- Content Modifications: Changes to the content of a configuration file, such as modifying `/etc/ssh/sshd_config` on Linux or `C:\Windows\System32\drivers\etc\hosts` on Windows.
- Permission Changes: Altering file permiss  

| Log source | Channel |
|---|---|
| `File` |  |
| `auditd:SYSCALL` | open/write calls modifying ~/.bashrc, ~/.profile, or /etc/paths.d |
| `macos:unifiedlog` | File modification in /etc/paths.d or user shell rc files |
| `fs:fileevents` | /var/log/quarantine.log |
| `macos:unifiedlog` | Modification of ~/Library/LaunchAgents or /Library/LaunchDaemons plist |
| `auditd:SYSCALL` | open, write |
| `auditd:SYSCALL` | AUDIT_SYSCALL (open, write, rename, unlink) |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_WRITE, targeting .zshrc, .zlogin, .zprofile |
| `fs:fileevents` | /var/log/install.log |
| `auditd:SYSCALL` | PATH |
| `macos:osquery` | file_events |
| `WinEventLog:Sysmon` | EventCode=2 |
| `auditd:SYSCALL` | execve call for modification of /etc/sudoers or writing to /var/db/sudo |
| `auditd:SYSCALL` | open, write: File modifications under /etc/ssl/certs, /usr/local/share/ca-certificates, or /etc/pki/ca-trust/source/anchors |
| `macos:osquery` | query: Enumeration of root certificates showing unexpected additions |
| `auditd:SYSCALL` | open, unlink, rename: Suspicious file access, deletion, or modification of sensitive paths |
| `macos:unifiedlog` | Anomalous plist modifications or sensitive file overwrites by non-standard processes |
| `auditd:FILE` | Modification or deletion of /etc/audit/audit.rules or /etc/audit/audit.conf |
| `auditd:SYSCALL` | open/write of .service unit files |
| `auditd:SYSCALL` | open/write/unlink |
| `macos:unifiedlog` | loginwindow or desktopservices modified settings or files |
| `ESXiLogs:messages` | changes to /etc/motd or /etc/vmware/welcome |
| `auditd:SYSCALL` | write, rename |
| `containerd:runtime` | file change monitoring within /etc/cron.*, /tmp, or mounted volumes |
| `esxi:cron` | manual edits to /etc/rc.local.d/local.sh or cron.d |
| `auditd:PATH` | /etc/passwd or /etc/group file write |
| `auditd:SYSCALL` | write |
| `macos:unifiedlog` | SecurityAgentPlugins modification |
| `macos:unifiedlog` | write: File modifications to *.plist within LaunchAgents, LaunchDaemons, Application Support, or Preferences directories |
| `linux:osquery` | file_events |
| `esxi:hostd` | boot |
| `networkdevice:syslog` | config |
| `macos:unifiedlog` | Modification of backgrounditems.btm or creation of LoginItems subdirectory in .app bundle |
| `fs:filesystem` | Modification or creation of files matching 'com.apple.loginwindow.*.plist' in ~/Library/Preferences/ByHost |
| `auditd:SYSCALL` | write | PATH=/home/*/.ssh/authorized_keys |
| `macos:auth` | ~/.ssh/authorized_keys |
| `gcp:audit` | compute.instances.setMetadata |
| `azure:resource` | PATCH vm/authorized_keys |
| `esxi:shell` | file write or edit |
| `linux:syslog` | rename |
| `ebpf:syscalls` | file_write |
| `macos:unifiedlog` | Modification of plist with apple.awt.UIElement set to TRUE |
| `fs:fsusage` | unlink, write |
| `auditd:SYSCALL` | open, write: Write operations targeting /dev/sda, /dev/nvme0n1, or EFI partition mounts |
| `auditd:PATH` | write: Modification of /boot/grub/*, /boot/efi/EFI/*, or initramfs images |
| `networkdevice:config` | config-change: timezone or ntp server configuration change after a time query command |
| `macos:unifiedlog` | replace existing dylibs |
| `networkdevice:config` | Configuration changes to boot variables, startup image paths, or checksum verification failures |
| `firmware:update` | Unexpected or unscheduled firmware updates, image overwrites, or failed signature validation |
| `IntegrityCheck:ImageValidation` | Checksum or hash mismatch between running image and known-good vendor-provided image |
| `macos:osquery` | File modifications in ~/Library/Preferences/ |
| `auditd:SYSCALL` | open/write to /etc/pam.d/* |
| `macos:unifiedlog` | Modification of /Library/Security/SecurityAgentPlugins |
| `macos:unifiedlog` | Modifications to Mail.app plist files controlling message rules |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `auditd:SYSCALL` | write: Modification of structured stored data by suspicious processes |
| `linux:syslog` | Unexpected log entries or malformed SQL operations in databases |
| `macos:unifiedlog` | Unexpected creation or modification of stored data files in protected directories |
| `auditd:SYSCALL` | openat, write, rename, unlink |
| `macos:unifiedlog` | file encrypted|new file with .encrypted extension|disk write burst |
| `esxi:vmkernel` | rename .vmdk to .*.locked|datastore write spike |
| `macos:unifiedlog` | Mach-O binary modified or LC_LOAD_DYLIB segment inserted |
| `auditd:SYSCALL` | open/write syscalls targeting /etc/ld.so.preload or binaries in /usr/bin |
| `macos:unifiedlog` | Modified application plist or binary replacement in /Applications |
| `esxi:shell` | admin command usage |
| `networkdevice:syslog` | startup-config |
| `macos:unifiedlog` | File creation or overwrite in common web-hosting folders |
| `esxi:vmkernel` | Unauthorized file modifications within datastore volumes via shell access or vCLI |
| `networkdevice:config` | Configuration changes referencing 'crypto', 'key length', 'cipher', or downgrade of encryption settings |
| `FirmwareLogs:Update` | Unexpected firmware or image updates modifying cryptographic modules |
| `fs:plist` | /var/root/Library/Preferences/com.apple.loginwindow.plist |
| `auditd:SYSCALL` | modification of existing .service file |
| `auditd:PATH` | write or create events on *.pth, sitecustomize.py, usercustomize.py in site-packages or dist-packages |
| `macos:unifiedlog` | write of plist files in /Library/LaunchAgents or /Library/LaunchDaemons |
| `WinEventLog:System` | Unexpected modification to lsass.exe or cryptdll.dll |
| `networkconfig` | unexpected OS image file upload or modification events |
| `network:runtime` | checksum or runtime memory verification failures |
| `macos:unifiedlog` | write |
| `auditd:SYSCALL` | open, write: Modification of /boot/grub/* or /boot/efi/* |
| `macos:unifiedlog` | Modification of /System/Library/CoreServices/boot.efi |
| `macos:unifiedlog` | Modification of LaunchAgents or LaunchDaemons plist files |
| `auditd:SYSCALL` | chmod |
| `auditd:SYSCALL` | rename,chmod |
| `fs:fsevents` | create/write/rename under user-writable paths |
| `macos:osquery` | Changes to LSFileQuarantineEnabled field in Info.plist |
| `fs:fsusage` | file access to /usr/lib/cron/tabs/ and cron output files |
| `esxi:hostd` | modification of crontab or local.sh entries |
| `networkdevice:config` | Configuration file modified or replaced on network device |
| `macos:unifiedlog` | Plist modifications containing virtualization run configurations |
| `fs:fsusage` | file access to /usr/lib/cron/at and job execution path |
| `macos:unifiedlog` | binary modified or replaced |
| `esxi:hostd` | binary or module replacement event |
| `networkdevice:config` | Configuration change events referencing encryption, TLS/SSL, or IPSec settings |
| `networkdevice:firmware` | Unexpected firmware update or image modification affecting crypto modules |
| `fs:fsevents` | file system events indicating permission, ownership, or extended attribute changes on critical paths. File system modification events with kFSEventStreamEventFlagItemChangeOwner, kFSEventStreamEventFlagItemXattrMod flags |
| `auditd:FILE` | Modification of Display Manager configuration files (/etc/gdm3/*, /etc/lightdm/*) |
| `macos:unifiedlog` | Modification of /Library/Preferences/com.apple.loginwindow plist |
| `auditd:SYSCALL` | Modification of user shell profile or trap registration via echo/redirection (e.g., echo "trap 'malicious_cmd' INT" >> ~/.bashrc) |
| `macos:unifiedlog` | File write or append to .zshrc, .bash_profile, .zprofile, etc. |
| `auditd:SYSCALL` | chmod, write, create, open |
| `fs:fsevents` | Extensions |
| `auditd:SYSCALL` | open, write: File writes to application binaries or libraries at runtime |
| `macos:osquery` | CALCULATE: Mismatch in file integrity of critical macOS applications |
| `auditd:SYSCALL` | file write operations in /Library/WebServer/Documents |
| `fs:launchdaemons` | file_modify |
| `auditd:PATH` | write: File modifications to /etc/systemd/sleep.conf or related power configuration files |
| `macos:unifiedlog` | write: File modification to com.apple.PowerManagement.plist or related system preference files |
| `fs:fsusage` | modification of existing LaunchAgents plist |
| `macos:unifiedlog` | create/modify dylib in monitored directories |
| `WinEventLog:CodeIntegrity` | EventCode=3033 |
| `auditd:SYSCALL` | write operation on /etc/passwd or /etc/shadow |
| `macos:unifiedlog` | modification to /var/db/dslocal/nodes/Default/users/ |
| `linux:osquery` | New or modified kernel object files (.ko) within /lib/modules directory |
| `macos:osquery` | Modifications to /var/db/SystemPolicyConfiguration/KextPolicy or kext_policy table |
| `networkdevice:audit` | SNMP configuration changes, such as enabling read/write access or modifying community strings |
| `macos:osquery` | write |
| `auditd:SYSCALL` | mount or losetup commands creating hidden or encrypted FS |
| `macos:unifiedlog` | Hidden volume attachment or modification events |
| `macos:unifiedlog` | Suspicious plist edits for volume mounting behavior |
| `networkdevice:config` | Configuration changes to startup image paths, boot loader parameters, or debug flags |
| `networkdevice:syslog` | Checksum/hash mismatch between device OS image and baseline known-good version |
| `macos:unifiedlog` | file writes |
| `m365:defender` | OfficeTelemetry or DLP |
| `fs:fsusage` | Filesystem Access Logging |
| `networkdevice:config` | Configuration changes referencing cryptographic hardware modules or disabling hardware acceleration |
| `FirmwareLogs:Update` | Unexpected firmware updates that alter encryption libraries or disable hardware crypto modules |
| `m365:office` | Anomalous editing of invoice or payment document templates |
| `fs:fsusage` | truncate, unlink, write |
| `macos:unifiedlog` | Modification or replacement of /Library/Application Support/com.apple.TCC/TCC.db or ~/Library/Application Support/com.apple.TCC/TCC.db |
| `linux:fim` | Changes to /etc/rc.local.d/local.sh or creation of unexpected startup files in persistent partitions (/etc/init.d, /store, /locker) |
| `macos:endpointsecurity` | write, rename |
| `auditd:SYSCALL` | open/write to /proc/*/mem or /proc/*/maps |
| `sysdig:file` | evt.type=write |
| `macos:unifiedlog` | rule definitions written to emond rule plists |
| `networkdevice:config` | Configuration changes referencing older image versions or unexpected boot parameters |
| `FileIntegrity:ImageValidation` | Hash/checksum mismatch against baseline vendor-provided OS image versions |
| `auditd:SYSCALL` | write or rename to /etc/systemd/system or /etc/init.d |
| `fs:fsusage` | file write to launchd plist paths |
| `auditd:SYSCALL` | modification of entrypoint scripts or init containers |
| `fs:plist_monitoring` | /Users/*/Library/Mail/V*/MailData/RulesActiveState.plist |
| `auditd:SYSCALL` | chmod/chown to /etc/passwd or /etc/shadow |
| `auditd:SYSCALL` | open/write syscalls targeting web directory files |
| `macos:unifiedlog` | Terminal/Editor processes modifying web folder |
| `esxi:vmkernel` | /var/log/vmkernel.log |

---

### Module Load
**Feeds detection for 109 techniques.**  
When a process or program dynamically attaches a shared library, module, or plugin into its memory space. This action is typically performed to extend the functionality of an application, access shared system resources, or interact with kernel-mode components.  

| Log source | Channel |
|---|---|
| `Module` |  |
| `WinEventLog:Sysmon` | EventCode=7 |
| `ETW:LoadImage` | provider: ETW LoadImage events for images from user-writable/UNC paths |
| `auditd:SYSCALL` | openat/read/mmap: Open/mmap .so files from non-standard paths |
| `linux:osquery` | select: Open files path LIKE '/tmp/%.so' OR '/dev/shm/%.so' |
| `macos:unifiedlog` | dyld/unified log entries indicating image load from non-system paths |
| `macos:osquery` | select: path LIKE '%/Library/%/*.dylib' OR '/tmp/*.dylib' |
| `macos:unifiedlog` | dynamic loading of sleep-related functions or sandbox detection libraries |
| `auditd:SYSCALL` | LD_PRELOAD Logging |
| `linux:osquery` | Dynamic Linking State |
| `macos:unifiedlog` | DYLD event subsystem |
| `linux:osquery` | Process linked with libcrypto.so making external connections |
| `macos:unifiedlog` | process execution events with dylib load activity |
| `linux:Sysmon` | EventCode=7 |
| `WinEventLog:Application` | CLR Assembly creation, loading, or modification logs via MSSQL CLR integration |
| `macos:unifiedlog` | Process memory maps new dylib (dylib_load event) |
| `macos:unifiedlog` | Dylib loaded from abnormal location |
| `WinEventLog:Security` | EventCode=3033 |
| `WinEventLog:Security` | EventCode=3063 |
| `auditd:MMAP` | load: Loading of libzip.so, libz.so, or libbz2.so by processes not normally associated with archiving |
| `macos:unifiedlog` | Loading of libz.dylib, libarchive.dylib by non-standard applications |
| `macos:unifiedlog` | suspicious dlopen/dlsym usage in non-development processes |
| `m365:unified` | Non-standard Office startup component detected (e.g., unexpected DLL path) |
| `auditd:SYSCALL` | mmap |
| `esxi:vmkernel` | unexpected module load |
| `snmp:status` | Status change in cryptographic hardware modules (enabled -> disabled) |
| `esxi:vmkernel` | module load |
| `macos:unifiedlog` | delay/sleep library usage in user context |
| `linux:syslog` | kmod |
| `macos:unifiedlog` | subsystem=com.apple.kextd |
| `macos:unifiedlog` | loading of unexpected dylibs compared to historical baselines |
| `auditd:file-events` | open of suspicious .so from non-standard paths |
| `macos:syslog` | DYLD_INSERT_LIBRARIES anomalies |
| `auditd:SYSCALL` | dmesg |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_KEXTLOAD |
| `auditd:SYSCALL` | module load or memory map path |
| `macos:unifiedlog` | launch and dylib load |
| `linux:osquery` | Processes linked with libssl/libcrypto performing network activity |
| `etw:Microsoft-Windows-Kernel-ImageLoad` | provider: Unsigned/user-writable image loads into msbuild.exe |

---

### Application Log Content
**Feeds detection for 98 techniques.**  
Application Log Content refers to logs generated by applications or services, providing a record of their activity. These logs may include metrics, errors, performance data, and operational alerts from web, mail, or other applications. These logs are vital for monitoring application behavior and detecting malicious activities or anomalies. Examples: 

- Web Application Logs: These logs include information about requests, responses, errors, and security events (e.g., unauthorized access attempts)  

| Log source | Channel |
|---|---|
| `Application Log` |  |
| `WinEventLog:Application` | Outlook errors loading or processing custom form templates |
| `m365:unified` | Unusual form activity within Outlook client, including load of non-default forms |
| `saas:okta` | Conditional Access policy rule modified or MFA requirement disabled |
| `ApplicationLog:EntraIDPortal` | DeviceRegistration events |
| `ApplicationLog:Intune/MDM Logs` | Enrollment events (e.g., MDMDeviceRegistration) |
| `m365:purview` | MailItemsAccessed & Exchange Audit |
| `m365:purview` | MailItemsAccessed, Search-Mailbox events |
| `WinEventLog:Application` | Office Add-in load errors, abnormal loading context, or unsigned add-in warnings |
| `m365:unified` | SendOnBehalf, MessageSend, ClickThrough, MailItemsAccessed |
| `Application:Mail` | smtpd$.*$: .*from=[.*@internaldomain.com](mailto:.*@internaldomain.com) to=[.*@internaldomain.com](mailto:.*@internaldomain.com) |
| `saas:slack` | file_upload, message_send, message_click |
| `saas:teams` | ChatMessageSent, ChatMessageEdited, LinkClick |
| `saas:gmail` | SendEmail, OpenAttachment, ClickLink |
| `m365:unified` | SendOnBehalf, MessageSend, AttachmentPreviewed |
| `WinEventLog:System` | Changes to applicationhost.config or DLLs loaded by w3wp.exe |
| `WinEventLog:Security` | EventCode=6416 |
| `WinEventLog:System` | Device started/installed (UMDF) GUIDs |
| `linux:syslog` | usb * new|thunderbolt|pci .* added|block.*: new .* device |
| `macos:unifiedlog` | Device attached|enumerated VID/PID |
| `m365:unified` | Send/Receive: Emails with suspicious sender domains, spoofed headers, or anomalous attachment types |
| `Application:Mail` | Inbound messages with anomalous headers, spoofed SPF/DKIM failures |
| `macos:unifiedlog` | Inbound email activity with suspicious domains or mismatched sender information |
| `m365:unified` | FileAccessed: Access of email attachments by Office applications |
| `saas:collaboration` | MessagePosted: Suspicious links or attachment delivery via collaboration tools (Slack, Teams, Zoom) |
| `ApplicationLog:IIS` | IIS W3C logs in C:\inetpub\logs\LogFiles\W3SVC* (spikes in 5xx, RCE/SQLi/path traversal/JNDI patterns) |
| `ApplicationLog:WebServer` | /var/log/httpd/access_log, /var/log/apache2/access.log, /var/log/nginx/access.log with exploit indicators and burst errors |
| `macos:unifiedlog` | App/web server logs ingested via unified logging or filebeat (nginx/apache/node). |
| `ApplicationLog:Ingress` | Kubernetes NGINX/Envoy ingress controller logs with anomalous payloads and 5xx spikes |
| `esxi:hostd` | /var/log/hostd.log anomalies (faults, crashes, restarts) around inbound connections |
| `esxi:vmkernel` | vmkernel / OpenSLP logs for malformed requests |
| `networkdevice:controlplane` | Syslog from edge devices with HTTP 500s on mgmt portal, SmartInstall events, unexpected CLI commands |
| `WinEventLog:Application` | Outlook rule execution failure or abnormal rule execution context |
| `m365:unified` | Creation or modification of inbox rule outside of normal user behavior |
| `m365:unified` | Send/Receive: Inbound emails containing embedded or shortened URLs |
| `Application:Mail` | Inbound emails containing hyperlinks from suspicious sources |
| `macos:unifiedlog` | Received messages with embedded or shortened URLs |
| `azure:signinlogs` | ConsentGrant: Suspicious consent grants to non-approved or unknown applications |
| `m365:unified` | AppRegistration: Unexpected application registration or OAuth authorization |
| `m365:unified` | MessageSend, MessageRead, or FileAttached events containing credential-like patterns |
| `m365:exchange` | Emails containing cleartext secrets (password=, api_key=, token=) shared across internal/external domains |
| `saas:slack` | chat.postMessage, files.upload, or discovery API calls involving token/credential regex |
| `linux:syslog` | Inbound messages from webmail services containing attachments or URLs |
| `macos:unifiedlog` | Received messages containing embedded links or attachments from non-enterprise services |
| `WinEventLog:System` | EventCode=1000 |
| `linux:syslog` | kernel|systemd messages indicating 'segmentation fault'|'core dumped'|'service terminated unexpectedly' for sshd, smbd, vsftpd, mysqld, httpd, etc. |
| `esxi:hostd` | Keywords: 'Backtrace','Signal 11','PANIC','hostd restarted','assert' or 'Service terminated unexpectedly' in /var/log/hostd.log, /var/log/vmkernel.log, /var/log/syslog.log. |
| `macos:unifiedlog` | process 'crashed'|'EXC_BAD_ACCESS' for sshd, screensharingd, httpd; launchd restarts of these daemons. |
| `esxi:hostd` | unexpected script/command invocations via hostd |
| `linux:syslog` | System daemons initiating encrypted sessions with unexpected destinations |
| `esxi:vpxd` | Symmetric crypto routines triggered for external session |
| `AWS:CloudTrail` | SendEmail |
| `AWS:CloudTrail` | InvokeModel |
| `saas:openai` | High volume of requests to /v1/chat/completions or /v1/images/generations |
| `m365:unified` | Set-Mailbox, Add-InboxRule, RegisterWebhook |
| `saas:application` | High-frequency invocation of SMS-related API endpoints from publicly accessible OTP or verification forms (e.g., Twilio: SendMessage, Cognito: AdminCreateUser) with irregular destination patterns. |
| `NSM:Connections` | PushNotificationSent |
| `saas:okta` | MFAChallengeIssued |
| `WinEventLog:Application` | Exchange Transport Service loads unusual .NET assembly or errors upon transport agent execution |
| `linux:syslog` | milter configuration updated, transport rule initialized, unexpected script execution |
| `WinEventLog:Application` | Unexpected spikes in request volume, application-level errors, or thread pool exhaustion in web or API logs |
| `linux:syslog` | Repetitive HTTP 408, 500, or 503 errors logged within short timeframe |
| `macos:unifiedlog` | opendirectoryd crashes or abnormal authentication errors |
| `m365:unified` | ConsentGranted: Abuse of application integrations to mint tokens bypassing MFA |
| `WinEventLog:Application` | Browser or plugin/application logs showing script errors, plugin enumerations, or unusual extension load events |
| `linux:syslog` | Application or browser logs (webview errors, plugin enumerations) indicating suspicious script evaluation or plugin loads |
| `macos:unifiedlog` | Logs from unifiedlogging that show browser crashes, plugin enumerations, extension installs or errors around the same time as suspicious network fetches |
| `m365:unified` | Application Consent grants, new OAuth client registrations, or unusual admin-level activities executed by a user account shortly after suspected drive-by compromise |
| `WinEventLog:Application` | Outlook logs indicating failure to load or render HTML page in Home Page view |
| `m365:unified` | Folder configuration updated with external or HTML-formatted Home Page via Set-MailboxFolder |
| `WinEventLog:Security` | EventCode=1102 |
| `linux:cli` | cleared or truncated .bash_history |
| `macos:unifiedlog` | log stream cleared or truncated |
| `m365:unified` | PurgeAuditLogs, Remove-MailboxAuditLog |
| `WinEventLog:System` | EventCode=104 |
| `WinEventLog:Application` | EventCode=1000 |
| `EDR:detection` | ThreatDetected, QuarantineLog |
| `macos:unifiedlog` | quarantine or AV-related subsystem |
| `EDR:detection` | ThreatLog |
| `azure:signinlogs` | Modify Conditional Access Policy |
| `m365:unified` | Set-CsOnlineUser or UpdateAuthPolicy |
| `m365:unified` | New-InboxRule or Set-InboxRule events recorded in Exchange Online |
| `ApplicationLog:MailServer` | Unexpected additions of sieve rules or filtering directives |
| `m365:unified` | Transport rule or inbox rule creation events |
| `ApplicationLog:Outlook` | Outlook client-level rule creation actions not consistent with normal user activity |
| `kubernetes:orchestrator` | Access to orchestrator logs containing credentials (Docker/Kubernetes logs) |
| `WinEventLog:Application` | Service crash, unhandled exception, or application hang warnings for critical services (e.g., IIS, DNS, SQL Server) |
| `journald:systemd` | Repeated service restart attempts or unit failures |
| `macos:unifiedlog` | Repeated process crashes logged by CrashReporter or system instability logs in com.apple.console |
| `docker:events` | Container exited with non-zero code repeatedly in short period |
| `WinEventLog:Application` | SCCM, Intune logs |
| `macos:jamf` | RemoteCommandExecution |
| `networkdevice:syslog` | config push events |
| `linux:syslog` | processes binding to non-standard ports or sshd configured on unexpected port |
| `m365:unified` | GAL Lookup or Address Book download |
| `esxi:hostd` | Guest Operations API invocation: StartProgramInGuest, ListProcessesInGuest, ListFileInGuest, InitiateFileTransferFromGuest |
| `m365:unified` | Send/Receive: Inbound emails with attachments from suspicious or spoofed senders |
| `Application:Mail` | Inbound email attachments logged from MTAs with suspicious metadata |
| `macos:unifiedlog` | Inbound messages with attachments from suspicious domains |
| `WinEventLog:Application` | Unexpected web application errors or CMS logs showing modification to index.html, default.aspx, or other public-facing files |
| `m365:unified` | certificate added or modified in application credentials |
| `saas:Snowflake` | QUERY: Large or repeated SELECT * queries to sensitive tables |
| `saas:Airtable` | EXPORT: User-triggered data export via GUI or API |
| `ApplicationLog:CallRecords` | Outbound or inbound calls to high-risk or blocklisted numbers |
| `networkdevice:syslog` | SIP REGISTER, INVITE, or unusual call destination metadata |
| `macos:unifiedlog` | Outgoing or incoming calls with non-standard caller IDs or unusual metadata |
| `m365:unified` | Unusual MFA requests or OAuth consent events temporally aligned with user-reported vishing call |
| `docker:daemon` | container_create,container_start |
| `saas:github` | Bulk access to multiple files or large volume of repo requests within short time window |
| `m365:exchange` | Transport Rule Modification |
| `m365:exchange` | Admin Audit Logs, Transport Rules |
| `saas:application` | High-volume API calls or traffic via messaging or webhook service |
| `m365:unified` | Set federation settings on domain|Set domain authentication|Add federated identity provider |
| `linux:syslog` | system daemons initiating TLS sessions outside expected services |
| `m365:unified` | SendOnBehalf/SendAs: Emails sent where the sending identity mismatches account ownership |
| `Application:Mail` | Mismatch between authenticated username and From header in email |
| `macos:unifiedlog` | Mail.app or third-party clients sending messages with mismatched From headers |
| `gcp:workspaceaudit` | SendAs: Outbound messages with alias identities that differ from primary account |
| `m365:unified` | Set-MailboxAutoReplyConfiguration: Unexpected rule changes creating impersonated replies |
| `m365:unified` | SendOnBehalf/SendAs: Office Suite initiated messages using impersonated identities |
| `linux:syslog` | browser/office crash, segfault, abnormal termination |
| `macos:unifiedlog` | process crash, abort, code signing violations |
| `saas:okta` | WebUI access to administrator dashboard |
| `m365:unified` | Read-only configuration review from GUI |
| `saas:box` | User navigated to admin interface |
| `azure:signinlogs` | Register PTA Agent or Modify AD FS trust |
| `m365:unified` | Modify Federation Settings or Update Authentication Policy |
| `saas:okta` | Federation configuration update or signing certificate change |
| `macos:unifiedlog` | Configuration profile modified or new profile installed |
| `journald:Application` | Segfault or crash log entry associated with specific application binary |
| `macos:unifiedlog` | Crash log entries for a process receiving malformed input or known exploit patterns |
| `AWS:CloudWatch` | Repeated crash pattern within container or instance logs |
| `esxi:hostd` | unexpected script invocations producing long encoded strings |
| `docker:runtime` | execution of cloud CLI tool (e.g., aws, az) inside container |
| `WinEventLog:Application` | VPN, Citrix, or remote access gateway logs showing external IP addresses |
| `NSM:Connections` | Failed password or accepted password for SSH users |
| `ApplicationLog:API` | Docker/Kubernetes API access from external sources |
| `m365:unified` | Send/Receive: Unusual spikes in inbound messages to a single recipient |
| `Application:Mail` | High-frequency inbound mail activity to a specific recipient address |
| `m365:exchange` | MailDelivery: High-frequency delivery of messages or attachments to a single recipient |
| `macos:unifiedlog` | Repetitive inbound email delivery activity logged within a short time window |
| `saas:confluence` | access.content |
| `m365:unified` | PowerShell: Add-MailboxPermission |
| `AWS:CloudTrail` | InvokeFunction: Unexpected or repeated invocation of functions not tied to known workflows |
| `m365:exchange` | New-InboxRule: Automation that triggers abnormal forwarding or external link generation |
| `saas:googledrive` | FileOpen / FileAccess: Event-driven script triggering on user file actions |
| `networkdevice:syslog` | Failed authentication requests redirected to non-standard portals |
| `saas:okta` | System API Call: user.read, group.read |
| `esxi:hostd` | Host daemon command log entries related to vib enumeration |
| `m365:unified` | Add-MailboxPermission or Set-ManagementRoleAssignment |
| `WinEventLog:Application` | Outlook rule creation, form load, or homepage redirection |
| `m365:mailboxaudit` | Outlook rule creation or custom form deployment |
| `saas:zoom` | unusual web session tokens and automation patterns during login |
| `WinEventLog:Application` | High-frequency errors or hangs from resource-intensive application components (e.g., .NET, IIS, Office Suite) |
| `linux:syslog` | Error/warning logs from services indicating load spike or worker exhaustion |
| `macos:unifiedlog` | Application errors or resource contention from excessive frontend or script invocation |
| `AWS:CloudWatch` | Elevated 5xx response rates in application logs or gateway layer |
| `m365:messagetrace` | AuthenticationDetails=fail OR SPF=fail OR DKIM=fail OR DMARC=fail |
| `linux:syslog` | SPF fail OR DKIM fail OR DMARC fail OR mismatched from_domain vs return_path_domain |
| `macos:unifiedlog` | SPF fail OR DKIM fail OR DMARC fail OR mismatched header vs envelope domains |
| `saas:email` | AuthenticationFailures (SPF/DKIM/DMARC) OR Domain Mismatch |
| `WinEventLog:System` | EventCode=1341, 1342, 1020, 1063 |
| `linux:syslog` | suspicious DHCP lease assignment with unexpected DNS or gateway |
| `macos:unifiedlog` | new DHCP configuration with anomalous DNS or router values |
| `WinEventLog:Application` | Exchange logs or header artifacts |
| `macos:unifiedlog` | Mail or AppleScript subsystem |
| `m365:exchange` | MessageTrace logs |
| `linux:syslog` | opened document|clicked link|segfault|abnormal termination|sandbox |
| `macos:unifiedlog` | opened document|clicked link|EXC_BAD_ACCESS|abort|LSQuarantine |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `m365:unified` | Set-PartnerOfRecord / CompanyAdministrator role assignments / New-DelegatedAdminRelationship |
| `AWS:CloudTrail` | CreateUser|AttachRolePolicy|CreateAccessKey|UpdateAssumeRolePolicy|CreateLoginProfile |
| `azure:activity` | Add role assignment / ElevateAccess / Create service principal |
| `saas:googleworkspace` | OAuth2 authorization grants / Admin role assignments |
| `m365:unified` | Add-DelegatedAdmin, Set-PartnerOfRecord, Add-MailboxPermission, Set-OrganizationRelationship |
| `linux:syslog` | Authentication attempts into finance-related servers from unusual IPs or times |
| `macos:unifiedlog` | Anomalous keychain access attempts targeting payment credentials |
| `saas:finance` | Transaction/Transfer: Unusual or large transactions initiated outside business hours or by unusual accounts |
| `saas:audit` | Rule/ConfigChange: Auto-forward rules, delegate assignments, or changes to financial approval workflows |
| `m365:unified` | MailSend: Outlook messages with suspicious subject/body terms (e.g., urgent payment, wire transfer) targeting finance teams |
| `m365:unified` | FileAccessed, FileDownloaded, SearchQueried |
| `m365:unified` | Detection of hidden macro streams or SetHiddenAttribute actions |
| `m365:unified` | RunMacro |
| `azure:audit` | App registrations or consent grants by abnormal users or at unusual times |
| `azure:signinlogs` | Resource access initiated using application credentials, not user accounts |
| `saas:slack` | OAuth token use by unknown app client_id accessing private channels or files |
| `esxi:esxupdate` | /var/log/esxupdate.log contains VIB installed with `--force` or `--no-sig-check` and non-standard acceptance levels |
| `linux:syslog` | sshd sessions with unusual port forwarding parameters |
| `saas:audit` | Application added or consent granted: Integration persisting after original user disabled |
| `linux:syslog` | Non-standard processes negotiating SSL/TLS key exchanges |
| `esxi:vpxd` | ESXi process initiating asymmetric handshake with external host |
| `WinEventLog:Application` | Unusual DLL/plugin registration for IIS/SQL/Apache or unexpected error logs |
| `linux:syslog` | Module registration or stacktrace logs indicating segmentation faults or unknown module errors |
| `esxi:hostd` | New extension/module install with unknown vendor ID |
| `m365:unified` | FileUploaded or FileCopied events |
| `saas:salesforce` | DataExport, RestAPI, Login, ReportExport |
| `saas:hubspot` | contact_viewed, contact_exported, login |
| `saas:slack` | conversations.history, files.list, users.info, audit_logs |
| `m365:unified` | TeamsMessageAccess, TeamsExport, ExternalAppAccess |
| `m365:unified` | TeamsMessagesAccessedViaEDiscovery, TeamsGraphMessageExport |
| `m365:unified` | FileAccessed |
| `m365:messagetrace` | X-MS-Exchange-Organization-AutoForwarded |
| `linux:syslog` | Segfaults, kernel oops, or crashes in security software processes |
| `macos:unifiedlog` | Abnormal terminations of com.apple.security.* or 3rd-party security daemons |
| `AWS:CloudTrail` | StopLogging, DeleteTrail, UpdateTrail: API calls that disable or modify logging services |
| `m365:unified` | ApplicationModified, ConsentGranted: Unexpected app consent or modification events linked to security evasion |

---

### Network Traffic Flow
**Feeds detection for 92 techniques.**  
Summarized network packet data that captures session-level details such as source/destination IPs, ports, protocol types, timestamps, and data volume, without storing full packet payloads. This is commonly used for traffic analysis, anomaly detection, and network performance monitoring.  

| Log source | Channel |
|---|---|
| `Network Traffic` |  |
| `macos:osquery` | socket_events |
| `NSM:Flow` | Unexpected flows between segmented networks or prohibited ports |
| `snmp:config` | Configuration change traps or policy enforcement failures |
| `NSM:Flow` | First-time outbound connections to package registries or unknown hosts immediately after restore/build |
| `NSM:Flow` | First-time egress to new registries/CDNs post-install/build |
| `NSM:Flow` | First-time egress to non-approved registries after dependency install |
| `NSM:Flow` | Outbound connections to TCP 139,445 and HTTP/HTTPS to WebDAV endpoints from workstation subnets |
| `NSM:Flow` | large outbound data flows or long-duration connections |
| `AWS:VPCFlowLogs` | egress > 90th percentile or frequent connection reuse |
| `NSM:Flow` | conn.log |
| `auditd:SYSCALL` | socket/connect |
| `esxi:syslog` | esxcli network vswitch or DNS resolver configuration updates |
| `esxi:vobd` | Network Events |
| `iptables:LOG` | TCP connections |
| `NSM:Flow` | connection metadata |
| `wineventlog:dhcp` | DHCP Lease Granted |
| `NSM:Flow` | LEASE_GRANTED |
| `NSM:Flow` | MAC not in allow-list acquiring IP (DHCP) |
| `Windows Firewall Log` | SMB over high port |
| `NSM:Connections` | Internal connection logging |
| `NSM:Flow` | pf firewall logs |
| `esxi:vmkernel` | /var/log/vmkernel.log |
| `NSM:Flow` | Inter-segment traffic |
| `NSM:Flow` |  |
| `NSM:Flow` | Long-lived or hijacked SSH sessions maintained with no active user activity |
| `AWS:VPCFlowLogs` | VPC/NSG flow logs for pod/instance egress to Internet or metadata |
| `macos:unifiedlog` | Suspicious outbound traffic from browser binary to non-standard domains |
| `NSM:Flow` | Abnormal browser traffic volume or destination |
| `NSM:Flow` | Outbound requests to domains not previously resolved or associated with phishing campaigns |
| `NSM:Flow` | Outbound traffic to domains/IPs not previously resolved, occurring shortly after attachment download or link click |
| `M365Defender:DeviceNetworkEvents` | NetworkConnection: bytes_sent >> bytes_received anomaly |
| `PF:Logs` | outbound flows with bytes_out >> bytes_in |
| `NSX:FlowLogs` | network_flow: bytes_out >> bytes_in to external |
| `NSM:Flow` | NetFlow/Zeek conn.log |
| `AWS:VPCFlowLogs` | Outbound data flows |
| `NSM:Flow` | Flow records with entropy signatures resembling symmetric encryption |
| `NSM:Flow` | flow records |
| `networkdevice:syslog` | flow records |
| `macos:unifiedlog` | HTTPS POST to known webhook URLs |
| `saas:api` | Webhook registrations or repeated POST activity |
| `NSM:Flow` | Source/destination IP translation inconsistent with intended policy |
| `SNMP:DeviceLogs` | Unexpected NAT translation statistics or rule insertion events |
| `NSM:Flow` | Sudden spike in incoming flows to web service ports from single/multiple IPs |
| `AWS:VPCFlowLogs` | Unusual volume of inbound packets from single source across short time interval |
| `NSM:Flow` | port 5900 inbound |
| `NSM:Flow` | TCP port 5900 open |
| `NSM:firewall` | inbound connection to port 5900 |
| `NSM:Firewall` | Outbound connections to 139/445 to multiple destinations |
| `VPCFlowLogs:All` | High volume internal traffic with low entropy indicating looped or malicious DoS script |
| `NSM:Flow` | NetFlow/sFlow/PCAP |
| `NSM:Flow` | Outbound Network Flow |
| `macos:unifiedlog` | com.apple.network |
| `NSM:Flow` | Device-to-Device Deployment Flows |
| `auditd:SYSCALL` | socket/connect syscalls |
| `macos:unifiedlog` | outbound TCP/UDP traffic over unexpected port |
| `esxi:vpxd` | ESXi service connections on unexpected ports |
| `iptables:LOG` | OUTBOUND |
| `macos:unifiedlog` | tcp/udp |
| `esxi:hostd` | CLI network calls |
| `NSM:Flow` | Outbound traffic from suspicious new processes post-attachment execution |
| `macos:unifiedlog` | Suspicious anomalies in transmitted data integrity during application network operations |
| `esxi:syslog` | DNS resolution events leading to outbound traffic on unexpected ports |
| `NSM:Flow` | Outbound traffic to mining pools or proxies |
| `AWS:VPCFlowLogs` | Outbound flow logs to known mining pools |
| `container:cni` | Outbound network traffic to mining proxies |
| `esxi:vpxd` | TLS session established by ESXi service to unapproved endpoint |
| `NSM:Flow` | Session records with TLS-like byte patterns |
| `macos:unifiedlog` | HTTPS POST requests to pastebin.com or similar |
| `NetFlow:Flow` | new outbound connections from exploited process tree |
| `NSM:Connections` | new connections from exploited lineage |
| `NSM:Flow` | Unexpected route changes or duplicate gateway advertisements |
| `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | EventCode=2004, 2005, 2006 |
| `NSM:Flow` | Knock pattern: repeated REJ/S0 across ≥MinSequenceLen ports from same src_ip then SF success. |
| `macos:unifiedlog` | Firewall/PF anchor load or rule change events. |
| `networkdevice:syslog` | Config/ACL changes, line vty transport input changes, telnet/ssh/http(s) enable, image/feature module changes. |
| `NSM:Flow` | First-time egress to non-approved update hosts right after install/update |
| `NSM:Flow` | New outbound flows to non-approved vendor hosts post install |
| `NSM:Flow` | New/rare egress to non-approved update hosts after install |
| `NSM:Flow` | large outbound HTTPS uploads to repo domains |
| `esxi:vmkernel` | HTTPS traffic to repository domains |
| `NSM:Flow` | alert log |
| `esxi:vmkernel` |  |
| `NSM:Flow` | Outbound flow records |
| `m365:defender` | NetworkConnection: high out:in ratio, periodic beacons, protocol mismatch |
| `PF:Logs` | high out:in ratio or fixed-size periodic flows |
| `NSM:Flow` | network_flow: bytes_out >> bytes_in, fixed packet sizes/intervals to non-approved CIDRs |
| `auditd:SYSCALL` | connect or sendto system call with burst pattern |
| `macos:unifiedlog` | sudden burst in outgoing packets from same PID |
| `AWS:VPCFlowLogs` | source instance sends large volume of traffic in short window |
| `NSM:Flow` | session stats with bytes_out > bytes_in |
| `NIDS:Flow` | session stats with bytes_out > bytes_in |
| `esxi:vpxa` | connection attempts and data transmission logs |
| `PF:Logs` | External traffic to remote access services |
| `NSM:Flow` | High volumes of SYN/ACK packets with unacknowledged TCP handshakes |
| `dns:query` | Outbound resolution to hidden service domains (e.g., `.onion`) |
| `NSM:Flow` | conn.log + ssl.log with Tor fingerprinting |
| `macos:unifiedlog` | forwarded encrypted traffic |
| `NSM:Flow` | Relayed session pathing (multi-hop) |
| `NSM:Flow` | Outbound TCP SYN or UDP to multiple ports/hosts |
| `containerd:runtime` | container-level outbound traffic events |
| `WLANLogs:Association` | Multiple APs advertising the same SSID but with different BSSID/MAC or encryption type |
| `linux:osquery` | socket_events |
| `WinEventLog:Security` | ARP cache modification attempts observed through event tracing or security baselines |
| `NSM:Flow` | Gratuitous ARP replies with mismatched IP-MAC binding |
| `macos:unifiedlog` | ARP table updates inconsistent with expected gateway or DHCP lease assignments |
| `macos:unifiedlog` | networkd or com.apple.network |
| `macos:unifiedlog` | log stream 'eventMessage contains "dns_request"' |
| `esxi:syslog` | /var/log/syslog.log |
| `AWS:CloudTrail` | CreateTrafficMirrorSession or ModifyTrafficMirrorTarget |
| `networkdevice:syslog` | Config change: CLI/NETCONF/SNMP – 'monitor session', 'mirror port' |
| `NSM:Flow` | Outbound UDP floods targeting common reflection services with spoofed IP headers |
| `macos:unifiedlog` | Outbound UDP spikes to external reflector IPs |
| `AWS:VPCFlowLogs` | Large outbound UDP traffic to multiple public reflector IPs |
| `macos:unifiedlog` | High entropy domain queries with multiple NXDOMAINs |
| `esxi:syslog` | Frequent DNS queries with high entropy names or NXDOMAIN results |
| `vpxd.log` | API communication |
| `NSM:Connections` | Outbound Connection |
| `NSM:Flow` | Connection Tracking |
| `NSM:Firewall` | pf firewall logs |
| `NSM:Flow` | Flow Creation (NetFlow/sFlow) |
| `NSM:Flow` | conn.log, icmp.log |
| `NSM:Flow` | Abnormal SMB authentication attempts correlated with poisoned LLMNR/NBT-NS sessions |
| `NSM:Flow` | Gratuitous or duplicate DHCP OFFER packets from non-legitimate servers |
| `NSM:Connections` | Inbound on ports 5985/5986 |
| `linux:syslog` | Multiple IP addresses assigned to the same domain in rapid sequence |
| `macos:unifiedlog` | Rapid domain-to-IP resolution changes for same domain |
| `esxi:syslog` | Frequent DNS resolution of same domain with rotating IPs |
| `NSM:Flow` | uncommon ports |
| `NSM:Flow` | alternate ports |
| `esxi:vpxd` |  |
| `NSM:Flow` | conn.log or flow data |
| `esxi:vmkernel` | egress log analysis |
| `esxi:vmkernel` | egress logs |
| `NSM:Flow` | High volume flows with incomplete TCP sessions or single-packet bursts |
| `NSM:Flow` | Knock pattern: multiple REJ/S0 to distinct closed ports then successful connection to service_port |
| `macos:unifiedlog` | Firewall rule enable/disable or listen socket changes |
| `networkdevice:syslog` | Config/ACL/line vty changes, service enable (telnet/ssh/http(s)), module reloads |
| `auditd:SYSCALL` | ioctl: Changes to wireless network interfaces (up, down, reassociate) |
| `macos:osquery` | query: Historical list of associated SSIDs compared against baseline |
| `NSM:Flow` | First-time egress from host after new install to unknown update endpoints |
| `NSM:Flow` | First-time egress to unknown registries/mirrors immediately after install |
| `NSM:Flow` | New egress from app just installed to unknown update endpoints |
| `esxi:vpxd` | ESXi processes relaying traffic via SSH or unexpected ports |
| `NSM:Flow` | Outbound connection to mining pool port (3333, 4444, 5555) |
| `NSM:Flow` | Outbound traffic to mining pool upon container launch |
| `NSM:Flow` | Flow records with RSA key exchange on unexpected port |
| `NSM:Flow` | Outbound connections from web server binaries (apache2, nginx, php-fpm) to unknown external IPs |
| `NSM:Flow` | sustained outbound HTTPS sessions with high data volume |
| `NSM:Flow` | Connections from IDE hosts to marketplace/tunnel domains |
| `macos:unifiedlog` | Outbound connections from IDE processes to marketplace/tunnel domains |
| `NSM:Flow` | large HTTPS outbound uploads |
| `esxi:vmkernel` | network flows to external cloud services |
| `NSM:Flow` | TCP port 22 traffic |
| `esxi:vmkernel` | port 22 access |

---

### File Access
**Feeds detection for 91 techniques.**  
To events where a file is opened or accessed, making its contents available to the requester. This includes reading, executing, or interacting with files by authorized or unauthorized entities. Examples include logging file access events (e.g., Windows Event ID 4663), monitoring file reads, and detecting unusual file access patterns. Examples: 

- File Read Operations: A user opens a sensitive document (e.g., financial_report.xlsx) on a shared drive.
- File Execution: A script or executable file  

| Log source | Channel |
|---|---|
| `File` |  |
| `m365:unified` | FileAccessed, MailboxAccessed |
| `auditd:SYSCALL` | open, read, or stat of browser config files |
| `macos:unifiedlog` | Access to ~/Library/*/Safari or Chrome directories by non-browser processes |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `macos:unifiedlog` | file events |
| `gcp:audit` | Write operations to storage |
| `esxi:vmkernel` | VMFS access logs |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_OPEN: Open of .dylib/.so in user-writable locations |
| `auditd:SYSCALL` | open: File access attempt on /tmp/krb5cc_* or /tmp/krb5.ccache |
| `macos:unifiedlog` | Kerberos framework calls to API:{uuid} cache outside normal process lineage |
| `auditd:SYSCALL` | openat |
| `auditd:FILE` | /home/*/.mozilla/firefox/*/logins.json OR /home/*/.config/google-chrome/*/Login Data |
| `macos:unifiedlog` | ~/Library/Application Support/Google/Chrome/*/Login Data OR ~/Library/Application Support/Firefox/*/logins.json |
| `auditd:SYSCALL` | open |
| `auditd:FILE` | /proc/*/mem read attempt |
| `auditd:PATH` | Read access to known backup software configuration files (e.g., /etc/rsnapshot.conf, /opt/veeam/config.ini) |
| `macos:unifiedlog` | Read access to Time Machine plist files or CCC configurations in ~/Library/Preferences/ |
| `auditd:SYSCALL` | open, read |
| `linux:syslog` | auth.log or custom tool logs |
| `fs:fsusage` | file |
| `linux:syslog` | /var/log/syslog |
| `macos:osquery` | file_events |
| `auditd:SYSCALL` | open, flock, fcntl, unlink |
| `fs:fsusage` | File Access Monitor |
| `macos:unifiedlog` | log stream - file subsystem |
| `auditd:SYSCALL` | read/open of sensitive files |
| `macos:unifiedlog` | file read of sensitive directories |
| `esxi:hostd` | datastore file access |
| `auditd:SYSCALL` | Unusual processes accessing or modifying cookie databases |
| `macos:unifiedlog` | Abnormal process access to Safari or Chrome cookie storage |
| `auditd:SYSCALL` | PATH records referencing /dev/video* |
| `macos:endpointsecurity` | open: Process opens AppleCamera/IOUSB device nodes or AVFoundation frameworks |
| `ebpf:syscalls` | container_file_activity |
| `fs:fsusage` | Disk Activity Tracing |
| `macos:keychain` | Access to Keychain DB or system.keychain |
| `auditd:SYSCALL` | open, read: /etc/ssl/, /etc/pki/, ~/.pki/nssdb/ |
| `macos:keychain` | ~/Library/Keychains, /Library/Keychains |
| `m365:unified` | Bulk downloads or API extractions from Microsoft-hosted data repositories (e.g., Dynamics 365) |
| `auditd:PATH` | open: Access to sensitive log files (/var/log/auth.log, /var/log/secure, /var/log/syslog) |
| `macos:unifiedlog` | open: Access to /var/log/system.log or related security event logs |
| `azure:activity` | CollectGuestLogs: Unexpected collection of guest logs by Azure VM Agent outside normal maintenance windows |
| `esxi:hostd` | read: Access to sensitive log files by non-admin users |
| `auditd:SYSCALL` | Processes reading credential or token cache files |
| `auditd:SYSCALL` | read/open of sensitive file directories |
| `esxi:hostd` | datastore/log file access |
| `fs:fsusage` | filesystem activity |
| `WinEventLog:Microsoft-Windows-Windows Defender/Operational` | Suspicious file execution on removable media path |
| `auditd:PATH` | PATH |
| `auditd:SYSCALL` | open/read of sensitive config or secret files |
| `macos:unifiedlog` | open/read of *.plist or .env files |
| `ebpf:syscalls` | open/read on secret mount paths |
| `CloudTrail:GetObject` | sensitive credential files in buckets or local image storage |
| `auditd:SYSCALL` | open/read of sensitive directories |
| `macos:unifiedlog` | read of user document directories |
| `esxi:syslog` | guest OS outbound transfer logs |
| `fs:fsusage` | Filesystem Call Monitoring |
| `esxi:hostd` | vSphere File API Access |
| `auditd:SYSCALL` | open/read: Access to /proc/self/status with focus on TracerPID field |
| `fs:fsusage` | read/write |
| `esxis:vmkernel` | Datastore Access |
| `auditd:SYSCALL` | open/read access to ~/.bash_history |
| `macos:endpointsecurity` | open or read syscall to ~/.bash_history |
| `macos:unifiedlog` | read access to ~/Library/Keychains/login.keychain-db |
| `auditd:SYSCALL` | open,read |
| `macos:unifiedlog` | filesystem and process events |
| `auditd:SYSCALL` | open/read system calls to ~/.bash_history or /etc/shadow |
| `macos:unifiedlog` | read access to ~/Library/Keychains or history files by terminal processes |
| `auditd:SYSCALL` | read of /run/secrets or docker volumes by non-entrypoint process |
| `macos:unifiedlog` | access to /Volumes/SharePoint or network mount |
| `auditd:SYSCALL` | Reads of ~/.bash_history, ~/.mozilla, or access to /dev/input |
| `macos:unifiedlog` | Access to ~/Library/Safari/Bookmarks.plist or recent files |
| `auditd:SYSCALL` | open/read |
| `macos:unifiedlog` | access to keychain database |
| `auditd:PATH` | file read |
| `linux:syslog` | kernel messages related to cryptographic operations, module loading, and filesystem access patterns |
| `fs:fsevents` | file system events indicating access to system configuration files and environmental information sources |
| `macos:endpointsecurity` | es_event_open, es_event_exec |
| `auditd:SYSCALL` | open: Access to named pipes or FIFO in /tmp or /dev/shm by unexpected processes |
| `auditd:SYSCALL` | open or read to browser cookie storage |
| `fs:fsusage` | file open for known browser cookie paths |
| `auditd:SYSCALL` | open, read, mount |
| `fs:fsusage` | file reads/writes from /Volumes/ |
| `macos:unifiedlog` | log stream - file provider subsystem |
| `auditd:SYSCALL` | file |
| `kubernetes:audit` | GET or LIST requests to /var/run/secrets/kubernetes.io/serviceaccount/ followed by access to the Kubernetes API server |
| `auditd:SYSCALL` | Access to /var/lib/sss/secrets/secrets.ldb or .secrets.mkey |
| `fs:quarantine` | /var/log/quarantine.log |
| `desktop:file_manager` | nautilus, dolphin, or gvfs logs |
| `linux:osquery` | /proc/*/maps access |
| `auditd:SYSCALL` | open/read of sensitive directories (/etc, /home/*) |
| `macos:unifiedlog` | read/write of user documents prior to upload |
| `esxi:hostd` | file copy or datastore upload via HTTPS |
| `macos:unifiedlog` | open/read access to private key files (id_rsa, *.pem, *.p12) |
| `linux:osquery` |  |
| `macos:osquery` |  |
| `fs:fileevents` | File system access events with kFSEventStreamEventFlagItemRemoved, kFSEventStreamEventFlagItemRenamed flags for environmental artifact collection (/System/Library, /usr/sbin, plist files) |
| `auditd:FS` | read: File access to /proc/modules or /sys/module/ |
| `macos:unifiedlog` | read: File access to /System/Library/Extensions/ or related kernel extension paths |
| `auditd:SYSCALL` | PATH |
| `auditd:SYSCALL` | open/read on ~/.local/share/keepassxc/* OR ~/.password-store/* |
| `macos:unifiedlog` | *.opvault OR *.ldb OR *.kdbx |

---

### Windows Registry Key Modification
**Feeds detection for 86 techniques.**  
Changes made to an existing registry key or its values. These modifications can include altering permissions, modifying stored data, or updating configuration settings.

*Data Collection Measures:*

- Windows Event Logs
 - Event ID 4657 - Registry Value Modified: Logs changes to registry values, including modifications to startup entries, security settings, or system configurations.
- Sysmon (System Monitor) for Windows
 - Sysmon Event ID 13 - Registry Value Set: Captures changes to specific reg  

| Log source | Channel |
|---|---|
| `Windows Registry` |  |
| `WinEventLog:Security` | EventCode=4657 |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `WinEventLog:Sysmon` | StubPath value written under HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components |
| `m365:unified` | MacroSecuritySettingsChanged or SafeModeDisabled |
| `WinEventLog:Sysmon` | EventCode=13, 14 |
| `WinEventLog:Security` | modification to Winlogon registry keys such as Shell, Notify, or Userinit |
| `WinEventLog:Security` | Registry key modification HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast |
| `macos:unifiedlog` | g_CiOptions modification or SIP state change |
| `WinEventLog:Sysmon` | Autoruns reports DLLs in AppInit_DLLs key |

---

### Process Access
**Feeds detection for 77 techniques.**  
Refers to an event where one process attempts to open another process, typically to inspect or manipulate its memory, access handles, or modify execution flow. Monitoring these access attempts can provide valuable insight into both benign and malicious behaviors, such as debugging, inter-process communication (IPC), or process injection.

*Data Collection Measures:*

- Endpoint Detection and Response (EDR) Tools:
 - EDR solutions that provide telemetry on inter-process access and memory manipula  

| Log source | Channel |
|---|---|
| `WinEventLog:Sysmon` | EventCode=10 |
| `linux:osquery` | Process State |
| `auditd:SYSCALL` | ptrace attach |
| `macos:unifiedlog` | ptrace or task_for_pid |
| `macos:osquery` | process_open |
| `auditd:SYSCALL` | High frequency of accept(), read(), or SSL_read() syscalls tied to nginx/apache processes |
| `Apple TCC Logs` | Microphone Access Events |
| `auditd:SYSCALL` | ptrace |
| `linux:syslog` | syscalls (open, read, ioctl) on /dev/input or /proc/*/fd/* |
| `WinEventLog:Sysmon` | EventCode=25 |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_OPEN |
| `macos:unifiedlog` | Unexpected NSXPCConnection calls by non-Apple-signed or abnormal binaries |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `macos:unifiedlog` | Unusual Mach port registration or access attempts between unrelated processes |
| `macos:unifiedlog` | subsystem=com.apple.security, library=libsystem_kernel.dylib |
| `auditd:SYSCALL` | ptrace syscall or access to /proc/*/mem |
| `macos:unifiedlog` | vm_read, task_for_pid, or file open to cookie databases |
| `linux:osquery` | process_events |
| `auditd:SYSCALL` | ACCESS |
| `auditd:SYSCALL` | execve, fork, mmap, ptrace |
| `auditd:SYSCALL` | ptrace or process_vm_readv |
| `macos:osquery` | unexpected memory inspection |

---

### File Metadata
**Feeds detection for 64 techniques.**  
contextual information about a file, including attributes such as the file's name, size, type, content (e.g., signatures, headers, media), user/owner, permissions, timestamps, and other related properties. File metadata provides insights into a file's characteristics and can be used to detect malicious activity, unauthorized modifications, or other anomalies. Examples: 

- File Ownership and Permissions: Checking the owner and permissions of a critical configuration file like /etc/passwd on Linu  

| Log source | Channel |
|---|---|
| `File` |  |
| `linux:osquery` | event-based |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Invalid/Unsigned image when developer tool launches newly installed binaries |
| `journald:package` | dpkg/apt or yum/dnf transaction logs (install/update of build tools) |
| `linux:osquery` | file_events, hash |
| `macos:unifiedlog` | softwareupdated/homebrew/install logs, pkginstalld events |
| `macos:unifiedlog` | AMFI or Gatekeeper signature/notarization failures for newly installed dev components |
| `auditd:SYSCALL` | Inotify watch creation or auditctl changes on /etc/cron* or /lib/systemd/system/ |
| `linux:syslog` | Discrepancies in _VBA_PROJECT p-code vs source code extracted with oletools/pcodedmp |
| `macos:unifiedlog` | Detection of altered _VBA_PROJECT or PerformanceCache streams |
| `EDR:file` | File Metadata Inspection (Low String Entropy, Missing PDB) |
| `linux:osquery` | hash, elf_info, file_metadata |
| `macos:osquery` | code_signing, file_metadata |
| `WinEventLog:Windows Defender` | Operational log |
| `macos:unifiedlog` | subsystem:syspolicyd |
| `macos:unifiedlog` | File metadata updated with UF_HIDDEN flag |
| `WinEventLog:Sysmon` | EventCode=15 |
| `auditd:PATH` | file path matches exclusion directories |
| `auditd:SYSCALL` | PATH |
| `auditd:PATH` | PATH |
| `macos:endpointsecurity` | es_event_file_rename_t or es_event_file_write_t |
| `linux:osquery` | file_events |
| `fs:fileevents` | /var/log/install.log |
| `auditd:SYSCALL` | file write after sleep delay |
| `esxi:vmkernel` | Upload of file to datastore |
| `ebpf:syscalls` | Unexpected container volume unmount + file deletion |
| `macos:osquery` | file_events |
| `EDR:file` | File Metadata Analysis (PE overlays, entropy) |
| `linux:osquery` | elf_info, hash, yara_matches |
| `macos:osquery` | mach_o_info, file_metadata |
| `macos:unifiedlog` | Code signature validation fails or is absent post-binary modification |
| `fs:filesystem` | Binary file hash changes outside of update/patch cycles |
| `linux:osquery` | Read headers and detect MIME type mismatch |
| `macos:unifiedlog` | Code signing verification failures or bypassed trust decisions |
| `NSM:Flow` | Observed File Transfers |
| `esxi:vmkernel` | Storage access and file ops |
| `macos:unifiedlog` | Creation of new LaunchAgent or LoginItem plist files in ~/Library/LaunchAgents/ |
| `auditd:CONFIG_CHANGE` | chmod or chown of hook files indicating privilege escalation or execution permission change |
| `macos:unifiedlog` | filesystem events |
| `macos:unifiedlog` | xattr -d com.apple.quarantine or similar attribute removal commands |
| `macos:unifiedlog` | Gatekeeper quarantine policy decision anomalies recorded in com.apple.LaunchServices.QuarantineEventsV2 |
| `linux:syslog` | application or system execution logs |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `auditd:SYSCALL` | syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, setxattr, lsetxattr, fsetxattr) |
| `linux:syslog` | file permission modification events in kernel messages |
| `fs:fsevents` | file system events indicating permission or attribute changes |
| `OpenBSM:AuditTrail` | BSM audit events for file permission modifications |
| `esxi:hostd` | host daemon events related to file or VM permission changes |
| `esxi:vmkernel` | VMware kernel events for file system permission modifications |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Unsigned or invalid image for newly installed/updated binaries |
| `journald:package` | dpkg/apt/yum/dnf transaction logs; vendor updaters in systemd journals |
| `macos:unifiedlog` | pkginstalld/softwareupdated/Homebrew install transactions |
| `macos:unifiedlog` | AMFI/Gatekeeper code signature or notarization failures |
| `EDR:detection` | App reputation telemetry |
| `gatekeeper/quarantine database` | LaunchServices quarantine |
| `linux:osquery` | file_events.path |
| `auditd:SYSCALL` | setuid or setgid bit changes |
| `linux:osquery` | Filesystem modifications to trusted paths |
| `fs:fsusage` | filesystem monitoring of exec/open |
| `auditd:SYSCALL` | syscall in (chmod, fchmod, fchmodat, chown, fchown, fchownat, lchown, setxattr, lsetxattr, fsetxattr, removexattr, lremovexattr, fremovexattr) |
| `auditd:PATH` | file path modifications on critical system directories (/etc, /usr/bin, /usr/sbin, /var, /opt) |
| `linux:syslog` | kernel messages related to file system permission changes and security violations |
| `OpenBSM:AuditTrail` | BSM audit events for file permission, ownership, and attribute modifications with user context |
| `macos:unifiedlog` | kernel extension and system extension logs related to file system security violations or SIP bypass attempts |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Code integrity violations in boot-start drivers or firmware |
| `fwupd:logs` | Firmware updates applied or failed |
| `macos:endpointsecurity` | es_event_authentication |
| `esxi:vmkernel` | Datastore modification events |
| `linux:osquery` | Write or modify .desktop file in XDG autostart path |
| `macos:unifiedlog` | Unexpected application binary modifications or altered signing status |
| `auditd:SYSCALL` | setxattr or getxattr system call |
| `macos:unifiedlog` | extended attribute write or modification |
| `WinEventLog:Security` | EventCode=4663, 4656, 4658 |
| `auditd:SYSCALL` | chmod, chown, setxattr, or file writes to /etc/ssl/* or /usr/local/share/ca-certificates/* |
| `macos:unifiedlog` | New certificate trust settings added by unexpected process |
| `esxi:syslog` | Datastore file hidden or renamed unexpectedly |
| `WinEventLog:Windows Defender` | Operational |
| `macos:unifiedlog` | subsystem=com.apple.lsd |
| `saas:RepoEvents` | New file added or modified in PR targeting CI/CD or build config (e.g., `gitlab-ci.yml`, `build.gradle`, `pom.xml`, `.github/workflows/*.yml`) |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | CodeIntegrity reports 'Invalid image hash' or 'Unsigned image' for new/updated binaries |
| `WinEventLog:Microsoft-Windows-Windows Defender/Operational` | SmartScreen or ASR blocks on newly downloaded installer/updater |
| `WinEventLog:Setup` | MSI/Product install, repair or update events |
| `journald:package` | dpkg/apt install, remove, upgrade events |
| `journald:package` | yum/dnf install or update transactions |
| `linux:osquery` | hash, rpm_packages, deb_packages, file_events |
| `macos:unifiedlog` | installer or system_installd 'PackageKit: install succeeded/failed' with non-notarized or unknown signer |
| `macos:unifiedlog` | Gatekeeper/AMFI 'code signature invalid' / 'not notarized' messages |
| `networkdevice:syslog` | OS version query results inconsistent with expected or approved version list |
| `macos:unifiedlog` | File creation or modification with com.apple.ResourceFork extended attribute |

---

### Logon Session Creation
**Feeds detection for 56 techniques.**  
The successful establishment of a new user session following a successful authentication attempt. This typically signifies that a user has provided valid credentials or authentication tokens, and the system has initiated a session associated with that user account. This data is crucial for tracking authentication events and identifying potential unauthorized access. Examples: 

- Windows Systems
 - Event ID: 4624
 - Logon Type: 2 (Interactive) or 10 (Remote Interactive via RDP).
 - Account Name:  

| Log source | Channel |
|---|---|
| `Logon Session` |  |
| `macos:unifiedlog` | UserLoggedIn |
| `AWS:CloudTrail` | ConsoleLogin, AssumeRole, ListResources |
| `azure:signin` | UserLoginSuccess, TokenIssued |
| `Okta:SystemLog` | user.authentication.sso, app.oauth.grant |
| `m365:signinlogs` | SignInSuccess, RoleAssignmentRead |
| `m365:unified` | UserLoggedIn |
| `gcp:audit` | LoginAudit, DriveAudit |
| `saas:auth` | LoginSuccess, APIKeyUse, AdminAction |
| `azure:signinlogs` | Abnormal sign-in from scripting tools (PowerShell, AADInternals) |
| `azure:signinlogs` | Suspicious login to cloud mailbox system |
| `azure:signinlogs` | Failed MFA attempts, unusual conditional access triggers, login attempts from unexpected IP ranges |
| `AWS:CloudTrail` | ConsoleLogin |
| `WinEventLog:Security` | EventCode=4624, 4648 |
| `NSM:Connections` | Mismatch between recorded user logon and active sessions (e.g., wtmp/utmp entries without corresponding authentication in auth.log) |
| `macos:unifiedlog` | Authentication inconsistencies where commands are executed without corresponding login events |
| `CloudTrail:Signin` | SAML login without corresponding IdP authentication log |
| `m365:sharepoint` | File access with forged or anomalous SAML claims |
| `AWS:CloudTrail` | Web console logins using session cookies without corresponding MFA event |
| `saas:access` | Multiple concurrent logins using same cookie from different locations |
| `AWS:CloudTrail` | ConsoleLogin: If IdP backed by cloud provider, Console login from new IP/agent after correlated endpoint compromise |
| `macos:unifiedlog` | authentication |
| `AWS:CloudTrail` | SendSSHPublicKey, StartSession (SSM), EC2InstanceConnect |
| `azure:signin` | Microsoft.Compute/virtualMachines/serialConsole/connect/action |
| `gcp:audit` | cloud.ssh.publicKey.inserted, compute.instances.osLogin |
| `NSM:Connections` | Missing new login event but session activity continues |
| `macos:unifiedlog` | Session reuse without new auth event |
| `AWS:CloudTrail` | Temporary security credentials used to authenticate into management console or APIs |
| `macos:unifiedlog` | Access to Keychain items or browser credential stores |
| `m365:signinlogs` | Token usage events with device/user mismatch |
| `saas:github` | Login from unusual IP, device fingerprint, or location; access token creation from new client |
| `linux:syslog` | sshd: Accepted password/publickey |
| `macos:unifiedlog` | eventMessage CONTAINS 'screensharingd' or 'AuthorizationRefCreate' |
| `AWS:CloudTrail` | AWS ConsoleLogin, StartSession |
| `esxi:vmkernel` | vim.fault.*, DCUI login, SSH shell |
| `AWS:CloudTrail` | GetConsoleOutput |
| `saas:okta` | user.session.start |
| `m365:unified` | ViewAdminReport |
| `saas:zoom` | Zoom Admin Dashboard accessed from unfamiliar IP/device |
| `WinEventLog:Security` | Anomalous logon without MFA enforcement |
| `networkdevice:Firewall` | Login from untrusted IP, or new admin account accessing firewall console/API |
| `linux:syslog` | authentication success after file access |
| `macos:unifiedlog` | Keychain or user login post-access |
| `AWS:CloudTrail` | sudden role assumption after credential file access |
| `NSM:Connections` | Accepted publickey for user from unusual IP or without tty |
| `saas:confluence` | logon |
| `linux:syslog` | auth.log / secure.log |
| `esxi:auth` | Shell login or escalation |
| `linux:auth` | User login event followed by unexpected process tree |
| `azure:signinlogs` | InteractiveUserLogin: Discovery behavior linked to privileged logins from atypical IP ranges |
| `m365:signinlogs` | UserLogin: Discovery operations shortly after account logins from new geolocations |
| `saas:auth` | Login, TokenGranted: Discovery actions tied to anomalous login sessions or tokens |
| `NSM:Connections` | simultaneous or anomalous logon sessions across multiple systems |
| `macos:unifiedlog` | authentication plugin load or modification events |
| `azure:ad` | SignInEvents |
| `linux:syslog` | Accepted publickey/password for * from * port * ssh2 |
| `macos:unifiedlog` | loginwindow or sshd successful login events |
| `azure:signinlogs` | InteractiveUser, ServicePrincipalSignIn |
| `AWS:CloudTrail` | AssumeRole,AssumeRoleWithSAML,AssumeRoleWithWebIdentity |
| `azure:signinlogs` | InteractiveUser, NonInteractiveUser |
| `azure:signinlogs` | UserLogin, ConditionalAccessPolicyEvaluated |
| `saas:okta` | session.token.reuse |
| `auditd:SYSCALL` | capset or setns |
| `gcp:audit` | admin.googleapis.com |
| `m365:signinlogs` | UserLoggedIn |
| `WinEventLog:Security` | EventCode=4624 |
| `linux:syslog` |  |

---

### OS API Execution
**Feeds detection for 54 techniques.**  
Calls made by a process to operating system-provided Application Programming Interfaces (APIs). These calls are essential for interacting with system resources such as memory, files, and hardware, or for performing system-level tasks. Monitoring these calls can provide insight into a process's intent, especially if the process is malicious.  

| Log source | Channel |
|---|---|
| `Process` |  |
| `etw:Microsoft-Windows-Kernel-Base` | GetLocaleInfoW, GetTimeZoneInformation API calls |
| `AWS:CloudTrail` | GetMetadata, DescribeInstanceIdentity |
| `macos:osquery` | open, execve: Unexpected processes accessing or modifying critical files |
| `auditd:SYSCALL` | ptrace, ioctl |
| `etw:Microsoft-Windows-Kernel-Process` | API tracing / stack tracing via ETW or telemetry-based EDR |
| `EDR:memory` | Behavioral API telemetry (GetProcAddress, LoadLibrary, VirtualAlloc) |
| `networkdevice:syslog` | aaa privilege_exec |
| `macos:unifiedlog` |  |
| `etw:Microsoft-Windows-Kernel-Process` | APCQueueOperations |
| `macos:unifiedlog` | Invocation of SMLoginItemSetEnabled by non-system or recently installed application |
| `macos:unifiedlog` | flock|NSDistributedLock|FileHandle.*lockForWriting |
| `etw:Microsoft-Windows-Directory-Services-SAM` | api_call: Calls to DsAddSidHistory or related RPC operations |
| `macos:unifiedlog` | application logs referencing NSTimer, sleep, or launchd delays |
| `etw:Microsoft-Windows-Kernel-Process` | High-frequency or suspicious sequence of QueryPerformanceCounter/GetTickCount API calls from a non-standard process lineage |
| `auditd:SYSCALL` | Rules capturing clock_gettime, time, gettimeofday syscalls when enabled |
| `networkdevice:syslog` | Unexpected reload, crashinfo, or boot message not tied to scheduled maintenance |
| `etw:Microsoft-Windows-RPC` | rpc_call: srvsvc.NetShareEnum / NetShareEnumAll from non-admin or unusual processes |
| `NSM:Flow` | smb_command: TreeConnectAndX to \\*\IPC$ / srvsvc or Trans2/NT_CREATE for listing shares |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `EDR:memory` | API usage MFCreateDeviceSource, IAMStreamConfig, ICaptureGraphBuilder2, DirectShow filter graph creation from uncommon callers |
| `auditd:SYSCALL` | openat/read/ioctl: openat/read/ioctl on /dev/video* by uncommon user/process |
| `macos:unifiedlog` | Access decisions to kTCCServiceCamera for unexpected binaries |
| `EDR:memory` | Objective‑C/Swift calls to AVCaptureDevice/AVCaptureSession by non-whitelisted processes |
| `auditd:SYSCALL` | mmap, ptrace, process_vm_writev or direct memory ops |
| `WinEventLog:Application` | API call to AddMonitor invoked by non-installer process |
| `etw:Microsoft-Windows-Win32k` | SetWindowLong, SetClassLong, NtUserMessageCall, SendNotifyMessage, PostMessage |
| `auditd:SYSCALL` | unshare, mount, keyctl, setns syscalls executed by containerized processes |
| `macos:unifiedlog` | audio APIs |
| `WinEventLog:Microsoft-Windows-COM/Operational` | CLSID activation events where ProcessName=mmc.exe and CLSID not in allowed baseline |
| `macos:unifiedlog` | com.apple.securityd, com.apple.tccd |
| `auditd:SYSCALL` | send, recv, write: Abnormal interception or alteration of transmitted data |
| `macos:osquery` | CALCULATE: Integrity validation of transmitted data via hash checks |
| `ETW:Token` | token_analysis: API calls such as DuplicateTokenEx or ImpersonateLoggedOnUser |
| `etw:Microsoft-Windows-Kernel-Process` | API Calls |
| `etw:Microsoft-Windows-DotNETRuntime` | AssemblyLoad/ModuleLoad (Loader keyword) from Microsoft-Windows-DotNETRuntime |
| `EDR:memory` | VirtualAlloc/VirtualProtect/MapViewOfFile indicators via stack/heap activity and ImageLoad |
| `auditd:MMAP` | memory region with RWX permissions allocated |
| `snmp:trap` | management queries |
| `AWS:CloudTrail` | Describe* or List* API calls |
| `etw:Microsoft-Windows-Win32k` | SendMessage, PostMessage, LVM_* |
| `auditd:SYSCALL` | sudo or pkexec invocation |
| `macos:unifiedlog` | authorization execute privilege requests |
| `etw:Microsoft-Windows-Kernel-Process` | NtQueryInformationProcess |
| `macos:unifiedlog` | ptrace: Processes invoking ptrace with PTRACE_TRACEME flag |
| `esxi:hostd` | Remote access API calls and file uploads |
| `etw:Microsoft-Windows-Kernel-Process` | NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, SetThreadContext, ResumeThread |
| `linux:syslog` | Execution of modified binaries or abnormal library load sequences |
| `macos:unifiedlog` | Calls to AuthorizationExecuteWithPrivileges() observed via Apple System Logger or security_auditing tools |
| `macos:unifiedlog` | access or unlock attempt to keychain database |
| `macos:unifiedlog` | Execution of input detection APIs (e.g., CGEventSourceKeyState) |
| `auditd:SYSCALL` | mount system call with bind or remap flags |
| `AWS:CloudTrail` | Decrypt |
| `etw:Microsoft-Windows-Kernel-File` | ZwSetEaFile or ZwQueryEaFile function calls |
| `auditd:SYSCALL` | fork/clone/daemon syscall tracing |
| `fs:fsusage` | Detached process execution with no associated parent |
| `auditd:SYSCALL` | ptrace, mmap, mprotect, open, dlopen |
| `ETW:ProcThread` | api_call: CreateProcessWithTokenW, CreateProcessAsUserW |
| `EDR:memory` | MemoryWriteToExecutable |
| `ETW:Token` | api_call: DuplicateTokenEx, ImpersonateLoggedOnUser, SetThreadToken |
| `etw:Microsoft-Windows-Kernel-Process` | api_call: UpdateProcThreadAttribute (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) and CreateProcess* with EXTENDED_STARTUPINFO_PRESENT / StartupInfoEx |
| `etw:Microsoft-Windows-Security-Auditing` | api_call: LogonUser(A|W), LsaLogonUser, SetThreadToken, ImpersonateLoggedOnUser |
| `etw:Microsoft-Windows-Kernel-Process` | API calls |
| `auditd:SYSCALL` | ptrace, mmap, process_vm_writev |
| `auditd:SYSCALL` | execve of dd or sed targeting /proc/*/mem |
| `etw:Microsoft-Windows-Kernel-Process` | CreateTransaction, CreateFileTransacted, RollbackTransaction, NtCreateProcessEx, NtCreateThreadEx |
| `ETW` | Calls to GetUserDefaultUILanguage, GetSystemDefaultUILanguage, GetKeyboardLayoutList |
| `etw:Microsoft-Windows-Kernel-Process` | WriteProcessMemory: WriteProcessMemory targeting regions containing KernelCallbackTable addresses |
| `EDR:file` | SetFileTime |

---

### User Account Authentication
**Feeds detection for 53 techniques.**  
An attempt (successful and failed login attempts) by a user, service, or application to gain access to a network, system, or cloud-based resource. This typically involves credentials such as passwords, tokens, multi-factor authentication (MFA), or biometric validation.  

| Log source | Channel |
|---|---|
| `User Account` |  |
| `NSM:Flow` | TGS-REQ and AS-REQ seen for new user shortly after domain-modifying process |
| `WinEventLog:Security` | EventCode=4625 |
| `saas:okta` | session.impersonation.start |
| `Okta:SystemLog` | eventType: user.authentication.sso, app.oauth2.token.grant |
| `azure:signinlogs` | Success logs from high-risk accounts |
| `networkdevice:syslog` | config access, authentication logs |
| `ESXiLogs:authlog` | Unexpected login followed by encoding commands |
| `saas:okta` | Unusual OAuth app requesting message-read scopes for Slack/Teams/Jira |
| `NSM:Connections` | Accepted password or publickey for user from remote IP |
| `macos:unifiedlog` | successful sudo or authentication for account not normally associated with admin actions |
| `esxi:vpxa` | user login from unexpected IP or non-admin user role |
| `m365:signinlogs` | Sign-in from anomalous location or impossible travel condition |
| `networkdevice:syslog` | User privilege escalation to level 15/root prior to destructive commands |
| `networkdevice:syslog` | authorization/accounting logs |
| `WinEventLog:Security` | EventCode=4769, 1200, 1202 |
| `linux:syslog` | sudo/date/timedatectl execution by non-standard users |
| `saas:audit` | Repeated requests to SMS-generating endpoints using anomalous or new user agents, IP ranges, or geographies. |
| `azure:signinlogs` | Multiple MFA challenge requests without successful primary login |
| `AWS:CloudTrail` | AssumeRole or ConsoleLogin with repeated MFA failures followed by repeated MFA requests |
| `auditd:AUTH` | pam_unix or pam_google_authenticator invoked repeatedly within short interval |
| `WinEventLog:Security` | EventCode=4768, 4769, 4770 |
| `NSM:Connections` | Repeated failed authentication attempts or replay patterns |
| `azure:signinlogs` | TokenIssued, TokenRenewed: Unexpected or anomalous token issuance events |
| `azure:signinlogs` | SignIn: Sign-ins flagged as atypical (new geographic region, unfamiliar device id) shortly after correlated endpoint/browser compromise times |
| `AWS:CloudTrail` | sts:GetFederationToken |
| `m365:unified` | Delegated permission grants without user login event |
| `saas:salesforce` | API login using access_token without login history |
| `AWS:CloudTrail` | AssumeRoleWithWebIdentity |
| `azure:signinlogs` | Operation=UserLogin |
| `esxi:auth` | interactive shell or SSH access preceding storage enumeration |
| `NSM:Connections` | Successful login without expected MFA challenge |
| `macos:unifiedlog` | Login success without MFA step |
| `kubernetes:apiserver` | get/list requests to /api/v1/secrets or /api/v1/namespaces/*/serviceaccounts |
| `auditd:SYSCALL` | pam_authenticate, sshd |
| `macos:unifiedlog` | log show --predicate 'eventMessage contains "Authentication"' |
| `esxi:vpxd` | /var/log/vmware/vpxd.log |
| `azure:signinlogs` | Unusual Token Usage or Application Consent |
| `networkdevice:syslog` | Failed and successful logins to network devices outside approved admin IP ranges |
| `azure:signinlogs` | OperationName=SetDomainAuthentication OR Set-FederatedDomain |
| `network:auth` | repeated successful authentications with previously unknown accounts or anomalous password acceptance |
| `azure:signinlogs` | Sign-in with unfamiliar location/device + portal navigation |
| `m365:signinlogs` | UserLoginSuccess |
| `saas:salesforce` | Login |
| `networkdevice:syslog` | Privileged login followed by destructive format command |
| `networkdevice:syslog` | admin login events |
| `networkdevice:syslog` | Privileged login followed by destructive command sequence |
| `azure:signinlogs` | Login from newly created account |
| `auditd:SYSCALL` | execution of ssh, scp, or sftp using previously unseen credentials or keys |
| `m365:unified` | login using refresh_token with no preceding authentication context |
| `saas:googleworkspace` | API access without user login |
| `WinEventLog:Security` | EventCode=4769 |
| `WinEventLog:Security` | EventCode=4776, 4625 |
| `azure:signinlogs` | Interactive/Non-Interactive Sign-In |
| `AWS:CloudTrail` | AWS IAM: ListUsers, ListRoles |
| `gcp:workspaceaudit` | Token Generation via Domain Delegation |
| `m365:signinlogs` | Unusual sign-in from service principal to user mailbox |
| `macos:unifiedlog` | User credential prompt events without associated trusted installer package |
| `linux:auth` | sshd login |
| `saas:googleworkspace` | Accessed third-party credential management service |
| `azure:signinlogs` | Reset password or download key from portal |
| `linux:syslog` | SSH failed login |
| `macos:unifiedlog` | Login failure / authorization denied |
| `azure:signinlogs` | status = failure |
| `Okta:authn` | authentication_failure |
| `saas-app:auth` | login_failure |
| `networkdevice:syslog` | AAA, RADIUS, or TACACS authentication |
| `kubernetes:apiserver` | authentication.k8s.io/v1beta1 |
| `m365:exchange` | Logon failure |
| `AWS:CloudTrail` | eventName=ConsoleLogin | eventType=AwsConsoleSignIn |
| `auditd:USER_LOGIN` | USER_AUTH |
| `azure:signinlogs` | Sign-in logs |
| `macos:unifiedlog` | auth |
| `m365:unified` | Sign-in logs |
| `AWS:CloudTrail` | ConsoleLogin or AssumeRole |
| `esxi:auth` | /var/log/auth.log |
| `networkdevice:syslog` | authentication logs |
| `azure:signinlogs` | SigninSuccess |
| `WinEventLog:Security` | EventCode=4625, 4771, 4648 |
| `linux:syslog` | Failed password for invalid user |
| `macos:unifiedlog` | Login Window and Authd errors |
| `azure:signinlogs` | Failure Reason + UserPrincipalName |
| `saas:okta` | authentication_failure |
| `networkdevice:syslog` | AAA or TACACS authentication failures |
| `kubernetes:audit` | Failed login |
| `m365:exchange` | FailedLogin |
| `saas:auth` | signin_failed |
| `saas:googleworkspace` | login with reused session token and mismatched user agent or IP |
| `saas:googleworkspace` | Access via OAuth credentials with unusual scopes or from anomalous IPs |
| `networkdevice:syslog` | authentication & authorization |
| `azure:signinlogs` | Sign-in activity |
| `AWS:CloudTrail` | ConsoleLogin, AssumeRole, ListAccessKeys, CreateUser |
| `gcp:audit` | drive.activity |
| `gcp:audit` | login.event |
| `linux:syslog` | sshd[pid]: Failed password |
| `macos:unifiedlog` | authd |
| `networkdevice:syslog` | login failed |
| `GCPAuditLogs:login.googleapis.com` | Failed sign-in events |
| `esxi:auth` | SSH session/login |
| `NSM:Connections` | sshd or PAM logins |
| `saas:okta` | Sign-in logs / audit events |
| `gcp:audit` | Sign-in logs / audit events |
| `azure:signinlogs` | Sign-in logs / audit events |
| `kubernetes:audit` | authentication.k8s.io |
| `WinEventLog:Security` | EventCode=4648 |
| `linux:syslog` | authentication and authorization events during environmental validation phase |

---

### Logon Session Metadata
**Feeds detection for 30 techniques.**  
Contextual data about a logon session, such as username, logon type, access tokens (security context, user SIDs, logon identifiers, and logon SID), and any activity associated within it  

| Log source | Channel |
|---|---|
| `Logon Session` |  |
| `WinEventLog:Security` | EventCode=4672 |
| `macos:unifiedlog` | LoginWindow context with associated PID linked to reopened plist paths |
| `WinEventLog:Security` | EventCode=4672, 4634 |
| `azure:signinlogs` | SAML-based login with anomalous issuer or NotOnOrAfter lifetime |
| `m365:unified` | Abnormal user claims or unexpected elevated role assignment in SAML assertion |
| `macos:unifiedlog` | authd generating multiple MFA token requests |
| `linux:syslog` |  |
| `WinEventLog:Security` | EventCode=4624, 4625, 4768, 4769 |
| `linux:syslog` | sssd / sudo logs |
| `esxi:hostd` | /var/log/hostd.log |
| `WinEventLog:Security` | EventCode=4778, EventCode=4779 |
| `auditd:SYSCALL` | ssh logins or execve of remote commands |
| `macos:unifiedlog` | Remote login (ssh) or screen sharing authentication attempts |
| `kubernetes:audit` | Unauthorized container creation or kubelet exec logs |
| `auditd:USER_LOGIN` | USER_LOGIN |
| `macos:unifiedlog` | loginwindow or sshd |
| `WinEventLog:Security` | EventCode=4800, 4801 |
| `WinEventLog:Security` | EventCode=4776, 4771, 4770 |
| `auditd:SYSCALL` | execve,socket,connect,openat |
| `macos:unifiedlog` | Group membership change for admin or wheel |
| `azure:audit` | Add delegated admin / Assign admin roles / Update application consent |
| `saas:okta` | user.session.start, app.oauth2.as.authorize, policy.mfa.bypass |
| `gcp:audit` | google.iam.credentials.generateAccessToken / serviceAccountTokenCreator |
| `saas:salesforce` | ConnectedApp OAuth policy change / Login as user |
| `macos:unifiedlog` | Unusual Kerberos TGS-REQ without TGT or anomalous ticket lifetime |
| `saas:okta` | user.authentication.sso |
| `m365:unified` | FileAccessed, SharingSet |
| `m365:signinlogs` | UserLogin |
| `macos:unifiedlog` | loginwindow, sshd |
| `NSM:Connections` | Successful sudo or ssh from unknown IPs |
| `macos:unifiedlog` | loginwindow or sshd events with external IP |
| `macos:unifiedlog` | process = 'sshd' |
| `esxi:auth` |  |

---

### Process Metadata
**Feeds detection for 30 techniques.**  
Contextual data about a running process, which may include information such as environment variables, image name, user/owner, etc.  

| Log source | Channel |
|---|---|
| `Process` |  |
| `macos:unifiedlog` | subsystem=com.apple.process |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | CodeIntegrity/WDAC events indicating unsigned/invalid DLL loads |
| `linux:syslog` | sudo or service accounts invoking loaders with suspicious env vars |
| `macos:osquery` | Process Context |
| `esxi:auth` | user session |
| `networkdevice:syslog` | Admin activity |
| `auditd:SYSCALL` | execve call for sudo where euid != uid |
| `macos:unifiedlog` | subsystem=com.apple.TCC |
| `macos:unifiedlog` | exec of binary with setuid/setgid and EUID != UID |
| `macos:unifiedlog` | process |
| `auditd:SYSCALL` | Use of fork/exec with DISPLAY unset or redirected |
| `EDR:Telemetry` | Process lineage and API usage enrichment (GetSystemTime, GetTimeZoneInformation, NtQuerySystemTime) |
| `esxi:hostd` | /var/log/hostd.log API calls reading/altering time/ntp settings |
| `auditd:SYSCALL` | execve, prctl, or ptrace activity affecting process memory or command-line arguments |
| `linux:osquery` | Cross-reference argv[0] with actual executable path and parent process metadata |
| `WinEventLog:AppLocker` | AppLocker audit/blocks showing developer utilities executing scripts/binaries outside policy |
| `EDR:hunting` | Correlation of signer info, parent-child lineage, rare invocation context (user host role), and API surfaces (CreateProcess*, LoadLibrary*) |
| `WinEventLog:Microsoft-Windows-Security-Mitigations/KernelMode` | ETW telemetry indicating ClickOnce deployment (dfsvc.exe) launching payloads |
| `etw:Microsoft-Windows-ClickOnce` | provider: Event Tracing for Windows (ETW) events associated with ClickOnce deployment (dfsvc.exe activity) |
| `WinEventLog:Microsoft-Windows-Windows Camera Frame Server/Operational` | Process session start/stop events for camera pipeline by unexpected executables |
| `linux:osquery` | select: path LIKE '/dev/video%' |
| `linux:osquery` | state=attached/debugged |
| `macos:unifiedlog` | Code Execution & Entitlement Access |
| `macos:unifiedlog` | Process opening SSH_AUTH_SOCK or /tmp/ssh-* socket not owned by same UID |
| `macos:unifiedlog` | code signature/memory protection |
| `auditd:SYSCALL` | execve with UID ≠ EUID |
| `auditd:SYSCALL` | execve with escalated privileges |
| `AWS:CloudTrail` | cross-account or unexpected assume role |
| `macos:unifiedlog` | log collect from launchd and process start |
| `containerd:events` | Docker or containerd image pulls and process executions |
| `linux:syslog` | Kernel or daemon warnings of downgraded TLS or cryptographic settings |
| `macos:unifiedlog` | Modifications or writes to EFI system partition for downgraded bootloaders |
| `macos:unifiedlog` | non-shell process tree accessing bash history |
| `linux:osquery` | process metadata mismatch between /proc and runtime attributes |
| `linux:osquery` | process environment variables containing LD_PRELOAD |
| `WinEventLog:PowerShell` | EventCode=400, 403 |
| `macos:osquery` | Process Execution + Hash |
| `etw:Microsoft-Windows-Kernel-Process` | process_start: EventHeader.ProcessId true parent vs reported PPID mismatch |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_MMAP |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Unsigned/invalid signature modules or images loaded by msbuild.exe or its children |
| `WinEventLog:Microsoft-Windows-DeviceGuard/Operational` | WDAC policy audit/block affecting msbuild.exe spawned payloads |
| `WinEventLog:Microsoft-Windows-SmartAppControl/Operational` | Smart App Control decisions (audit/block) for msbuild.exe-launched executables |
| `WinEventLog:Microsoft-Windows-CodeIntegrity/Operational` | Unsigned or untrusted modules loaded during JamPlus.exe runtime |

---

### Response Content
**Feeds detection for 28 techniques.**  
Captured network traffic that provides details about responses received during an internet scan. This data includes both protocol header values (e.g., HTTP status codes, IP headers, or DNS response codes) and response body content (e.g., HTML, JSON, or raw data). Examples:

- HTTP Scan: A web server responds to a probe with an HTTP 200 status code and an HTML body indicating the default page is accessible.
- DNS Scan: A DNS server replies to a query with a resolved IP address for a domain, along  

| Log source | Channel |
|---|---|
| `Internet Scan` |  |
| `NSM:Flow` | Suspicious changes in TLS certificate responses or redirected domains |

---

### Service Creation
**Feeds detection for 28 techniques.**  
The registration of a new service or daemon on an operating system.

*Data Collection Measures:*

- Windows Event Logs
 - Event ID 4697 - Captures the creation of a new Windows service.
 - Event ID 7045 - Captures services installed by administrators or adversaries.
 - Event ID 7034 - Could indicate malicious service modification or exploitation.
- Sysmon Logs
 - Sysmon Event ID 1 - Process Creation (captures service executables).
 - Sysmon Event ID 4 - Service state changes (detects service ins  

| Log source | Channel |
|---|---|
| `Service` |  |
| `WinEventLog:System` | EventCode=7036 |
| `auditd:CONFIG_CHANGE` | creation or modification of systemd services |
| `macos:osquery` | Process Events and Launch Daemons |
| `WinEventLog:System` | EventCode=7045 |
| `linux:osquery` | newly registered unit file with ExecStart pointing to unknown binary |
| `macos:unifiedlog` | creation or loading of new launchd services |
| `WinEventLog:Security` | EventCode=4697 |
| `linux:syslog` | systemctl start/enable with uncommon binary paths |
| `WinEventLog:System` | EventCode=7031, 7034 |
| `macos:osquery` | launch_daemons |
| `macos:unifiedlog` | launchd loading new LaunchDaemon or changes to existing daemon configuration |
| `macos:osquery` | detection of new launch agents with suspicious paths or unsigned binaries |
| `kubernetes:audit` | create |
| `containerLogs:systemd_unit_files` | unit file referencing container binary with persistent flags |

---

### Script Execution
**Feeds detection for 28 techniques.**  
The execution of a text file that contains code via the interpreter.  

| Log source | Channel |
|---|---|
| `Script` |  |
| `m365:office` | VBA auto_open, auto_close, or document_open events |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "python"' |
| `linux:syslog` | /var/log/syslog |
| `WinEventLog:System` | EventCode=1502, 1503 |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "wscript" OR "vbs"' |
| `macos:unifiedlog` | osascript or AppleScript invocation modifying UI |
| `networkdevice:runtime` | runtime |
| `macos:unifiedlog` | log |
| `esxi:vmkernel` | boot |
| `macos:unifiedlog` | AppleScript creating login item via 'System Events' dictionary |
| `WinEventLog:PowerShell` | EventCode=4103, 4104, 4105, 4106 |
| `WinEventLog:Application` | Stored procedure creation, modification, or xp_cmdshell invocation via SQL logs or SQL Server auditing |
| `ApplicationLogs:SQL` | Stored procedure creation or modification with shell invocation (e.g., system(), exec()) |
| `macos:unifiedlog` | subsystem=launchservices |
| `WinEventLog:PowerShell` | Set-ADUser or Set-ADAuthenticationPolicy with MFA attributes disabled |
| `EDR:scriptblock` | Process Tree + Script Block Logging |
| `linux:syslog` | boot logs |
| `m365:defender` | ScriptBlockLogging + AMSI |
| `macos:unifiedlog` | log stream with predicate 'eventMessage CONTAINS "osascript"' |
| `etw:Microsoft-Antimalware-Scan-Interface` | Amsi/Script content + API verdicts during in-memory staging |
| `esxi:shell` |  |
| `WinEventLog:System` | EventCode=4016, 5312 |
| `auditd:PROCTITLE` | scripting loop invoking sleep/ping |
| `WinEventLog:PowerShell` | Scripts with references to XML parsing, AES decryption, or gpprefdecrypt logic |
| `macos:syslog` | system.log, asl.log |
| `macos:osquery` | exec: Unexpected execution of osascript or AppleScript targeting sensitive apps |
| `macos:unifiedlog` | subsystem=com.apple.Security or com.apple.applescript |
| `azure:activity` | Microsoft.Compute/virtualMachines/runCommand/action: Abnormal initiation of Azure RunCommand jobs or PowerShell/Bash payloads |
| `EDR:AMSI` | Malicious inline C#/script blobs embedded in MSBuild projects if intercepted by AMSI-aware loaders (rare but possible via chained LOLBins) |
| `macos:unifiedlog` | osascript, AppleScript, or Python execution triggered immediately after HID connection |
| `m365:unified` | Scripted Activity |

---

### Process Modification
**Feeds detection for 24 techniques.**  
Changes made to a running process, such as writing data into memory, modifying execution behavior, or injecting code into an existing process. Adversaries frequently modify processes to execute malicious payloads, evade detection, or gain escalated privileges.  

| Log source | Channel |
|---|---|
| `auditd:SYSCALL` | rename, chmod |
| `auditd:SYSCALL` | mprotect |
| `macos:endpointsecurity` | ES_EVENT_MMAP |
| `auditd:SYSCALL` | kill syscalls targeting auditd process |
| `macos:unifiedlog` | memory mapping |
| `WinEventLog:Sysmon` | EventCode=8 |
| `macos:osquery` | Memory Mappings |
| `ebpf:tracepoints` | Runtime memory overwrite of argv[] memory region |
| `etw:Microsoft-Windows-Kernel-Process` | Memory Modification / Unmapped module load or suspicious RWX allocations in the process space of a browser process |
| `macos:unifiedlog` | Anomalous dyld dynamic library loads or RWX memory mappings in browser process |
| `auditd:SYSCALL` | open, rename |
| `auditd:SYSCALL` | SYSCALL ptrace/mprotect |
| `macos:endpointsecurity` | ES_EVENT_TYPE_NOTIFY_MMAP |
| `macos:unifiedlog` | process, library load, memory operations |
| `auditd:SYSCALL` | rename |
| `linux:osquery` | Detection of bitwise operations or custom encryption functions in memory traces |
| `macos:unifiedlog` | Abnormal memory operations (XOR/bitwise loops) during archive generation |
| `auditd:memprotect` | change from PROT_READ|PROT_WRITE to PROT_EXEC |
| `linux:procfs` | /proc/[pid]/maps, /proc/[pid]/mem |

---

### User Account Modification
**Feeds detection for 21 techniques.**  
Changes made to an existing user, service, or machine account, including alterations to attributes, permissions, roles, authentication methods, or group memberships.  

| Log source | Channel |
|---|---|
| `azure:audit` | Operation IN ("Add device", "Add registered users to device", "Add registered owner to device") |
| `linux:syslog` | sudo or su access prior to content change |
| `WinEventLog:Security` | EventCode=4738, 4728, 4670 |
| `auditd:SYSCALL` | usermod, groupmod, passwd |
| `macos:unifiedlog` | com.apple.accountsd, com.apple.opendirectoryd |
| `saas:okta` | User Attribute Modified / Role Assignment Changed |
| `m365:unified` | Admin Activity > Role Change or Sharing Change |
| `gcp:audit` | Admin Activity > Role Change or Sharing Change |
| `m365:unified` | Set-ADUser OR Set-ADAccountControl |
| `AWS:CloudTrail` | UpdateLoginProfile |
| `WinEventLog:Security` | EventCode=4723, 4724, 4740 |
| `saas:okta` | user.lifecycle.delete, user.account.lock |
| `m365:unified` | User excluded from MFA or MFA method registered |
| `saas:zoom` | DisableMFA or RegisterNewFactor |
| `AWS:CloudTrail` | AttachUserPolicy, CreatePolicyVersion, PutRolePolicy |
| `gcp:audit` | google.iam.admin.v1.RoleAssignment |
| `m365:audit` | Add member to role, Add app role assignment |
| `Okta:SystemLog` | user.account.privilege.grant |
| `m365:unified` | Add member to role, Set-Mailbox |
| `m365:unified` | Set-MailboxAuditBypassAssociation or disabling Advanced Auditing |
| `m365:unified` | New agent registration by non-admin user |
| `WinEventLog:Security` | EventCode=4704 |
| `WinEventLog:Security` | EventCode=4728, 4729, 4732, 4733, 4756, 4757 |
| `auditd:SYSCALL` | SYSCALL for usermod or /etc/group file modification |
| `macos:unifiedlog` | Process execution or directory service changes |
| `azure:policy` | DisableMfaPolicy or change to ConditionalAccess rules |
| `azure:audit` | Add member to role |
| `AWS:CloudTrail` | AttachUserPolicy |
| `AWS:CloudTrail` | CreateAccessKey |
| `azure:signinlogs` | unusual role assumption or elevation path |
| `saas:okta` | admin role granted outside approved workflows |
| `AWS:CloudTrail` | role privilege expansion detected |
| `m365:unified` | Add-MailboxPermission, UpdateFolderPermissions |
| `gcp:audit` | Set Gmail Delegation |
| `auditd:SYSCALL` | usermod, or account rename system calls |
| `azure:audit` | Rename user |
| `m365:unified` | Set-Mailbox, Set-InboxRule, Set-MailboxFolderPermission |
| `azure:audit` | Add service principal credentials, app password added, app role assignment |
| `gcp:audit` | iam.serviceAccounts.keys.create, os-login.sshPublicKeys.add |
| `gcp:audit` | API Key Created, OAuth Client Registered |
| `kubernetes:audit` | create or update events for RoleBinding or ClusterRoleBinding objects |

---

### User Account Metadata
**Feeds detection for 20 techniques.**  
Contextual data about an account, which may include a username, user ID, environmental data, etc.  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | EventCode=4720, 4738 |
| `WinEventLog:Security` | EventCode=4673 |
| `AWS:CloudTrail` | AssumeRole |
| `auditd:SYSCALL` | open,openat,read |
| `macos:MDM` | profiles -P|getaccountpolicies |
| `AWS:CloudTrail` | GetAccountPasswordPolicy |
| `azure:audit` | operation contains 'Get*Password*Policy' OR 'List*Authentication*Policy' OR 'Get-ADDefaultDomainPasswordPolicy' |
| `m365:unified` | Workload=AzureActiveDirectory OR Exchange AND (Operation=Cmdlet AND Parameters contains 'Password' AND (CmdletName='Get-*' OR CmdletName='Get-OrganizationConfig')) |
| `saas:auth` | Refresh token issuance or refresh token usage from new IPs or user agents |
| `gcp:audit` | Directory API Access: users.list or groups.list |
| `CloudTrail:GetCallerIdentity` | GetCallerIdentity |
| `vpxd.log` | vCenter Management |
| `macos:unifiedlog` | Creation of user account with UID <500 |
| `WinEventLog:Security` | EventCode=4674 |
| `windows:osquery` | User enumeration with creation/last modified timestamps |
| `linux:osquery` | Listing of /etc/passwd and /etc/shadow metadata |
| `saas:okta` | User lifecycle events |
| `Microsoft Entra ID Audit Logs` | RoleManagement.Read.Directory or Directory.Read.All |
| `azure:activity` | Azure CLI Operation: Microsoft.Graph/users/read |
| `gcp:audit` | IAM API call: serviceAccounts.list or projects.getIamPolicy |
| `Microsoft Graph API Logs` | users.list, directoryObjects.getByIds |
| `Defender for Identity` | Suspicious Enumeration of Cloud Directory |
| `Google Admin Audit` | users.list, groups.list |
| `AWS:CloudTrail` | PassRole |
| `gcp:iam` | PrincipalEmail with serviceAccountTokenCreator impersonating new identity |
| `AWS:CloudTrail` | AssumeRole: Discovery actions tied to assumed identities outside of normal context |
| `saas:okta` | User Enumeration Events |
| `gcp:audit` | Directory API Access |

---

### Cloud Service Modification
**Feeds detection for 18 techniques.**  
Cloud service modification refers to changes made to the configuration, settings, or data of a cloud service. These modifications can include administrative changes such as enabling or disabling features, altering permissions, or deleting critical components. Monitoring these changes is critical to detect potential misconfigurations or malicious activity. Examples: 

- AWS Cloud Service Modifications: A user disables AWS CloudTrail logging (StopLogging) or deletes a CloudWatch configuration rule  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | CreateFunction |
| `m365:unified` | Creation of Power Automate flow triggered by OneDrive or Exchange event |
| `AWS:CloudTrail` | PutUserPolicy, PutGroupPolicy, PutRolePolicy, CreatePolicyVersion |
| `AWS:CloudTrail` | Condition block updated in IAM policy (e.g., aws:SourceIp, aws:RequestedRegion) |
| `azure:activity` | operationName: Write, Access Review, RoleAssignment |
| `azure:policy` | UpdatePolicy |
| `AWS:CloudTrail` | UpdateAccountPasswordPolicy |
| `AWS:CloudTrail` | PutIdentityPolicy |
| `AWS:CloudTrail` | LeaveOrganization: API calls severing accounts from AWS Organizations |
| `AWS:CloudTrail` | CreateAccount: API calls creating new accounts in AWS Organizations |
| `azure:audit` | Tenant subscription transfers or new management group creation |
| `AWS:CloudTrail` | UpdateIdentityPolicy or DisableMFA |
| `m365:unified` | SendMessage |
| `gcp:config` | UpdateSink request modifying log export destinations |
| `azure:policy` | DisableAuditLogs or ConditionalAccess logging changes |
| `AWS:CloudTrail` | UpdateFederationSettings or RegisterHybridConnector |
| `AWS:CloudTrail` | CreateTrafficMirrorSession / ModifyTrafficMirrorTarget |
| `azure:activity` | Microsoft.Network/networkWatchers/flowLogSettings/write |
| `gcp:audit` | compute.packetMirroring.insert |
| `AWS:CloudTrail` | CreateFunction / UpdateFunctionConfiguration: Function creation, role assignment, or configuration change events |
| `m365:unified` | AddFlow / UpdateFlow: New automation or workflow creation events |
| `saas:appsscript` | Create / Update: Deployment of scripts with event-driven triggers |
| `saas:slack` | Exported file or accessed admin API |
| `AWS:CloudTrail` | RequestServiceQuotaIncrease |
| `azure:activity` | MICROSOFT.AUTHORIZATION/POLICIES/WRITE |
| `gcp:audit` | projects.updateQuota or orgPolicies.updatePolicy |
| `AWS:CloudTrail` | Delete* / Stop*: DeleteAlarms, StopLogging, or DisableMonitoring API calls |
| `AWS:CloudTrail` | Use of temporary credentials issued from IMDS access |
| `saas:github` | Workflow triggered via pull_request_target from forked repo |
| `azure:audit` | Consent to application: OAuth application consent granted to service principal |
| `saas:integration` | New or modified third-party application integrations with elevated permissions |

---

### Active Directory Object Modification
**Feeds detection for 17 techniques.**  
Changes to AD objects (e.g., users, groups, OUs) are logged as Event ID 5136 (Object Modification) or 5163 (Attribute Changes). Examples:

- User Account: Modifying attributes (e.g., group membership, enabling/disabling accounts).
- Group Membership: Adding/removing members.
- OU: Changing properties/permissions (e.g., delegation).
- Service Account: Modifying SPNs or other attributes.
- Object Attributes: Changes to passwords, logon hours, or control flags.  

| Log source | Channel |
|---|---|
| `azure:activity` | Update conditionalAccessPolicy |
| `esxi:vpxa` | vim.SessionManager.login / vim.AccountManager.createUser |
| `WinEventLog:Security` | EventCode=5163 |
| `WinEventLog:Security` | EventCode=4739 |
| `azure:signinlogs` | Add certificate credential, Update certificate credential |
| `m365:dirsync` | Replication cookie changes involving Configuration partition with new server/nTDSDSA objects. |
| `WinEventLog:Security` | EventCode=5136 |
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `esxi:vpxd` | permission change operations on datastores or VMs |
| `m365:unified` | Set-Mailbox, Set-AppPassword, Add-MailboxPermission |
| `m365:unified` | Add app role assignment grant to user: Consent to application by privileged or unexpected accounts |

---

### Scheduled Job Creation
**Feeds detection for 15 techniques.**  
The establishment of a task or job that will execute at a predefined time or based on specific triggers.  

| Log source | Channel |
|---|---|
| `Scheduled Job` |  |
| `WinEventLog:Security` | EventCode=4698 |
| `linux:syslog` | Execution of non-standard script or binary by cron |
| `WinEventLog:TaskScheduler` | EventCode=106 |
| `linux:osquery` | crontab, systemd_timers |
| `macos:osquery` | launchd_jobs |
| `esxi:vmkernel` | Startup script and task execution logs |
| `kubernetes:apiserver` | verb=create, resource=cronjobs, group=batch |
| `linux:osquery` | file_events |
| `macos:unifiedlog` | process: crontab edits, launch of cron job |
| `macos:osquery` | file_events - cron, launchd |
| `esxi:cron` | execution of scheduled job |
| `esxi:hostd` | task creation events |
| `macos:cron` | cron/launchd |
| `WinEventLog:Security` | EventCode=4699 |
| `linux:cron` | Scheduled execution of unknown or unusual script/binary |

---

### Driver Load
**Feeds detection for 14 techniques.**  
The process of attaching a driver, which is a software component that allows the operating system and applications to interact with hardware devices, to either user-mode or kernel-mode of a system. This can include benign actions (e.g., hardware drivers) or malicious behavior (e.g., rootkits or unsigned drivers). Examples: 

- Legitimate Driver Loading: A new graphics driver from a vendor like NVIDIA or AMD is loaded into the system.
- Unsigned Driver Loading: A driver without a valid digital si  

| Log source | Channel |
|---|---|
| `WinEventLog:Sysmon` | EventCode=6 |
| `linux:syslog` | dmesg or syslog for module loads |
| `linux:syslog` | Driver load events or firmware load failures for hardware devices |

---

### Host Status
**Feeds detection for 14 techniques.**  
Logging, messaging, and other artifacts that highlight the health and operational state of host-based security sensors, such as Endpoint Detection and Response (EDR) agents, antivirus software, logging services, and system monitoring tools. Monitoring sensor health is essential for detecting misconfigurations, sensor failures, tampering, or deliberate security control evasion by adversaries.

*Data Collection Measures:*

- Windows Event Logs:
 - Event ID 1074 (System Shutdown): Detects unexpecte  

| Log source | Channel |
|---|---|
| `Sensor Health` |  |
| `macos:osquery` | interface_details  |
| `Windows:perfmon` | Sustained CPU/memory exhaustion by service process (e.g., w3wp.exe) |
| `macos:unifiedlog` | Web service process (e.g., httpd) entering crash loop or consuming excessive CPU |
| `AWS:CloudWatch` | Sustained spike in CPU usage on EC2 instance with web service role |
| `WinEventLog:System` | System shutdowns due to bugcheck (Event ID 1001) or watchdog timer expirations |
| `linux:syslog` | Out of memory killer invoked or kernel panic entries |
| `macos:unifiedlog` | Spike in CPU or memory use from non-user-initiated processes |
| `AWS:CloudWatch` | StatusCheckFailed or StatusCheckFailed_System for burstable instances (t2/t3) |
| `kubernetes:events` | CrashLoopBackOff, OOMKilled, container restart count exceeds threshold |
| `WinEventLog:Sysmon` | EventCode=16 |
| `Windows:perfmon` | High sustained CPU usage by a single process |
| `linux:procfs` | Sustained high /proc/[pid]/stat usage |
| `AWS:CloudWatch` | Sustained EC2 CPU usage above normal baseline |
| `prometheus:metrics` | Container CPU/Memory usage exceeding threshold |
| `linux:syslog` | Service stop or disable messages for security tools not reflected in SIEM alerts |
| `macos:unifiedlog` | Termination or disabling of XProtect, Gatekeeper, or third-party AV daemons |
| `AWS:CloudWatch` | NetworkOut spike beyond baseline |
| `WinEventLog:Microsoft-Windows-TCPIP` | Connection queue overflow or failure to allocate TCP state object |
| `NSM:Flow` | TCP: possible SYN flood or backlog limit exceeded |
| `macos:unifiedlog` | network stack resource exhaustion, tcp_accept queue overflow, repeated resets |
| `WinEventLog:Security` | EventCode=1166, 7045 |
| `auditd:SYSCALL` | firmware_update, kexec_load |
| `journald:boot` | Secure Boot failure, firmware version change |
| `macos:unifiedlog` | EFI firmware integrity check failed |
| `macos:syslog` | Hardware UUID or device list drift |
| `Windows:perfmon` | Sudden spike in outbound throughput without corresponding inbound traffic |
| `sar:network` | Outbound network saturation with minimal process activity |
| `AWS:CloudWatch` | Sudden spike in network output without a corresponding inbound request ratio |
| `Windows:perfmon` | Sudden spikes in CPU/Memory usage linked to specific application processes |
| `AWS:CloudMetrics` | Autoscaling, memory/cpu alarms, or instance unhealthiness |
| `macos:unifiedlog` | System Integrity Protection (SIP) state reported as disabled |
| `AWS:CloudWatch` | Unusual CPU burst or metric anomalies |
| `WinEventLog:Security` | EventCode=1074 |
| `WinEventLog:Security` | EventCode=6006 |
| `linux:syslog` | system is powering down |
| `macos:unifiedlog` | System shutdown or reboot requested |
| `esxi:hostd` | Powering off or restarting host |
| `networkdevice:syslog` | System reboot scheduled or performed |

---

### Service Metadata
**Feeds detection for 13 techniques.**  
Contextual data about a service/daemon, which may include information such as name, service executable, start type, etc.  

| Log source | Channel |
|---|---|
| `Service` |  |
| `WinEventLog:Sysmon` | EventCode=4 |
| `linux:syslog` | service stopped messages |
| `macos:unifiedlog` | launchctl disable or bootout calls |
| `esxi:hostd` | Stop VM or disable service events via vim-cmd |
| `linux:syslog` | auditd service stopped or disabled |
| `macos:osquery` | launchd |
| `linux:osquery` | scheduled/real-time |
| `macos:unifiedlog` | subsystem=com.apple.launchservices |
| `esxi:hostd` | registers services with legitimate-sounding names |
| `WinEventLog:System` | EventCode=7035 |
| `linux:syslog` | Service restart with modified executable path |
| `macos:unifiedlog` | Observed loading of new LaunchAgent or LaunchDaemon plist |
| `kubernetes:audit` | seccomp or AppArmor profile changes |
| `WinEventLog:System` | Service stopped or RecoveryDisabled set via REAgentC |
| `esxi:hostd` | Service events |
| `WinEventLog:WinRM` | EventCode=6 |
| `auditd:CONFIG_CHANGE` | delete: Modification of systemd unit files or config for security agents |
| `macos:unifiedlog` | Modification of system configuration profiles affecting security tools |
| `kubernetes:audit` | kubectl delete or patch of security pods/admission controllers |
| `networkdevice:config` | write: Startup configuration changes disabling security checks |

---

### Firewall Rule Modification
**Feeds detection for 12 techniques.**  
The creation, deletion, or alteration of firewall rules to allow or block specific network traffic. Monitoring changes to these rules is critical for detecting misconfigurations, unauthorized access, or malicious attempts to bypass network protections. Examples: 

- Rule Creation: Adding a new rule to allow inbound traffic on port 3389 (RDP).
- Rule Deletion: Deleting a rule that blocks inbound traffic from untrusted IP ranges.
- Rule Modification: Changing a rule to allow traffic from "any" sou  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | Firewall Rule Modification |
| `Firewall Audit Logs` | Config Change |
| `esxi:hostd` | vSphere API calls modifying firewall settings |
| `networkdevice:cli` | firewall disable commands or suspicious ACL modifications |
| `AWS:CloudTrail` | AuthorizeSecurityGroupIngress |
| `WinEventLog:Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | new rule allowing inbound or outbound connections for remote desktop software |
| `networkdevice:Firewall` | update_rule: Access control or NAT rule modified or disabled outside maintenance window |
| `linux:syslog` | iptables or nftables rule changes |
| `Firewall Audit Logs` | Outbound NAT Rule Changes |
| `AWS:CloudTrail` | Create egress rule allowing UDP to port 53, 123, 11211 |
| `AWS:CloudTrail` | Ingress rule creation or modification for security group |
| `AWS:CloudTrail` | New security group created with permissive rules |
| `NSM:Firewall` | Policy Change / Rule Update |
| `NSM:Firewall` | rule_modification: New or modified firewall rules related to wireless interfaces |

---

### File Deletion
**Feeds detection for 12 techniques.**  
Refers to events where files are removed from a system or storage device. These events can indicate legitimate housekeeping activities or malicious actions such as attackers attempting to cover their tracks. Monitoring file deletions helps organizations identify unauthorized or suspicious activities.  

| Log source | Channel |
|---|---|
| `File` |  |
| `auditd:SYSCALL` | unlink/unlinkat on service binaries or data targets |
| `auditd:SYSCALL` | file deletion |
| `macos:osquery` | file_events |
| `esxi:shell` | shell history |
| `WinEventLog:Sysmon` | EventCode=23 |
| `auditd:SYSCALL` | PATH |
| `esxi:shell` | /var/log/shell.log |
| `esxi:hostd` | delete action |
| `auditd:SYSCALL` | unlink, unlinkat, openat, write |
| `macos:unifiedlog` | exec rm -rf|dd if=/dev|srm|file unlink |
| `auditd:SYSCALL` | unlink, unlinkat, rmdir |
| `auditd:SYSCALL` | unlink, rename, open |
| `linux:Sysmon` | EventCode=23 |
| `fs:fsusage` | unlink, fs_delete |
| `docker:daemon` | container file operations |
| `esxi:hostd` | rm, clearlogs, logrotate |
| `esxi:hostd` | Datastore file operations |
| `macos:osquery` | CREATE, DELETE, WRITE: Stored data manipulation attempts by unauthorized processes |
| `auditd:SYSCALL` | unlink/unlinkat |
| `WinEventLog:Microsoft-Windows-Backup` | Windows Backup Catalog deletion or catalog corruption |
| `auditd:CONFIG_CHANGE` | /etc/fstab, /etc/systemd/* |

---

### Cloud Storage Access
**Feeds detection for 11 techniques.**  
Cloud storage access refers to the retrieval or interaction with data stored in cloud infrastructure. This data component includes activities such as reading, downloading, or accessing files and objects within cloud storage systems. Common examples include API calls like GetObject in AWS S3, which retrieves objects from cloud buckets. Examples: 

- AWS S3 Access: An adversary uses the `GetObject` API to retrieve sensitive data from an AWS S3 bucket.
- Azure Blob Storage Access: A user accesses a  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | GetObject, CopyObject |
| `AWS:CloudTrail` | PutObject: S3 writes with .sql/.csv extension by same identity or within 5 min of DB access |
| `m365:unified` | Accessed SharePoint files or pages |
| `m365:unified` | FileAccessed, FileDownloaded, ConsentGranted |
| `gcp:workspaceaudit` | download, authorization_grant |
| `m365:sharepoint` | AnonymousLinkCreated, FileDownloaded |
| `m365:unified` | App-only or delegated access patterns where client_id != known enterprise apps |
| `saas:github` | Artifact generated includes base64/encoded exfil payload or URL |

---

### Windows Registry Key Creation
**Feeds detection for 11 techniques.**  
Initial construction of a new registry key within the Windows operating system.  

| Log source | Channel |
|---|---|
| `WinEventLog:Sysmon` | EventCode=12 |

---

### Instance Start
**Feeds detection for 11 techniques.**  
The initiation or activation of a virtual machine instance within a cloud infrastructure. This action typically involves starting an existing instance that had been stopped or paused, allowing it to resume operation. Examples: 

- Google Cloud Platform (GCP): Starting an instance through `instance.start` API activity.
- AWS: Logging of `StartInstances` in AWS CloudTrail for EC2 instances.
- Azure: `Microsoft.Compute/virtualMachines/start` entries indicate a VM instance being started.  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | StartInstances |
| `AWS:CloudTrail` | RunInstances |

---

### Firmware Modification
**Feeds detection for 10 techniques.**  
Changes made to firmware, which may include its settings, configurations, or underlying data. This can encompass alterations to the Master Boot Record (MBR), Volume Boot Record (VBR), or other firmware components critical to system boot and functionality. Such modifications are often indicators of adversary activity, including malware persistence and system compromise. Examples: 

- Changes to Master Boot Record (MBR): Modifying the MBR to load malicious code during the boot process.
- Changes t  

| Log source | Channel |
|---|---|
| `Firmware` |  |
| `networkdevice:syslog` | Image Upgrade / Configuration Change |
| `networkdevice:config` | Boot image path or firmware configuration variable modified outside of maintenance windows |
| `WinEventLog:Microsoft-Windows-Kernel-Boot` | Firmware integrity validation failed or boot configuration tampered |
| `auditd:SYSCALL` | write access to /dev/mem or /sys/firmware/efi/efivars |
| `macos:unifiedlog` | boot failure events or SMC validation errors |
| `networkdevice:firmware` | Firmware update initiated or bootloader tampering detected |
| `networkdevice:config` | Log entries indicating ROMMON image upgrade commands (boot system, upgrade rom-monitor) |
| `networkdevice:config` | Boot variable modified to point to non-standard or unsigned image |
| `firmware:integrity ` | Firmware integrity verification failures or mismatches against expected UEFI/firmware image baselines |
| `auditd:SYSCALL` | ioctl/write: Direct firmware update or device memory manipulation syscalls |
| `firmware:smart` | Unexpected firmware-level errors or abnormal S.M.A.R.T. log entries |
| `macos:unifiedlog` | Firmware update events or kernel extension (kext) loads not signed by Apple |
| `firmware:integrity` | Baseline mismatch or unexpected EFI module detected during integrity checks |
| `macos:osquery` | Unexpected changes in EFI or NVRAM variables controlling hardware boot state |
| `networkdevice:syslog` | Custom firmware or routing changes |
| `etw:Microsoft-Windows-Kernel-Storage` | Raw disk I/O operations bypassing NTFS APIs |
| `firmware:runtime` | Debug or memory access commands indicating attempts to alter OS instructions in memory |
| `networkdevice:syslog` | Boot information log showing image loaded from TFTP server instead of local storage |

---

### Active Directory Credential Request
**Feeds detection for 9 techniques.**  
Requests for authentication credentials via Kerberos or other methods like NTLM and LDAP queries. Examples:

- Kerberos TGT and Service Tickets (Event IDs 4768, 4769)
- NTLM Authentication Events
- LDAP Bind Requests.  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | EventCode=4768 |
| `WinEventLog:Security` | EventCode=4769 |
| `WinEventLog:Kerberos` | Kerberos TGS-REQ anomalies without KDC validation (Silver Ticket behavior) |
| `WinEventLog:Security` | EventCode=4929 |
| `linux:syslog` | Unusual kinit or klist activity |

---

### Process Termination
**Feeds detection for 9 techniques.**  
The exit or termination of a running process on a system. This can occur due to normal operations, user-initiated commands, or malicious actions such as process termination by malware to disable security controls.  

| Log source | Channel |
|---|---|
| `Process` |  |
| `WinEventLog:Sysmon` | EventCode=5 |
| `linux:syslog` | Unexpected termination of daemons or critical services not aligned with admin change tickets |
| `macos:osquery` | process_termination: Unexpected termination of processes tied to vulnerable or high-value services |
| `esxi:hostd` | Log entries indicating VM powered off or forcibly terminated |
| `macos:unifiedlog` | Terminal process killed (killall Terminal) immediately after sudoers modification |
| `auditd:SYSCALL` | exit_group |
| `macos:unifiedlog` | process.*exit.*code |
| `linux:osquery` | unexpected termination of syslog or rsyslog processes |
| `auditd:SYSCALL` | Process segfault or abnormal termination after invoking vulnerable syscall sequence |
| `auditd:SYSCALL` | kill syscalls targeting logging/security processes |
| `macos:unifiedlog` | Termination of syspolicyd or XProtect processes |
| `docker:runtime` | Termination of monitoring sidecar or security container |

---

### Cloud Service Metadata
**Feeds detection for 9 techniques.**  
Cloud service metadata refers to the contextual and descriptive information about cloud services, including their name, type, purpose, configuration, and activity around them. This metadata is essential for understanding the roles and functions of cloud services, their operational status, and their potential misuse. Examples: 

- Azure Service Metadata: Metadata describing a resource in Azure, such as an Azure Storage Account or a Virtual Machine.
- AWS Cloud Service Metadata: Metadata for an AW  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | GetInstanceIdentityDocument |
| `AWS:CloudTrail` | rds:ExecuteStatement: Large data access via RDS or Aurora with unknown session context |
| `saas:github` | repo.download, repo.clone, oauth.authorize, repo.getContent |
| `AWS:CloudWatch` | unexpected IAM user or role assuming privileges for instance/snapshot operations |
| `AWS:CloudTrail` | GetSecretValue |
| `AWS:CloudTrail` | InvokeFunction |
| `m365:sharepoint` | Multiple file download operations on a site by a privileged account in a short time window |
| `saas:github` | CI/CD secret accessed or exported |
| `m365:exchange` | Cmdlet - New-InboxRule |
| `m365:unified` | New-InboxRule, Set-InboxRule |

---

### Network Share Access
**Feeds detection for 9 techniques.**  
Opening a network share, which makes the contents available to the requestor (ex: Windows EID 5140 or 5145)  

| Log source | Channel |
|---|---|
| `Network Share` |  |
| `WinEventLog:Microsoft-Windows-SMBClient/Security` | EventCode=31001 |
| `WinEventLog:Security` | EventCode=5140 |
| `WinEventLog:Security` | EventCode=5145 |
| `WinEventLog:Microsoft-Windows-SMBServer` | Access to SYSVOL share from non-admin user or unusual endpoints |
| `NSM:Flow` | smb_files.log |
| `m365:unified` | FileUploaded, FileAccessed |

---

### Drive Creation
**Feeds detection for 8 techniques.**  
The activity of assigning a new drive letter or creating a mount point for a data storage device, such as a USB, network share, or external hard drive, enabling access to its content on a host system. Examples: 

- USB Drive Insertion: A USB drive is plugged in and automatically assigned the letter `E:\` on a Windows machine.
- Network Drive Mapping: A network share `\\server\share` is mapped to the drive `Z:\`.
- Virtual Drive Creation: A virtual disk is mounted on `/mnt/virtualdrive` using an   

| Log source | Channel |
|---|---|
| `Drive` |  |
| `WinEventLog:System` | Kernel-PnP 410/400 device install, disk added |
| `auditd:SYSCALL` | mknod,open,openat |
| `macos:unifiedlog` | mounted|appeared|DA: disk* attached |
| `WinEventLog:System` | EventCode=1006 |
| `auditd:SYSCALL` | Removable media mount notification |
| `macos:unifiedlog` | com.apple.diskarbitration |
| `WinEventLog:System` | EventCode=1006, 10001 |
| `auditd:SYSCALL` | device event logs |
| `linux:osquery` | mount_events |
| `macos:unifiedlog` | Volume Mount + File Read |
| `WinEventLog:System` | EventCode=2003 |
| `auditd:SYSCALL` | udev events or drive enumeration involving TinyPilot paths or device classes |
| `linux:syslog` | Device attach logs containing TinyPilot/PiKVM identifiers |
| `macos:unifiedlog` | Hardware enumeration events via IOKit or USBMuxd showing TinyPilot or unknown keyboard/mouse |
| `auditd:SYSCALL` | Kernel Device Events - USB Block Devices |
| `maos:osquery` | mount_events |
| `macos:unifiedlog` | Volume Mount + Process Trace + File Read |
| `journald:systemd` | udisks2 or udevd logs |
| `macos:unifiedlog` | log stream --predicate 'eventMessage contains "USBMSC"' |
| `linux:syslog` | New HID device enumeration with type 'keyboard' followed by immediate input injection |
| `macos:unifiedlog` | New IOUSB keyboard/HID device enumerated with suspicious attributes |

---

### Drive Access
**Feeds detection for 8 techniques.**  
Refers to the act of accessing a data storage device, such as a hard drive, SSD, USB, or network-mounted drive. This data component logs the opening or mounting of drives, capturing activities such as reading, writing, or executing files within an assigned drive letter (e.g., `C:\`, `/mnt/drive`) or mount point. Examples: 

- Removable Drive Insertion: A USB drive is inserted, assigned the letter `F:\`, and files are accessed.
- Network Drive Mounting: A network share `\\server\share` is mapped   

| Log source | Channel |
|---|---|
| `WinEventLog:Sysmon` | EventCode=9 |
| `auditd:SYSCALL` | open/write syscalls on /dev/sd* or /dev/nvme* |
| `auditd:SYSCALL` | write syscalls to /dev/sd* targeting offset 0 |
| `auditd:SYSCALL` | open/write syscalls to block devices (/dev/sd*, /dev/nvme*) |
| `linux:syslog` | mount/umount or file copy logs |
| `fs:fsusage` | open/read/mount operations |
| `linux:osquery` | hardware_events |
| `macos:osquery` | usb_devices |

---

### Container Creation
**Feeds detection for 8 techniques.**  
"Container Creation" data component captures details about the initial construction of a container in a containerized environment. This includes events where a new container is instantiated, such as through Docker, Kubernetes, or other container orchestration platforms. Monitoring these events helps detect unauthorized or potentially malicious container creation. Examples:

- Docker Example: `docker create my-container`, `docker run --name=my-container nginx:latest`
- Kubernetes Example: `kubect  

| Log source | Channel |
|---|---|
| `kubernetes:apiserver` | create/exec: Kubernetes API calls to exec into containers or create pods from curl, kubectl, or SDK clients |
| `kubernetes:events` | container start/stop activity via Docker, containerd, or CRI-O |
| `docker:daemon` | container create/start with privileged flag or host volume mount |
| `kubernetes:audit` | create: Pod/Container created with image tag 'latest' or mutable tag; imagePullPolicy=Always; noDigest=true |
| `systemd:unit` | container run with restart policy set to 'always' or 'unless-stopped' |
| `docker:events` | created,started: new container from untrusted registry or unexpected entrypoint |
| `containerd:events` | create |
| `docker:events` | docker run with restart=always or modifying init |

---

### WMI Creation
**Feeds detection for 7 techniques.**  
Initial construction of a WMI object, such as a filter, consumer, subscription, binding, or providers.  

| Log source | Channel |
|---|---|
| `WinEventLog:WMI` | Creation or modification of __EventFilter, __FilterToConsumerBinding, or CommandLineEventConsumer |
| `WinEventLog:WMI` | EventCode=5857, 5858, 5860, 5861 |
| `WinEventLog:Application` | WMI Object Creation Events |

---

### Response Metadata
**Feeds detection for 7 techniques.**  
Contextual information about an Internet-facing resource collected during a scan, including details such as open ports, running services, protocols, and versions. This metadata is typically derived from interpreting scan results and helps build a profile of the targeted system. Examples: 

- Port and Service Details:
 - Open ports (e.g., 22, 80, 443).
 - Identified services running on those ports (e.g., SSH, HTTP, HTTPS).
- Service Versions: Detected software version information (e.g., Apache 2.  

| Log source | Channel |
|---|---|
| `Internet Scan` |  |
| `NSM:Flow` | Altered response metadata or blocked content based on user-agent or geolocation |

---

### Malware Metadata
**Feeds detection for 7 techniques.**  
Contextual data about a malicious payload, such as compilation times, file hashes, as well as watermarks or other identifiable configuration information  

| Log source | Channel |
|---|---|
| `Malware Repository` |  |

---

### Drive Modification
**Feeds detection for 6 techniques.**  
The alteration of a drive letter, mount point, or other attributes of a data storage device, which could involve reassignment, renaming, permissions changes, or other modifications. Examples: 

- Drive Letter Reassignment: A USB drive previously assigned `E:\` is reassigned to `D:\` on a Windows machine.
- Mount Point Change: On a Linux system, a mounted storage device at `/mnt/external` is moved to `/mnt/storage`.
- Drive Permission Changes: A shared drive's permissions are modified to allow wr  

| Log source | Channel |
|---|---|
| `Drive` |  |
| `networkdevice:runtime` | Firmware image uploaded via TFTP/FTP/SCP |
| `WinEventLog:Sysmon` | Raw disk write access via \\.\PhysicalDrive* or \\.\C: |
| `macos:unifiedlog` | IOKit disk write calls targeting raw devices |
| `linux:syslog` | Block device write errors or unusual bootloader activity |
| `networkdevice:firmware` | Unexpected firmware image upload events via TFTP/FTP/SCP |
| `WinEventLog:Sysmon` | Raw write attempts targeting \\.\PhysicalDrive0 or sector 0 (MBR/partition table) |
| `macos:unifiedlog` | IOKit raw disk write to EFI/boot partition sectors |
| `WinEventLog:Sysmon` | Raw disk writes targeting \\.\PhysicalDrive* or MBR locations |
| `macos:unifiedlog` | IOKit raw disk write activity targeting physical devices |

---

### Active Directory Object Access
**Feeds detection for 6 techniques.**  
Object access refers to activities where AD objects (e.g., user accounts, groups, policies) are accessed or queried. Example: Windows Event ID 4661 logs object access attempts. Examples:

- Attribute Access: e.g., `userPassword`, `memberOf`, `securityDescriptor`.
- Group Enumeration: Enumerating critical group members (e.g., Domain Admins).
- User Attributes: Commonly accessed attributes like `samAccountName`, `lastLogonTimestamp`.
- Policy Access: Accessing GPOs to understand security settings.  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | EventCode=4662 |
| `WinEventLog:Security` | EventCode=4661 |

---

### Cloud Service Enumeration
**Feeds detection for 6 techniques.**  
Cloud service enumeration involves listing or querying available cloud services in a cloud control plane. This activity is often performed to identify resources such as virtual machines, storage buckets, compute clusters, or other services within a cloud environment. Examples include API calls like `AWS ECS ListServices`, `Azure ListAllResources`, or `Google Cloud ListInstances`. Examples: 

AWS Cloud Service Enumeration: The adversary gathers details about existing ECS services to identify oppo  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | GetSecretValue |
| `gcp:secrets` | accessSecretVersion |
| `azure:ad` | SecretGet |
| `AWS:CloudTrail` | ssm:ListInventoryEntries |
| `AWS:CloudTrail` | DescribeInstances, DescribeServices, ListFunctions: High frequency enumeration calls or unusual user agents performing discovery |
| `azure:audit` | ListApplications, ListServicePrincipals: Large-scale queries against identity or application objects |
| `m365:unified` | Get-MsolServicePrincipal, ListAppRoles: Service discovery operations executed by accounts not normally performing administrative tasks |
| `saas:adminapi` | ListIntegrations, ListServices: Repeated service discovery requests from accounts without administrative responsibilities |
| `AWS:CloudTrail` | GetInstanceIdentityDocument or IMDSv2 token requests |
| `AWS:CloudTrail` | DescribeUsers / ListUsers / GetUser |
| `azure:signinlogs` | Graph API Query |

---

### User Account Creation
**Feeds detection for 6 techniques.**  
The initial establishment of a new user, service, or machine account within an operating system, cloud environment, or identity management system.  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | EventCode=4720 |
| `azure:audit` | Add user |
| `AWS:CloudTrail` | CreateUser |
| `saas:zoom` | New user created |
| `saas:slack` | admin.user.create |
| `m365:unified` | Add user |
| `auditd:SYSCALL` | adduser |
| `docker:daemon` | ExecCreate + usermod or useradd |
| `auditd:SYSCALL` | useradd or adduser executed |
| `networkdevice:syslog` | username <user> privilege <level> |
| `saas:okta` | user.lifecycle.create |

---

### Windows Registry Key Access
**Feeds detection for 6 techniques.**  
The action of opening a specific Windows Registry key, typically to read its associated value. This activity can be used for system configuration, application settings retrieval, and security policies.  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | EventCode=4663, 4670, 4656 |
| `WinEventLog:Security` | EventCode=4657 |
| `EDR:hunting` | Behavioral rule for registry enumeration under credential-related paths |
| `Autoruns:RegistryScan` | Enumerate Winlogon subkeys for unknown or unsigned binaries |

---

### Web Credential Usage
**Feeds detection for 6 techniques.**  
An attempt by a user to gain access to a network or computing resource by providing web credentials (ex: Windows EID 1202)  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | SessionToken used without preceding MFA or login event |
| `m365:unified` | SessionId reused from different device/browser fingerprint |
| `AWS:CloudTrail` | AssumeRoleWithSAML |
| `saas:access` | SAML token accepted without preceding login challenge |
| `m365:exchange` | Mailbox access using SAML token without corresponding MFA event |
| `AWS:CloudTrail` | GetSessionToken, AssumeRoleWithWebIdentity |
| `macos:unifiedlog` | New session initiated using cookies without normal MFA or password validation |
| `m365:unified` | Session activity without correlated login event |
| `AWS:CloudTrail` | AssumeRole, GetFederationToken, GetSessionToken |
| `azure:signinlogs` | TokenIssued, RefreshTokenUsed |
| `saas:googleworkspace` | OAuthTokenGranted, APIRequest |
| `m365:unified` | OAuthTokenIssued, FileAccessed, MailItemsAccessed |
| `kubernetes:apiserver` | serviceAccount token used in API requests not tied to workload identity |
| `NSM:Connections` | Pre-authentication keys generated or token signing anomalies |
| `macos:unifiedlog` | Web sessions initiated with newly forged tokens |
| `saas:auth` | API requests made with tokens not associated with expected user logins |
| `azure:signinlogs` | TokenIssuanceStart, TokenIssuanceSuccess |
| `saas:googleworkspace` | access_token issued |
| `m365:unified` | TokenIssued, FileAccessed |
| `AWS:CloudTrail` | GetCallerIdentity |

---

### Active DNS
**Feeds detection for 5 techniques.**  
"Domain Name: Active DNS" data component captures queried DNS registry data that highlights current domain-to-IP address resolutions. This data includes both direct queries to DNS servers and records that provide mappings between domain names and associated IP addresses. It serves as a critical resource for tracking active infrastructure and understanding the network footprint of an organization or adversary. Examples: 

- DNS Query Example: `nslookup example.com`, `dig example.com A`
- PTR Reco  

| Log source | Channel |
|---|---|
| `Domain Name` |  |

---

### Passive DNS
**Feeds detection for 5 techniques.**  
"Domain Name: Passive DNS" captures logged historical and real-time domain name system (DNS) data. This includes records of domain-to-IP address resolutions over time, enabling analysts to track the evolution of domain infrastructure, uncover historical patterns of use, and detect malicious activities tied to domains and their associated IP addresses. Examples: 

- Historical Resolutions
- Shared IP Usage
- Temporal Patterns
- Malicious Domain Clustering
- Historical Lookback

This data componen  

| Log source | Channel |
|---|---|
| `Domain Name` |  |

---

### Domain Registration
**Feeds detection for 5 techniques.**  
"Domain Name: Domain Registration" data component captures information about the assignment, ownership, and metadata of domain names. This information is often sourced from registries like WHOIS and includes details such as registrant names, contact information, registration dates, expiration dates, and registrar details. This data is invaluable for tracking domain ownership, detecting malicious domain registrations, and identifying trends in adversary behavior. Examples: 

- Registrant Informat  

| Log source | Channel |
|---|---|
| `Domain Name` |  |
| `dns:query` | Excessive lookups for domains with suspicious WHOIS or short TTL values |
| `esxi:vmkernel` | DNS lookups resolving to domains with rapid changes in registration metadata |

---

### Instance Stop
**Feeds detection for 4 techniques.**  
The deactivation or shutdown of a virtual machine instance within a cloud infrastructure. This action typically involves stopping a running instance, which halts its operation and releases certain associated resources, such as CPU and memory. Examples: 

- Google Cloud Platform (GCP): `instance.stop` events recorded in GCP Audit Logs indicate the deactivation of an instance.
- Amazon Web Services (AWS): `StopInstances` actions in AWS CloudTrail indicate EC2 instances being stopped.
- Microsoft A  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | TerminateInstances |
| `AWS:CloudTrail` | StopInstances |

---

### Malware Content
**Feeds detection for 4 techniques.**  
Code, strings, signatures, and other identifying characteristics of a malicious payload stored within a malware repository. It includes both static (file-based) and dynamic (behavioral or execution-based) components that can be analyzed for threat intelligence, detection, and prevention purposes. Examples:

- Static Analysis:
 - Executable Code: Analyze binary data to identify unique patterns, obfuscated code, or embedded resources.
 - Strings Extraction: Use tools like strings or YARA rules to   

| Log source | Channel |
|---|---|
| `Malware Repository` |  |

---

### Snapshot Creation
**Feeds detection for 4 techniques.**  
The process of taking a point-in-time copy of a cloud storage volume (files, settings, configurations, etc.), virtual machine (VM), or database that can be created and deployed in cloud environments.  

| Log source | Channel |
|---|---|
| `esxi:vmkernel` | snapshot create/write events |
| `AWS:CloudTrail` | CreateSnapshot |
| `azure:activity` | MICROSOFT.COMPUTE/SNAPSHOTS/WRITE |

---

### Container Start
**Feeds detection for 4 techniques.**  
"Container Start" data component captures events related to the activation or invocation of a container within a containerized environment. This includes starting a previously stopped container, restarting an existing container, or initializing a container for runtime. Monitoring these activities is critical for identifying unauthorized or unexpected container activations, which may indicate potential adversarial activity or misconfigurations. Examples: 

- Docker Example: `docker start <contain  

| Log source | Channel |
|---|---|
| `docker:events` | exec_create: docker exec events targeting running containers from non-CI sources |
| `kubernetes:events` | start: ContainerStarted or Pulling image → Started container |
| `containerd:runtime` | CRI CreateContainer/StartContainer with privileged=true OR added capabilities OR host* namespaces |
| `docker:events` | start |

---

### Social Media
**Feeds detection for 4 techniques.**  
Established, compromised, or otherwise acquired by adversaries to conduct reconnaissance, influence operations, social engineering, or other cyber threats.

*Data Collection Measures:*

- API Monitoring 
 - Social media APIs (e.g., Twitter API, Facebook Graph API) can extract behavioral patterns of accounts.
- Web Scraping
 - Extracts public profile data, friend lists, or interactions to identify impersonation attempts.
- Threat Intelligence Feeds 
 - External feeds track malicious personas link  

| Log source | Channel |
|---|---|
| `Persona` |  |

---

### Named Pipe Metadata
**Feeds detection for 4 techniques.**  
Contextual data about a named pipe on a system, including pipe name and creating process (ex: Sysmon EIDs 17-18)

*Data Collection Measures:*

- Windows:
 - Sysmon Event ID 17: Logs the creation of a named pipe.
 - Sysmon Event ID 18: Logs connection attempts to a named pipe.
 - Windows Security Event ID 5145: Logs access attempts to named pipes via SMB shares.
 - ETW (Event Tracing for Windows): Provides deep telemetry into named pipe interactions.
- Linux/macOS:
 - AuditD (`mkfifo`, `open`, `r  

| Log source | Channel |
|---|---|
| `WinEventLog:Sysmon` | EventCode=17 |
| `macos:unifiedlog` | XPC messages requesting privileged actions from untrusted or unsigned clients |

---

### Active Directory Object Creation
**Feeds detection for 3 techniques.**  
Creating new objects in AD, such as user accounts, groups, organizational units (OUs), or trust relationships. Logged as Event ID 5137. Examples:

- User Account Creation: New user account.
- Group Creation: New security/distribution group.
- OU Creation: New organizational unit.
- Service Account Creation: New service account for automation or malicious tasks.
- Trust Object Creation: Trust relationship with another domain.  

| Log source | Channel |
|---|---|
| `azure:audit` | New device object creation |
| `WinEventLog:Security` | Device Object Creation |
| `WinEventLog:Security` | EventCode=4928 |
| `AWS:CloudTrail` | CreateAccessKey, ImportKeyPair, CreateLoginProfile, CreateKeyPair |

---

### Cloud Storage Modification
**Feeds detection for 3 techniques.**  
Cloud Storage Modification involves tracking changes made to cloud storage infrastructure, including updates to settings, permissions, or stored data. Examples include modifying object access control lists (ACLs), uploading new objects, or updating bucket policies. Examples: 

AWS S3: An object is uploaded or its ACL is modified.
- Azure Blob Storage: A blob's metadata or permissions are updated.
- Google Cloud Storage: An object's lifecycle policy is updated, or a bucket policy is changed.
- Op  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | PutBucketLifecycle, PutLifecycleConfiguration, SetBucketLifecycle, storage.buckets.update |
| `AWS:CloudTrail` | PutObject (with SSE-C), UploadPart (SSE-C) |
| `AWS:CloudTrail` | PutBucketPolicy |
| `m365:unified` | SharingSet |
| `saas:googledrive` | drive.permission.add |

---

### Instance Metadata
**Feeds detection for 3 techniques.**  
Contextual data about an instance and activity around it such as name, type, or status  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | DescribeInstances |

---

### Scheduled Job Metadata
**Feeds detection for 3 techniques.**  
Contextual data about a scheduled job, which may include information such as name, timing, command(s), etc.  

| Log source | Channel |
|---|---|
| `Scheduled Job` |  |
| `linux:cron` | cron activity |
| `fs:fileevents` | /Library/LaunchDaemons/*.plist, ~/Library/LaunchAgents/*.plist |
| `WinEventLog:TaskScheduler` | Task registration/execution shortly after a time discovery event |
| `macos:unifiedlog` | New/modified launchd plist (persistence/scheduling) within TimeWindow after time query |
| `esxi:syslog` | /var/log/vpxa.log task invocations tied to time configuration |
| `WinEventLog:System` | EventCode=106, 200 |
| `macos:launchd` | launchd.plist and logs |

---

### Image Creation
**Feeds detection for 3 techniques.**  
Initial construction of a virtual machine image within a cloud environment. Virtual machine images are templates containing an operating system and installed applications, which can be deployed to create new virtual machines. Monitoring the creation of these images is important because adversaries may create custom images to include malicious software or misconfigurations for later exploitation. Examples: 

- Azure Compute Service Image Creation
 - Example: Creating a virtual machine image in Az  

| Log source | Channel |
|---|---|
| `containerd:events` | Image pull from untrusted registry (name NOT IN allowlist) or new digest never seen before |
| `docker:daemon` | docker build or docker commit commands followed by docker push to internal registry |
| `kubernetes:audit` | create |
| `AWS:CloudTrail` | RegisterImage |
| `docker:daemon` | docker build or POST /build API request |
| `kubernetes:apiserver` | Pod spec triggering build or custom controller activity invoking image builds |

---

### Image Metadata
**Feeds detection for 3 techniques.**  
contextual information associated with a virtual machine image, such as its name, resource group, status (active or inactive), type (custom or prebuilt), size, creation date, and permissions. This metadata is critical for understanding the state and configuration of virtual machine images in cloud environments. Examples: 

- Azure Compute Service Image Metadata Example:
 - Name: MyCustomImage
 - Resource Group: MyResourceGroup
 - State: Available
 - Type: Managed Image
- AWS EC2 AMI Metadata Exa  

| Log source | Channel |
|---|---|
| `docker:events` | docker.events.json |
| `esxi:vmkernel` | VMX startup messages without associated vCenter inventory records |
| `kubernetes:apiserver` | Resource creation and update logs |

---

### Instance Creation
**Feeds detection for 3 techniques.**  
The initial provisioning and construction of a virtual machine (VM) or compute instance within a cloud infrastructure environment. This activity involves defining and allocating resources such as CPU, memory, storage, and networking to spin up a new compute instance. Examples:

- AWS: creating an EC2 instance using RunInstances API calls.
- Azure, creating a VM through the Azure Resource Manager (ARM).
- GCP, an `instance.insert` action recorded.  

| Log source | Channel |
|---|---|
| `azure:activity` | Microsoft.Compute/virtualMachines/write: imageReference publisher NOT IN allowlist OR plan is new/unknown |
| `gcp:audit` | compute.instances.insert: sourceImage not in approved projects OR has external image link |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE |
| `gcp:audit` | compute.instances.insert |
| `AWS:CloudTrail` | RunInstances,CreateImage |

---

### Scheduled Job Modification
**Feeds detection for 3 techniques.**  
Changes made to an existing scheduled job, including modifications to its execution parameters, command payload, or execution timing.  

| Log source | Channel |
|---|---|
| `Scheduled Job` |  |
| `auditd:CONFIG_CHANGE` | /var/log/audit/audit.log |
| `m365:exchange` | Remove-InboxRule, Clear-Mailbox |
| `WinEventLog:Security` | EventCode=4702 |

---

### Cloud Storage Enumeration
**Feeds detection for 3 techniques.**  
Cloud Storage Enumeration involves retrieving a list of available cloud storage infrastructure, such as buckets, containers, or objects, within a cloud environment. This activity may be performed for legitimate administrative purposes or malicious reconnaissance by adversaries seeking to identify accessible storage resources.Examples:

- AWS S3 Bucket Enumeration: An AWS user lists all buckets using the `ListBuckets` API call.
- Azure Blob Storage Container Enumeration: A user retrieves a list o  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | ListBuckets |
| `AWS:CloudTrail` | ListObjectsV2 |
| `azure:activity` | List Blobs |
| `gcp:storage` | storage.objects.list |

---

### Snapshot Deletion
**Feeds detection for 2 techniques.**  
The removal of a point-in-time backup of a cloud storage volume, virtual machine (VM), or database.

*Data Collection Measures:*

- AWS CloudTrail
 - Logs `DeleteSnapshot` API calls in EC2, RDS, and EBS services.
- Azure Monitor Logs
 - Tracks snapshot deletions via `Microsoft.Compute/snapshots/delete` API calls.
- Google Cloud Logging
 - Detects snapshot removal through `compute.disks.deleteSnapshot` events.  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | DeleteSnapshot |
| `esxi:hostd` | snapshot.removeall or snapshot file deletion |

---

### Certificate Registration
**Feeds detection for 2 techniques.**  
Certificate Registration refers to the collection and analysis of information about digital certificates, including current, revoked, and expired certificates. Sources such as Certificate Transparency logs and other public resources provide visibility into certificates issued for specific domains or organizations. Monitoring certificate registrations can help identify potential misuse, such as unauthorized certificates or signs of adversary reconnaissance. Examples: 

- Certificate Transparency   

| Log source | Channel |
|---|---|
| `Certificate` |  |

---

### Kernel Module Load
**Feeds detection for 2 techniques.**  
The process of loading a kernel module into the operating system kernel. Kernel modules are object files that extend the kernel’s functionality, such as adding support for device drivers, new filesystems, or additional system calls. This action can be legitimate (e.g., loading a driver) or malicious (e.g., adding a rootkit). 

*Data Collection Measures:*

- Linux:
 - Auditd: Enable auditing of kernel module loading. Example rule: `-a always,exit -F arch=b64 -S init_module,delete_module`.
 - Sysl  

| Log source | Channel |
|---|---|
| `esxi:vmkernel` | VM exit/entry anomalies, unexpected hypercalls, or kernel module loading |
| `macos:osquery` | New kext entries not signed by Apple or outside standard identifier prefix |

---

### Instance Enumeration
**Feeds detection for 2 techniques.**  
The process of retrieving or querying a list of virtual machine instances or compute instances within a cloud infrastructure. This activity provides a view of all available or running instances, typically including their associated metadata such as instance ID, name, state, and configuration details. Examples:

- AWS: instance enumeration involves the `DescribeInstances` API call, which retrieves information about running or stopped EC2 instances.
- Azure: VM enumeration can be monitored via the  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | DescribeDBInstances |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/LIST |
| `gcp:audit` | compute.instances.list OR storage.buckets.list |
| `AWS:CloudTrail` | DescribeInstances, GetConsoleOutput, DescribeImages |
| `azure:activity` | Microsoft.Compute/virtualMachines/read |

---

### Volume Deletion
**Feeds detection for 2 techniques.**  
The removal of a cloud-based or on-premise block storage volume. This action permanently deletes the allocated storage and may result in data loss if not backed up.

*Data Collection Measures:*

- Cloud Logging & APIs
 - AWS CloudTrail Logs
 - `eventName: DeleteVolume` (tracks volume deletions)
 - Azure Monitor Logs
 - `operationName: Microsoft.Compute/disks/delete`
 - `status: Success | Failure` (flag unauthorized delete attempts)
 - Google Cloud Audit Logs
 - `protoPayload.methodName: "v1.comp  

| Log source | Channel |
|---|---|
| `esxi:vmkernel` | file delete|datastore purge |
| `AWS:CloudTrail` | DeleteVolume |

---

### Cloud Storage Deletion
**Feeds detection for 2 techniques.**  
Cloud Storage Deletion refers to the removal or destruction of cloud storage infrastructure, such as buckets, containers, or directories, within a cloud environment. Monitoring this activity is critical to detecting potential unauthorized or malicious actions, such as data destruction by adversaries or accidental deletions that may lead to data loss. Examples: 

- AWS S3 Bucket Deletion: An AWS user deletes an S3 bucket using the `DeleteBucket` API call.
- Azure Blob Storage Container Deletion:   

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | DeleteBucket, DeleteDBCluster, DeleteSnapshot, TerminateInstances |

---

### Pod Creation
**Feeds detection for 2 techniques.**  
The initial deployment or instantiation of a new pod in a containerized environment. This includes creating a pod manually, through orchestration tools (Kubernetes), or via Infrastructure-as-Code (IaC) configurations. A Pod is the smallest deployable unit in Kubernetes, typically containing one or more containers. Creation methods include:
- Direct pod deployment (`kubectl run`, `kubectl apply`)
- Automated deployment via CI/CD pipelines (e.g., ArgoCD, Jenkins, GitOps)
- Infrastructure-as-Code (  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | CreatePod: Programmatic creation of new pod resources using container images not seen before in the environment |
| `kubernetes:audit` | create |

---

### Web Credential Creation
**Feeds detection for 2 techniques.**  
Initial construction of new web credential material (ex: Windows EID 1200 or 4769)  

| Log source | Channel |
|---|---|
| `WinEventLog:ADFS` | Token issuance events showing anomalous claims or issuers |
| `AWS:CloudTrail` | AssumeRole, GetFederationToken API calls by unusual or new entities |
| `azure:signinlogs` | SAML/OIDC tokens issued without corresponding MFA or password validation |
| `m365:unified` | Session creation without MFA or login event |
| `m365:oauth` | OAuth grants or tokens issued without expected user consent |

---

### Service Modification
**Feeds detection for 2 techniques.**  
Changes made to an existing service or daemon, such as modifying the service name, start type, execution parameters, or security configurations.  

| Log source | Channel |
|---|---|
| `Service` |  |
| `WinEventLog:Microsoft-IIS-Configuration` | Module or ISAPI filter registration events |
| `WinEventLog:System` | EventCode=7040 |

---

### Snapshot Metadata
**Feeds detection for 2 techniques.**  
Contextual data about a snapshot, which may include information such as ID, type, and status  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | DescribeSnapshots |
| `gcp:audit` | compute.disks.insert with sourceSnapshot parameter |
| `AWS:CloudTrail` | CopySnapshot |

---

### Container Enumeration
**Feeds detection for 2 techniques.**  
"Container Enumeration" data component captures events and actions related to listing and identifying active or available containers within a containerized environment. This includes information about running, stopped, or configured containers, such as their names, IDs, statuses, or associated images. Monitoring this activity is crucial for detecting unauthorized discovery or reconnaissance efforts. Examples: 

- Docker Example: `docker ps`, `docker ps -a`
- Kubernetes Example: `kubectl get pods  

| Log source | Channel |
|---|---|
| `docker:daemon` | docker ps, docker inspect, or docker images commands |
| `AWS:CloudTrail` | DescribeCluster, ListClusters, ListNodegroups |
| `containerd:runtime` | e.g., containerd, Docker events |

---

### Firewall Disable
**Feeds detection for 2 techniques.**  
The deactivation, misconfiguration, or complete stoppage of firewall services, either on a host or in a cloud control plane. Such activity may involve turning off firewalls, modifying rules to disable protection, or deleting firewall-related configurations and activity logs. Examples: 

- Disabling Host-Based Firewalls: Stopping the Windows Defender Firewall service or using `iptables -F` to flush all rules on a Linux system.
- Cloud Firewall Modification or Deactivation: Modifying or deleting s  

| Log source | Channel |
|---|---|
| `esxi:vmkernel` | Disabling or modifying firewall rules |
| `AWS:CloudTrail` | Removal of restrictive egress rules from a security group |

---

### Volume Modification
**Feeds detection for 2 techniques.**  
Changes made to a cloud volume, including its settings and control data (ex: AWS modify-volume)  

| Log source | Channel |
|---|---|
| `kubernetes:apiserver` | Pod spec with hostPath or privileged securityContext |
| `AWS:CloudTrail` | ModifyVolume |

---

### User Account Deletion
**Feeds detection for 2 techniques.**  
The removal of a user, service, or machine account from an operating system, cloud identity management system, or directory service.  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | EventCode=4726, 4657 |
| `esxi:hostd` | method=RemoveUser or esxcli system account remove invocation |
| `m365:unified` | Remove-Mailbox, Set-Mailbox |

---

### Volume Creation
**Feeds detection for 2 techniques.**  
The initial provisioning of block storage volumes in cloud or on-prem environments, typically used for data storage, backup, or workload scaling.  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | CreateVolume |
| `WinEventLog:Microsoft-Windows-VSS` | Volume Shadow Copy Creation |

---

### Cloud Storage Metadata
**Feeds detection for 2 techniques.**  
Cloud Storage Metadata provides contextual information about cloud storage infrastructure and its associated activity. This data may include attributes such as storage name, size, owner, permissions, creation date, region, and activity metadata. It is essential for monitoring, auditing, and identifying anomalies in cloud storage environments. Examples: 

- AWS S3 Bucket Metadata: Metadata about an S3 bucket includes the bucket name, region, creation date, owner, storage class, and permissions.
-  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | Post-authentication metadata enumeration from GUI session |
| `m365:unified` | AnonymousLinkCreated |
| `saas:box` | collaboration.invite |
| `saas:dropbox` | Shared link created to external account |

---

### Cloud Service Disable
**Feeds detection for 2 techniques.**  
This data component refers to monitoring actions that deactivate or stop a cloud service in a cloud control plane. Examples include disabling essential logging services like AWS CloudTrail (`StopLogging` API call), Microsoft Azure Monitor Logs, or Google Cloud's Operations Suite (formerly Stackdriver). Disabling such services can hinder visibility into adversary activities within the cloud environment. Examples: 

- AWS CloudTrail StopLogging: This action stops logging of API activity for a part  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | Stop logging for an existing CloudTrail |
| `AWS:CloudTrail` | Removal of CloudTrail trail |
| `azure:activity` | az monitor diagnostic-settings delete |
| `saas:audit` | Log export integration removed or disabled |
| `AWS:CloudTrail` | StopLogging, DeleteTrail, or DisableSecurityService |

---

### Snapshot Modification
**Feeds detection for 2 techniques.**  
Changes made to a cloud snapshot's metadata, attributes, or control settings. These modifications may involve adjusting access permissions, changing retention policies, or altering encryption settings. 

*Data Collection Measures:*

- AWS CloudTrail
 - Tracks API calls such as `ModifySnapshotAttribute`, `ResetSnapshotAttribute`, and `ModifySnapshotTier`.
- Azure Monitor Logs
 - Logs changes via `Microsoft.Compute/snapshots/write`.
- Google Cloud Logging
 - Captures modifications through `compute  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | ModifySnapshotAttribute |

---

### Group Modification
**Feeds detection for 1 techniques.**  
Changes made to a group, such as membership, name, or permissions (ex: Windows EID 4728 or 4732, AWS IAM UpdateGroup). Examples: 

- Active Directory:
 - Event ID 4728: Member added to a global group.
 - Event ID 4732: Member added to a local group.
- Azure AD: `Set-AzureADGroup -ObjectId <GroupId> -DisplayName "New Name"`
- AWS IAM: `aws iam update-group --group-name <GroupName> --new-path "/admin/"`
- Google Workspace: Modify permissions via Admin SDK API: `PATCH https://admin.googleapis.com/a  

| Log source | Channel |
|---|---|
| `m365:unified` | Add member to group |

---

### Image Modification
**Feeds detection for 1 techniques.**  
Changes made to a virtual machine image, including setting and/or control data (ex: Azure Compute Service Images PATCH)  

| Log source | Channel |
|---|---|
| `docker:registry` | push event of new image version from unrecognized user or context |
| `AWS:CloudTrail` | ModifyImageAttribute |

---

### Pod Enumeration
**Feeds detection for 1 techniques.**  
Extracting a list of running or existing pods within a containerized cluster environment. Pods are the smallest deployable units in a Kubernetes cluster and typically represent an application or workload. Enumeration of pods provides insight into the structure and state of applications running in the cluster, such as the names of pods, their namespaces, and their associated metadata.

*Data Collection Measures:*

- Kubernetes API Server Audit Logs:
 - Enable Audit Logging in Kubernetes to captur  

| Log source | Channel |
|---|---|
| `kubernetes:apiserver` | list or get requests against pods, deployments, or nodes |

---

### Instance Modification
**Feeds detection for 1 techniques.**  
Changes made to a virtual machine (VM) or compute instance, including alterations to its configuration, metadata, attached policies, or operational state. Such modifications can include updating metadata, attaching or detaching resource policies, resizing instances, or modifying network configurations. Examples:

- AWS: instance modifications include API actions like `ModifyInstanceAttribute`, `ModifyInstanceMetadataOptions`, or `RebootInstances`.
- Azure: modifications can be tracked through op  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | RevertSnapshot |
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/RESTORE |
| `gcp:audit` | compute.instances.restore |

---

### Cloud Storage Creation
**Feeds detection for 1 techniques.**  
Cloud Storage Creation refers to the initial creation of a new cloud storage resource, such as buckets, containers, or directories, within a cloud environment. This action is critical to track as it might indicate the legitimate provisioning of resources or unauthorized actions taken by adversaries to stage, store, or exfiltrate data. Examples: 

- AWS S3 Bucket Creation: An AWS user creates a new S3 bucket using the `CreateBucket` API call.
- Azure Blob Storage Container Creation: A user create  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | CreateBucket |

---

### Instance Deletion
**Feeds detection for 1 techniques.**  
Removal of a virtual machine (VM) or compute instance within a cloud infrastructure. This activity results in the termination and deletion of the allocated resources (e.g., CPU, memory, storage), making the instance unavailable for future use. Examples:

- AWS: instance deletion involves the `TerminateInstances` API call, which is recorded in CloudTrail logs.
- Azure: VM deletion can be monitored via Azure Activity Logs, showing the `Microsoft.Compute/virtualMachines/delete` operation.
- GCP: in  

| Log source | Channel |
|---|---|
| `azure:activity` | MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE |
| `gcp:audit` | compute.instances.delete |

---

### Group Metadata
**Feeds detection for 1 techniques.**  
Group metadata includes attributes like name, permissions, purpose, and associated user accounts or roles, which adversaries may exploit for privilege escalation. Examples:

- Active Directory: `Get-ADGroup -Identity "Domain Admins" -Properties Members, Description`
- Azure AD: `Get-AzureADGroup -ObjectId <GroupId>`
- Google Workspace: `GET https://admin.googleapis.com/admin/directory/v1/groups/<groupKey>`
- AWS IAM: `aws iam list-group-policies --group-name <group_name>`
- Office 365: `GET http  

| Log source | Channel |
|---|---|
| `m365:sharepoint` | Enumerate ACLs/role bindings |

---

### Group Enumeration
**Feeds detection for 1 techniques.**  
Extracting group lists from identity systems identifies permissions, roles, or configurations. Adversaries may exploit high-privilege groups or misconfigurations. Examples:

- AWS CLI: `aws iam list-groups`
- PowerShell: `Get-ADGroup -Filter *`
- (Saas) Google Workspace: Admin SDK Directory API
- Azure: `Get-AzureADGroup`
- Microsoft 365: Graph API `GET https://graph.microsoft.com/v1.0/groups`

*Data Collection Measures:*

- Cloud Logging: Enable AWS CloudTrail, Azure Activity Logs, and Google W  

| Log source | Channel |
|---|---|
| `AWS:CloudTrail` | ListGroups, ListAttachedRolePolicies |
| `azure:audit` | az ad user get-member-groups, Get-AzRoleAssignment |
| `gcp:audit` | cloudidentity.groups.list |
| `saas:salesforce` | GET /services/data/vXX.X/groups |
| `saas:github` | GET /orgs/:org/teams, GET /teams/:team/members |

---

### Active Directory Object Deletion
**Feeds detection for 1 techniques.**  
Object deletion in AD (e.g., user accounts, groups, OUs) is logged as Event ID 5141. Examples:

- User Account: Deleted user.
- Group: Deleted security/distribution group.
- Organizational Unit (OU): Loss of configurations or policies.
- Service Account: Disrupted operations or cover tracks.
- Trust Object: Removed domain trust, disrupting connectivity.

*Data Collection Measures:*

- Audit Policy:
 - Enable "Audit Directory Service Changes" (Success and Failure).
 - Path: `Computer Configuratio  

| Log source | Channel |
|---|---|
| `WinEventLog:Security` | EventCode=4929 |

---

### Volume Metadata
**Feeds detection for 0 techniques.**  
Contextual data about a cloud volume and activity around it, such as id, type, state, and size  

| Log source | Channel |
|---|---|
| `Metadata` |  |

---

### Windows Registry Key Deletion
**Feeds detection for 0 techniques.**  
The removal of a registry key within the Windows operating system.

*Data Collection Measures:*

- Windows Event Logs
 - Event ID 4658 - Registry Key Handle Closed: Captures when a handle to a registry key is closed, which may indicate deletion.
 - Event ID 4660 - Object Deleted: Logs when a registry key is deleted.
- Sysmon (System Monitor) for Windows
 - Sysmon Event ID 12 - Registry Key Deleted: Logs when a registry key is removed.
 - Sysmon Event ID 13 - Registry Value Deleted: Captures remo  

| Log source | Channel |
|---|---|
| `Windows Registry` |  |

---

### Pod Modification
**Feeds detection for 0 techniques.**  
Changes made to a pod’s configuration or control data within a containerized cluster. This can include updating settings such as resource limits, environment variables, annotations, labels, or even the containers running within the pod. Pod modifications are often executed using commands like kubectl set, kubectl patch, or kubectl edit.

*Data Collection Measures:* 

- Kubernetes API Server Audit Logs:
 - Capture all API calls related to pod modification, such as PATCH, PUT, or UPDATE methods on  

---

### Firewall Metadata
**Feeds detection for 0 techniques.**  
Contextual information about firewalls, including their configurations, policies, status, and other details such as names and associated rules. This metadata provides valuable insights into the operational state and configurations of firewalls, both in cloud control planes and host systems. Examples: 

- Firewall Name and Configuration: The name, type, and purpose of a firewall such as "Azure Firewall - Production Environment."
- Policy Details: Capturing firewall policy details, such as "Allow   

---

### Image Deletion
**Feeds detection for 0 techniques.**  
Removal of a virtual machine image in a cloud infrastructure (ex: Azure Compute Service Images DELETE) Examples: 

- Azure Compute Service Image Deletion
 - Example: Deleting a virtual machine image using Azure CLI: `az image delete --name MyImage --resource-group MyResourceGroup`
- AWS EC2 AMI (Amazon Machine Image) Deletion
 - Example: Deregistering an AMI in AWS: `aws ec2 deregister-image --image-id ami-1234567890abcdef0`
- Google Cloud Compute Engine Image Deletion
 - Example: Deleting a cus  

---

### Firewall Enumeration
**Feeds detection for 0 techniques.**  
Querying and extracting a list of available firewalls or their associated configurations and rules. This activity can occur across host systems and cloud control planes, providing insight into the state and configuration of firewalls that protect the environment. Examples: 

- Querying Host-Based Firewalls: Using Windows PowerShell commands like `Get-NetFirewallRule` or Linux commands such as `iptables -L` or `firewalld --list-all`.
- Cloud Firewall Rule Listing: Running commands like `az networ  

---

### Volume Enumeration
**Feeds detection for 0 techniques.**  
An extracted list of available volumes within a cloud environment (ex: AWS describe-volumes)  

---

### Driver Metadata
**Feeds detection for 0 techniques.**  
to contextual data about a driver, including its attributes, functionality, and activity. This can involve details such as the driver's origin, integrity, cryptographic signature, issues reported during its use, and runtime behavior. Examples include metadata captured during driver integrity checks, hash validation, or error reporting. Examples: 

- Driver Signature Validation: A driver is validated to ensure it is signed by a trusted Certificate Authority (CA).
- Driver Hash Verification: The h  

---

### Snapshot Enumeration
**Feeds detection for 0 techniques.**  
The process of listing or retrieving metadata about existing snapshots in a cloud environment.

*Data Collection Measures:*

- AWS CloudTrail
 - Logs API calls such as `DescribeSnapshots`, `ListSnapshots`, and `GetSnapshotAttributes`.
- Azure Monitor Logs
 - Tracks snapshot enumeration via `Microsoft.Compute/snapshots/read`.
- Google Cloud Logging
 - Detects snapshot listing through `compute.disks.listSnapshots`.  

---

