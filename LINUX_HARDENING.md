# Linux Hardening Reference

> Practical Linux hardening guide covering CIS Benchmark controls, DISA STIG requirements,
> MITRE ATT&CK mappings, and production-ready configurations for Ubuntu 22.04 / RHEL 9.

---

## Table of Contents

1. [Linux Attack Surface](#1-linux-attack-surface)
2. [Initial System Hardening](#2-initial-system-hardening)
3. [User & Account Management](#3-user--account-management)
4. [SSH Hardening](#4-ssh-hardening)
5. [Kernel Hardening (sysctl)](#5-kernel-hardening-sysctl)
6. [Filesystem & File Permissions](#6-filesystem--file-permissions)
7. [SELinux & AppArmor](#7-selinux--apparmor)
8. [Auditd — Linux Audit Framework](#8-auditd--linux-audit-framework)
9. [Firewall (nftables & iptables)](#9-firewall-nftables--iptables)
10. [Service Hardening](#10-service-hardening)
11. [Logging & Monitoring](#11-logging--monitoring)
12. [CIS Benchmark Quick Reference](#12-cis-benchmark-quick-reference)
13. [DISA STIG CAT I Requirements](#13-disa-stig-cat-i-requirements)
14. [Rootkit Detection & Response](#14-rootkit-detection--response)
15. [Incident Response on Linux](#15-incident-response-on-linux)

---

## 1. Linux Attack Surface

### Linux in Enterprise Environments

Linux powers a significant portion of enterprise workloads:

- **Server workloads** — web servers (nginx, Apache), databases (PostgreSQL, MySQL), middleware
- **Cloud VMs** — EC2, Azure VMs, GCE instances running Amazon Linux, Ubuntu, RHEL, CentOS Stream
- **Containers** — Docker images, Kubernetes pods, container runtimes (containerd, CRI-O)
- **WSL (Windows Subsystem for Linux)** — development environments on Windows workstations
- **Embedded / IoT** — network appliances, PLCs, SCADA gateways, Raspberry Pi deployments

### Linux Attack Techniques (MITRE ATT&CK)

| ATT&CK ID | Technique | Description |
|---|---|---|
| T1059.004 | Unix Shell | Bash/sh/zsh command execution, reverse shells, script execution |
| T1053.003 | Cron | Scheduled tasks via crontab, /etc/cron.d, at, systemd timers |
| T1548.001 | Setuid/Setgid | Abusing SUID/SGID binaries for privilege escalation |
| T1014 | Rootkit | Kernel-level persistence hiding processes, files, and network connections |
| T1070.002 | Clear Linux/Mac Logs | Clearing /var/log/auth.log, bash_history, utmp/wtmp |
| T1136.001 | Create Local Account | Adding backdoor accounts to /etc/passwd |
| T1055.009 | Proc Memory | Writing to /proc/PID/mem for process injection |
| T1083 | File/Dir Discovery | find, ls, locate for reconnaissance |
| T1057 | Process Discovery | ps, top, pgrep enumerating running processes |
| T1049 | System Network Connections | ss, netstat, lsof -i discovering connections |
| T1078.003 | Local Accounts | Abusing valid local accounts for persistence |
| T1098.004 | SSH Authorized Keys | Inserting attacker keys into ~/.ssh/authorized_keys |
| T1543.002 | Systemd Service | Malicious systemd units for persistence |
| T1574.006 | LD_PRELOAD | Hijacking dynamic linker via LD_PRELOAD |
| T1003.008 | /etc/passwd and /etc/shadow | Dumping credentials from shadow file |

### CIS Benchmark Coverage

This document maps to:
- **CIS Benchmark for Ubuntu Linux 22.04 LTS** (v1.0.0+)
- **CIS Benchmark for Red Hat Enterprise Linux 9** (v1.0.0+)
- **DISA STIG for Red Hat Enterprise Linux 9** (V1R1+)

---

## 2. Initial System Hardening

### Filesystem Partitioning

CIS Control 1.1.x — Separate partitions prevent privilege escalation via SUID binaries,
symlink attacks, and disk exhaustion in critical paths.

```bash
# /etc/fstab entries — recommended partition layout
/dev/sda1  /boot       ext4  defaults,nodev,nosuid,noexec  0 2
/dev/sdb1  /tmp        ext4  defaults,nodev,nosuid,noexec  0 0
/dev/sdb2  /var        ext4  defaults                       0 0
/dev/sdb3  /var/log    ext4  defaults,nodev,nosuid,noexec  0 0
/dev/sdb4  /var/tmp    ext4  defaults,nodev,nosuid,noexec  0 0
/dev/sdb5  /home       ext4  defaults,nodev,nosuid         0 0
tmpfs      /dev/shm    tmpfs defaults,nodev,nosuid,noexec  0 0

# Remount /tmp if already mounted
mount -o remount,nodev,nosuid,noexec /tmp
```

**Verify mount options:**
```bash
findmnt -n /tmp | awk '{print $4}'
# Expected: nodev,nosuid,noexec
```

### Bootloader Password (GRUB2 Hardening)

CIS Control 1.4.1 — Prevents booting into single-user mode without authentication.

```bash
# Generate PBKDF2 password hash
grub-mkpasswd-pbkdf2
# Enter password twice — copy the grub.pbkdf2.sha512.10000.HASH output

# /etc/grub.d/40_custom — add these lines
set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.10000.YOURHASHHERE

# Protect the GRUB config file
chmod 600 /boot/grub2/grub.cfg
chmod 600 /boot/grub/grub.cfg  # Ubuntu path
```

```bash
# Rebuild GRUB config
grub2-mkconfig -o /boot/grub2/grub.cfg      # RHEL
update-grub                                   # Ubuntu
```

### Secure Boot

```bash
# Check Secure Boot status
mokutil --sb-state
# Expected: SecureBoot enabled

# Verify kernel module signing
grep -r "module.sig_enforce" /boot/cmdline 2>/dev/null || \
  grep "GRUB_CMDLINE_LINUX" /etc/default/grub
```

### Remove Unnecessary Packages

```bash
# Ubuntu/Debian
apt-get remove --purge telnet rsh-client rsh-redone-client nis yp-tools talk talk-server
apt-get autoremove

# RHEL/CentOS
yum remove telnet rsh ypbind talk
rpm -e --nodeps package_name
```

### Disable Unused Filesystems (CIS 1.1.1.x)

```bash
# /etc/modprobe.d/CIS.conf
echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf

# Verify — should return nothing (module disabled)
modprobe cramfs 2>&1
lsmod | grep cramfs
```

---

## 3. User & Account Management

### Password Policies (/etc/login.defs)

CIS Controls 5.4.1.x

```
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
PASS_MIN_LEN    14
ENCRYPT_METHOD  SHA512
SHA_CRYPT_MIN_ROUNDS 5000
```

**Apply retroactively to existing accounts:**
```bash
chage --maxdays 90 --mindays 7 --warndays 14 username
# Audit all users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    echo "=== $user ===" && chage -l $user
done
```

### PAM Password Quality (pam_pwquality.so)

File: `/etc/security/pwquality.conf` or `/etc/pam.d/common-password`

```
# /etc/security/pwquality.conf
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
```

```bash
# /etc/pam.d/common-password (Ubuntu)
password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1

# /etc/pam.d/system-auth (RHEL)
password requisite pam_pwquality.so try_first_pass retry=3
```

### PAM Lockout (pam_faillock.so)

CIS Control 5.4.2 — Lock accounts after N failed attempts.

```bash
# /etc/pam.d/common-auth (Ubuntu) or /etc/pam.d/system-auth (RHEL)
# Add BEFORE pam_unix.so:
auth required pam_faillock.so preauth silent deny=5 unlock_time=900 even_deny_root
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900 even_deny_root
auth sufficient pam_faillock.so authsucc

# /etc/security/faillock.conf
deny = 5
fail_interval = 900
unlock_time = 900
even_deny_root
```

```bash
# Check failed attempts
faillock --user username

# Unlock account manually
faillock --user username --reset
```

### Root Account Hardening

```bash
# Lock direct root login via passwd
passwd -l root

# Verify root account is locked
passwd -S root
# Expected: root L (locked)

# Prevent root SSH login (in /etc/ssh/sshd_config)
PermitRootLogin no

# Check for unauthorized UID 0 accounts
awk -F: '($3 == "0") { print $1 }' /etc/passwd
# Should only return: root
```

### Sudo Hardening

```bash
# /etc/sudoers.d/hardening
Defaults logfile=/var/log/sudo.log
Defaults log_input,log_output
Defaults passwd_timeout=1
Defaults timestamp_timeout=5
Defaults requiretty
Defaults !visiblepw
Defaults use_pty

# Secure sudoers permissions
chmod 440 /etc/sudoers
chmod 750 /etc/sudoers.d/

# Review sudo access
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/
```

### Remove Unused Accounts

```bash
# Remove user and their home directory
userdel -r olduser

# Lock account instead of removing
usermod -L -e 1 olduser

# Find accounts with no password set (!)
awk -F: '($2 == "") { print $1 }' /etc/shadow

# Find system accounts with interactive shell
awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $3 < 1000) { print $1, $7 }' /etc/passwd
```

### Login Restrictions

```bash
# /etc/securetty — restrict root console login to specific TTYs
# Remove all entries except needed ones
echo "tty1" > /etc/securetty
chmod 600 /etc/securetty

# /etc/security/access.conf — restrict by user/group/origin
+ : root : LOCAL
- : ALL EXCEPT admin_group : ALL

# Inactive account locking — lock accounts inactive >30 days
useradd -D -f 30
# Or per-user: chage -I 30 username

# Check current inactive setting
useradd -D | grep INACTIVE
```

---

## 4. SSH Hardening (Complete /etc/ssh/sshd_config)

### Full Hardened Configuration

```
# /etc/ssh/sshd_config — hardened production config
# CIS Section 5.2, DISA STIG RHEL-09-255xxx

# Protocol
Protocol 2

# Network
Port 22
# NOTE: Change to non-standard port in production (e.g., 2222 or a random high port)
AddressFamily inet
ListenAddress 0.0.0.0

# Authentication settings
PermitRootLogin no
MaxAuthTries 4
MaxSessions 2
LoginGraceTime 60
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
UsePAM yes

# Forwarding restrictions
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# Session settings
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
ClientAliveInterval 300
ClientAliveCountMax 0
Compression no
UseDNS no

# Banner
Banner /etc/issue.net

# Allow only specific users or groups
AllowUsers deploy_user monitoring_user
# OR
AllowGroups sshusers

# Subsystems
Subsystem sftp /usr/lib/openssh/sftp-server

# Cryptographic settings (CIS 5.2.14-17)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
```

```bash
# Validate config before restarting
sshd -t

# Restart SSH
systemctl restart sshd

# Verify active settings
sshd -T | grep -E 'permitrootlogin|maxauthtries|passwordauthentication|x11forwarding'
```

### SSH Key Management

```bash
# Generate strong key pair
ssh-keygen -t ed25519 -C "user@host-$(date +%Y%m%d)"
# For RSA (older clients): ssh-keygen -t rsa -b 4096

# Set correct permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub

# Audit authorized_keys for all users
for user in $(cut -f1 -d: /etc/passwd); do
    keyfile=$(eval echo ~$user/.ssh/authorized_keys)
    [ -f "$keyfile" ] && echo "=== $user ===" && cat "$keyfile"
done
```

### SSH Certificate Authorities

```bash
# Create CA key
ssh-keygen -t ed25519 -f /etc/ssh/ca_key -C "SSH CA"

# Sign user key — valid 52 weeks, principal matches Unix username
ssh-keygen -s /etc/ssh/ca_key \
    -I "user@corp - $(date +%Y%m%d)" \
    -n username \
    -V +52w \
    user_key.pub

# Sign host key
ssh-keygen -s /etc/ssh/ca_key \
    -I "host $(hostname -f)" \
    -h \
    -V +52w \
    /etc/ssh/ssh_host_ed25519_key.pub

# /etc/ssh/sshd_config additions for CA
TrustedUserCAKeys /etc/ssh/ca_key.pub
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

### Two-Factor SSH (pam_google_authenticator)

```bash
# Install
apt-get install libpam-google-authenticator  # Ubuntu
yum install google-authenticator-libpam       # RHEL

# User setup
google-authenticator --time-based --disallow-reuse --force --qr-mode=ANSI

# /etc/pam.d/sshd — add at top:
auth required pam_google_authenticator.so nullok

# /etc/ssh/sshd_config
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

---

## 5. Kernel Hardening (sysctl)

### Full /etc/sysctl.d/99-hardening.conf

```ini
###############################################################################
# NETWORK SETTINGS
###############################################################################

# Disable IP forwarding (not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable ICMP redirects — prevents routing table manipulation (T1557)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log suspicious packets (martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore broadcast ICMP (Smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPv6 if not needed
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1
# net.ipv6.conf.lo.disable_ipv6 = 1

# TCP hardening
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0

###############################################################################
# MEMORY / KERNEL SETTINGS
###############################################################################

# Address Space Layout Randomization (ASLR) — 2 = full randomization
kernel.randomize_va_space = 2

# Restrict dmesg to root
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Disable SysRq key (prevents reboot, dump requests)
kernel.sysrq = 0

# Enable core dump PIDs
kernel.core_uses_pid = 1

# Restrict ptrace (YAMA LSM — 1 = only parent can ptrace)
kernel.yama.ptrace_scope = 1

# Restrict perf events
kernel.perf_event_paranoid = 3

###############################################################################
# FILESYSTEM SETTINGS
###############################################################################

# Protect hard links (only owner can create hard links)
fs.protected_hardlinks = 1

# Protect symbolic links (only owner can follow in sticky dirs)
fs.protected_symlinks = 1

# Disable SUID core dumps
fs.suid_dumpable = 0

# Protected FIFOs and regular files
fs.protected_fifos = 2
fs.protected_regular = 2
```

```bash
# Apply settings immediately
sysctl -p /etc/sysctl.d/99-hardening.conf

# Verify a specific setting
sysctl kernel.randomize_va_space
sysctl net.ipv4.conf.all.accept_redirects

# Display all current settings
sysctl -a 2>/dev/null | sort
```

### Memory Protection Explanations

| Feature | Description | Verification |
|---|---|---|
| ASLR | Randomizes memory addresses of stack, heap, libraries | `cat /proc/sys/kernel/randomize_va_space` → 2 |
| SMEP | Supervisor Mode Execution Prevention — prevents kernel from executing user-space code | `grep smep /proc/cpuinfo` |
| SMAP | Supervisor Mode Access Prevention — prevents kernel from accessing user-space data | `grep smap /proc/cpuinfo` |
| NX/XD bit | No-execute bit on memory pages — prevents data regions from executing | `grep -E ' nx | pae' /proc/cpuinfo` |
| Stack Canaries | Random value placed on stack to detect overflows | Compiler: `-fstack-protector-strong` |
| PIE | Position Independent Executables — works with ASLR | `file /usr/bin/ls | grep pie` |
| RELRO | Relocation Read-Only — prevents GOT overwrites | `checksec --file=/usr/bin/ls` |

### Kernel Module Restriction

```bash
# Load all needed modules first, then lock
# /etc/sysctl.d/99-hardening.conf — add after boot config is stable:
# kernel.modules_disabled = 1

# Verify no unexpected modules loaded
lsmod | sort
diff <(lsmod | sort) /etc/baseline_modules.txt

# Blacklist specific modules via modprobe
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
echo "install usb-storage /bin/true" >> /etc/modprobe.d/blacklist.conf
```

---

## 6. Filesystem & File Permissions

### SUID/SGID Audit

```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null | sort

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null | sort

# Find world-writable files (excluding /proc, /sys)
find / -perm -0002 -type f ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null

# Find world-writable directories
find / -perm -0002 -type d ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null

# Find unowned files (no user or group)
find / -nouser -nogroup ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null

# Expected minimal SUID set — compare against this baseline
EXPECTED_SUID=(
    /usr/bin/sudo
    /usr/bin/su
    /usr/bin/passwd
    /usr/bin/chfn
    /usr/bin/chsh
    /usr/bin/newgrp
    /usr/bin/gpasswd
    /usr/bin/mount
    /usr/bin/umount
    /usr/bin/pkexec
)
```

### Critical File Permissions

```bash
# Verify and fix critical file permissions
chmod 644 /etc/passwd
chown root:root /etc/passwd

chmod 000 /etc/shadow
chown root:shadow /etc/shadow
# Ubuntu may use 640:
chmod 640 /etc/shadow

chmod 000 /etc/gshadow
chown root:shadow /etc/gshadow

chmod 644 /etc/group
chown root:root /etc/group

chmod 440 /etc/sudoers
chown root:root /etc/sudoers

chmod 600 /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config

chmod 600 /boot/grub2/grub.cfg   # RHEL
chmod 600 /boot/grub/grub.cfg    # Ubuntu
chown root:root /boot/grub/grub.cfg

# SSH host keys
chmod 600 /etc/ssh/ssh_host_*_key
chmod 644 /etc/ssh/ssh_host_*_key.pub
chown root:root /etc/ssh/ssh_host_*

# Audit current permissions
stat -c "%n: %a %U:%G" /etc/passwd /etc/shadow /etc/gshadow /etc/group /etc/sudoers
```

### umask Hardening

```bash
# /etc/profile — system-wide default
umask 027

# /etc/bashrc or /etc/bash.bashrc
umask 027

# For root: stricter umask
# In /root/.bashrc
umask 077

# Verify current umask
umask
# 027 = owner: rwx, group: rx, others: none
```

### Sticky Bit on World-Writable Directories

```bash
# Set sticky bit (CIS 1.1.18)
chmod +t /tmp
chmod +t /var/tmp

# Verify
ls -ld /tmp /var/tmp
# Expected: drwxrwxrwt

# Find sticky-bit missing world-writable dirs
find / -type d -perm -0002 ! -perm -1000 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null
```

### File Integrity Monitoring with AIDE

```bash
# Install AIDE
apt-get install aide          # Ubuntu
yum install aide              # RHEL

# Configure /etc/aide/aide.conf or /etc/aide.conf
# Define what to monitor:
/etc PERMS+SHA256
/bin PERMS+SHA256
/sbin PERMS+SHA256
/usr/bin PERMS+SHA256
/usr/sbin PERMS+SHA256
/lib PERMS+SHA256
/lib64 PERMS+SHA256
/boot PERMS+SHA256

# Initialize database (do this on a known-clean system)
aide --init
cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Check against database
aide --check

# Update database after legitimate changes
aide --update

# Automate with cron
echo "0 5 * * * root /usr/sbin/aide --check | mail -s 'AIDE Report' security@corp.local" \
  >> /etc/crontab
```

---

## 7. SELinux & AppArmor

### SELinux (RHEL / CentOS / Fedora)

**Modes:**
- `enforcing` — policy is enforced; violations are denied and logged
- `permissive` — violations are logged only; policy is not enforced
- `disabled` — SELinux is not loaded (requires reboot to change)

```bash
# Check status
getenforce
sestatus

# /etc/selinux/config — persistent configuration
SELINUX=enforcing
SELINUXTYPE=targeted

# Temporarily change mode (no reboot needed)
setenforce 1   # enforcing
setenforce 0   # permissive

# Never set to disabled in production — use permissive for debugging
```

**File Context Management:**
```bash
# View file context
ls -Z /var/www/html

# Restore default contexts
restorecon -Rv /var/www/html

# Set custom context permanently
semanage fcontext -a -t httpd_sys_content_t "/var/www/html(/.*)?"
restorecon -Rv /var/www/html

# List all defined contexts
semanage fcontext -l
```

**Port Labeling:**
```bash
# Add non-standard port for httpd
semanage port -a -t http_port_t -p tcp 8080

# List ports for a service
semanage port -l | grep http

# Remove a port label
semanage port -d -t http_port_t -p tcp 8080
```

**Boolean Management:**
```bash
# List all booleans
getsebool -a

# Enable a boolean (persistent with -P)
setsebool -P httpd_can_network_connect on
setsebool -P httpd_use_nfs on

# Common production booleans
getsebool httpd_can_network_connect
getsebool allow_ftpd_full_access
```

**Troubleshooting:**
```bash
# Human-readable denial explanations
audit2why < /var/log/audit/audit.log

# Generate allow rules from denials
audit2allow -a

# Use sealert for graphical explanation (setroubleshoot-server)
sealert -a /var/log/audit/audit.log

# Find recent AVC denials
ausearch -m avc -ts recent

# Common fix: file created outside of managed dir
restorecon -Rv /path/to/dir
```

**Custom Policy Module:**
```bash
# Generate module from audit log
audit2allow -a -M myapp_policy
semodule -i myapp_policy.pp

# Remove module
semodule -r myapp_policy

# List loaded modules
semodule -l
```

### AppArmor (Ubuntu/Debian)

```bash
# Check status
aa-status
apparmor_status

# Enforce a profile
aa-enforce /etc/apparmor.d/usr.sbin.nginx

# Set profile to complain mode (log but don't block)
aa-complain /etc/apparmor.d/usr.sbin.nginx

# Disable a profile
aa-disable /etc/apparmor.d/usr.sbin.nginx
ln -s /etc/apparmor.d/usr.sbin.nginx /etc/apparmor.d/disable/
apparmor_parser -R /etc/apparmor.d/usr.sbin.nginx

# Reload a profile
apparmor_parser -r /etc/apparmor.d/usr.sbin.nginx
```

**Profile Development:**
```bash
# Generate profile interactively
aa-genprof /usr/bin/myapp

# Update profile based on log entries
aa-logprof

# View denials
dmesg | grep DENIED
grep DENIED /var/log/syslog
grep DENIED /var/log/kern.log
```

**Snap Confinement:**
```bash
# Check snap confinement status
snap list
snap info package_name | grep confinement

# Snap uses strict, devmode, or classic confinement
# strict = full AppArmor/seccomp confinement
```

---

## 8. Auditd — Linux Audit Framework

### Full /etc/audit/rules.d/hardening.rules

```
## /etc/audit/rules.d/hardening.rules
## CIS Section 4.1 — DISA STIG Audit Rules

# Delete all existing rules
-D

# Buffer size — increase for busy systems
-b 8192

# Failure mode: 0=silent, 1=printk, 2=panic
-f 2

###############################################################################
# TIME CHANGES (T1070.006)
###############################################################################
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

###############################################################################
# IDENTITY CHANGES (T1136, T1098)
###############################################################################
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

###############################################################################
# SUDO / SUDOERS (T1548.003)
###############################################################################
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

###############################################################################
# AUTHENTICATION / LOGINS (T1110)
###############################################################################
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/log/tallylog -p wa -k logins

###############################################################################
# SESSION TRACKING
###############################################################################
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

###############################################################################
# PRIVILEGE ESCALATION (T1548.001)
###############################################################################
-a always,exit -F arch=b64 -S setuid -F a0=0 -F exe=/usr/bin/su -k privileged
-a always,exit -F arch=b32 -S setuid -F a0=0 -F exe=/usr/bin/su -k privileged
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /usr/bin/newgrp -p x -k priv_esc
-w /usr/bin/chsh -p x -k priv_esc
-w /usr/bin/chfn -p x -k priv_esc

###############################################################################
# KERNEL MODULE LOADING (T1215)
###############################################################################
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /usr/sbin/insmod -p x -k modules
-w /usr/sbin/rmmod -p x -k modules
-w /usr/sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules

###############################################################################
# SYSTEM LOCALE / NETWORK CONFIG
###############################################################################
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/network/interfaces -p wa -k system-locale

###############################################################################
# MANDATORY ACCESS CONTROLS
###############################################################################
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

###############################################################################
# PROCESS EXECUTION LOGGING (T1059.004)
###############################################################################
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

###############################################################################
# FILE DELETION (T1070.004)
###############################################################################
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -k delete

###############################################################################
# ACCESS CONTROL CHANGES (T1222)
###############################################################################
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -k perm_mod

###############################################################################
# UNAUTHORIZED FILE ACCESS (T1083)
###############################################################################
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EACCES -F auid>=1000 -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EPERM -F auid>=1000 -k access

###############################################################################
# MOUNT OPERATIONS (T1052)
###############################################################################
-a always,exit -F arch=b64 -S mount -F auid>=1000 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -k mounts

###############################################################################
# MAKE RULES IMMUTABLE (must reboot to modify audit rules)
###############################################################################
-e 2
```

```bash
# Load rules
augenrules --load
# OR
auditctl -R /etc/audit/rules.d/hardening.rules

# Verify rules loaded
auditctl -l

# Check audit daemon status
systemctl status auditd

# Query audit log
ausearch -k priv_esc -ts today
ausearch -k identity -ts recent
ausearch -k exec -ui 1001 -ts yesterday

# Reports
aureport --summary
aureport --login --summary
aureport --auth --summary
aureport --exe --summary

# Trace a process
autrace /bin/ls /tmp
```

---

## 9. Firewall (nftables & iptables)

### nftables (Modern — Recommended)

```bash
# Check status
nft list ruleset
systemctl status nftables

# /etc/nftables.conf — default-deny with logging
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established/related connections
        ct state established,related accept

        # Drop invalid connections
        ct state invalid drop

        # Allow SSH (change port as needed)
        tcp dport 22 ct state new accept

        # Allow web services (remove if not needed)
        tcp dport {80, 443} ct state new accept

        # Allow ICMP (rate limited)
        ip protocol icmp icmp type echo-request limit rate 10/second accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 10/second accept

        # Log and drop everything else
        log prefix "INPUT DROP: " flags all drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
        # Optionally restrict egress
        # ct state established,related accept
    }
}
```

```bash
# Apply config
systemctl enable nftables
systemctl restart nftables

# Test config without applying
nft --check --file /etc/nftables.conf

# Add rule dynamically (not persistent)
nft add rule inet filter input tcp dport 8080 accept
```

### iptables (Legacy — Still Common)

```bash
# Default-deny policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established/related
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Allow SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Allow web
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Rate-limit SSH (prevent brute force)
iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# Log and drop
iptables -A INPUT -j LOG --log-prefix "IPTABLES DROP: " --log-level 7
iptables -A INPUT -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
```

### firewalld (RHEL/CentOS)

```bash
# Check status
firewall-cmd --state
firewall-cmd --get-default-zone    # Should be public or drop

# Set default to drop
firewall-cmd --set-default-zone=drop

# Allow SSH in drop zone explicitly
firewall-cmd --permanent --zone=drop --add-service=ssh
firewall-cmd --permanent --zone=drop --add-service=https

# List rules
firewall-cmd --permanent --zone=drop --list-all

# Reload
firewall-cmd --reload

# Panic mode (drop ALL incoming/outgoing)
firewall-cmd --panic-on
firewall-cmd --panic-off
```

### ufw (Ubuntu Simplified Firewall)

```bash
# Set default policies
ufw default deny incoming
ufw default allow outgoing

# Allow specific services
ufw allow 22/tcp comment 'SSH'
ufw allow 443/tcp comment 'HTTPS'

# Rate-limit SSH
ufw limit 22/tcp

# Enable
ufw enable
ufw status verbose

# Delete a rule
ufw delete allow 80/tcp
```

---

## 10. Service Hardening

### systemd Service Sandboxing

Apply to any service requiring additional isolation. Add to `[Service]` section:

```ini
[Service]
# Privilege restrictions
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=

# Filesystem restrictions
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/myapp /run/myapp
PrivateTmp=yes
PrivateDevices=yes

# Kernel restrictions
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes

# Namespace restrictions
PrivateNetwork=no
RestrictNamespaces=yes
PrivateMounts=yes

# System call filtering
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native

# Memory restrictions
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes

# Network restrictions
RestrictAddressFamilies=AF_INET AF_INET6
IPAddressAllow=any
# Or restrict to specific IPs:
# IPAddressAllow=10.0.0.0/8
# IPAddressDeny=any
```

```bash
# Analyze current service security level
systemd-analyze security nginx
systemd-analyze security sshd

# Higher score = more exposure
# Target: 0-2 (SAFE), avoid 7+ (UNSAFE)
```

### Disable Unnecessary Services

```bash
# Common services to disable on servers
DISABLE_SERVICES=(
    avahi-daemon    # mDNS/zeroconf — unneeded on servers
    cups            # Printing
    rpcbind         # NFS prerequisite
    nfs-server      # Network file sharing
    rsh             # Remote shell (insecure)
    telnet          # Unencrypted remote access
    vsftpd          # FTP (use SFTP instead)
    talk talkd      # Talk daemon
    xinetd          # Super-server (legacy)
    sendmail        # Mail server (if not needed)
)

for svc in "${DISABLE_SERVICES[@]}"; do
    systemctl disable --now $svc 2>/dev/null && echo "Disabled: $svc" || true
done
```

```bash
# Enumerate running services
systemctl list-units --type=service --state=running

# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# Check listening ports and responsible services
ss -tlnp
```

---

## 11. Logging & Monitoring

### rsyslog Centralization

```bash
# /etc/rsyslog.conf or /etc/rsyslog.d/99-remote.conf

# Forward all logs to SIEM over TCP with TLS
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /etc/ssl/certs/siem-ca.crt
$DefaultNetstreamDriverCertFile /etc/ssl/certs/client-cert.pem
$DefaultNetstreamDriverKeyFile /etc/ssl/private/client-key.pem

*.* @@siem.corp.local:514    # TCP (double @)
*.* @siem.corp.local:514     # UDP (single @)

# Or with omrelp for reliable delivery
module(load="omrelp")
*.* action(type="omrelp" target="siem.corp.local" port="20514")
```

### journald Remote Forwarding

```bash
# Install
apt-get install systemd-journal-remote    # Ubuntu
yum install systemd-journal-remote        # RHEL

# /etc/systemd/journal-upload.conf
[Upload]
URL=https://siem.corp.local:19532
ServerKeyFile=/etc/ssl/private/journal-upload.key
ServerCertificateFile=/etc/ssl/certs/journal-upload.cert
TrustedCertificateFile=/etc/ssl/certs/ca-bundle.crt

systemctl enable systemd-journal-upload
systemctl start systemd-journal-upload
```

### Key Log Files

| Log File | Content | ATT&CK Relevance |
|---|---|---|
| `/var/log/auth.log` (Ubuntu) | Authentication, sudo, SSH | T1110, T1021.004, T1548.003 |
| `/var/log/secure` (RHEL) | Authentication events | T1110 |
| `/var/log/syslog` (Ubuntu) | General system messages | General |
| `/var/log/messages` (RHEL) | General system messages | General |
| `/var/log/audit/audit.log` | Auditd events | All categories |
| `/var/log/faillog` | Failed login attempts | T1110 |
| `/var/log/lastlog` | Last login per user | T1078 |
| `/var/log/kern.log` | Kernel messages, hardware | T1215, T1014 |
| `/var/log/cron` | Cron job execution | T1053.003 |
| `/var/log/sudo.log` | Sudo command logging | T1548.003 |
| `/var/log/wtmp` | Login/logout history | T1078 |
| `/var/log/btmp` | Failed logins | T1110 |

### Detection Commands

```bash
# New SUID binary since last baseline
find / -newer /var/lib/aide/aide.db -perm -4000 2>/dev/null

# Unusual crontabs for all users
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v '^#' | \
      while read line; do echo "$user: $line"; done
done

# System cron jobs
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/
cat /etc/crontab

# Current listening ports vs baseline
ss -tlnp | sort > /tmp/current_ports.txt
diff /etc/baseline_ports.txt /tmp/current_ports.txt

# Unusual established connections
ss -anp | grep ESTABLISHED

# Processes with deleted executables (indicator of in-memory malware)
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Users currently logged in
who; w; last -25

# Recent authentication events
tail -n 100 /var/log/auth.log | grep -E 'Failed|Invalid|Accepted|session opened'
journalctl -u sshd --since "1 hour ago"
```

---

## 12. CIS Benchmark Quick Reference

| CIS ID | Level | Control | Command / Setting |
|---|---|---|---|
| 1.1.1.1 | 1 | Disable cramfs | `echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf` |
| 1.1.2 | 1 | /tmp — nodev,nosuid,noexec | `/etc/fstab` mount options |
| 1.1.6 | 1 | /dev/shm — nodev,nosuid,noexec | `tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0` |
| 1.3.1 | 1 | AIDE installed | `apt install aide` / `yum install aide` |
| 1.3.2 | 1 | AIDE cron check | Daily cron: `aide --check` |
| 1.4.1 | 1 | GRUB password set | `grub-mkpasswd-pbkdf2` + `/etc/grub.d/40_custom` |
| 1.5.1 | 1 | core dumps restricted | `fs.suid_dumpable = 0` in sysctl |
| 1.5.2 | 1 | ASLR enabled | `kernel.randomize_va_space = 2` |
| 1.6.1.1 | 1 | SELinux/AppArmor installed | `sestatus` / `aa-status` |
| 1.6.1.2 | 1 | SELinux/AppArmor enabled | SELINUX=enforcing in `/etc/selinux/config` |
| 2.1.1 | 1 | inetd/xinetd not installed | `systemctl disable xinetd` |
| 2.2.x | 1 | Disable unused servers | Disable cups, rpcbind, nfs, etc. |
| 3.1.1 | 1 | IP forwarding disabled | `net.ipv4.ip_forward = 0` |
| 3.2.1 | 1 | Source routed packets rejected | `net.ipv4.conf.all.accept_source_route = 0` |
| 3.2.2 | 1 | ICMP redirects not accepted | `net.ipv4.conf.all.accept_redirects = 0` |
| 3.2.4 | 1 | Suspicious packets logged | `net.ipv4.conf.all.log_martians = 1` |
| 3.3.2 | 1 | nftables/iptables installed | `systemctl enable nftables` |
| 4.1.1.1 | 2 | Auditd installed | `yum install audit` |
| 4.1.1.2 | 2 | Auditd enabled | `systemctl enable auditd` |
| 4.1.1.3 | 2 | Audit backlog limit | `-b 8192` in rules |
| 4.1.3 | 2 | Log file permissions | `chmod 640 /var/log/audit/audit.log` |
| 4.2.1.1 | 1 | rsyslog installed | `apt install rsyslog` |
| 4.2.1.4 | 1 | rsyslog remote logging | `*.* @@siem.corp.local:514` |
| 5.1.1 | 1 | cron daemon enabled | `systemctl enable cron` |
| 5.1.2 | 1 | /etc/crontab permissions | `chmod 600 /etc/crontab` |
| 5.2.1 | 1 | sshd_config permissions | `chmod 600 /etc/ssh/sshd_config` |
| 5.2.7 | 1 | SSH MaxAuthTries ≤ 4 | `MaxAuthTries 4` |
| 5.2.8 | 1 | SSH IgnoreRhosts yes | `IgnoreRhosts yes` |
| 5.2.11 | 1 | SSH PermitEmptyPasswords no | `PermitEmptyPasswords no` |
| 5.2.13 | 1 | SSH Limit access | `AllowUsers` or `AllowGroups` |
| 5.4.1.1 | 1 | PASS_MAX_DAYS 365 or less | `/etc/login.defs`: `PASS_MAX_DAYS 90` |
| 5.4.1.4 | 1 | Inactive account lockout | `useradd -D -f 30` |
| 5.4.2.7 | 1 | Root default group is GID 0 | `usermod -g 0 root` |
| 6.1.2 | 1 | /etc/passwd permissions | `chmod 644 /etc/passwd` |
| 6.1.3 | 1 | /etc/shadow permissions | `chmod 000 /etc/shadow` |
| 6.1.6 | 1 | /etc/passwd- permissions | `chmod 600 /etc/passwd-` |
| 6.2.1 | 1 | No accounts with empty passwords | `awk -F: '($2==""){print}' /etc/shadow` |
| 6.2.2 | 1 | No legacy '+' entries | `grep '^+' /etc/passwd /etc/shadow /etc/group` |

---

## 13. DISA STIG CAT I Requirements (Linux)

CAT I findings represent the highest severity — immediate risk if not addressed.

| STIG ID | Title | Remediation |
|---|---|---|
| RHEL-09-211010 | RHEL 9 must not have accounts with empty passwords | `awk -F: '($2==""){print $1}' /etc/shadow` → lock or set password |
| RHEL-09-211020 | RHEL 9 must not have root logins on non-console TTYs | Remove all entries from `/etc/securetty` except `console` or `tty1` |
| RHEL-09-215010 | RHEL 9 must use a FIPS-validated cryptographic module | `fips-mode-setup --enable` (requires reboot) |
| RHEL-09-231090 | RHEL 9 /etc/shadow must be group-owned by root | `chown root:root /etc/shadow` |
| RHEL-09-232035 | RHEL 9 must not allow USB storage (removable media) | `echo "install usb-storage /bin/true" >> /etc/modprobe.d/blacklist.conf` |
| RHEL-09-251010 | RHEL 9 must not permit SSH root login | `PermitRootLogin no` in sshd_config |
| RHEL-09-251020 | RHEL 9 SSH daemon must not use CBC ciphers | Remove cbc ciphers from `Ciphers` in sshd_config |
| RHEL-09-251035 | RHEL 9 must enforce SSH v2 only | `Protocol 2` in sshd_config |
| RHEL-09-255040 | RHEL 9 SSH must not allow empty passwords | `PermitEmptyPasswords no` |
| RHEL-09-271040 | RHEL 9 must use the latest PKI standards | Configure smartcard/CAC authentication via sssd + pam_pkcs11 |
| RHEL-09-431010 | RHEL 9 must enable SELinux in enforcing mode | `SELINUX=enforcing` in `/etc/selinux/config` |
| RHEL-09-431015 | RHEL 9 SELinux must use targeted or MLS policy | `SELINUXTYPE=targeted` or `mls` |
| RHEL-09-611010 | RHEL 9 must enforce password complexity | PAM pwquality: `minlen=15 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1` |
| RHEL-09-611030 | RHEL 9 passwords must not be reused within 5 generations | PAM: `remember=5` on pam_unix.so line |
| RHEL-09-651010 | RHEL 9 must implement DoD-approved PKI for authentication | Enable certificate-based authentication; disable password auth |

---

## 14. Rootkit Detection & Response

### Detection Tools

```bash
# rkhunter — Rootkit Hunter
rkhunter --update                      # Update database
rkhunter --check --sk --rwo            # Check (skip keypress, report warnings only)
rkhunter --check --verbose             # Full verbose output
cat /var/log/rkhunter.log              # Review log

# chkrootkit
chkrootkit                             # Run all tests
chkrootkit -x | less                   # Expert mode

# Lynis — Security audit
lynis audit system                     # Full audit
lynis audit system --quick             # Quick audit
lynis show details [test-id]           # Details on specific test
cat /var/log/lynis.log                 # Review log
cat /var/log/lynis-report.dat          # Machine-readable report
```

### /proc Analysis

```bash
# Find processes with deleted executables (hollowed processes)
ls -la /proc/*/exe 2>/dev/null | grep deleted

# Check process command lines
for pid in /proc/[0-9]*; do
    [ -f "$pid/cmdline" ] && printf "%s: " $pid && cat "$pid/cmdline" | tr '\0' ' ' && echo
done 2>/dev/null | grep -v '^$'

# Compare loaded libraries of a process to on-disk files
lsof -p PID | grep REG | awk '{print $9}' | sort -u

# Check for hidden processes (compare ps vs /proc)
comm -23 <(ps -eo pid= | sort -n) <(ls /proc | grep '^[0-9]' | sort -n)
```

### LD_PRELOAD Rootkit Detection

```bash
# Check ld.so.preload (should be empty or absent)
cat /etc/ld.so.preload
ls -la /etc/ld.so.preload

# Check LD_PRELOAD in running processes
for pid in /proc/[0-9]*; do
    preload=$(cat "$pid/environ" 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD)
    [ -n "$preload" ] && echo "PID $pid: $preload"
done

# Use lsof to find unusual loaded libraries
lsof -p PID | grep mem | grep -v '\.so'

# Check maps for anonymous executable regions
grep rwxp /proc/PID/maps | grep -v '\.so\|vsyscall\|vdso\|stack\|heap'
```

### Kernel Rootkit Indicators

```bash
# Check syscall table via /proc/kallsyms (requires root)
cat /proc/kallsyms | grep sys_call_table

# Check for hidden kernel modules
# Compare lsmod to /proc/modules
diff <(lsmod | awk '{print $1}' | sort) <(cat /proc/modules | awk '{print $1}' | sort)

# Check /dev for unusual files
ls -la /dev | grep -v "^[bcl]"    # Non-block/char/link files in /dev

# Detect DKOM (Direct Kernel Object Manipulation) — harder, use Volatility
# Acquire memory with LiME
modprobe lime path=/tmp/memory.lime format=lime
```

### Memory Forensics with LiME

```bash
# Build LiME (Linux Memory Extractor)
git clone https://github.com/504ensicslabs/lime.git
cd lime/src
make

# Acquire memory
insmod lime-$(uname -r).ko "path=/tmp/memory.lime format=lime"
# Over network:
insmod lime.ko "path=tcp:4444 format=lime"
# On collecting machine:
nc victim_ip 4444 > memory.lime

# Analyze with Volatility 3
python3 vol.py -f memory.lime linux.pslist
python3 vol.py -f memory.lime linux.pstree
python3 vol.py -f memory.lime linux.netstat
python3 vol.py -f memory.lime linux.lsmod
```

---

## 15. Incident Response on Linux

### Quick Triage Commands

```bash
#!/bin/bash
# Linux Incident Response Triage Script
# Run as root; output to timestamped directory

IR_DIR="/tmp/ir-$(hostname)-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$IR_DIR"
exec 1> >(tee -a "$IR_DIR/triage.log") 2>&1

echo "=== SYSTEM INFO ==="
uname -a; hostname; date; uptime

echo "=== LOGGED IN USERS ==="
who; w; last -25

echo "=== PROCESS TREE ==="
ps auxf

echo "=== NETWORK CONNECTIONS ==="
ss -anp
netstat -antp 2>/dev/null

echo "=== OPEN NETWORK FILES ==="
lsof -i

echo "=== LISTENING PORTS ==="
ss -tlnp

echo "=== SCHEDULED TASKS ==="
crontab -l 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.*
for user in $(cut -f1 -d: /etc/passwd); do
    output=$(crontab -u $user -l 2>/dev/null)
    [ -n "$output" ] && echo "CRONTAB $user: $output"
done

echo "=== TEMP FILES ==="
find /tmp /var/tmp -type f -ls 2>/dev/null

echo "=== SUSPICIOUS TEMP EXECUTABLES ==="
find /tmp /var/tmp -type f -perm /111 2>/dev/null

echo "=== UID 0 ACCOUNTS ==="
awk -F: '($3 == "0") { print $1 }' /etc/passwd

echo "=== RECENTLY MODIFIED FILES ==="
find /etc /bin /sbin /usr/bin /usr/sbin -newer /tmp -type f 2>/dev/null | head -50

echo "=== DELETED EXECUTABLES IN /proc ==="
ls -la /proc/*/exe 2>/dev/null | grep deleted

echo "=== KERNEL MODULES ==="
lsmod

echo "=== LD_PRELOAD CHECK ==="
cat /etc/ld.so.preload 2>/dev/null && echo "(file exists)" || echo "(file not found — normal)"

echo "=== AUTHORIZED KEYS ==="
for user in $(cut -f1 -d: /etc/passwd); do
    keyfile=$(eval echo "~$user/.ssh/authorized_keys" 2>/dev/null)
    [ -f "$keyfile" ] && echo "=== $user ===" && cat "$keyfile"
done

echo "=== SYSTEMD USER UNITS ==="
find /etc/systemd /usr/lib/systemd /run/systemd -name "*.service" -newer /var/lib/dpkg/info 2>/dev/null

echo "=== RECENT AUTH EVENTS ==="
tail -n 200 /var/log/auth.log 2>/dev/null || tail -n 200 /var/log/secure 2>/dev/null

echo "Triage complete: $IR_DIR"
```

### Persistence Mechanisms Checklist

| Mechanism | Check Command | ATT&CK |
|---|---|---|
| User crontab | `for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null; done` | T1053.003 |
| System cron | `cat /etc/crontab; ls /etc/cron.d/` | T1053.003 |
| Systemd services | `find /etc/systemd /usr/lib/systemd -name "*.service"` | T1543.002 |
| Init scripts | `ls /etc/init.d/ /etc/rc.local` | T1037.004 |
| .bashrc / .profile | `find /home /root -name ".bashrc" -o -name ".bash_profile" -o -name ".profile"` | T1546.004 |
| /etc/profile.d | `ls -la /etc/profile.d/` | T1546.004 |
| SSH authorized_keys | `find / -name authorized_keys 2>/dev/null` | T1098.004 |
| SUID binaries | `find / -perm -4000 -type f 2>/dev/null` | T1548.001 |
| LD_PRELOAD | `cat /etc/ld.so.preload` | T1574.006 |
| Kernel modules | `lsmod` and check `/etc/modules-load.d/` | T1215 |
| /etc/passwd new accounts | `awk -F: '$3 >= 1000 {print}' /etc/passwd` | T1136.001 |
| AT jobs | `atq 2>/dev/null` | T1053.001 |
| PAM backdoors | `diff /etc/pam.d/sshd /etc/pam.d/sshd.bak` | T1556.003 |
| Alias backdoors | `grep -r alias /etc/profile.d/ /etc/bash.bashrc /root/.bashrc` | T1059.004 |

### Evidence Preservation

```bash
# Capture volatile data first (memory, running processes, network)
date -u > /tmp/ir-timeline.txt

# Process list with full paths
ps auxwwef >> /tmp/ir-procs.txt

# Network connections with PIDs
ss -anpe >> /tmp/ir-network.txt

# Hash all running executable binaries
for pid in /proc/[0-9]*/exe; do
    target=$(readlink $pid 2>/dev/null)
    [ -f "$target" ] && md5sum "$target"
done 2>/dev/null | sort -u >> /tmp/ir-exe-hashes.txt

# Disk image (if needed — requires offline media)
dd if=/dev/sda of=/media/external/disk.img bs=4M status=progress
# Or targeted:
dc3dd if=/dev/sda hash=sha256 hlog=/media/external/disk.log of=/media/external/disk.img

# Memory acquisition
insmod /path/to/lime.ko "path=/media/external/memory.lime format=lime"
```

---

## Quick Reference — Hardening Checklist

```
[ ] Separate /tmp, /var, /var/log with noexec/nosuid/nodev
[ ] GRUB2 bootloader password set
[ ] Unnecessary packages removed
[ ] Unused filesystems disabled in modprobe
[ ] Password policy: max 90 days, min 14 chars, complexity
[ ] PAM faillock: 5 attempts, 15-minute lockout
[ ] Root login locked; PermitRootLogin no in sshd
[ ] Sudo logging enabled; NOPASSWD removed
[ ] SSH: Protocol 2, key auth only, no root, no empty passwords
[ ] SSH: Hardened ciphers, MACs, KEX algorithms
[ ] Kernel: ASLR=2, dmesg_restrict=1, kptr_restrict=2
[ ] Kernel: IP forwarding off, ICMP redirects off, martian logging on
[ ] SELinux enforcing OR AppArmor enforced
[ ] Auditd running with hardened ruleset; -e 2 immutable
[ ] Firewall default-deny; only required ports open
[ ] Unnecessary services disabled
[ ] Logs forwarded to centralized SIEM over TLS
[ ] AIDE file integrity database initialized and daily check scheduled
[ ] SUID/SGID audit complete; no unexpected binaries
[ ] CIS Benchmark scan: score >75%
[ ] STIG STIG Viewer: 0 CAT I open findings
```

---

*Generated for TeamStarWolf Cybersecurity Reference Library — Linux Hardening*
*Covers: Ubuntu 22.04 LTS | RHEL 9 | CIS Benchmarks | DISA STIGs | MITRE ATT&CK v14*
