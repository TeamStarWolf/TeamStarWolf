# Linux Hardening Reference Library

> **A comprehensive professional reference for Linux system hardening, compliance, and security operations.**

---

## Table of Contents

1. [Linux Hardening Fundamentals & CIS Benchmarks](#1-linux-hardening-fundamentals--cis-benchmarks)
2. [User & Authentication Hardening](#2-user--authentication-hardening)
3. [Filesystem Security](#3-filesystem-security)
4. [Kernel Hardening & sysctl](#4-kernel-hardening--sysctl)
5. [SELinux Configuration](#5-selinux-configuration)
6. [Network Security & Firewall](#6-network-security--firewall)
7. [Auditd & System Logging](#7-auditd--system-logging)
8. [Service Hardening & Application Security](#8-service-hardening--application-security)
9. [Intrusion Detection & Monitoring](#9-intrusion-detection--monitoring)
10. [Compliance, Automation & References](#10-compliance-automation--references)

---

## 1. Linux Hardening Fundamentals & CIS Benchmarks

### 1.1 CIS Benchmark Overview

The Center for Internet Security (CIS) publishes benchmarks for all major Linux distributions. Benchmarks are organized into two profiles:

| Profile | Description | Target |
|---------|-------------|--------|
| **Level 1** | Essential, practical controls with minimal performance impact | All systems |
| **Level 2** | Defense-in-depth controls that may impact functionality | High-security environments |

Key CIS Benchmark publications:
- CIS Red Hat Enterprise Linux 9 Benchmark
- CIS Ubuntu Linux 22.04 LTS Benchmark
- CIS Debian Linux 12 Benchmark
- CIS Amazon Linux 2023 Benchmark
- CIS Oracle Linux 9 Benchmark

### 1.2 Automated Compliance Scoring

**CIS-CAT Pro** (commercial, requires membership):
```
# Run CIS-CAT Pro against local system
./Assessor-CLI.sh -i -rd /var/reports -rp ciscat_report
```

**OpenSCAP** (open source, fully functional):
```bash
# Install on RHEL/CentOS/Fedora
dnf install openscap-scanner scap-security-guide

# Install on Ubuntu/Debian
apt-get install libopenscap8 ssg-debian ssg-debderived

# Run CIS Level 2 profile assessment on RHEL 9
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --results /tmp/results.xml \
  --report /tmp/report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Run Level 1 profile
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_server_l1 \
  --results /tmp/results-l1.xml \
  --report /tmp/report-l1.html \
  /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Generate a remediation script from scan results
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --fix-type bash \
  /tmp/results.xml > remediation.sh
```

### 1.3 STIG (Security Technical Implementation Guide)

DISA STIGs are mandatory for U.S. Department of Defense systems and represent the gold standard for government Linux hardening.

- **Source**: https://public.cyber.mil/stigs/
- **STIG Viewer**: GUI tool for reviewing STIG checklists
- **SCAP Content**: Downloadable XCCDF/OVAL content for automated scanning

```bash
# Run DISA STIG profile assessment
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results /tmp/stig-results.xml \
  --report /tmp/stig-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

### 1.4 Hardening Categories Overview

| Category | Key Controls |
|----------|-------------|
| OS Configuration | Boot security, GRUB password, core dumps disabled |
| User Management | Password policy, MFA, PAM, sudo restrictions |
| Network | Firewall rules, service minimization, TCP wrappers |
| Logging & Auditing | auditd rules, rsyslog forwarding, log retention |
| Filesystem | Mount options, SUID audit, file integrity monitoring |
| Services | Disable unused services, systemd hardening directives |
| Kernel Parameters | sysctl hardening, ASLR, ptrace restrictions |

### 1.5 Minimal Installation Principle

Servers should never have a graphical desktop environment (GUI). Remove all unneeded packages:

```bash
# RHEL/CentOS/Fedora -- remove legacy/insecure services
dnf remove telnet ftp rsh ypbind nis xinetd talk talk-server

# Verify installed packages
rpm -qa | sort
rpm -qa --queryformat '%{NAME}\n' | sort > /tmp/installed.txt

# Debian/Ubuntu -- remove unnecessary packages
apt-get remove telnet nis rsh-client rsh-redone-client
dpkg -l | grep "^ii" | awk '{print $2}' | sort

# List and remove packages no longer needed
apt-get autoremove --purge

# Check for packages with no reason to be installed
deborphan   # Debian/Ubuntu
```

### 1.6 OS Update Management

**RHEL/CentOS -- dnf-automatic:**
```bash
# Install
dnf install dnf-automatic

# Configure /etc/dnf/automatic.conf
# apply_updates = yes
# upgrade_type = security   # Only security updates
# emit_via = stdio

# Enable and start timer
systemctl enable --now dnf-automatic-install.timer

# Check status
systemctl status dnf-automatic-install.timer
```

**Debian/Ubuntu -- unattended-upgrades:**
```bash
apt-get install unattended-upgrades apt-listchanges

# Configure /etc/apt/apt.conf.d/50unattended-upgrades
# Unattended-Upgrade::Allowed-Origins {
#   "${distro_id}:${distro_codename}-security";
# };
# Unattended-Upgrade::AutoFixInterruptedDpkg "true";
# Unattended-Upgrade::Remove-Unused-Dependencies "true";
# Unattended-Upgrade::Automatic-Reboot "false";

# Enable
dpkg-reconfigure --priority=low unattended-upgrades

# Test (dry run)
unattended-upgrades --dry-run --debug
```

### 1.7 Hardening Automation

**Ansible Hardening Roles:**

```bash
# dev-sec/linux-baseline -- comprehensive baseline
ansible-galaxy install dev-sec.os-hardening
ansible-galaxy install dev-sec.ssh-hardening

# Example playbook
# ---
# - hosts: all
#   roles:
#     - dev-sec.os-hardening
#     - dev-sec.ssh-hardening
#   vars:
#     os_auth_pw_max_age: 90
#     os_auth_pw_min_age: 7
#     ssh_permit_root_login: "no"

# openstack/ansible-hardening (STIG-focused)
ansible-galaxy install openstack.ansible_hardening

# RedHat RHEL System Roles
dnf install rhel-system-roles
# /usr/share/ansible/roles/rhel-system-roles.security_profiles
```

**Quick Hardening Check:**
```bash
# Lynis -- comprehensive security audit
apt-get install lynis   # or: dnf install lynis
lynis audit system
# Review: /var/log/lynis.log and /var/log/lynis-report.dat

# Check hardening index score (target: > 80)
grep "hardening_index" /var/log/lynis-report.dat
```

---

## 2. User & Authentication Hardening

### 2.1 PAM (Pluggable Authentication Modules)

PAM provides a flexible framework for authentication. Configuration files live in `/etc/pam.d/`.

**Key PAM config files:**

| File | System | Purpose |
|------|--------|---------|
| `/etc/pam.d/system-auth` | RHEL/CentOS | System-wide auth stack |
| `/etc/pam.d/password-auth` | RHEL/CentOS | Remote auth stack |
| `/etc/pam.d/common-auth` | Debian/Ubuntu | System-wide auth |
| `/etc/pam.d/common-password` | Debian/Ubuntu | Password policies |

**PAM module stack order:**
```
auth     required   pam_faillock.so preauth
auth     required   pam_unix.so
auth     [default=die] pam_faillock.so authfail
account  required   pam_faillock.so
account  required   pam_unix.so
password required   pam_pwquality.so retry=3
password required   pam_unix.so shadow sha512 remember=24
session  required   pam_limits.so
session  required   pam_unix.so
```

### 2.2 Password Policy Enforcement

**pam_pwquality configuration** (`/etc/security/pwquality.conf`):
```ini
# Minimum password length
minlen = 14

# Minimum number of character classes required (lowercase, uppercase, digits, other)
minclass = 4

# Maximum number of allowed same consecutive characters
maxrepeat = 3

# Maximum number of allowed same consecutive characters in the same class
maxclassrepeat = 4

# Reject password if it contains the username
reject_username = 1

# Check against common word dictionaries
dictcheck = 1

# Number of characters that must differ from old password
difok = 8

# Remember last N passwords (prevents reuse)
# Note: Actual enforcement is in pam_unix: remember=24
```

**PAM password module line:**
```
password requisite pam_pwquality.so try_first_pass local_users_only retry=3 authtok_type=
```

**Password aging via chage:**
```bash
# Set password maximum age (90 days), minimum age (7 days), warning (14 days)
chage -M 90 -m 7 -W 14 username

# View current settings
chage -l username

# Set account expiry date
chage -E 2025-12-31 username

# Force password change on next login
chage -d 0 username

# /etc/login.defs -- global defaults
# PASS_MAX_DAYS   90
# PASS_MIN_DAYS   7
# PASS_WARN_AGE   14
# PASS_MIN_LEN    14  (supplemental to pam_pwquality)
```

### 2.3 Account Lockout Policy

**pam_faillock (RHEL 8+/modern systems):**

`/etc/security/faillock.conf`:
```ini
# Lock account after 5 failed attempts
deny = 5

# Unlock after 15 minutes (900 seconds)
unlock_time = 900

# Consider failures only within this window (seconds)
fail_interval = 900

# Also lock root (use with caution)
# even_root

# Audit failed attempts
audit
```

**PAM lines for faillock:**
```
auth  required   pam_faillock.so preauth
auth  [default=die] pam_faillock.so authfail
account required pam_faillock.so
```

**Faillock management commands:**
```bash
# View failed attempts for a user
faillock --user username

# Reset lockout for a user
faillock --user username --reset

# View all locked accounts
faillock

# Legacy pam_tally2 (older systems)
pam_tally2 --user username
pam_tally2 --user username --reset
```

### 2.4 Shadow Password Security

```bash
# Correct permissions on sensitive files
chmod 000 /etc/shadow
chmod 644 /etc/passwd
chmod 000 /etc/gshadow
chmod 644 /etc/group

# Verify no password hashes in /etc/passwd (should show 'x')
awk -F: '($2 != "x") {print $1}' /etc/passwd

# Find accounts with empty passwords
awk -F: '($2 == "" ) {print $1}' /etc/shadow

# Lock accounts that should not log in
usermod -L -s /sbin/nologin serviceuseraccount

# Find all accounts with UID 0 (should only be root)
awk -F: '($3 == 0) {print $1}' /etc/passwd
```

### 2.5 Privileged Access Management (sudo)

**Best practices for `/etc/sudoers` (edit with `visudo`):**
```bash
# Good: Specific command restrictions
username ALL=(ALL) /usr/bin/systemctl restart nginx, /usr/bin/tail -f /var/log/nginx/error.log

# Good: Group-based access
%wheel  ALL=(ALL) ALL

# Avoid: NOPASSWD in production
# username ALL=(ALL) NOPASSWD: ALL  <-- Do not use

# Enable sudo logging
Defaults log_output
Defaults logfile="/var/log/sudo.log"
Defaults loglinelen=0

# Require TTY (prevents sudo from scripts without a terminal)
Defaults requiretty

# Set timeout (minutes of inactivity before re-prompt)
Defaults timestamp_timeout=5

# Drop-in files in /etc/sudoers.d/
# Use: visudo -f /etc/sudoers.d/myapp
```

### 2.6 SSH Hardening

**`/etc/ssh/sshd_config` hardened configuration:**
```bash
# Protocol and identity
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no

# Session limits
MaxAuthTries 3
LoginGraceTime 60
MaxSessions 4
MaxStartups 10:30:60

# Idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict users/groups
AllowUsers admin deployuser
# AllowGroups sshusers wheel

# Disable unused features
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
PrintMotd no

# Modern cryptography only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Logging
LogLevel VERBOSE
SyslogFacility AUTHPRIV

# Banner
Banner /etc/issue.net
```

**SSH key management:**
```bash
# Generate ed25519 key (preferred -- smaller, faster, more secure than RSA)
ssh-keygen -t ed25519 -C "user@hostname" -f ~/.ssh/id_ed25519

# RSA key (if ed25519 not supported -- minimum 4096 bits)
ssh-keygen -t rsa -b 4096 -C "user@hostname"

# Set correct permissions
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_ed25519

# Audit SSH configuration with ssh-audit
pip install ssh-audit
ssh-audit localhost
ssh-audit -p 22 targethost.example.com

# Deploy public key to remote host
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@remotehost
```

### 2.7 MFA for SSH

**Google Authenticator PAM:**
```bash
# Install
dnf install google-authenticator    # RHEL
apt-get install libpam-google-authenticator  # Ubuntu

# Configure per user
google-authenticator   # Interactive setup -- say yes to time-based tokens

# /etc/pam.d/sshd -- add before other auth lines:
auth required pam_google_authenticator.so

# /etc/ssh/sshd_config
ChallengeResponseAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
```

**Duo Security PAM:**
```bash
# Install duo_unix
# Configure /etc/duo/pam_duo.conf with ikey, skey, host
# /etc/pam.d/sshd:
auth required pam_duo.so
```

---

## 3. Filesystem Security

### 3.1 Filesystem Mount Hardening

Separate partitions with restrictive mount options are a core CIS Benchmark requirement.

**Recommended partition layout:**
```
/boot           -- separate partition
/               -- root
/home           -- nodev,nosuid
/tmp            -- nodev,nosuid,noexec
/var            -- nodev
/var/log        -- nodev,nosuid,noexec
/var/log/audit  -- nodev,nosuid,noexec
/var/tmp        -- nodev,nosuid,noexec
```

**`/etc/fstab` hardened entries:**
```fstab
# /tmp with hardening flags
tmpfs  /tmp  tmpfs  defaults,nodev,nosuid,noexec,size=2G  0 0

# Separate /var/tmp bound to /tmp (or dedicated partition)
/tmp  /var/tmp  none  bind  0 0

# /home partition (no execution of binaries from home dirs)
/dev/mapper/vg0-home  /home  xfs  defaults,nodev,nosuid  0 0

# /dev/shm
tmpfs  /dev/shm  tmpfs  defaults,nodev,nosuid,noexec  0 0
```

**systemd override for /tmp:**
```bash
# Create override
mkdir -p /etc/systemd/system/tmp.mount.d/
cat > /etc/systemd/system/tmp.mount.d/options.conf << 'EOF'
[Mount]
Options=mode=1777,strictatime,nosuid,nodev,noexec,size=2G
EOF
systemctl daemon-reload
systemctl restart tmp.mount
```

**Verify mount options:**
```bash
# Check current mount options
findmnt -n -o OPTIONS /tmp
mount | grep " /tmp "
cat /proc/mounts | grep /tmp
```

### 3.2 SUID/SGID Bit Audit

Setuid and setgid binaries run with elevated privileges and represent a significant attack surface.

```bash
# Find all SUID files on the system
find / -xdev -perm /4000 -type f -ls 2>/dev/null

# Find all SGID files
find / -xdev -perm /2000 -type f -ls 2>/dev/null

# Find both SUID and SGID
find / -xdev \( -perm /4000 -o -perm /2000 \) -type f -ls 2>/dev/null | tee /tmp/suid_sgid_audit.txt

# Save a baseline (compare after changes)
find / -xdev -perm /6000 -type f -printf '%p %U %G %m
' 2>/dev/null | sort > /var/lib/security/suid_baseline.txt

# Remove SUID bit from a specific binary (example: mount)
chmod u-s /usr/bin/mount

# Commonly acceptable SUID binaries (review against your policy):
# /usr/bin/passwd, /usr/bin/sudo, /usr/bin/su, /usr/bin/newgrp
# /usr/bin/gpasswd, /usr/bin/chage, /usr/bin/chsh, /usr/bin/chfn
```

### 3.3 World-Writable File Detection

```bash
# Find world-writable files (security risk -- anyone can modify)
find / -xdev -type f -perm -0002 -ls 2>/dev/null

# Find world-writable directories without sticky bit
find / -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null

# Verify sticky bit on shared writable directories
stat /tmp | grep "Access:"
ls -ld /tmp /var/tmp
# Should show: drwxrwxrwt (note the 't' = sticky bit)

# Set sticky bit
chmod +t /tmp
chmod +t /var/tmp
chmod 1777 /tmp

# Find files with no owner
find / -xdev -nouser -ls 2>/dev/null
find / -xdev -nogroup -ls 2>/dev/null
```

### 3.4 File Integrity Monitoring (FIM)

**AIDE (Advanced Intrusion Detection Environment):**
```bash
# Install
dnf install aide    # RHEL
apt-get install aide  # Ubuntu

# Initialize the database (baseline)
aide --init

# Move new database to active
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Run a check (compare current state to baseline)
aide --check

# Update database after authorized changes
aide --update
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Automate daily checks via cron
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
/usr/sbin/aide --check 2>&1 | mail -s "AIDE Integrity Check - $(hostname)" security@example.com
EOF
chmod 755 /etc/cron.daily/aide-check
```

**AIDE configuration** (`/etc/aide.conf`):
```
# Watch critical system files
/etc/passwd CONTENT_EX
/etc/shadow CONTENT_EX
/etc/group  CONTENT_EX
/etc/gshadow CONTENT_EX
/etc/sudoers CONTENT_EX
/etc/ssh/sshd_config CONTENT_EX
/bin FIPSR
/sbin FIPSR
/usr/bin FIPSR
/usr/sbin FIPSR
```

**Tripwire:**
```bash
# Initialize Tripwire policy
twadmin --create-polfile /etc/tripwire/twpol.txt
tripwire --init

# Run integrity check
tripwire --check

# Print report
twprint --print-report --twrfile /var/lib/tripwire/report/$(ls /var/lib/tripwire/report/ | tail -1)
```

**Wazuh FIM (syscheck module):**
```xml
<!-- /var/ossec/etc/ossec.conf -->
<syscheck>
  <frequency>43200</frequency>
  <alert_new_files>yes</alert_new_files>
  <directories realtime="yes" check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/bin,/sbin</directories>
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/mnttab</ignore>
</syscheck>
```

### 3.5 umask Hardening

```bash
# Set restrictive umask in /etc/profile (all users)
echo "umask 027" >> /etc/profile

# Set in /etc/bashrc (interactive shells)
echo "umask 027" >> /etc/bashrc

# Even more restrictive for root -- add to /root/.bashrc:
# umask 077

# Verify current umask
umask

# umask values:
# 022 = files: 644, dirs: 755 (default, too permissive)
# 027 = files: 640, dirs: 750 (recommended)
# 077 = files: 600, dirs: 700 (most restrictive)
```

### 3.6 TCP Wrappers

```bash
# /etc/hosts.allow -- permitted connections
sshd: 10.0.0.0/255.0.0.0
sshd: 192.168.1.0/255.255.255.0

# /etc/hosts.deny -- deny everything not explicitly allowed
ALL: ALL

# Test TCP wrapper decision
tcpdmatch sshd 203.0.113.5

# Note: TCP wrappers only apply to services using libwrap
# Check: ldd /usr/sbin/sshd | grep libwrap
```

### 3.7 Removable Media Controls

```bash
# Block USB storage via udev rule
cat > /etc/udev/rules.d/40-usb-storage-disable.rules << 'EOF'
# Disable USB storage devices
SUBSYSTEM=="block", KERNEL=="sd[a-z]", ATTRS{removable}=="1", RUN+="/bin/false"
ACTION=="add", SUBSYSTEMS=="usb", SUBSYSTEM=="block", RUN+="/bin/false"
EOF

# Blacklist USB storage kernel module
echo "blacklist usb-storage" > /etc/modprobe.d/usb-storage.conf
echo "install usb-storage /bin/false" >> /etc/modprobe.d/usb-storage.conf

# Apply immediately
modprobe -r usb-storage
udevadm control --reload-rules

# Verify module is blocked
modprobe usb-storage 2>&1
```

---

## 4. Kernel Hardening & sysctl

### 4.1 Network-Level Kernel Parameters

Create `/etc/sysctl.d/99-hardening.conf`:

```ini
#######################################
# NETWORK HARDENING
#######################################

# Disable IP forwarding (enable only on routers/gateways)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable sending of ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable accepting ICMP redirects (prevent route poisoning)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable accepting source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable SYN cookie protection (prevent SYN flood DoS)
net.ipv4.tcp_syncookies = 1

# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6 router advertisements acceptance
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Disable IPv6 if not in use
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Ignore ICMP broadcasts (Smurf attack mitigation)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable reverse path filtering (prevent IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable TCP timestamp responses (helps prevent fingerprinting)
net.ipv4.tcp_timestamps = 0

# Increase socket backlog
net.core.somaxconn = 65535
```

### 4.2 Kernel Self-Protection Parameters

```ini
#######################################
# KERNEL HARDENING
#######################################

# Restrict kernel log (dmesg) to root only
kernel.dmesg_restrict = 1

# Restrict kernel pointer exposure (prevent address leaks)
kernel.kptr_restrict = 2

# Enable ASLR (Address Space Layout Randomization) -- full randomization
kernel.randomize_va_space = 2

# Restrict ptrace (prevent process inspection from non-parent processes)
# 0=disabled, 1=restricted to parents, 2=admin only, 3=disabled
kernel.yama.ptrace_scope = 1

# Protect hard and symlinks from unprivileged users
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# Additional filesystem protections (kernel 4.19+)
fs.protected_fifos = 2
fs.protected_regular = 2

# Disable core dump SUID/SGID (prevent extracting sensitive info)
fs.suid_dumpable = 0

# Restrict unprivileged user namespaces (prevents container escapes)
kernel.unprivileged_userns_clone = 0   # Debian/Ubuntu
# kernel.unprivileged_bpf_disabled = 1

# Restrict perf events (can expose kernel internals)
kernel.perf_event_paranoid = 3

# Disable magic SysRq key (can be used for DoS)
kernel.sysrq = 0

# Increase PID max
kernel.pid_max = 65536
```

**Apply sysctl settings:**
```bash
# Apply immediately
sysctl --system
sysctl -p /etc/sysctl.d/99-hardening.conf

# Verify a specific setting
sysctl kernel.randomize_va_space
sysctl -a | grep kptr_restrict
```

### 4.3 Kernel Self Protection Project (KSPP) Recommendations

The KSPP (https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project) recommends:

```bash
# Kernel compile-time options (relevant for custom builds)
# CONFIG_CC_STACKPROTECTOR_STRONG=y
# CONFIG_STRICT_KERNEL_RWX=y
# CONFIG_STRICT_MODULE_RWX=y
# CONFIG_DEBUG_RODATA=y
# CONFIG_PAGE_TABLE_ISOLATION=y   (Meltdown mitigation)
# CONFIG_RETPOLINE=y               (Spectre mitigation)
# CONFIG_FORTIFY_SOURCE=y
# CONFIG_UBSAN=y
# CONFIG_LOCKDOWN_LSM=y

# Check current kernel security features
cat /boot/config-$(uname -r) | grep CONFIG_CC_STACKPROTECTOR
grep . /sys/kernel/security/lockdown 2>/dev/null

# Spectre/Meltdown mitigation status
grep -r '' /sys/devices/system/cpu/vulnerabilities/
```

### 4.4 Secure Boot Configuration

```bash
# Check Secure Boot status
mokutil --sb-state
# Output: SecureBoot enabled

# Check if UEFI or legacy BIOS
[ -d /sys/firmware/efi ] && echo "UEFI" || echo "Legacy BIOS"

# List enrolled Machine Owner Keys
mokutil --list-enrolled

# Sign a custom kernel module for Secure Boot
openssl req -new -x509 -newkey rsa:2048 -keyout signing_key.pem \
  -out signing_cert.pem -days 365 -subj "/CN=Module Signing/"
/usr/src/linux-headers-$(uname -r)/scripts/sign-file sha256 \
  signing_key.pem signing_cert.pem mymodule.ko

# Enroll the signing certificate
mokutil --import signing_cert.pem
```

### 4.5 Kernel Module Blacklisting

```bash
# /etc/modprobe.d/blacklist-rare-filesystems.conf
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
blacklist udf

# Prevent module from loading even if explicitly called
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false

# /etc/modprobe.d/blacklist-misc.conf
# Disable USB storage (if not needed)
blacklist usb-storage
install usb-storage /bin/false

# Disable Firewire (if not needed)
blacklist firewire-core
install firewire-core /bin/false

# Disable uncommon network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
install dccp /bin/false
install sctp /bin/false

# Apply immediately
dracut -f   # RHEL -- rebuild initramfs
update-initramfs -u  # Debian/Ubuntu

# List currently loaded modules
lsmod | sort

# Verify a module is blocked
modprobe cramfs 2>&1
```

### 4.6 AppArmor vs SELinux Comparison

| Feature | SELinux | AppArmor |
|---------|---------|----------|
| **Default on** | RHEL, Fedora, CentOS | Ubuntu, Debian, SUSE |
| **Policy model** | Label-based (inode labels) | Path-based profiles |
| **Complexity** | Higher -- steep learning curve | Lower -- easier to write profiles |
| **Granularity** | Very fine-grained | Profile-level |
| **Learning mode** | Permissive mode | Complain mode |
| **Tooling** | audit2allow, semanage, sealert | aa-genprof, aa-logprof |
| **MLS/MCS** | Yes (Multi-Level Security) | Limited |
| **DoD/STIG** | Required for STIG compliance | Not STIG compliant |

```bash
# AppArmor status and management
aa-status
apparmor_status
aa-enforce /etc/apparmor.d/usr.sbin.nginx
aa-complain /etc/apparmor.d/usr.sbin.nginx  # Learning mode

# Generate AppArmor profile for application
aa-genprof /usr/bin/myapp
# Run the application, then press S to scan logs
aa-logprof   # Review and update profile from logs
```

---

## 5. SELinux Configuration

### 5.1 SELinux Fundamentals

SELinux implements Mandatory Access Control (MAC) using security labels attached to every process, file, and network socket.

**Security context format:**
```
user:role:type:level
system_u:system_r:httpd_t:s0
```

| Component | Description | Example |
|-----------|-------------|---------|
| **user** | SELinux user identity | system_u, unconfined_u |
| **role** | What roles a user can assume | system_r, unconfined_r |
| **type** | The primary enforcement mechanism | httpd_t, sshd_t |
| **level** | MLS sensitivity level | s0, s0:c0.c1023 |

**Enforcement modes:**
| Mode | Description |
|------|-------------|
| **Enforcing** | Active enforcement -- violations are blocked and logged |
| **Permissive** | Logging only -- violations logged but NOT blocked |
| **Disabled** | SELinux completely off (requires reboot to change) |

**Policy types:**
| Policy | Description |
|--------|-------------|
| **targeted** | Default -- enforces on specific targeted daemons |
| **minimum** | Minimal set of processes confined |
| **mls** | Multi-Level Security -- required for government classified |

### 5.2 SELinux Status Commands

```bash
# Check enforcement mode
getenforce
# Returns: Enforcing, Permissive, or Disabled

# Detailed status
sestatus

# Change mode temporarily (no reboot needed)
setenforce 0   # Permissive
setenforce 1   # Enforcing

# Change permanent mode -- /etc/selinux/config
# SELINUX=enforcing    (enforcing/permissive/disabled)
# SELINUXTYPE=targeted

# Inspect process contexts
ps auxZ | grep httpd
ps -eZ | grep sshd

# Inspect file contexts
ls -Z /var/www/html/
ls -lZ /etc/shadow

# Search SELinux type info
seinfo -t | grep httpd   # All httpd types
seinfo -r               # All roles
seinfo --stats          # Policy statistics
```

### 5.3 Boolean Management

SELinux booleans allow runtime modification of policy behavior without recompiling policy.

```bash
# List all booleans
getsebool -a
getsebool -a | grep httpd

# Get a specific boolean
getsebool httpd_can_network_connect
# httpd_can_network_connect --> off

# Set boolean temporarily (lost on reboot)
setsebool httpd_can_network_connect on

# Set boolean permanently (-P flag)
setsebool -P httpd_can_network_connect on

# List booleans with descriptions
semanage boolean -l | grep httpd

# Common important booleans:
# httpd_can_network_connect -- allow httpd to make network connections
# httpd_can_sendmail -- allow httpd to send email
# httpd_enable_cgi -- allow httpd to run CGI scripts
# httpd_use_nfs -- allow httpd to serve NFS-mounted files
# samba_enable_home_dirs -- allow Samba to share home directories
# ftp_home_dir -- allow FTP to read user home directories
# ssh_sysadm_login -- allow sysadm_r to log in via SSH
```

### 5.4 File Context Management

```bash
# View default file context policy
semanage fcontext -l | grep httpd
semanage fcontext -l | grep ssh_home_t

# Add a custom file context rule
semanage fcontext -a -t httpd_sys_content_t '/var/www/html(/.*)?'
semanage fcontext -a -t httpd_log_t '/var/log/myapp(/.*)?'

# Apply file contexts to filesystem (restorecon)
restorecon -Rv /var/www/html
restorecon -v /etc/ssh/sshd_config

# Restore all contexts for a path recursively
restorecon -RFv /var/www/

# Check what context a path should have
matchpathcon /var/www/html/index.html
matchpathcon /etc/passwd

# Change context of a file (temporary -- will be reset by restorecon)
chcon -t httpd_sys_content_t /tmp/myfile.html
```

### 5.5 Port Labeling

```bash
# List all port labels
semanage port -l
semanage port -l | grep http

# Allow httpd to bind on custom port 8080
semanage port -a -t http_port_t -p tcp 8080

# Allow sshd on alternate port 2222
semanage port -a -t ssh_port_t -p tcp 2222

# Remove a port label
semanage port -d -t http_port_t -p tcp 8080

# Modify existing label
semanage port -m -t http_port_t -p tcp 8080
```

### 5.6 Creating Custom SELinux Policy Modules

When a legitimate application is being blocked by SELinux, create a custom policy module:

```bash
# Step 1: Run the application in permissive mode to capture all denials
setenforce 0
# ... run application and exercise all features ...

# Step 2: Collect AVC denials from audit log
grep AVC /var/log/audit/audit.log | grep myapp

# Step 3: Generate policy module using audit2allow
audit2allow -M mypolicy < /var/log/audit/audit.log

# Step 4: Review the generated policy
cat mypolicy.te   # Type enforcement file

# Step 5: Install the policy module
semodule -i mypolicy.pp

# Step 6: Re-enable enforcing
setenforce 1

# List installed modules
semodule -l | grep mypolicy

# Remove a module
semodule -r mypolicy
```

### 5.7 SELinux Troubleshooting

```bash
# Search for AVC denial messages (recent)
ausearch -m AVC -ts recent
ausearch -m AVC -ts today

# Search for denials related to a specific context
ausearch -m AVC -c httpd

# Use sealert for human-readable explanations
dnf install setroubleshoot-server
sealert -a /var/log/audit/audit.log

# Watch for AVC denials in real time
tail -f /var/log/audit/audit.log | grep AVC

# audit2why -- explain why a denial occurred
ausearch -m AVC -ts recent | audit2why

# Check if a domain is unconfined (outside SELinux enforcement)
ps -eZ | grep unconfined_t

# SELinux sandbox for untrusted programs
sandbox -X -t sandbox_web_t firefox   # Run Firefox in sandbox
sandbox -t sandbox_t /bin/untrusted-program
```

### 5.8 SELinux MLS (Multi-Level Security)

```bash
# Switch to MLS policy (RHEL only -- requires reinstall in practice)
# SELINUXTYPE=mls in /etc/selinux/config

# In MLS mode, every object has a sensitivity level
# s0 (unclassified) through s15 with categories c0-c1023

# Example -- set file to sensitivity level s1 category c1
chcon -l s1:c1 secretfile.txt

# runcon -- run command with specific SELinux context
runcon -t guest_t -r guest_r /bin/bash
```

---

## 6. Network Security & Firewall

### 6.1 iptables Reference

iptables is the traditional Linux packet filtering framework (still widely used, though nftables is the modern replacement).

**Tables and Chains:**
| Table | Chains | Purpose |
|-------|--------|---------|
| **filter** | INPUT, OUTPUT, FORWARD | Default -- packet filtering |
| **nat** | PREROUTING, OUTPUT, POSTROUTING | Network address translation |
| **mangle** | All five chains | Packet header modification |
| **raw** | PREROUTING, OUTPUT | Connection tracking bypass |

**Essential iptables commands:**
```bash
# View current rules
iptables -L -n -v
iptables -L -n -v --line-numbers
ip6tables -L -n -v   # IPv6 rules

# Default deny policy (set BEFORE adding allow rules)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT   # Usually allow outbound

# Allow established/related connections (stateful -- essential)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow SSH from specific subnet only
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

# Allow HTTPS from anywhere
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Rate limit SSH (brute force mitigation)
iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Log and drop everything else
iptables -A INPUT -j LOG --log-prefix "iptables-DROP: " --log-level 4
iptables -A INPUT -j DROP

# Persist rules
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# Restore rules at boot (iptables-persistent package)
iptables-restore < /etc/iptables/rules.v4
```

### 6.2 nftables (Modern Replacement)

nftables replaces iptables, ip6tables, arptables, and ebtables with a unified framework.

```bash
# Check nftables status
systemctl status nftables
nft list ruleset

# Basic nftables configuration /etc/nftables.conf:

#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif lo accept

        # Allow established/related connections
        ct state established,related accept

        # Drop invalid
        ct state invalid drop

        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Allow SSH from management network
        ip saddr 10.0.0.0/8 tcp dport 22 accept

        # Allow HTTPS
        tcp dport 443 accept

        # Allow HTTP
        tcp dport 80 accept

        # Log and drop everything else
        log prefix "nft drop: " level warn
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}

# Apply and enable
systemctl enable --now nftables
nft -f /etc/nftables.conf

# Add a rule dynamically
nft add rule inet filter input ip saddr 203.0.113.0/24 tcp dport 443 accept

# List with handles (needed for deletion)
nft list ruleset -a

# Delete a rule by handle
nft delete rule inet filter input handle 10
```

### 6.3 firewalld Zone-Based Management

firewalld provides dynamic zone-based firewall management, default on RHEL/Fedora/CentOS.

```bash
# Check status and default zone
firewall-cmd --state
firewall-cmd --get-default-zone
firewall-cmd --get-active-zones

# List all rules for a zone
firewall-cmd --zone=public --list-all

# Add a service (permanent)
firewall-cmd --zone=public --add-service=https --permanent
firewall-cmd --zone=public --add-service=ssh --permanent

# Add a specific port (permanent)
firewall-cmd --zone=public --add-port=8443/tcp --permanent

# Remove a service
firewall-cmd --zone=public --remove-service=telnet --permanent

# Reload to apply permanent rules
firewall-cmd --reload

# Add a rich rule (allow SSH from specific IP)
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="10.0.0.5" service name="ssh" accept' --permanent

# Block an IP address
firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="203.0.113.10" reject' --permanent

# Multi-homed server -- assign interfaces to zones
firewall-cmd --zone=internal --change-interface=eth1 --permanent

# Create custom zone
firewall-cmd --new-zone=management --permanent
firewall-cmd --zone=management --add-source=10.10.0.0/24 --permanent
firewall-cmd --zone=management --add-service=ssh --permanent
```

### 6.4 UFW (Ubuntu Firewall)

```bash
# Check status
ufw status verbose
ufw status numbered

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow specific services
ufw allow ssh
ufw allow 443/tcp
ufw allow http

# Allow from specific IP/subnet
ufw allow from 10.0.0.0/8 to any port 22
ufw allow from 192.168.1.100

# Deny a port
ufw deny 23/tcp   # Telnet

# Enable UFW
ufw enable

# Delete a rule by number
ufw delete 3

# Rate limiting (against brute force)
ufw limit ssh

# Application profiles
ufw app list
ufw allow 'Nginx Full'
```

### 6.5 Network Service Minimization

```bash
# List all listening ports and associated services
ss -tlnp
ss -tlnp4   # IPv4 only
ss -tlnp6   # IPv6 only

# Alternative using netstat
netstat -tulnp

# Identify and disable unneeded services
systemctl list-units --type=service --state=running
systemctl disable avahi-daemon --now
systemctl disable cups --now
systemctl disable bluetooth --now

# Check for unexpected network connections
ss -tnp
lsof -i -n -P | grep LISTEN
```

### 6.6 fail2ban Configuration

```bash
# Install
apt-get install fail2ban   # Ubuntu/Debian
dnf install fail2ban       # RHEL

# /etc/fail2ban/jail.local (override jail.conf)
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5
action = %(action_mwl)s

[sshd]
enabled = true
port    = ssh
logpath = %(sshd_log)s
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled  = true
port     = http,https
logpath  = /var/log/nginx/error.log

[postfix]
enabled  = true
port     = smtp,465,submission
logpath  = /var/log/mail.log

# Manage
systemctl enable --now fail2ban
fail2ban-client status
fail2ban-client status sshd

# Unban an IP
fail2ban-client set sshd unbanip 203.0.113.10

# View banned IPs
fail2ban-client get sshd banned
iptables -L f2b-sshd -n
```

---

## 7. Auditd & System Logging

### 7.1 auditd Configuration

The Linux Audit System records system calls and file access events for security monitoring and compliance.

**`/etc/audit/auditd.conf`:**
```ini
# Log location and format
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root

# Log rotation settings
max_log_file = 50          # MB per log file
num_logs = 5               # Number of log files to retain
max_log_file_action = ROTATE

# Disk space management
space_left = 75            # MB remaining -- trigger warning
space_left_action = SYSLOG
admin_space_left = 50      # Critical low disk
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND

# Flush to disk
flush = INCREMENTAL_ASYNC
freq = 50

# Distribution
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = HOSTNAME
```

### 7.2 Audit Rules

**`/etc/audit/rules.d/hardening.rules`** (CIS Benchmark comprehensive ruleset):

```bash
# Delete all previous rules
-D

# Set buffer size (increase if seeing lost events)
-b 8192

# Failure mode: 0=silent, 1=printk, 2=panic
-f 1

# -- Identity and authentication changes --
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# -- Privilege escalation -- sudo --
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# -- Login/logout events --
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# -- Session initiation --
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# -- Privileged commands --
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# -- Unauthorized file access --
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# -- Process execution --
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# -- System locale changes --
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# -- Kernel module operations --
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# -- File deletion by users --
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# -- Time changes --
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# -- Mount operations --
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# -- Make rules immutable (must reboot to change) -- uncomment in production --
# -e 2
```

**Load audit rules:**
```bash
# Load rules immediately
augenrules --load
# or
auditctl -R /etc/audit/rules.d/hardening.rules

# Verify loaded rules
auditctl -l
auditctl -s   # Status including backlog
```

### 7.3 ausearch and aureport

```bash
# Search for specific key
ausearch -k exec -ts today
ausearch -k identity -ts yesterday
ausearch -k sudoers

# Search by user
ausearch -ua root -ts recent
ausearch -ua 1001    # By UID

# Search by executable
ausearch -x /usr/bin/sudo

# Search by time range
ausearch -ts 2024-01-15 08:00:00 -te 2024-01-15 17:00:00

# Search AVC denials (SELinux)
ausearch -m AVC -ts today

# Generate summary reports
aureport --summary
aureport --login --summary
aureport --auth --summary
aureport --failed --summary
aureport --file --summary
aureport --exec --summary

# View login report for today
aureport --login -ts today

# Authentication failures report
aureport --auth -i --failed -ts this-week
```

### 7.4 rsyslog Forwarding to SIEM

**`/etc/rsyslog.conf`** and `/etc/rsyslog.d/`:
```bash
# Load TLS module
module(load="imtls")
module(load="gtls")

# Forward all logs to SIEM over TLS (TCP 6514)
action(type="omfwd"
       target="siem-server.example.com"
       port="6514"
       protocol="tcp"
       StreamDriver="gtls"
       StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="siem-server.example.com")

# TLS certificates
global(
  DefaultNetstreamDriver="gtls"
  DefaultNetstreamDriverCAFile="/etc/pki/tls/certs/ca-bundle.crt"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/client.crt"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/client.key"
)

# Also keep local copy
*.* /var/log/messages
```

**Log rotation `/etc/logrotate.d/syslog`:**
```
/var/log/messages {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2>/dev/null` 2>/dev/null || true
    endscript
}
```

### 7.5 systemd-journald

```bash
# /etc/systemd/journald.conf key settings:
# Storage=persistent         # Keep logs across reboots
# Compress=yes               # Compress stored logs
# SystemMaxUse=1G            # Max disk space for journal
# SystemKeepFree=200M        # Keep this much space free
# MaxRetentionSec=1year      # Retain 1 year of logs
# ForwardToSyslog=yes        # Forward to rsyslog

# Useful journalctl queries
journalctl -u sshd --since "2024-01-01"
journalctl -u nginx --since "1 hour ago"
journalctl -p err -b    # Error+ priority since boot
journalctl --since yesterday --until now
journalctl -f           # Follow (like tail -f)
journalctl -k           # Kernel messages only (like dmesg)
journalctl -b -1        # Previous boot logs
journalctl _UID=1001    # Logs for specific user ID
journalctl --disk-usage
journalctl --vacuum-time=1year   # Clean old entries
```

### 7.6 Log Retention Requirements

| Regulation | Minimum Retention |
|------------|------------------|
| PCI DSS 4.0 | 12 months (3 months immediately available) |
| HIPAA | 6 years |
| SOX | 7 years |
| GDPR | Depends on data category -- minimize |
| NIST 800-53 | AU-11: organization-defined period |
| FISMA | 3 years |
| CIS Benchmark | 90 days minimum |

---

## 8. Service Hardening & Application Security

### 8.1 systemd Service Hardening Directives

systemd provides powerful sandboxing capabilities for services. Add these to service unit files:

**`/etc/systemd/system/myapp.service.d/hardening.conf`:**
```ini
[Service]
# Run as dedicated non-root user
User=myapp
Group=myapp

# Private /tmp -- service gets its own /tmp
PrivateTmp=true

# Prevent privilege escalation (no setuid, no capabilities gain)
NoNewPrivileges=true

# Mount /usr, /boot, /efi as read-only
ProtectSystem=strict

# Block access to home directories
ProtectHome=true

# Read-write paths (must be explicitly listed when ProtectSystem=strict)
ReadWritePaths=/var/lib/myapp /var/log/myapp

# ReadOnly paths
ReadOnlyPaths=/etc/myapp

# Restrict capabilities to minimum needed
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Seccomp filter -- restrict system calls
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# Restrict address families
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Deny write+execute memory mappings (prevents shellcode injection)
MemoryDenyWriteExecute=true

# Protect kernel variables (/proc/sys, /sys)
ProtectKernelTunables=true

# Prevent loading kernel modules
ProtectKernelModules=true

# Protect kernel logs
ProtectKernelLogs=true

# Protect control groups
ProtectControlGroups=true

# Restrict namespaces
RestrictNamespaces=true

# Prevent realtime scheduling
RestrictRealtime=true

# Private device namespace
PrivateDevices=true

# Lock down the service personality
LockPersonality=true

# Remove IPC objects on exit
RemoveIPC=true
```

**Analyze service security:**
```bash
# Score a service's security hardening
systemd-analyze security myapp.service
systemd-analyze security --no-pager nginx.service

# List all services with security scores
systemd-analyze security | sort -k 4 -n

# Show detailed exposure breakdown
systemd-analyze security --json=pretty myapp.service
```

### 8.2 Cron Security

```bash
# Restrict cron access using allowlist
# Only users listed in /etc/cron.allow can use cron
echo "root" > /etc/cron.allow
echo "deployuser" >> /etc/cron.allow

# If cron.allow exists, cron.deny is ignored
# Remove cron.deny or create empty file
> /etc/cron.deny

# Correct permissions on cron configuration
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.monthly
chmod 700 /etc/cron.weekly
chmod 600 /etc/crontab

# Audit all cron jobs on the system
for user in $(cut -f1 -d: /etc/passwd); do
    cron_output=$(crontab -u "$user" -l 2>/dev/null)
    if [ -n "$cron_output" ]; then
        echo "=== Cron for $user ==="
        echo "$cron_output"
    fi
done

# Also check system cron directories
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
cat /etc/crontab

# at command restrictions
echo "root" > /etc/at.allow
> /etc/at.deny
chmod 640 /etc/at.allow /etc/at.deny
```

### 8.3 NTP Security (chrony)

Accurate time is critical for log correlation, Kerberos authentication, and audit integrity.

**`/etc/chrony.conf`:**
```ini
# Use pool of NTP servers
pool pool.ntp.org iburst minpoll 6 maxpoll 10

# Stratum 1 servers (use organization's internal NTP server)
server ntp1.example.com iburst prefer
server ntp2.example.com iburst

# Allow the system clock to be stepped in the first three updates
makestep 1.0 3

# Record the rate at which the system clock gains/loses time
driftfile /var/lib/chrony/drift

# NTS (Network Time Security -- authenticated NTP)
# server time.cloudflare.com iburst nts
# ntsdumpdir /var/lib/chrony

# Restrict management interface
bindcmdaddress 127.0.0.1
cmdallow 127.0.0.1
```

```bash
# Check synchronization status
chronyc tracking
chronyc sources -v
chronyc sourcestats

# Force sync now
chronyc makestep

# Enable and start
systemctl enable --now chronyd
```

### 8.4 Postfix Minimal Configuration

If an MTA is required, configure Postfix securely:

```bash
# /etc/postfix/main.cf -- minimal secure configuration

# Listen only on loopback
inet_interfaces = loopback-only

# Relay only from localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128

# Restrict to relaying only
relay_domains =

# SASL authentication (if accepting external SMTP)
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination

# TLS enforcement
smtpd_tls_cert_file = /etc/ssl/certs/postfix.pem
smtpd_tls_key_file = /etc/ssl/private/postfix.key
smtpd_use_tls = yes
smtpd_tls_auth_only = yes

# Hide version information
smtpd_banner = $myhostname ESMTP
```

### 8.5 NFS Security

```bash
# /etc/exports -- NFS export configuration
# Avoid no_root_squash (prevents root on client from being root on server)
/data/share  10.0.0.0/8(ro,sync,no_subtree_check,root_squash)
/home        10.0.0.0/8(rw,sync,no_subtree_check,root_squash)

# NEVER use (unless absolutely required):
# /share *(rw,no_root_squash,no_all_squash)

# Use Kerberos authentication for NFS 4
/secure  10.0.0.0/8(rw,sync,sec=krb5p)

# Restrict NFS ports via firewall
firewall-cmd --zone=internal --add-service=nfs --permanent
firewall-cmd --zone=internal --add-service=mountd --permanent
firewall-cmd --zone=internal --add-service=rpc-bind --permanent

# Apply exports
exportfs -rav

# Show current exports
exportfs -v
showmount -e localhost
```

### 8.6 Samba Security

```bash
# /etc/samba/smb.conf -- secure configuration
[global]
    workgroup = EXAMPLE
    server string = File Server
    security = user

    # Restrict access to specific hosts
    hosts allow = 10.0.0.0/8 192.168.1.0/24
    hosts deny = ALL

    # Disable anonymous access
    restrict anonymous = 2

    # SMB signing (prevents MITM)
    server signing = mandatory
    client signing = mandatory

    # Minimum SMB protocol version (disable SMBv1!)
    server min protocol = SMB2
    client min protocol = SMB2

    # Use encrypted passwords
    encrypt passwords = yes

    # Logging
    log file = /var/log/samba/log.%m
    log level = 1

[data]
    path = /srv/samba/data
    valid users = @sambagroup
    read only = no
    create mask = 0640
    directory mask = 0750
```

---

## 9. Intrusion Detection & Monitoring

### 9.1 Host-Based IDS

**Wazuh (OSSEC fork -- most actively maintained):**
```bash
# Install Wazuh agent (connects to central manager)
# RHEL/CentOS
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
dnf install wazuh-agent

# Configure /var/ossec/etc/ossec.conf
# <client>
#   <server>
#     <address>wazuh-manager.example.com</address>
#     <port>1514</port>
#     <protocol>tcp</protocol>
#   </server>
# </client>

# Enable and start
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

**Wazuh syscheck (FIM) configuration:**
```xml
<!-- /var/ossec/etc/ossec.conf -->
<syscheck>
  <frequency>43200</frequency>
  <alert_new_files>yes</alert_new_files>
  <directories realtime="yes" check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/bin,/sbin</directories>
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/mnttab</ignore>
</syscheck>

<rootcheck>
  <frequency>43200</frequency>
  <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
  <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
</rootcheck>
```

**rkhunter (rootkit detection):**
```bash
# Install
dnf install rkhunter
apt-get install rkhunter

# Update database
rkhunter --update

# Run check (non-interactive, report warnings only)
rkhunter --check --skip-keypress --report-warnings-only

# Full check with logging
rkhunter --check --logfile /var/log/rkhunter.log

# After system updates -- update baseline
rkhunter --propupd

# Schedule daily check
cat > /etc/cron.daily/rkhunter << 'EOF'
#!/bin/bash
/usr/bin/rkhunter --check --skip-keypress --report-warnings-only 2>&1 |   mail -s "rkhunter report - $(hostname)" security@example.com
EOF
chmod 755 /etc/cron.daily/rkhunter
```

**chkrootkit:**
```bash
# Install
apt-get install chkrootkit
dnf install chkrootkit

# Run quietly (only show positives)
chkrootkit -q

# Specific test
chkrootkit lkm   # Check for kernel module rootkits

# Schedule
echo "0 3 * * * root /usr/sbin/chkrootkit -q 2>&1 | mail -s 'chkrootkit - $(hostname)' security@example.com" > /etc/cron.d/chkrootkit
```

### 9.2 AIDE File Integrity Monitoring (Detailed Workflow)

```bash
# 1. Install and configure
dnf install aide

# 2. Initialize database (do this on a known-clean system)
aide --init 2>&1 | tee /var/log/aide-init.log
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 3. Store the database offline or in tamper-resistant location
# cp /var/lib/aide/aide.db.gz /mnt/usb/aide-baseline-$(hostname)-$(date +%Y%m%d).db.gz

# 4. Daily check workflow
aide --check 2>&1 | tee /var/log/aide-$(date +%Y%m%d).log
# Review output:
# Added files: new files not in baseline (investigate)
# Removed files: files deleted (expected or suspicious?)
# Changed files: files that differ from baseline (expected changes vs tampering)

# 5. After authorized changes, update the database
aide --update
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 6. Cron automation
cat > /etc/cron.d/aide-daily << 'EOF'
30 2 * * * root /usr/sbin/aide --check 2>&1 | mail -s "AIDE Check - $(hostname)" security@example.com
EOF
```

### 9.3 eBPF-Based Monitoring with Falco

Falco is a cloud-native runtime security tool using eBPF/kernel module to detect anomalous behavior.

```bash
# Install Falco
rpm --import https://falco.org/repo/falcosecurity-packages.asc
dnf install falco

# Start with eBPF driver
falco --modern-bpf

# Key default rules detected by Falco:
# - Write below binary dir
# - Read sensitive files untrusted
# - Shell in container
# - Unexpected outbound connection

# Custom rule example
cat >> /etc/falco/falco_rules.local.yaml << 'EOF'
- rule: Sensitive file opened for reading
  desc: Detect reading of sensitive files
  condition: >
    open_read and
    fd.name in (sensitive_files) and
    not proc.name in (known_readers)
  output: >
    Sensitive file opened (user=%user.name command=%proc.cmdline file=%fd.name)
  priority: WARNING
  tags: [filesystem, mitre_credential_access]
EOF

systemctl enable --now falco
journalctl -u falco -f   # Monitor alerts
```

### 9.4 osquery -- SQL-Based Host Security Queries

```bash
# Install
dnf install osquery

# Interactive query
osqueryi

# Useful security queries:

# Find processes not backed by a binary on disk
# SELECT name, path, pid FROM processes WHERE on_disk = 0;

# List listening ports and associated processes
# SELECT DISTINCT p.name, l.address, l.port FROM listening_ports l
# JOIN processes p ON p.pid = l.pid;

# Find world-writable files in /etc
# SELECT path, mode FROM file WHERE path LIKE '/etc/%'
# AND (cast(mode as integer) & 2) > 0;

# Detect recently modified files in critical directories
# SELECT path, mtime, datetime(mtime, 'unixepoch') AS modified FROM file
# WHERE path LIKE '/etc/%' AND mtime > (strftime('%s', 'now') - 3600);

# List all users with empty passwords
# SELECT username FROM shadow WHERE password_status = 'empty';

# Find kernel modules
# SELECT name, address, size, status FROM kernel_modules;

# Scheduled queries via osquery packs in /etc/osquery/osquery.conf
```

### 9.5 Lynis Security Auditing

```bash
# Install
dnf install lynis
apt-get install lynis

# Full system audit
lynis audit system

# Non-interactive for automation
lynis audit system --quiet --no-colors 2>&1 | tee /var/log/lynis-$(date +%Y%m%d).log

# Check only specific category
lynis audit system --tests-from-group authentication
lynis audit system --tests-from-group networking

# Read the hardening index
grep "hardening_index" /var/log/lynis-report.dat
# Target: > 80

# Key output files:
# /var/log/lynis.log        -- detailed log
# /var/log/lynis-report.dat -- machine-readable report

# Review suggestions
grep "suggestion" /var/log/lynis-report.dat

# Schedule monthly audit
cat > /etc/cron.monthly/lynis << 'EOF'
#!/bin/bash
lynis audit system --quiet 2>&1 | mail -s "Lynis Audit - $(hostname)" security@example.com
EOF
chmod 755 /etc/cron.monthly/lynis
```

### 9.6 Compliance Scanning Schedule

| Frequency | Tool | Task |
|-----------|------|------|
| **Real-time** | auditd, Falco, Wazuh | Continuous event monitoring |
| **Hourly** | fail2ban | Auto-block brute force |
| **Daily** | AIDE, rkhunter | File integrity and rootkit check |
| **Daily** | OpenSCAP | CIS Benchmark compliance scan |
| **Weekly** | Lynis | Comprehensive security audit |
| **Weekly** | chkrootkit | Secondary rootkit scan |
| **Monthly** | Manual review | Review all alerts and findings |
| **Monthly** | Nessus/OpenVAS | Vulnerability scan |
| **Quarterly** | Penetration test | Manual security assessment |

### 9.7 Log Monitoring for Security Events

```bash
# logwatch -- daily log summary digest
dnf install logwatch
apt-get install logwatch

# Run manually
logwatch --output mail --mailto security@example.com --detail high

# Configure /etc/logwatch/conf/logwatch.conf:
# MailTo = security@example.com
# Detail = Med
# Service = All
# Archives = Yes

# GoAccess -- web server log analysis
dnf install goaccess
goaccess /var/log/nginx/access.log -c

# Real-time dashboard
goaccess /var/log/nginx/access.log --log-format=COMBINED \
  -o /var/www/html/report.html --real-time-html

# Custom log monitoring with pattern searches:

# Check for SSH brute force
grep "Failed password" /var/log/secure | awk '{print $11}' | sort | uniq -c | sort -rn | head -20

# Check for successful logins
grep "Accepted publickey\|Accepted password" /var/log/secure | tail -50

# Check for sudo usage
grep "sudo:" /var/log/secure | tail -50

# Check for su attempts
grep "pam_unix(su" /var/log/secure | tail -20
```

---

## 10. Compliance, Automation & References

### 10.1 Compliance Frameworks for Linux Systems

#### CIS Benchmarks

The Center for Internet Security publishes free benchmarks (PDF) at https://www.cisecurity.org/cis-benchmarks/

| Benchmark | Current Version | Key Controls |
|-----------|----------------|-------------|
| RHEL 9 | 2.0+ | 300+ recommendations |
| Ubuntu 22.04 | 1.0+ | 280+ recommendations |
| Debian 12 | 1.0+ | 270+ recommendations |
| Amazon Linux 2023 | 1.0+ | 250+ recommendations |
| SUSE Linux 15 | 1.1+ | 260+ recommendations |

**CIS Level 1 vs Level 2 summary:**
| Area | Level 1 | Level 2 |
|------|---------|---------|
| Password policy | 14 char, complexity | 14 char + MFA |
| SSH | PermitRoot=no, key auth | Key + MFA, FIPS ciphers |
| Services | Disable obvious risks | Minimal, all disabled |
| Auditing | Basic audit rules | Full CIS auditd ruleset |
| Filesystem | noexec on /tmp | All partitions hardened |
| AppArmor/SELinux | Enabled, enforcing | Custom policies |

#### DISA STIGs

```bash
# Download STIG content
# Source: https://public.cyber.mil/stigs/downloads/
# STIG Viewer 2.x: Java-based GUI for reviewing STIG checklists
# stigviewer.com -- web-based alternative

# OpenSCAP STIG profile
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --results /tmp/stig-results.xml \
  --report /tmp/stig-report.html \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml

# Generate STIG remediation script
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_stig \
  --fix-type bash \
  /tmp/stig-results.xml > stig-remediation.sh
```

#### NIST SP 800-53 Controls Mapping

| Linux Control Area | NIST 800-53 Controls |
|-------------------|---------------------|
| User authentication | IA-2, IA-3, IA-5, IA-6 |
| Audit logging | AU-2, AU-3, AU-6, AU-9, AU-12 |
| System hardening | CM-6, CM-7, SI-2 |
| Access control | AC-2, AC-3, AC-6, AC-17 |
| Incident response | IR-4, IR-5, IR-6 |
| Cryptography | SC-8, SC-28, IA-7 |
| Network protection | SC-7, SC-5, SI-3 |

#### PCI DSS 4.0 for Linux

| PCI DSS Requirement | Linux Controls |
|--------------------|---------------|
| Req 1 -- Network controls | iptables/nftables/firewalld |
| Req 2 -- Secure defaults | Minimal install, service disable |
| Req 5 -- Malware protection | ClamAV, Wazuh, rkhunter |
| Req 6 -- Secure development | Patch management, dnf-automatic |
| Req 8 -- Identity | PAM, MFA, password policy |
| Req 10 -- Logging | auditd, rsyslog, SIEM |
| Req 11 -- Testing | OpenSCAP, Nessus, pen testing |

### 10.2 Hardening Automation Tools

**OpenSCAP -- Remediation Playbook Generation:**
```bash
# Generate Ansible remediation playbook from scan results
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --fix-type ansible \
  /tmp/results.xml > cis_remediation.yml

# Generate Bash remediation script
oscap xccdf generate fix \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --fix-type bash \
  /tmp/results.xml > cis_remediation.sh

# Run remediation directly (dangerous -- test in non-prod first)
oscap xccdf eval \
  --remediate \
  --profile xccdf_org.ssgproject.content_profile_cis \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

**Ansible dev-sec linux-hardening role:**
```bash
# Install
ansible-galaxy role install dev-sec.os-hardening
ansible-galaxy role install dev-sec.ssh-hardening

# Example hardening playbook
cat > harden.yml << 'EOF'
---
- name: Apply Linux hardening baseline
  hosts: all
  become: yes

  vars:
    os_auth_pw_max_age: 90
    os_auth_pw_min_age: 7
    os_auth_lockout_time: 900
    os_auth_retries: 5
    os_security_users_allow: []
    os_filesystem_main_hardening: true
    ssh_permit_root_login: "no"
    ssh_password_authentication: "no"
    ssh_max_auth_retries: 3
    ssh_client_alive_interval: 300
    ssh_client_alive_count_max: 2
    ssh_allow_tcp_forwarding: "no"

  roles:
    - dev-sec.os-hardening
    - dev-sec.ssh-hardening
EOF

# Run playbook
ansible-playbook -i inventory.ini harden.yml --check   # Dry run
ansible-playbook -i inventory.ini harden.yml           # Apply
```

**Chef InSpec -- Compliance Testing:**
```bash
# Install InSpec
curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

# Run CIS Linux benchmark profile
inspec exec https://github.com/dev-sec/linux-baseline

# Run against remote host
inspec exec dev-sec/linux-baseline -t ssh://user@hostname

# Generate compliance report
inspec exec linux-baseline --reporter html:/tmp/report.html json:/tmp/report.json
```

**Puppet Hardening Module:**
```puppet
class { 'os_hardening':
  password_max_age => 90,
  password_min_age => 7,
  enable_sysrq     => false,
  enable_ipv6      => false,
}
```

### 10.3 Container Base Image Hardening

```dockerfile
# Minimal base image -- no unnecessary packages or shell
FROM scratch
# or use distroless:
# FROM gcr.io/distroless/static-debian12

# Copy only what's needed
COPY --chown=nonroot:nonroot myapp /app/myapp

# Run as non-root user (never root in production!)
USER nonroot:nonroot

# Expose only required ports
EXPOSE 8080
```

**Kubernetes Pod Security Context:**
```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    runAsGroup: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: myapp
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

### 10.4 Hardening Verification Checklist

```bash
# 1. SSH Configuration audit
ssh-audit localhost
ssh-audit -p 22 targethost
# Target: No red/warning findings

# 2. Lynis hardening score
lynis audit system
grep "hardening_index" /var/log/lynis-report.dat
# Target: hardening_index >= 80

# 3. OpenSCAP CIS compliance
oscap xccdf eval --profile cis --results results.xml /path/to/content.xml
# Review report.html -- target: >90% pass rate for Level 1

# 4. Port/service audit
ss -tlnp
nmap -sV localhost  # Verify only expected ports open

# 5. SUID/SGID audit
find / -xdev -perm /6000 -type f -ls 2>/dev/null > /tmp/suid-audit.txt
diff /var/lib/security/suid_baseline.txt /tmp/suid-audit.txt

# 6. Check for world-writable files
find / -xdev -type f -perm -0002 -ls 2>/dev/null

# 7. Verify SELinux enforcing
getenforce   # Should return: Enforcing

# 8. Verify no empty passwords
awk -F: '($2 == "" ) {print $1}' /etc/shadow

# 9. Kernel parameters
sysctl kernel.randomize_va_space   # Should be 2
sysctl kernel.dmesg_restrict       # Should be 1
sysctl net.ipv4.tcp_syncookies    # Should be 1

# 10. Firewall active
firewall-cmd --state   # Should be: running
```

### 10.5 Linux Security Certifications & Training

| Certification | Organization | Focus Area |
|--------------|-------------|------------|
| **LFCS** | Linux Foundation | Linux system administration |
| **RHCSA** | Red Hat | RHEL system administration |
| **RHCE** | Red Hat | Ansible automation |
| **LPIC-3 303 Security** | LPI | Linux enterprise security |
| **GIAC GCUX** | GIAC/SANS | Unix/Linux security |
| **CompTIA Linux+** | CompTIA | Linux fundamentals |
| **GIAC GPEN** | GIAC/SANS | Penetration testing (Linux focus) |

### 10.6 Key References & Resources

| Resource | URL / Command | Description |
|----------|--------------|-------------|
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks/ | Free PDF downloads |
| DISA STIGs | https://public.cyber.mil/stigs/ | DoD hardening guides |
| SCAP Content | https://www.open-scap.org/security-policies/scap-security-guide/ | OpenSCAP policies |
| dev-sec.io | https://dev-sec.io | Hardening framework |
| Ansible Galaxy | https://galaxy.ansible.com/search?keywords=hardening | Security roles |
| NVD / NIST | https://nvd.nist.gov | CVE database |
| KSPP | https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project | Kernel hardening |
| Arch Linux Security | https://wiki.archlinux.org/title/Security | Excellent general reference |
| Lynis | `lynis audit system` | Local security auditing |
| ssh-audit | `ssh-audit hostname` | SSH configuration testing |
| OpenSCAP | `oscap xccdf eval ...` | Automated compliance scanning |

### 10.7 Quick-Reference Command Summary

```bash
# -- User Management --
chage -l username                    # View password aging settings
faillock --user username             # View failed login attempts
faillock --user username --reset     # Unlock account
passwd -l username                   # Lock account

# -- SELinux --
getenforce                           # Check SELinux mode
setenforce 0/1                       # Permissive/Enforcing (temp)
ausearch -m AVC -ts today            # Today's SELinux denials
audit2allow -M mypol < audit.log     # Generate policy from denials
restorecon -Rv /path                 # Restore correct file contexts

# -- Firewall --
firewall-cmd --list-all              # List current rules
firewall-cmd --zone=public --add-port=443/tcp --permanent
firewall-cmd --reload
ss -tlnp                             # List listening services

# -- Audit --
auditctl -l                          # List loaded audit rules
ausearch -k identity -ts today       # Search by key
aureport --summary                   # Summary report
aureport --login --summary           # Login summary

# -- Integrity --
aide --check                         # Check file integrity
rkhunter --check --skip-keypress     # Rootkit check
lynis audit system                   # Full security audit
oscap xccdf eval --profile cis ...   # Compliance scan

# -- Kernel --
sysctl -a | grep randomize           # Check ASLR
sysctl --system                      # Apply all sysctl configs
uname -r                             # Kernel version
cat /proc/version                    # Kernel build info
```

---

*Last updated: 2026-05-04 | Reference library for Linux system hardening, compliance, and security operations.*
*Maintained by the security engineering team -- validate all commands in a test environment before production use.*
