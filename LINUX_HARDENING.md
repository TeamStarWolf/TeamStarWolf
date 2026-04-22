# Linux Hardening Reference

Practical hardening for Linux servers and workstations covering CIS Benchmark controls, auditd, SSH, kernel parameters, PAM, SELinux/AppArmor, and detection-oriented configurations. Complements [Windows Hardening & GPO Reference](WINDOWS_HARDENING_GPO.md).

---

## CIS Benchmark Overview

The CIS Benchmark for Linux (Ubuntu, RHEL/CentOS, Debian) is the industry standard for hardening. Organized into:
- **Level 1**: Foundational, minimal performance impact — apply to all systems
- **Level 2**: Defense-in-depth, may impact functionality — evaluate per workload

Benchmark downloads: [cisecurity.org/benchmark/debian_linux](https://www.cisecurity.org/benchmark/debian_linux), [cisecurity.org/benchmark/red_hat_linux](https://www.cisecurity.org/benchmark/red_hat_linux)

---

## SSH Hardening

### /etc/ssh/sshd_config — Hardened Configuration

```bash
# Protocol and authentication
Protocol 2
PermitRootLogin no
MaxAuthTries 3
MaxSessions 4
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no          # Prefer key-based auth; disable passwords
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Key exchange and ciphers (strong only)
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Connection settings
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
MaxStartups 10:30:60

# Restrictions
AllowGroups sshusers                # Only allow specific group
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PrintLastLog yes
Banner /etc/issue.net

# Logging
LogLevel VERBOSE
SyslogFacility AUTH
```

```bash
# Apply and test
sshd -t                    # Test config before reloading
systemctl reload sshd
```

### SSH Key Management
```bash
# Generate strong key for admin use
ssh-keygen -t ed25519 -a 100 -C "admin@hostname-$(date +%Y%m%d)"

# Restrict authorized_keys options
echo 'from="192.168.1.0/24",no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... admin' >> ~/.ssh/authorized_keys

# Set correct permissions (SSH will refuse keys with wrong perms)
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

## Kernel Hardening (sysctl)

### /etc/sysctl.d/99-hardening.conf

```bash
# ── Network hardening ─────────────────────────────────────────────────────────
# Disable IP forwarding (unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable ICMP redirects (prevent routing table poisoning)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable reverse path filtering (prevent IP spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast pings (Smurf attack prevention)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1

# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# ── Memory and exploit mitigation ────────────────────────────────────────────
# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict kernel pointer exposure
kernel.kptr_restrict = 2

# Restrict dmesg access to root
kernel.dmesg_restrict = 1

# Restrict ptrace to own processes (mitigates privilege escalation)
kernel.yama.ptrace_scope = 1

# Disable core dumps for SUID programs
fs.suid_dumpable = 0

# Restrict /proc/pid to process owner (mitigates information leakage)
kernel.hidepid = 2

# Protect hardlinks and symlinks (prevent TOCTOU attacks)
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# ── Performance-safe security tweaks ─────────────────────────────────────────
# Increase entropy pool size
kernel.random.read_wakeup_threshold = 128

# Limit max open files
fs.file-max = 65536
```

```bash
# Apply immediately
sysctl -p /etc/sysctl.d/99-hardening.conf
# Verify
sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.yama.ptrace_scope
```

---

## Auditd Configuration

Auditd provides kernel-level audit logging — captures file access, system calls, user actions even before logging daemons start.

### Install and Enable
```bash
apt install auditd audispd-plugins   # Debian/Ubuntu
yum install audit audit-libs         # RHEL/CentOS
systemctl enable --now auditd
```

### /etc/audit/rules.d/hardening.rules

```bash
# Delete existing rules and set failure mode
-D
-b 8192
-f 2    # Panic on auditd failure (use -f 1 for production to log instead)

# ── Authentication and privilege events ──────────────────────────────────────
-w /var/log/faillog -p wa -k authentication
-w /var/log/lastlog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/run/utmp -p wa -k session

# Privilege escalation monitoring
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# ── File and configuration changes ───────────────────────────────────────────
-w /etc/passwd -p wa -k user_modification
-w /etc/shadow -p wa -k user_modification
-w /etc/group -p wa -k user_modification
-w /etc/gshadow -p wa -k user_modification
-w /etc/security/opasswd -p wa -k user_modification

-w /etc/hosts -p wa -k network_modification
-w /etc/hostname -p wa -k network_modification
-w /etc/resolv.conf -p wa -k network_modification
-w /etc/iptables/ -p wa -k firewall_modification
-w /etc/nftables.conf -p wa -k firewall_modification

-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# ── Module loading ────────────────────────────────────────────────────────────
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# ── System calls — privilege escalation ──────────────────────────────────────
-a always,exit -F arch=b64 -S setuid -S setgid -S setreuid -S setregid -k setuid
-a always,exit -F arch=b64 -S ptrace -k ptrace

# ── Executable changes ────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -k exec

# ── Network connections ───────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S socket -F a0=2 -k network_socket_ipv4
-a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket_ipv6

# ── Immutable flag (must be last line) ───────────────────────────────────────
-e 2
```

```bash
# Reload rules
auditctl -R /etc/audit/rules.d/hardening.rules
# Verify rules loaded
auditctl -l
# Search audit log
ausearch -k priv_esc --start today
aureport --summary
```

---

## PAM (Pluggable Authentication Modules) Hardening

### Password Complexity — /etc/security/pwquality.conf
```bash
minlen = 14           # Minimum length
minclass = 3          # Require uppercase, lowercase, digits, special chars (3 of 4)
maxrepeat = 3         # No more than 3 same consecutive chars
maxclassrepeat = 4    # No more than 4 same class chars in a row
lcredit = -1          # Require at least 1 lowercase
ucredit = -1          # Require at least 1 uppercase
dcredit = -1          # Require at least 1 digit
ocredit = -1          # Require at least 1 special character
difok = 5             # Must differ by at least 5 chars from old password
reject_username       # Cannot contain username
```

### Account Lockout — /etc/pam.d/common-auth (Debian) or /etc/pam.d/system-auth (RHEL)
```bash
# Add to top of auth section (BEFORE pam_unix.so)
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900 fail_interval=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900

# Check locked accounts
faillock --user USERNAME
# Unlock
faillock --user USERNAME --reset
```

### Password Aging — /etc/login.defs
```bash
PASS_MAX_DAYS   90       # Force change every 90 days
PASS_MIN_DAYS   7        # Prevent immediate re-change
PASS_WARN_AGE   14       # 14-day warning before expiry
PASS_MIN_LEN    14       # Minimum password length
LOGIN_RETRIES   5        # Failed logins before lockout
LOGIN_TIMEOUT   60       # Seconds before login timeout
```

```bash
# Apply to existing users
chage --maxdays 90 --mindays 7 --warndays 14 USERNAME
# View current settings
chage -l USERNAME
```

---

## SELinux / AppArmor

### SELinux (RHEL/CentOS/Fedora)
```bash
# Check status
sestatus
getenforce

# Set enforcing mode (persistent)
setenforce 1
sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config

# Investigate denials
ausearch -m avc -ts recent
audit2allow -a        # Generate allow rules from denials (use carefully)
audit2why < /var/log/audit/audit.log

# List contexts
ls -lZ /etc/passwd
ps -eZ | grep httpd

# Restore default contexts
restorecon -Rv /var/www/html/

# SELinux booleans for services
getsebool -a | grep httpd
setsebool -P httpd_can_network_connect on   # -P = persistent
```

### AppArmor (Debian/Ubuntu)
```bash
# Check status
aa-status
apparmor_status

# Modes: enforce (block) vs complain (log only)
aa-enforce /etc/apparmor.d/usr.bin.firefox   # Block violations
aa-complain /etc/apparmor.d/usr.bin.firefox  # Log only for testing

# Check logs for denials
grep "apparmor" /var/log/syslog | grep DENIED
grep "apparmor" /var/log/kern.log | grep DENIED

# Generate profile for new application
aa-genprof /usr/bin/myapp      # Run app, then press S to scan, F to finish
aa-logprof                     # Update profile from denials in logs
```

---

## Firewall — nftables

```bash
# /etc/nftables.conf — hardened server ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established and related connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Drop invalid packets
        ct state invalid drop

        # Limit ICMP
        ip protocol icmp limit rate 4/second accept
        ip6 nexthdr icmpv6 limit rate 4/second accept

        # Allow SSH from management network only
        tcp dport 22 ip saddr 192.168.1.0/24 ct state new accept

        # Allow application ports (customize per role)
        tcp dport { 80, 443 } ct state new accept

        # Log and drop everything else
        log prefix "[nftables] DROP: " limit rate 5/minute
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
```

```bash
nft -f /etc/nftables.conf
systemctl enable --now nftables
nft list ruleset
```

---

## File System Security

### /etc/fstab — Secure Mount Options
```bash
# /tmp — noexec, nosuid, nodev
tmpfs  /tmp  tmpfs  defaults,noexec,nosuid,nodev,size=2G  0 0

# /var/tmp — bind mount from /tmp with same restrictions
/tmp  /var/tmp  none  bind  0 0

# /home — noexec, nosuid
/dev/sda3  /home  ext4  defaults,noexec,nosuid  0 2

# Shared memory
tmpfs  /dev/shm  tmpfs  defaults,noexec,nosuid,nodev  0 0
```

```bash
# Remount without reboot (testing)
mount -o remount,noexec,nosuid,nodev /tmp
```

### Find SUID/SGID Binaries
```bash
# Baseline at build time, diff later
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > /root/suid_baseline.txt
# Check for new ones
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | diff /root/suid_baseline.txt -
```

### World-Writable Files and Directories
```bash
find / -xdev -type f -perm -0002 -ls 2>/dev/null    # World-writable files
find / -xdev -type d -perm -0002 -ls 2>/dev/null    # World-writable directories
find / -xdev -nouser -ls 2>/dev/null                 # Files with no owner (orphaned after user deletion)
```

---

## Service Hardening

### Disable Unnecessary Services
```bash
# List enabled services
systemctl list-unit-files --state=enabled

# Common services to disable if not needed
systemctl disable --now avahi-daemon     # mDNS/zeroconf - network discovery
systemctl disable --now cups             # Printing service
systemctl disable --now bluetooth        # Bluetooth
systemctl disable --now rpcbind          # NFS portmapper
systemctl disable --now nfs-server       # NFS server
systemctl disable --now telnet           # Telnet (use SSH)
systemctl disable --now rsh-server       # Remote shell (use SSH)
systemctl disable --now tftp             # TFTP
systemctl disable --now vsftpd           # FTP server
systemctl disable --now xinetd          # inetd super-daemon
```

### Systemd Service Hardening (Drop-in Units)
```ini
# /etc/systemd/system/nginx.service.d/hardening.conf
[Service]
# Run as non-root
User=www-data
Group=www-data

# Filesystem isolation
PrivateTmp=yes               # Private /tmp
ProtectSystem=strict         # Read-only system dirs
ProtectHome=yes              # No access to /home, /root, /run/user
ReadWritePaths=/var/log/nginx /var/cache/nginx

# Namespace isolation
PrivateDevices=yes           # No access to device files
ProtectKernelTunables=yes    # Read-only /sys, /proc
ProtectKernelModules=yes     # Cannot load kernel modules
ProtectControlGroups=yes     # Read-only cgroups
RestrictNamespaces=yes       # Cannot create namespaces

# Capability restrictions
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETGID CAP_SETUID
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes          # No privilege escalation

# System call filtering
SystemCallFilter=@system-service
SystemCallArchitectures=native
```

```bash
systemctl daemon-reload && systemctl restart nginx
# Analyze service security score
systemd-analyze security nginx
```

---

## File Integrity Monitoring

### AIDE (Advanced Intrusion Detection Environment)
```bash
apt install aide   # Debian/Ubuntu
yum install aide   # RHEL

# Initialize baseline database
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Check for changes (run daily via cron)
aide --check
# Or update database after approved changes
aide --update

# /etc/aide/aide.conf — key sections
/etc CONTENT_EX            # Monitor /etc for content and extended attributes
/bin CONTENT_EX
/sbin CONTENT_EX
/usr/bin CONTENT_EX
/usr/sbin CONTENT_EX
!/var/log                  # Exclude volatile log dir
!/tmp                      # Exclude temp
```

---

## User and Account Hardening

```bash
# Lock unused system accounts
passwd -l daemon
passwd -l bin
passwd -l sys
passwd -l sync
passwd -l games
passwd -l news
passwd -l uucp
passwd -l proxy

# Set shell to /sbin/nologin for service accounts
usermod -s /sbin/nologin www-data
usermod -s /sbin/nologin nobody

# Find accounts with UID 0 (should only be root)
awk -F: '($3 == 0) { print $1 }' /etc/passwd

# Find accounts with empty passwords
awk -F: '($2 == "") { print $1 }' /etc/shadow

# List sudoers
grep -v '^#' /etc/sudoers | grep -v '^$'
sudo -l -U USERNAME

# Restrict su to wheel group
# /etc/pam.d/su — add:
# auth required pam_wheel.so use_uid
# Then: usermod -aG wheel adminuser
```

---

## Compliance Scanning

| Tool | Command | Framework |
|---|---|---|
| OpenSCAP | `oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis --results results.xml /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml` | CIS, DISA STIG, PCI-DSS |
| Lynis | `lynis audit system` | General hardening |
| CIS-CAT Pro | GUI tool — download from CIS | CIS Benchmarks |
| Inspec | `inspec exec dev-sec/linux-baseline` | DevSec Linux Baseline |
| Chef Auditor | Part of Chef ecosystem | Custom compliance |

```bash
# Install and run Lynis
apt install lynis
lynis audit system --quick
# Report at /var/log/lynis.log and /var/log/lynis-report.dat
# Hardening index: aim for 80+/100
```

---

## Quick Hardening Checklist

| Control | Command/Check | Priority |
|---|---|---|
| SSH key auth only | `grep PasswordAuthentication /etc/ssh/sshd_config` | Critical |
| Root SSH disabled | `grep PermitRootLogin /etc/ssh/sshd_config` | Critical |
| Firewall active | `nft list ruleset` or `iptables -L` | Critical |
| ASLR enabled | `sysctl kernel.randomize_va_space` (should be 2) | Critical |
| Auditd running | `systemctl is-active auditd` | High |
| SELinux/AppArmor enforcing | `sestatus` or `aa-status` | High |
| Automatic updates | `systemctl is-enabled unattended-upgrades` | High |
| No world-writable files | `find / -xdev -type f -perm -0002` | High |
| Password policy enforced | `grep -E 'minlen\|minclass' /etc/security/pwquality.conf` | High |
| Account lockout set | `grep pam_faillock /etc/pam.d/common-auth` | High |
| Unnecessary services disabled | `systemctl list-unit-files --state=enabled` | Medium |
| SUID baseline current | `find / -perm -4000 -type f` | Medium |
| AIDE baseline initialized | `aide --check` | Medium |

## Related Resources
- [Windows Hardening & GPO Reference](WINDOWS_HARDENING_GPO.md) — Windows equivalent
- [Enterprise Security Controls](ENTERPRISE_SECURITY_CONTROLS.md) — WAF, EDR, and enterprise tooling
- [Detection Rules Reference](DETECTION_RULES_REFERENCE.md) — Detections for Linux attack techniques
- [Privilege Escalation Reference](PRIVESC_REFERENCE.md) — Linux privesc techniques these controls mitigate
- [ICS / OT Security](disciplines/ics-ot-security.md) — Linux hardening in OT environments
