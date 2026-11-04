# Harden a Linux Host

> By the end of this guide you will have audited a Linux host, applied a reversible hardening subset (a network and kernel sysctl drop-in and a default-deny nftables firewall), verified that every change took effect, and written down how to undo each one. Written for administrators, homelab builders, and security engineers who look after their own Linux servers and want to see real terminal output at each step rather than a list of settings. The same audit, apply, and verify run was made on a lab host, and its screenshots appear below.

| Time | Difficulty | You need | You'll produce |
|---|---|---|---|
| About 2 hours for one host | Intermediate | Root on a Debian-family Linux host, a snapshot or backup, and a console that does not depend on SSH | An audit record, a sysctl drop-in, an nftables ruleset, an after-state record, and a tested rollback plan |

## Why this guide

In October 2026 the kernel project fixed CVE-2026-98432, an unauthenticated remote use-after-free in IPv4 TCP connection setup, and researchers reported that a Multipath TCP listener turns it into remote code execution. The library's case study on [CVE-2026-98432](/case-studies/LINUX_TCP_UAF_2026.md) explains the bug and the patch gap, and the [Multipath TCP attack surface](/case-studies/MPTCP_ATTACK_SURFACE_2026.md) study explains why an idle kernel feature is surface worth removing. Both end at the same three moves: patch and reboot, turn off Multipath TCP where nothing uses it, and drop inbound IPv4 TCP that carries IP options as a bridge until the patch lands. This guide does those three moves on a real host and adds the baseline around them that a host needs anyway.

What the guide covers: a read-only audit, kernel and update state, network stack and kernel information sysctl keys, a host firewall with nftables, SSH authentication, listening services, and audit rules for the files you change, followed by verification and rollback. What it leaves to the references: SELinux and AppArmor policy, PAM and password policy, filesystem mount options, file integrity monitoring, and the full CIS control set. Those live in the [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md).

How to read the screenshots: `lab#` is the prompt of a root shell on the lab host. The networks in the firewall are documentation placeholders (`203.0.113.0/24` and `198.51.100.0/24`, reserved for examples), so put your own admin networks in their place. Every command marked as run on the lab host appears in a screenshot with its real output. Commands for steps that were not applied on the lab host carry no screenshot and say so.

## Before you start

- [ ] Take a snapshot (virtual machine) or a full backup (physical host) and confirm you know how to restore it. Every change in this guide is reversible by hand, and the snapshot is the fallback if a mistake leaves the host unreachable.
- [ ] Have a console that does not depend on SSH: a hypervisor console, a serial console, an out-of-band controller, or a keyboard and screen. Step 4 sets an inbound default of drop; one wrong address in the admin set and SSH stops answering.
- [ ] Know which networks you administer the host from, written as CIDR ranges.
- [ ] Know what the host is for: which services must answer, and from where. Step 6 removes what is not on that list.
- [ ] Read the patch status for your distribution in the [CVE-2026-98432 patch gap table](/case-studies/LINUX_TCP_UAF_2026.md#the-patch-gap).

The lab host used here is a Kali Linux 2026.2 virtual machine on kernel `7.1.5+kali-amd64`, a Debian-family distribution, with OpenSSH listening on all interfaces and a container runtime listening on loopback. Commands use `apt`, `systemctl`, `nft`, and `sysctl`; on Red Hat-family hosts swap `apt` for `dnf` and check where your distribution keeps its nftables configuration file.

## Step 1: Audit the host (read-only)

Nothing in this step changes the host. Save the output (paste it into a ticket, or redirect each block to a file): it is your "before" record and the values you restore in a rollback.

### Kernel and update state

```bash
uname -r
apt-cache policy linux-image-amd64 | head -3
apt list --upgradable 2>/dev/null | wc -l
cat /sys/kernel/security/lockdown 2>&1
```

![Audit 1 on the lab host: uname -r prints 7.1.5+kali-amd64; apt-cache policy for linux-image-amd64 shows Installed and Candidate both at 7.1.5-1kali1; apt list --upgradable counts 263 lines; /sys/kernel/security/lockdown prints [none] integrity confidentiality](images/harden-audit-1-kernel.png)

How to read it:

- `uname -r` is the kernel that is running, which is the one that matters. A newer kernel package on disk does nothing until the host reboots into it.
- `Installed` equal to `Candidate` means the configured repositories offer no newer kernel meta-package. That is either "you are current" or "no fixed package exists yet"; the next step tells them apart.
- The upgradable count was 263 lines on the lab host. A large backlog is a patching finding in its own right, separate from the kernel.
- The lockdown file shows the [kernel lockdown](https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html) mode in brackets. `[none]` means lockdown is off. The kernel's `lockdown=` boot parameter ([kernel parameters](https://docs.kernel.org/admin-guide/kernel-parameters.html)) sets `integrity` (userland cannot modify the running kernel) or `confidentiality` (it also cannot read confidential kernel data). Lockdown was not changed on the lab host; it is a boot-time decision that can block tools you rely on, so test it on its own.

### Network stack and kernel sysctl keys

```bash
sysctl net.mptcp.enabled net.ipv4.conf.all.rp_filter net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.tcp_syncookies net.ipv4.icmp_echo_ignore_broadcasts kernel.kptr_restrict kernel.dmesg_restrict kernel.unprivileged_bpf_disabled kernel.yama.ptrace_scope kernel.sysrq fs.protected_symlinks fs.protected_hardlinks
```

![Audit 2 on the lab host, before hardening: net.mptcp.enabled = 1, net.ipv4.conf.all.rp_filter = 0, accept_redirects = 0, send_redirects = 1, accept_source_route = 0, tcp_syncookies = 1, icmp_echo_ignore_broadcasts = 1, kernel.kptr_restrict = 0, kernel.dmesg_restrict = 0, kernel.unprivileged_bpf_disabled = 2, kernel.yama.ptrace_scope = 0, kernel.sysrq = 438, fs.protected_symlinks = 1, fs.protected_hardlinks = 1](images/harden-audit-2-sysctl.png)

How to read it: compare each value with the "Set to" column in Step 3. On the lab host the findings were Multipath TCP enabled (`1`), no reverse-path filtering (`0`), redirects being sent (`1`), kernel pointers and the kernel log readable by unprivileged users (`0`, `0`), classic ptrace (`0`), and most Magic SysRq functions allowed (`438`). The other keys were already at the hardened value; Step 3 pins the network ones so a later package or file cannot quietly change them, and leaves `unprivileged_bpf_disabled` and both `fs.protected_*` keys alone.

### Listeners and firewall state

```bash
ss -lntup
nft list ruleset
```

![Audit 3 on the lab host, before hardening: ss -lntup lists containerd on 127.0.0.1 port 35595 and sshd on 0.0.0.0 port 22 and [::] port 22; nft list ruleset shows only an ip nat and an ip filter table managed by iptables-nft for the container runtime, abbreviated in the capture, and no host input policy, so every inbound packet is accepted](images/harden-audit-3-network.png)

How to read it:

- In [`ss`](https://man7.org/linux/man-pages/man8/ss.8.html), `-l` shows listening sockets, `-n` skips name resolution, `-t` and `-u` select TCP and UDP, and `-p` names the owning process. A local address of `0.0.0.0` or `[::]` is reachable from every interface; `127.0.0.1` is loopback only. On the lab host, `sshd` is the only service reachable from the network.
- The ruleset held only the tables a container runtime writes through `iptables-nft` (shown abbreviated in the capture), with no input policy of the host's own. Leave those tables alone: the runtime owns them, and Step 4 adds a separate table beside them.

### SSH effective settings

```bash
sshd -T | grep -E -i "^(permitrootlogin|passwordauthentication|pubkeyauthentication|x11forwarding|maxauthtries) "
```

`sshd -T` prints the configuration the daemon would actually use, after every `Include` and default is resolved ([sshd(8)](https://man.openbsd.org/sshd)). Reading the files is not enough, because a drop-in can override the main file. On the lab host this command ran in the Step 8 verification; SSH was not changed in between, so its output there is also the before state: `MaxAuthTries 6`, `PermitRootLogin prohibit-password`, `PubkeyAuthentication yes`, `PasswordAuthentication yes`, `X11Forwarding yes`. Password logins are accepted, which is the Step 5 finding.

Checkpoint: You have the before values of the kernel, the sysctl keys, the listeners, the ruleset, and the SSH settings saved where you can find them during a rollback.

## Step 2: Kernel and updates

Not applied on the lab host: the captures needed the package state to stay fixed so the before and after could be compared. The commands below are the procedure, not tested output.

1. Patch and reboot. On Debian and Ubuntu:

```bash
sudo apt-get update
sudo apt-get dist-upgrade
sudo reboot
# after the reboot, confirm the running kernel changed
uname -r
```

   Use `dist-upgrade`, not `upgrade`: a new kernel usually arrives as a new package that the kernel meta-package depends on, and [apt-get(8)](https://manpages.debian.org/stable/apt/apt-get.8.en.html) says `upgrade` never installs a package that is not already installed, so it leaves the kernel behind. Per-distribution commands are in the case study's [per-platform remediation table](/case-studies/LINUX_TCP_UAF_2026.md#per-platform-remediation).

2. Use live patching where it exists, as a bridge to the reboot. Ubuntu's [Livepatch documentation](https://ubuntu.com/security/livepatch/docs) describes the service, and its page on [what Livepatch provides](https://ubuntu.com/security/livepatch/docs/client/explanation/architecture/what-kind-of-updates-are-provided-by-livepatch/) is explicit that it addresses high and critical kernel vulnerabilities and that some code paths cannot be patched live, so a normal upgrade and reboot is still needed. Confirm coverage for the specific CVE before you count on it.

3. When no fixed package exists yet, check the distribution's tracker, not the kernel version string. For CVE-2026-98432, [Debian's security tracker](https://security-tracker.debian.org/tracker/CVE-2026-98432) lists the first fixed version per release (as of 3 November 2026: 6.1.190-1 for bookworm (DLA-4841-1), 6.12.113-1 for trixie (DSA-6568-1), 7.2.10-1 for unstable, and 6.12.113-1~deb12u1 for the bookworm linux-6.12 backport (DLA-4850-1)); a host running that version or any later one in the same release is fixed. The lab host runs its own distribution's kernel, `7.1.5-1kali1`, which is older than Debian's first fixed unstable version, and its repository offered no newer candidate: on the day of the capture that is the "no fixed package yet" case, and the distribution's own advisory is what closes it. Until the package arrives, apply the two bridges in this guide: turn off Multipath TCP where nothing uses it (Step 3) and drop inbound IPv4 TCP carrying IP options (Step 4). The case study's [two operational traps](/case-studies/LINUX_TCP_UAF_2026.md#two-operational-traps) explain why neither replaces the patch.

4. Turn on automatic security updates where the host's role allows it. On Debian, the [Debian Administrator's Handbook](https://www.debian.org/doc/manuals/debian-handbook/sect.regular-upgrades.en.html) covers `unattended-upgrades`, which by default installs only security updates and can be enabled with `dpkg-reconfigure -plow unattended-upgrades`; the [unattended-upgrade manual page](https://manpages.debian.org/stable/unattended-upgrades/unattended-upgrade.8.en.html) documents `--dry-run` for a test run. On Ubuntu, the [automatic updates how-to](https://ubuntu.com/server/docs/how-to/software/automatic-updates/) explains `/etc/apt/apt.conf.d/20auto-upgrades` and `50unattended-upgrades`, the logs in `/var/log/unattended-upgrades`, and the optional automatic reboot.

```bash
sudo apt-get install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
sudo unattended-upgrade --dry-run --debug
```

Checkpoint: `uname -r` names a kernel your distribution lists as fixed, or you have a dated note that no fixed package exists yet and the Step 3 and Step 4 bridges are in place.

Watch out: an updated kernel package on a host that has not rebooted is still vulnerable. Track "running kernel" and "installed kernel" as separate facts.

## Step 3: Network stack and kernel sysctl drop-in

Applied on the lab host. Settings go in a drop-in file under `/etc/sysctl.d/`. [sysctl.d(5)](https://man7.org/linux/man-pages/man5/sysctl.d.5.html) sorts every configuration file by name and, when several set the same key, the lexicographically latest file wins; it recommends the 60-90 range for files in `/etc/`, so a `90-` file overrides vendor defaults. This is the file applied on the lab host, installed as `/etc/sysctl.d/90-hardening.conf`:

```ini
# /etc/sysctl.d/90-hardening.conf : network stack and kernel information hardening
net.mptcp.enabled = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.sysrq = 4
```

Key by key, with the kernel documentation for each. "Lab before" is the Step 1 value; keys the audit did not read say so.

| Key | Lab before | Set to | What the value does | Kernel documentation |
|---|---|---|---|---|
| `net.mptcp.enabled` | 1 | 0 | Multipath TCP sockets cannot be created. Per network namespace, so containers in their own namespaces need it set there too. | [MPTCP sysfs variables](https://docs.kernel.org/networking/mptcp-sysctl.html) |
| `net.ipv4.conf.all.rp_filter`, `.default.rp_filter` | 0 (all) | 1 | Strict reverse-path filtering (RFC 3704): a packet whose source would not be routed back out the interface it arrived on is dropped. The higher of `all` and the interface value applies. Use `2` (loose) on hosts with asymmetric routing. | [IP sysctl: rp_filter](https://docs.kernel.org/networking/ip-sysctl.html) |
| `net.ipv4.conf.*.accept_redirects`, `net.ipv6.conf.*.accept_redirects` | 0 (IPv4 all) | 0 | Ignore ICMP redirects, which let a sender on the local network rewrite your routes. On a host that does not forward, IPv4 accepts redirects on an interface if either `all` or the interface value is true, so also check existing interfaces with `sysctl -a \| grep accept_redirects`. | [IP sysctl: accept_redirects](https://docs.kernel.org/networking/ip-sysctl.html) |
| `net.ipv4.conf.all.send_redirects`, `.default.send_redirects` | 1 (all) | 0 | Stop sending redirects, which only a router should do (kernel default: true). | [IP sysctl: send_redirects](https://docs.kernel.org/networking/ip-sysctl.html) |
| `net.ipv4.conf.*.accept_source_route` | 0 (all) | 0 | Refuse IPv4 packets with the source-route option (default for a host is already false; the drop-in pins it). | [IP sysctl: accept_source_route](https://docs.kernel.org/networking/ip-sysctl.html) |
| `net.ipv6.conf.all.accept_source_route` | not captured | 0 | `0` is the kernel default and still accepts routing header type 2 (Mobile IPv6); a negative value refuses all routing headers. Use `-1` if you do not run Mobile IPv6. | [IP sysctl: IPv6 accept_source_route](https://docs.kernel.org/networking/ip-sysctl.html) |
| `net.ipv4.tcp_syncookies` | 1 | 1 | Send SYN cookies when a listener's SYN backlog overflows, the fallback against SYN floods (kernel default 1; pinned). | [IP sysctl: tcp_syncookies](https://docs.kernel.org/networking/ip-sysctl.html) |
| `net.ipv4.icmp_echo_ignore_broadcasts` | 1 | 1 | Ignore ICMP echo and timestamp requests sent to broadcast or multicast addresses (pinned). | [IP sysctl: icmp_echo_ignore_broadcasts](https://docs.kernel.org/networking/ip-sysctl.html) |
| `kernel.kptr_restrict` | 0 | 2 | Kernel pointers printed with `%pK` are replaced with zeros for every user, root included, which takes away an easy address leak. | [Kernel sysctl: kptr_restrict](https://docs.kernel.org/admin-guide/sysctl/kernel.html) |
| `kernel.dmesg_restrict` | 0 | 1 | Reading the kernel log with `dmesg` requires `CAP_SYSLOG`. | [Kernel sysctl: dmesg_restrict](https://docs.kernel.org/admin-guide/sysctl/kernel.html) |
| `kernel.yama.ptrace_scope` | 0 | 1 | Restricted ptrace: a process can attach only to its own descendants (or a declared debugger), so one compromised process cannot read another's memory under the same user. `gdb EXE` still works; `gdb --pid` needs root. | [Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html) |
| `kernel.sysrq` | 438 | 4 | 438 is the bitmask 2+4+16+32+128+256 (log level, keyboard control, sync, remount read-only, reboot, renice). 4 leaves only keyboard control (SAK). | [Magic SysRq](https://docs.kernel.org/admin-guide/sysrq.html), [kernel sysctl: sysrq](https://docs.kernel.org/admin-guide/sysctl/kernel.html) |

Left unchanged because they were already hardened on the lab host: `kernel.unprivileged_bpf_disabled = 2` (unprivileged `bpf()` is off and an admin can still change it; `1` would lock it off until reboot; [kernel sysctl: unprivileged_bpf_disabled](https://docs.kernel.org/admin-guide/sysctl/kernel.html)), and `fs.protected_symlinks = 1` and `fs.protected_hardlinks = 1`, which close the classic link races in world-writable directories ([fs sysctl](https://docs.kernel.org/admin-guide/sysctl/fs.html)).

Turning Multipath TCP off is safe only where nothing uses it: a socket that asks for MPTCP while it is disabled fails rather than falling back. Run the case study's [Question 3 check](/case-studies/MPTCP_ATTACK_SURFACE_2026.md#question-3-is-anything-actually-using-it) first, and read its [container and namespace caveat](/case-studies/MPTCP_ATTACK_SURFACE_2026.md#the-container-and-namespace-caveat). The kernel's [MPTCP overview](https://docs.kernel.org/networking/mptcp.html) describes how applications opt in.

Apply it. The run on the lab host staged both files in `/tmp` and checked the firewall syntax first (this is the start of the apply screenshot shown in Step 4):

```bash
nft -c -f /tmp/hardening.nft
install -m 0644 /tmp/90-hardening.conf /etc/sysctl.d/90-hardening.conf
sysctl -p /etc/sysctl.d/90-hardening.conf
```

`sysctl -p` loads the file now and prints each key it set; the drop-in makes the values survive a reboot ([sysctl(8)](https://man7.org/linux/man-pages/man8/sysctl.8.html)).

Checkpoint: `sysctl -p` printed every line of the file with no error. An `unknown key` error means the kernel lacks that feature (for example, `net.mptcp.enabled` on a kernel built without MPTCP); remove the line rather than ignoring the error.

## Step 4: Host firewall with nftables

Applied on the lab host. This is the ruleset applied, installed as `/etc/nftables.conf`:

```nft
#!/usr/sbin/nft -f
# Host firewall: default-deny inbound, with the IPv4 IP-options drop that bridges CVE-2026-98432.
table inet hardening {}
flush table inet hardening
table inet hardening {
    set admin_nets {
        type ipv4_addr
        flags interval
        elements = { 203.0.113.0/24, 198.51.100.0/24 }
    }
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ip hdrlength > 5 meta l4proto tcp counter drop comment "CVE-2026-98432 bridge: IPv4 TCP carrying IP options"
        ct state invalid drop
        ct state established,related accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        tcp dport 22 ip saddr @admin_nets accept comment "SSH from admin networks only"
        counter comment "dropped by policy"
    }
}
```

What each part does:

- `table inet hardening {}` followed by `flush table inet hardening`: the empty declaration makes sure the table exists, so the flush succeeds on the first load, and the flush empties it on every later load. Because `nft -f` runs the whole file as one transaction, the old rules and the new ones are swapped in a single step, with no moment where the host is unfiltered ([atomic rule replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement), [scripting](https://wiki.nftables.org/wiki-nftables/index.php/Scripting)). The table is `inet`, so one chain sees IPv4 and IPv6, and it is its own table, so the container runtime's tables are untouched.
- `set admin_nets` with `flags interval` holds CIDR ranges ([sets](https://wiki.nftables.org/wiki-nftables/index.php/Sets)). Replace the placeholders with your admin networks. A flush does not empty sets, so removing a network from the file and reloading leaves it in the set; delete the table and reload to remove one.
- `type filter hook input priority 0; policy drop;`: a base chain on the input hook whose default is drop, the pattern in the wiki's [simple ruleset for a server](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server).
- `iif "lo" accept`: loopback traffic, which local services such as the container runtime depend on.
- `ip hdrlength > 5 meta l4proto tcp counter drop`: the CVE-2026-98432 bridge. The IPv4 header length field counts 32-bit words and a header without options is exactly 5 ([RFC 791](https://www.rfc-editor.org/rfc/rfc791.html)), so a value above 5 means IP options are present ([nft(8) `ip hdrlength`](https://www.netfilter.org/projects/nftables/manpage.html), [matching packet headers](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_headers)). It sits before the established rule on purpose, so options are dropped on every IPv4 TCP packet, including those of existing connections. The `counter` shows whether anything legitimate is hitting it ([counters](https://wiki.nftables.org/wiki-nftables/index.php/Counters)).
- `ct state invalid drop` and `ct state established,related accept`: connection tracking, so replies to the host's own traffic come back in ([conntrack metainformation](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation)).
- `ip protocol icmp accept` and `ip6 nexthdr ipv6-icmp accept`: ICMP stays open. IPv6 neighbor discovery and path MTU discovery (Packet Too Big) run over ICMPv6, which is why [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890.html) recommends against filtering it wholesale.
- `tcp dport 22 ip saddr @admin_nets accept`: SSH from the admin networks only. The match is on IPv4 source addresses, so SSH over IPv6 falls through to the drop policy even though `sshd` listens on `[::]`. Add an `ipv6_addr` set and rule if you administer over IPv6.
- `counter comment "dropped by policy"`: counts what reaches the default drop, so you can see what the policy is refusing.

Apply, then make it persistent. These are the commands run on the lab host, after the sysctl lines from Step 3 (the previous `/etc/nftables.conf` is copied aside first so it can be restored):

```bash
cp /etc/nftables.conf /etc/nftables.conf.pre-hardening
install -m 0644 /tmp/hardening.nft /etc/nftables.conf
nft -f /etc/nftables.conf
systemctl enable nftables
```

![The apply run on the lab host: nft -c -f /tmp/hardening.nft prints syntax OK; install copies the sysctl drop-in to /etc/sysctl.d/90-hardening.conf; sysctl -p prints all eighteen keys at their new values, from net.mptcp.enabled = 0 through kernel.sysrq = 4; the old /etc/nftables.conf is copied to /etc/nftables.conf.pre-hardening; the new ruleset is installed as /etc/nftables.conf; nft -f loads it and prints ruleset loaded; systemctl enable nftables creates the sysinit.target.wants symlink for nftables.service](images/harden-apply.png)

`nft -c` (`--check`) parses the file without applying it ([nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)); run it every time you edit the file. `systemctl enable nftables` makes the distribution's `nftables.service` load `/etc/nftables.conf` at boot ([systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)). The arrow in the symlink line is garbled in the capture by a character-encoding step; the message is the normal "Created symlink" line.

After the apply on the lab host, SSH from an admin network and ICMP echo were checked and still worked; that check is not in the screenshots.

Checkpoint: from a second terminal, open a new SSH session from an admin network before you close your current one. If the new session fails, fix the set from the console and reload.

Watch out:

- Container hosts: traffic to a published container port is translated in prerouting and then forwarded, so it passes the forward hook, not input ([netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)). This ruleset does not filter it, and on clusters the case study notes the IP-options rule covers only the host's own network namespace.
- Some networks use IP options legitimately. Watch the bridge rule's counter for a few days; a steady count from known peers means you need an exception, not silence.

## Step 5: SSH authentication

Not applied on the lab host: the run was kept to the reversible network and kernel subset, and key-only login needs a tested key on every admin account before it is switched on, or it locks people out. The directives below come from the [sshd_config(5) manual](https://man.openbsd.org/sshd_config).

1. Install and test a key for every admin account (`ssh-copy-id`, then log in with the key in a new session).
2. Write the directives to a drop-in. `sshd` uses the first value it obtains for each keyword, so a drop-in only wins if it is read before the main file sets the same keyword: check that `grep -i '^Include' /etc/ssh/sshd_config` shows an `Include` of `sshd_config.d/*.conf` above any of these keywords, and that no other file in that directory sorts earlier and sets them.

```text
# /etc/ssh/sshd_config.d/10-hardening.conf
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
```

   What each does, per the manual: `PasswordAuthentication no` refuses passwords (default yes); `KbdInteractiveAuthentication no` closes the keyboard-interactive path, which can also prompt for a password (default yes); `PermitRootLogin no` refuses root entirely, where the default `prohibit-password` still allows root with a key; `X11Forwarding no` turns off X11 forwarding (the upstream default is no, and the lab host's configuration had turned it on, as `sshd -T` shows); `MaxAuthTries 3` lowers the attempts per connection from the default 6.

3. Test the configuration, then reload, keeping your current session open:

```bash
sudo sshd -t
sudo sshd -T | grep -E -i "^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|x11forwarding|maxauthtries) "
sudo systemctl reload ssh
```

   `sshd -t` checks the files and keys; `sshd -T` prints the effective values ([sshd(8)](https://man.openbsd.org/sshd)). On Debian-family hosts the unit is `ssh`; elsewhere it is often `sshd`.

Checkpoint: `sshd -T` shows `passwordauthentication no`, `kbdinteractiveauthentication no`, `permitrootlogin no`, `x11forwarding no`, `maxauthtries 3`, and a new key-based session from an admin network succeeds.

## Step 6: Services and listeners

Not applied on the lab host: both of its listeners were expected (SSH for administration, the container runtime on loopback). The procedure for a host where `ss -lntup` shows something you cannot name:

```bash
ss -lntup                                   # who listens, and on which address
systemctl list-units --type=service --state=running
sudo systemctl disable --now <unit>         # stop it now and at boot
sudo systemctl mask <unit>                  # optional: refuse any start, even as a dependency
```

`disable --now` removes the unit's enable symlinks and stops it; `mask` makes every start attempt fail until `unmask` ([systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)). Prefer removing the package when the service is not needed at all. For a service that must run but only locally, bind it to `127.0.0.1` in its own configuration rather than relying on the firewall alone. The library's [systemd and systemctl reference](/commands/systemctl.md) covers unit sandboxing options for the services you keep.

Checkpoint: every line in `ss -lntup` maps to a service on your "what the host is for" list.

## Step 7: Logging and audit

Not applied on the lab host: the run was kept to the reversible subset, so these rules were not loaded there. They come from the [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html) manual, which gives the syscall form for file watches; [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html) marks the older `-w path -p wa` form as deprecated.

Watch the files this guide changed, so a later edit (by a person or by malware) leaves a record:

```text
# /etc/audit/rules.d/50-hardening.rules
-a always,exit -F arch=b64 -F path=/etc/sysctl.d/90-hardening.conf -F perm=wa -F key=hardening
-a always,exit -F arch=b64 -F path=/etc/nftables.conf -F perm=wa -F key=hardening
-a always,exit -F arch=b64 -F dir=/etc/ssh/sshd_config.d -F perm=wa -F key=hardening
-a always,exit -F arch=b64 -F path=/etc/ssh/sshd_config -F perm=wa -F key=hardening
```

```bash
sudo apt-get install auditd
sudo augenrules --load
sudo auditctl -l
sudo ausearch -k hardening
```

`augenrules` merges every `.rules` file in `/etc/audit/rules.d/` into `/etc/audit/audit.rules` ([augenrules(8)](https://man7.org/linux/man-pages/man8/augenrules.8.html)); `auditctl -l` lists the loaded rules; `ausearch -k` finds events by key ([ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html)). Records only help if someone reads them: forward `/var/log/audit/audit.log` and the journal to your SIEM with your usual log agent, and alert on the `hardening` key. The [Onboard a Log Source](/guides/ONBOARD_A_LOG_SOURCE.md) guide walks through doing that so the data powers a detection.

Checkpoint: `auditctl -l` lists the rules, and touching one of the watched files (for example, `sudo touch /etc/nftables.conf`) produces an event that `ausearch -k hardening` returns.

## Step 8: Verify, then know how to roll back

### Verify

Run on the lab host after the apply:

```bash
sysctl net.mptcp.enabled net.ipv4.conf.all.rp_filter net.ipv4.conf.all.send_redirects kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope kernel.sysrq
nft list table inet hardening
systemctl is-enabled nftables
ss -lntp
sshd -T | grep -E -i "^(permitrootlogin|passwordauthentication|pubkeyauthentication|x11forwarding|maxauthtries) "
```

![Verification on the lab host after hardening: sysctl shows net.mptcp.enabled = 0, rp_filter = 1, send_redirects = 0, kptr_restrict = 2, dmesg_restrict = 1, ptrace_scope = 1, sysrq = 4; nft list table inet hardening prints the admin_nets set with 198.51.100.0/24 and 203.0.113.0/24 and the input chain with policy drop, the IP-options drop rule and the policy counter both at packets 0 bytes 0; systemctl is-enabled nftables prints enabled; ss -lntp still lists containerd on 127.0.0.1 port 35595 and sshd on port 22 for IPv4 and IPv6; sshd -T shows MaxAuthTries 6, PermitRootLogin prohibit-password, PubkeyAuthentication yes, PasswordAuthentication yes, X11Forwarding yes, unchanged because SSH hardening was not applied](images/harden-verify.png)

How to read it:

- Every sysctl value matches the drop-in.
- `nft list table` prints the ruleset as the kernel holds it, not as you wrote it: indentation becomes tabs, `priority 0` is shown by its name `filter`, set elements are sorted, and counters show their packet and byte totals. Both counters at `0` right after the load is expected; check them again after a day.
- `enabled` means the ruleset is loaded at boot. Reboot once during a change window and run the same commands again, because a setting that only exists in memory is the most common hardening regression.
- The listeners are unchanged, which is expected: the firewall filters who can reach `sshd`, it does not stop it listening.
- The SSH lines still show password authentication on, because Step 5 was not applied on the lab host. On your host, after Step 5, they should match its checkpoint.

### Roll back

Work from the console, newest change first. These commands were not run on the lab host; its fallback was the snapshot taken before Step 1.

| Step | Undo | Confirm |
|---|---|---|
| 7 Audit rules | `sudo rm /etc/audit/rules.d/50-hardening.rules && sudo augenrules --load` | `sudo auditctl -l` no longer lists `key=hardening` |
| 6 Services | `sudo systemctl unmask <unit> && sudo systemctl enable --now <unit>` | `ss -lntup` shows the listener again |
| 5 SSH | `sudo rm /etc/ssh/sshd_config.d/10-hardening.conf && sudo sshd -t && sudo systemctl reload ssh` | `sudo sshd -T` shows the before values from Step 1 |
| 4 Firewall | `sudo nft delete table inet hardening`, then `sudo mv /etc/nftables.conf.pre-hardening /etc/nftables.conf` and `sudo systemctl disable nftables` (leave it enabled if the original file had rules you want at boot) | `sudo nft list ruleset` shows only the tables from the Step 1 audit |
| 3 Sysctl | `sudo rm /etc/sysctl.d/90-hardening.conf`, then set each key back to its Step 1 value with `sudo sysctl -w key=value`, or reboot | `sysctl <keys>` matches the Step 1 record |
| All | Restore the snapshot or backup taken before Step 1 | The host's Step 1 audit output matches the saved record |

Checkpoint: you can name, for each change, the command that undoes it and the command that proves it was undone.

## Checklist

| Control | Command | Verify command | Reference |
|---|---|---|---|
| Running a fixed kernel | `sudo apt-get dist-upgrade && sudo reboot` | `uname -r`, compared with the distribution's fixed version | [CVE-2026-98432 patch gap](/case-studies/LINUX_TCP_UAF_2026.md#the-patch-gap), [Debian security tracker](https://security-tracker.debian.org/tracker/CVE-2026-98432) |
| Automatic security updates | `sudo dpkg-reconfigure -plow unattended-upgrades` | `sudo unattended-upgrade --dry-run --debug` | [Debian Administrator's Handbook](https://www.debian.org/doc/manuals/debian-handbook/sect.regular-upgrades.en.html), [Ubuntu automatic updates](https://ubuntu.com/server/docs/how-to/software/automatic-updates/) |
| Multipath TCP off where unused | `net.mptcp.enabled = 0` in the drop-in, `sysctl -p` | `sysctl net.mptcp.enabled` | [MPTCP sysfs variables](https://docs.kernel.org/networking/mptcp-sysctl.html), [MPTCP case study](/case-studies/MPTCP_ATTACK_SURFACE_2026.md#part-4-reducing-the-surface-safely) |
| Reverse-path filtering | `net.ipv4.conf.all.rp_filter = 1` | `sysctl net.ipv4.conf.all.rp_filter` | [IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html) |
| No redirects accepted or sent | `accept_redirects = 0`, `send_redirects = 0` | `sysctl -a \| grep -E 'accept_redirects\|send_redirects'` | [IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html) |
| No source routing | `accept_source_route = 0` (IPv6: `-1` to refuse all) | `sysctl -a \| grep accept_source_route` | [IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html) |
| SYN cookies and broadcast echo ignored | `tcp_syncookies = 1`, `icmp_echo_ignore_broadcasts = 1` | `sysctl net.ipv4.tcp_syncookies net.ipv4.icmp_echo_ignore_broadcasts` | [IP sysctl](https://docs.kernel.org/networking/ip-sysctl.html) |
| Kernel pointers and log hidden | `kernel.kptr_restrict = 2`, `kernel.dmesg_restrict = 1` | `sysctl kernel.kptr_restrict kernel.dmesg_restrict` | [Kernel sysctl](https://docs.kernel.org/admin-guide/sysctl/kernel.html) |
| Restricted ptrace | `kernel.yama.ptrace_scope = 1` | `sysctl kernel.yama.ptrace_scope` | [Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html) |
| Magic SysRq limited | `kernel.sysrq = 4` | `sysctl kernel.sysrq` | [Magic SysRq](https://docs.kernel.org/admin-guide/sysrq.html) |
| Unprivileged BPF off, link protections on | already set on the lab host | `sysctl kernel.unprivileged_bpf_disabled fs.protected_symlinks fs.protected_hardlinks` | [Kernel sysctl](https://docs.kernel.org/admin-guide/sysctl/kernel.html), [fs sysctl](https://docs.kernel.org/admin-guide/sysctl/fs.html) |
| Default-deny inbound firewall | `nft -c -f` then `nft -f /etc/nftables.conf` | `nft list table inet hardening` | [Simple ruleset for a server](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server) |
| IPv4 IP-options drop (CVE bridge) | the `ip hdrlength > 5` rule | `nft list table inet hardening` (rule present, counter readable) | [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html), [CVE-2026-98432 traps](/case-studies/LINUX_TCP_UAF_2026.md#two-operational-traps) |
| Firewall loaded at boot | `systemctl enable nftables` | `systemctl is-enabled nftables` | [systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) |
| SSH key-only, no root | `sshd_config.d/10-hardening.conf`, `sshd -t`, reload | `sshd -T \| grep -E -i "^(permitrootlogin\|passwordauthentication\|kbdinteractiveauthentication) "` | [sshd_config(5)](https://man.openbsd.org/sshd_config), [sshd(8)](https://man.openbsd.org/sshd) |
| Only needed listeners | `systemctl disable --now <unit>` | `ss -lntup` | [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html), [systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) |
| Changes to hardened files audited | `50-hardening.rules`, `augenrules --load` | `auditctl -l`, `ausearch -k hardening` | [audit.rules(7)](https://man7.org/linux/man-pages/man7/audit.rules.7.html) |

See also, for control-by-control baselines beyond this guide: the [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux) and the DISA Security Technical Implementation Guides for your distribution, published on the DoD Cyber Exchange.

## What good looks like

- A fresh build of the host role lands with the drop-in, the ruleset, and the SSH drop-in from configuration management, not from someone's terminal history.
- `uname -r` on every host maps to a kernel the distribution lists as fixed for the CVEs you track, and the gap between "package installed" and "rebooted into it" is measured in days.
- Multipath TCP is off on every host that does not use it, and the ones that do use it are named and patched first.
- The firewall counters are read: the IP-options rule stays at or near zero, and the policy counter's top sources are known.
- Every change has a written undo and a verify command, and the verify commands run again after every reboot and every baseline update.

## Go deeper

- [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md): the reference behind this guide, including [kernel hardening and sysctl](/LINUX_HARDENING_REFERENCE.md#_4-kernel-hardening-amp-sysctl), [network security and firewall](/LINUX_HARDENING_REFERENCE.md#_6-network-security-amp-firewall), [user and authentication hardening](/LINUX_HARDENING_REFERENCE.md#_2-user-amp-authentication-hardening), and [auditd and system logging](/LINUX_HARDENING_REFERENCE.md#_7-auditd-amp-system-logging)
- [Linux Hardening](/LINUX_HARDENING.md): the older page, which now points to the reference
- [The CVE-2026-98432 Linux kernel flaw](/case-studies/LINUX_TCP_UAF_2026.md): the bug, the patch gap, and why the network bridge is not a fix
- [The Multipath TCP attack surface](/case-studies/MPTCP_ATTACK_SURFACE_2026.md): how to find out whether anything uses MPTCP before you turn it off
- [Triage a New CVE in 30 Minutes](/guides/TRIAGE_A_CVE.md): deciding how fast a kernel CVE like this one needs to move
- [Harden a Windows Baseline](/guides/HARDEN_A_WINDOWS_BASELINE.md): the same audit, apply, and verify discipline for Windows fleets
- [Linux Command Reference](/commands/linux-commands.md) and [systemd and systemctl Reference](/commands/systemctl.md): the commands used here, in more depth

*Guides are procedures, not gospel; verify every command against the current official documentation before you run it in production, and test on a host you can restore.*
