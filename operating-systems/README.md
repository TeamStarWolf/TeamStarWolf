<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Operating systems

> The operating systems defenders run, patch, and have to identify, from Linux and BSD servers to Windows, Apple, and Android devices, network appliances, hypervisors, and embedded systems: one page per system with its versions and support dates, where its security advisories are published, how it takes updates, and the commands that tell you which one you are on.

Support dates come from the [endoflife.date](https://endoflife.date/) API, fetched on 2026-11-03, or from the vendor page a row cites; where neither gives a date the page says so. Everything else comes from the vendor and project pages each page cites. For hardening steps, start with the [Linux Hardening Reference](/LINUX_HARDENING_REFERENCE.md), the [Harden a Linux Host](/guides/HARDEN_A_LINUX_HOST.md) guide, the [Windows Hardening Reference](/WINDOWS_HARDENING_REFERENCE.md), and the [macOS Security Reference](/MACOS_SECURITY_REFERENCE.md); for what each offensive, forensic, and privacy distribution is for, see [Security Operating Systems and Distributions](/SECURITY_OPERATING_SYSTEMS_REFERENCE.md).

## Debian family

Debian and Ubuntu, whose archive draws on Debian; both patch with apt and dpkg.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Debian](/operating-systems/debian.md) | 13, 12, 11 | `apt` and `dpkg` | Debian Security Advisories (DSA), Debian LTS Advisories (DLA), Debian Security Tracker |
| [Ubuntu](/operating-systems/ubuntu.md) | 26.04 LTS, 24.04 LTS, 22.04 LTS, 20.04 LTS | `apt` and `dpkg` | Ubuntu Security Notices (USN) |

## Red Hat Enterprise Linux family

Red Hat Enterprise Linux, the distributions that follow its releases, and Fedora, patched with dnf and rpm.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Red Hat Enterprise Linux](/operating-systems/rhel.md) | 10, 9, 8 | `dnf` and `rpm` | Red Hat Security Advisories (RHSA) |
| [AlmaLinux](/operating-systems/almalinux.md) | 10, 9, 8 | `dnf` and `rpm` | AlmaLinux Security Advisories (ALSA) |
| [Rocky Linux](/operating-systems/rocky-linux.md) | 10, 9, 8 | `dnf` and `rpm` | Rocky Linux Security Advisories (RLSA) |
| [Oracle Linux](/operating-systems/oracle-linux.md) | 10, 9, 8 | `dnf` and `rpm` | Oracle Linux Security Advisories (ELSA) |
| [Fedora](/operating-systems/fedora.md) | 45, 44 | `dnf` and `rpm` | Fedora updates (Bodhi), security type |

## SUSE family

SUSE Linux Enterprise and the openSUSE distributions, patched with zypper and rpm.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [SUSE Linux Enterprise Server](/operating-systems/sles.md) | 16.0, 15 SP7 | `zypper` and `rpm` | SUSE security updates (SUSE-SU) |
| [openSUSE Leap](/operating-systems/opensuse-leap.md) | 16.0 | `zypper` and `rpm` | openSUSE security updates (openSUSE-SU), SUSE security updates (SUSE-SU) |
| [openSUSE Tumbleweed](/operating-systems/opensuse-tumbleweed.md) | Rolling | `zypper` and `rpm` | openSUSE security updates (openSUSE-SU) |

## Independent distributions

Distributions with their own package managers and release models.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Arch Linux](/operating-systems/arch-linux.md) | Rolling | `pacman` | Arch Linux Security Advisories (ASA) |
| [Alpine Linux](/operating-systems/alpine-linux.md) | 3.24, 3.23 | `apk` | Alpine secdb |
| [Gentoo Linux](/operating-systems/gentoo.md) | Rolling | Portage (`emerge`) | Gentoo Linux Security Advisories (GLSA) |
| [NixOS](/operating-systems/nixos.md) | 26.05, 25.11 | Nix (`nixos-rebuild`) | Nixpkgs security tracker, NixOS Discourse security announcements |

## Cloud provider distributions

Distributions a cloud provider builds and patches for its own platform.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Amazon Linux](/operating-systems/amazon-linux.md) | 2023, 2 | `dnf` on AL2023, `yum` on AL2 (both rpm) | Amazon Linux Security Center (ALAS) |
| [Azure Linux](/operating-systems/azure-linux.md) | 3.0, 2.0 (CBL-Mariner) | `tdnf` and `rpm` | Azure Linux vulnerability data (OVAL), Microsoft Security Update Guide API |

## Container and immutable hosts

Systems built to run containers: a container base with no kernel, and hosts that update by swapping whole images.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Wolfi](/operating-systems/wolfi.md) | Rolling | `apk` | Wolfi advisories repository, Wolfi security database (secdb) |
| [Flatcar Container Linux](/operating-systems/flatcar.md) | Stable channel | None; whole-image updates through `update_engine` | Flatcar release notes, Flatcar security advisories on GitHub |
| [Bottlerocket](/operating-systems/bottlerocket.md) | 1.x | None; whole-image updates through the Bottlerocket API | Bottlerocket security advisories (BRSA) |

## Security testing distributions

Distributions for penetration testing and security research, built on Debian.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Kali Linux](/operating-systems/kali-linux.md) | Rolling (2026.3 snapshot) | `apt` and `dpkg` | No numbered advisories |
| [Parrot OS](/operating-systems/parrot-os.md) | 7.x (7.4) | `apt` and `dpkg` | No numbered advisories |

## BSD family

FreeBSD, OpenBSD, and NetBSD, each released as one base system (kernel and userland) with its own update tools and its own advisory series.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [FreeBSD](/operating-systems/freebsd.md) | 15, 14 | `freebsd-update` (base system) and `pkg` (packages) | FreeBSD Security Advisories, FreeBSD Errata Notices, FreeBSD VuXML (Ports Collection) |
| [OpenBSD](/operating-systems/openbsd.md) | 8.0, 7.9 | `syspatch` (base system) and `pkg_add` (packages) | OpenBSD errata |
| [NetBSD](/operating-systems/netbsd.md) | 11, 10 | `sysinst` or `sysupgrade` (base system) and pkgsrc packages | NetBSD Security Advisories, pkgsrc vulnerabilities list |

## Windows

Windows client and Windows Server, patched by the monthly cumulative updates that Microsoft publishes on the second Tuesday of each month.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Windows](/operating-systems/windows.md) | 11 26H2 (Home and Pro), 11 26H2 (Enterprise and Education), 11 25H2 (Home and Pro), 11 25H2 (Enterprise and Education), 11 24H2 (Enterprise and Education), 11 Enterprise LTSC 2024 (24H2), 10 22H2, 10 Enterprise LTSC 2021 (21H2) | Windows Update (cumulative updates, identified by KB number) | Microsoft Security Update Guide |
| [Windows Server](/operating-systems/windows-server.md) | 2025, 2022, 2019 (1809), 2016 (1607), 23H2 (Annual Channel) | Windows Update (cumulative updates, identified by KB number) | Microsoft Security Update Guide |

## macOS

Apple's desktop operating system, updated through Software Update.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [macOS](/operating-systems/macos.md) | 27, 26, 15 | Software Update (System Settings > General > Software Update) | Apple security releases |

## Mobile operating systems

Android and iOS: the phone and tablet systems whose security fixes arrive as vendor updates and monthly bulletins.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [iOS](/operating-systems/ios.md) | 27, 26 | Software Update (Settings > General > Software Update) | Apple security releases |
| [Android](/operating-systems/android.md) | 17 (API level 37), 16 (API level 36), 15 (API level 35) | System updates from the device maker; Google Play system updates | Android Security Bulletins, Pixel Update Bulletins |

## Network operating systems

The software on routers, switches, firewalls, and application delivery controllers, upgraded by installing a vendor image; their advisories fill a large share of the known-exploited record.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [Cisco IOS XE](/operating-systems/cisco-ios-xe.md) | 26.1, 17.18, 17.15, 17.12 | None; upgrades install a new IOS XE software image | Cisco Security Advisories |
| [Cisco NX-OS](/operating-systems/cisco-nx-os.md) | 10.x (standalone) | None; upgrades install a new NX-OS software image | Cisco Security Advisories |
| [Cisco Secure Firewall ASA and FTD](/operating-systems/cisco-secure-firewall.md) | ASA 9.24, ASA 9.22, ASA 9.20, FTD 10.1, FTD 7.7, FTD 7.6, FTD 7.4 | None; upgrades install a new ASA or FTD image (FTD through the Firewall Management Center or Device Manager) | Cisco Security Advisories |
| [Juniper Junos OS](/operating-systems/junos.md) | 24.4 | None; upgrades install a new Junos OS software package | Juniper Security Advisories (JSA) |
| [Palo Alto Networks PAN-OS](/operating-systems/pan-os.md) | 12.2, 12.1, 11.2, 11.1 | None; upgrades install a new PAN-OS software image (with hotfix releases such as -h1) | Palo Alto Networks Security Advisories |
| [Fortinet FortiOS](/operating-systems/fortios.md) | 8.0, 7.6, 7.4 | None; upgrades install a new FortiOS firmware image | FortiGuard PSIRT advisories |
| [NetScaler ADC and Gateway](/operating-systems/netscaler.md) | 14.1, 13.1 | None; upgrades install a new NetScaler firmware build | Citrix and NetScaler security bulletins |

## Hypervisors and Kubernetes node images

The hosts that run virtual machines and containers: bare-metal hypervisors, the KVM stack on general-purpose Linux, and the node images managed Kubernetes services boot.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [VMware ESXi](/operating-systems/vmware-esxi.md) | 9.1, 9.0, 8.0 | None; patches install ESXi image profiles or updates (managed through vCenter) | VMware Security Advisories (Broadcom) |
| [Microsoft Hyper-V](/operating-systems/hyper-v.md) | On Windows Server 2025, On Windows Server 2022, On Windows Server 2019 | Windows Update (as part of the host's cumulative updates) | Microsoft Security Update Guide |
| [Proxmox VE](/operating-systems/proxmox-ve.md) | 9, 8 | `apt` and `dpkg` | Proxmox VE security advisories (forum) |
| [KVM hosts on RHEL and Ubuntu](/operating-systems/kvm.md) | On RHEL 10, On RHEL 9, On Ubuntu 24.04 LTS | The host distribution's (`dnf` on RHEL, `apt` on Ubuntu) | Red Hat Security Advisories (RHSA), Ubuntu Security Notices (USN) |
| [Kubernetes node images](/operating-systems/kubernetes-node-images.md) | EKS: Amazon Linux 2023, GKE: Container-Optimized OS 125 LTS, GKE: Container-Optimized OS 121 LTS, AKS: Ubuntu 24.04, AKS: Ubuntu 22.04 | None on the node; the provider replaces the node image | Amazon Linux Security Center (ALAS), Container-Optimized OS release notes, GKE security bulletins, Ubuntu Security Notices (USN) |

## Embedded and real-time systems

Real-time kernels, embedded platforms, and router firmware, most of them built into products by a device maker rather than installed by the operator.

| System | Versions | Package manager | Advisories |
|---|---|---|---|
| [QNX](/operating-systems/qnx.md) | SDP 8.0 | None; the device maker builds QNX into its firmware | BlackBerry and QNX security advisories |
| [Wind River VxWorks](/operating-systems/vxworks.md) | VxWorks | None; the device maker builds VxWorks into its firmware | Wind River Security Center, Wind River safety and security notices |
| [FreeRTOS](/operating-systems/freertos.md) | Kernel V11 | None; the kernel is compiled into the device firmware | FreeRTOS-Kernel security advisories |
| [Zephyr RTOS](/operating-systems/zephyr.md) | 4.5, 4.4, 3.7 LTS | None; Zephyr is source code built into the firmware with West | Zephyr vulnerabilities, Zephyr GitHub security advisories |
| [OpenWrt](/operating-systems/openwrt.md) | 25.12, 24.10 | `apk` or `opkg` (both packages are in the 24.10 and 25.12 source trees) | OpenWrt security advisories, OpenWrt security policy (GitHub) |

## About the catalog

Every page here is written by `scripts/build_os_pages.py` from `data/os/os-catalog.jsonl`, one row per system and major version (or release train, channel, or node image). Edit the catalog, then run `python scripts/build_os_pages.py`; `--refresh-eol` re-reads the support dates from endoflife.date, and CI runs `--check`. The vocabulary ids in each page's last section are the `product:` rows of `data/vocab/entities.jsonl`.

<!-- os-pages:end -->
