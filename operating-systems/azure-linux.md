<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Azure Linux

> Microsoft's distribution for Azure, first released as CBL-Mariner, used as the Azure Linux container host on AKS and as a VM image.

Part of [Operating systems](/operating-systems/README.md) (Cloud provider distributions). endoflife.date does not track this system, so the support column below quotes the vendor's own statement.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| 3.0 | None | Not published | Not published | Not published | Not published | Not published | Vendor statement (see note) |
| 2.0 (CBL-Mariner) | None | Not published | Not published | Not published | Not published | Not published | Vendor statement (see note) |

- 3.0: Microsoft's AKS lifecycle page supports Azure Linux 3.0 until roughly three years after the AKS 1.32 release; it gives no general end-of-life date. ([source](https://learn.microsoft.com/en-us/azure/azure-linux/aks-support-cycle))
- 2.0 (CBL-Mariner): Microsoft's AKS lifecycle page lists AKS 1.31 as the last version supported with Azure Linux 2.0 and tells AKS long-term support users to migrate to 3.0 by November 2025; it gives no general end-of-life date. ([source](https://learn.microsoft.com/en-us/azure/azure-linux/aks-support-cycle))

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| 3.0 | Linux 6.6 (kernel spec on the 3.0 branch) | x86_64, aarch64 | Independent (Microsoft) | packages.microsoft.com azurelinux/3.0 |
| 2.0 (CBL-Mariner) | Linux 5.15 (kernel spec on the 2.0 branch) | x86_64, aarch64 | Independent (Microsoft) | packages.microsoft.com cbl-mariner/2.0 |

## Where its advisories live

- [Azure Linux vulnerability data (OVAL)](https://github.com/microsoft/AzureLinuxVulnerabilityData): IDs take the form `CVE-YYYY-NNNN`.
- [Microsoft Security Update Guide API](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API): IDs take the form `CVE-YYYY-NNNN`.

Microsoft publishes Azure Linux advisories in VEX format through the Microsoft Security Response Center and lists Azure Linux CVEs in the Security Update Guide's CVRF API (Azure Linux, manage CVEs).

## How it patches

Package manager: `tdnf` and `rpm`.

On a VM, fixes arrive as package updates. On AKS, the Azure Linux container host gets them as package updates bundled into monthly node image releases, and high and critical fixes can ship earlier as package updates (Azure Linux, manage CVEs).

```sh
sudo tdnf check-update
sudo tdnf upgrade
```

## Identify it from a terminal

| Command | What it shows |
|---|---|
| `cat /etc/os-release` | Distribution name, `ID`, `VERSION_ID` and, where set, `VERSION_CODENAME` |
| `uname -r` | Release of the running kernel |
| `hostnamectl` | Operating System, Kernel and Architecture lines (systemd hosts) |
| `rpm -qa \| grep -i kernel` | Every installed kernel package |

The `ID` and `VERSION_ID` fields of `/etc/os-release` (the [os-release format](https://www.freedesktop.org/software/systemd/man/latest/os-release.html)) for each version:

| Version | os-release fields | Checked against |
|---|---|---|
| 3.0 | `ID=azurelinux`, `VERSION_ID=3.0` | Azure Linux release package spec on GitHub |
| 2.0 (CBL-Mariner) | `ID=mariner`, `VERSION_ID=2.0` | Azure Linux release package spec on GitHub |

## Security relevance

Azure Linux (CBL-Mariner) is Microsoft's minimal host for containers and edge services, so like other node operating systems its real surface is the workload it carries and the node it runs on rather than an interactive login. The hardening story is a small package set and a controlled update stream. The main risk is a container escape that reaches the node; see the container and Kubernetes security references below.

## Hardening

- [Linux Hardening Reference Library](/LINUX_HARDENING_REFERENCE.md)
- [Linux Hardening](/LINUX_HARDENING.md)
- [Harden a Linux Host (guide)](/guides/HARDEN_A_LINUX_HOST.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [systemd and systemctl Reference](/commands/systemctl.md)
- [Package Managers](/PACKAGE_MANAGERS_REFERENCE.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)

## On the Intelligence Hub

The library's vocabulary id for Azure Linux is `product:azure-linux`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Open source; the sources are on GitHub (microsoft/azurelinux).

Vendor and project pages read for this page (2026-11-03):

- [Azure Linux Container Host support lifecycle for AKS](https://learn.microsoft.com/en-us/azure/azure-linux/aks-support-cycle)
- [Azure Linux: manage CVEs](https://learn.microsoft.com/en-us/azure/azure-linux/manage-cves)
- [Azure Linux: kernel management](https://learn.microsoft.com/en-us/azure/azure-linux/kernel-management)
- [Azure Linux vulnerability data (OVAL)](https://github.com/microsoft/AzureLinuxVulnerabilityData)
- [Azure Linux 3.0 README](https://raw.githubusercontent.com/microsoft/azurelinux/3.0/README-3.0.md)
- [azurelinux-release spec (3.0)](https://raw.githubusercontent.com/microsoft/azurelinux/3.0/SPECS/azurelinux-release/azurelinux-release.spec)
- [kernel spec (3.0)](https://raw.githubusercontent.com/microsoft/azurelinux/3.0/SPECS/kernel/kernel.spec)
- [Azure Linux 3.0 package repository](https://packages.microsoft.com/azurelinux/3.0/prod/base/)
- [CBL-Mariner 2.0 README](https://raw.githubusercontent.com/microsoft/azurelinux/2.0/README.md)
- [mariner-release spec (2.0)](https://raw.githubusercontent.com/microsoft/azurelinux/2.0/SPECS/mariner-release/mariner-release.spec)
- [kernel spec (2.0)](https://raw.githubusercontent.com/microsoft/azurelinux/2.0/SPECS/kernel/kernel.spec)
- [CBL-Mariner 2.0 package repository](https://packages.microsoft.com/cbl-mariner/2.0/prod/base/)

<!-- os-pages:end -->
