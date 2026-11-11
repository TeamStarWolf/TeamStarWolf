<!-- os-pages:start (written by scripts/build_os_pages.py from data/os/os-catalog.jsonl; do not edit) -->

# Kubernetes node images

> The operating system images that managed Kubernetes services boot on worker nodes: Amazon EKS on Amazon Linux 2023, Google GKE on Container-Optimized OS, and Azure AKS on Ubuntu.

Part of [Operating systems](/operating-systems/README.md) (Hypervisors and Kubernetes node images). Support dates come from the [endoflife.date](https://endoflife.date/) API (`https://endoflife.date/api/amazon-linux.json`, `https://endoflife.date/api/cos.json`, `https://endoflife.date/api/ubuntu.json`), fetched on 2026-11-03.

## Versions and support

| Version | Codename | Released | Latest release | Full support ends | Security support ends | Extended support ends | Status on the fetch date |
|---|---|---|---|---|---|---|---|
| EKS: Amazon Linux 2023 | None | 2023-03-01 | 2023.12.20261102.0 | 2027-06-30 | 2029-06-30 | Not published | Supported |
| GKE: Container-Optimized OS 125 LTS | None | 2025-10-09 | cos-125-19216-760-32 | Not published | 2028-02-01 | Not published | Supported |
| GKE: Container-Optimized OS 121 LTS | None | 2025-04-14 | cos-121-18867-652-12 | Not published | 2027-03-01 | Not published | Supported |
| AKS: Ubuntu 24.04 | None | 2024-04-25 | 24.04.5 | 2029-05-31 | 2029-05-31 | 2034-04-25 | Supported |
| AKS: Ubuntu 22.04 | None | Not published | Not published | Not published | 2027-06-30 | Not published | Supported |

- AKS: Ubuntu 22.04: AKS stops supporting and patching Ubuntu 22.04 node images on June 30, 2027 (AKS node images page). ([source](https://learn.microsoft.com/en-us/azure/aks/node-images))

Full support is the vendor's regular maintenance; security support is the end of security fixes from the vendor (endoflife.date's `eol` field); extended support is paid or third-party coverage after that (`extendedSupport`).

| Version | Kernel | Architectures | Based on | Updates from |
|---|---|---|---|---|
| EKS: Amazon Linux 2023 | Not checked | x86_64, arm64 | Amazon Linux 2023 | EKS-optimized AMI releases |
| GKE: Container-Optimized OS 125 LTS | Not checked | Not checked | Container-Optimized OS | cos-125-lts image family |
| GKE: Container-Optimized OS 121 LTS | Not checked | Not checked | Container-Optimized OS | cos-121-lts image family |
| AKS: Ubuntu 24.04 | Not checked | Not checked | Ubuntu 24.04 LTS | AKS node image releases |
| AKS: Ubuntu 22.04 | Not checked | Not checked | Ubuntu 22.04 LTS | AKS node image releases |

## Where its advisories live

- [Amazon Linux Security Center (ALAS)](https://alas.aws.amazon.com/): IDs take the form `ALAS2023-YYYY-NNN`. Machine-readable: [AL2023 RSS](https://alas.aws.amazon.com/AL2023/alas.rss).
- [Container-Optimized OS release notes](https://cloud.google.com/container-optimized-os/docs/release-notes).
- [GKE security bulletins](https://cloud.google.com/kubernetes-engine/security-bulletins).
- [Ubuntu Security Notices (USN)](https://ubuntu.com/security/notices): IDs take the form `USN-NNNN-N`. Machine-readable: [RSS](https://ubuntu.com/security/notices/rss.xml).

EKS points to the Amazon Linux security center for node advisories; COS fixes appear in the COS release notes and GKE bulletins; AKS Ubuntu nodes are built by Canonical with the available security updates applied, so USNs apply.

## How it patches

Package manager: None on the node; the provider replaces the node image.

Nodes are patched by rolling them to a newer node image: EKS managed node groups move to a newer EKS-optimized AMI, GKE node pools to a newer COS image, and AKS node pools take node image upgrades (for AKS clusters on a channel other than unmanaged, unattended upgrades inside the node are disabled).

## Identify it from a terminal

No identify command is listed for the images as a group: each one identifies itself like its base distribution, so see the [Amazon Linux](/operating-systems/amazon-linux.md) and [Ubuntu](/operating-systems/ubuntu.md) pages; the provider pages opened for this page describe the images, not commands.

## Security relevance

A Kubernetes node image is the operating system under a cluster, so its security is inseparable from the workloads it schedules. The surface is container escape to the node, an exposed or over-permissioned kubelet, and privileged pods that reach host resources. Minimal, regularly rebuilt node images and a locked-down kubelet are the controls; see the Kubernetes and container security references below.

## Hardening

- [Kubernetes Security Reference](/KUBERNETES_SECURITY_REFERENCE.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [kubectl Reference](/commands/kubectl.md)

## On the Intelligence Hub

The library's vocabulary id for Kubernetes node images is `product:kubernetes-node-images`. The [Intelligence Hub](https://teamstarwolf.github.io/intelligence-hub/) tags advisories, research, and news with ids from that vocabulary.

## Licence and sources

Each image keeps its distribution's licences; the managed services are provider products.

Vendor and project pages read for this page (2026-11-04):

- [Create nodes with optimized Amazon Linux AMIs](https://docs.aws.amazon.com/eks/latest/userguide/eks-optimized-ami.html)
- [Upgrade from Amazon Linux 2 to Amazon Linux 2023 (EKS)](https://docs.aws.amazon.com/eks/latest/userguide/al2023.html)
- [GKE node images](https://cloud.google.com/kubernetes-engine/docs/concepts/node-images)
- [Container-Optimized OS support policy](https://cloud.google.com/container-optimized-os/docs/resources/support-policy)
- [AKS node images](https://learn.microsoft.com/en-us/azure/aks/node-images)
- [AKS vulnerability management](https://learn.microsoft.com/en-us/azure/aks/concepts-vulnerability-management)
- [AKS node image upgrade](https://learn.microsoft.com/en-us/azure/aks/upgrade-node-image)

<!-- os-pages:end -->
