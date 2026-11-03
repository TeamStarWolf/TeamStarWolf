# Aqua Security

Aqua Security is a cloud-native security platform centered on containers and Kubernetes. It covers image assurance, admission control, runtime protection, and cloud security posture. The project also maintains the open-source Trivy scanner. The sections below describe the generally available product in 2026. The licence tier a team holds decides which modules are in force.

## What it is and where it fits

Aqua Security protects workloads from the image through to runtime. Its focus is the container lifecycle, so it scans images before they ship, decides what is allowed into a cluster, and watches containers while they run.

The platform treats the container as the unit of work. It builds assurance around images, enforces policy at the admission boundary, and applies controls to running containers and their hosts. Posture management extends the view to the cloud accounts and Kubernetes clusters those workloads run in.

A cloud security team uses Aqua when containers and Kubernetes are the heart of its estate. It answers which images are safe to run, which should be blocked at admission, and what a running container is permitted to do.

## Architecture and how it works

Aqua is available as a vendor-hosted service and in self-managed forms. A central management plane holds policy, findings, and reporting. Enforcement components run close to the workloads, in the clusters and on the hosts that need them.

Image assurance runs during build and in registries. Aqua scans images for vulnerabilities, misconfigurations, and secrets, then applies assurance policy that marks an image as compliant or not. Trivy, the open-source scanner Aqua maintains, underpins much of this scanning and is widely used on its own.

Admission control sits at the Kubernetes boundary. An admission controller checks each workload against assurance and policy before it is scheduled, so an image that fails policy can be stopped from running rather than caught later.

Runtime protection uses an enforcer deployed to clusters and hosts. It observes container behavior such as process, file, and network activity, and can enforce controls that limit a container to expected behavior. Posture management reads cloud and cluster configuration to find misconfiguration and drift.

## Key capabilities

- Image scanning and assurance for vulnerabilities, misconfigurations, and secrets, built on the Trivy scanner.
- Admission control that enforces assurance policy at the Kubernetes boundary before a workload runs.
- Runtime protection for containers and hosts, covering process, file, and network behavior.
- Kubernetes security posture management across clusters and their configuration.
- Cloud security posture management for the accounts that host the clusters and workloads.
- Secret detection in images and configuration.
- Policy as code so assurance and runtime rules can be versioned and promoted through environments.

## Deployment and operations

Image assurance is wired into build and registry workflows first. A team adds scanning to CI and to its registries, defines assurance policy, and decides which results warn and which block. Trivy can be adopted on its own as a starting point and later connected to the platform.

Admission control and runtime protection require components in the clusters. The admission controller is installed to evaluate workloads at scheduling time, and the enforcer is deployed to the nodes that need runtime coverage. Both are sized to the clusters in scope.

Operations split between pipeline findings and runtime events. On the pipeline side, a team keeps assurance policy current, triages new image findings, and tracks fixes back to the source. On the runtime side, it reviews behavioral alerts, tunes policy to the workload, and confirms that enforcement does not break legitimate activity.

Policy management is continuous. Assurance and runtime rules are refined as workloads change, with suppressions documented and routing set so findings reach owners.

## Integrations and data flow

Data flows into Aqua from CI systems, registries, clusters, and connected cloud accounts. Scanners report image findings, the admission controller reports policy decisions, and enforcers report runtime behavior back to the management plane.

Outbound, findings and events reach the team's wider tooling. Alerts and tickets route to messaging and work-tracking systems. Runtime and policy events can feed a SIEM for correlation and retention. An API and automation hooks let findings drive pipeline gates and response workflows.

Because Trivy is open source, its output also flows through standalone and third-party pipelines, which gives a team a consistent scanner across tooling.

## Hardening and secure use

Run the enforcer and the cloud connector with least privilege. The runtime enforcer needs only the access required to observe and control the containers in scope, and the cloud connector needs only read access for posture. Granting either more than it needs widens the blast radius if a component is compromised.

Use role-based access inside the platform. Separate responders, cluster owners, auditors, and administrators so routine work does not require platform-wide control. Review membership regularly and remove access that is no longer needed.

Protect API credentials as sensitive secrets (CWE-798). Keep registry tokens, platform API keys, and scanner credentials out of source, images, and pipeline definitions. Store them in a secrets manager, scope them narrowly, rotate them, and revoke any that are unused. Hard-coded credentials are a frequent cause of pipeline and cluster compromise.

Treat admission policy as a security control. Decide clearly what blocks and what only warns, and review changes to those rules the way a firewall change is reviewed.

## Where it fits in the program

Aqua Security is the container and Kubernetes backbone for a team whose estate runs on those technologies. It feeds the container security program with image assurance and runtime findings, and it feeds vulnerability management with image and workload data.

Alongside a broad CNAPP such as Wiz, Prisma Cloud, or Orca Security, Aqua often provides the deep container and admission coverage, while the CNAPP provides cross-cloud breadth. Trivy also serves teams that want a shared open-source scanner independent of the platform.

## Resources

- Aqua Security platform documentation
- Trivy scanner documentation
- Aqua Enforcer and admission controller deployment guides
- Aqua Security API reference

## Related pages

- [Security platforms](/platforms/README.md)
- [Container Security Reference](/CONTAINER_SECURITY_REFERENCE.md)
- [Cloud Security Reference Library](/CLOUD_SECURITY_REFERENCE.md)
- [Vulnerability Management Reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Sysdig](/platforms/sysdig.md)
- [Prisma Cloud](/platforms/prisma-cloud.md)
- [Snyk](/platforms/snyk.md)
