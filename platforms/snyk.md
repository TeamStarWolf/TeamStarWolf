# Snyk

Snyk is a developer-first application security platform. It scans code, open-source dependencies, container images, and infrastructure-as-code definitions, and it surfaces findings inside the tools developers already use. The aim is to find and fix issues early in the software lifecycle rather than after release.

## What it is and where it fits

Snyk sits in the application security and software supply-chain part of a security program. It targets the build and development stages, where fixing a flaw is cheaper than fixing it in production. Instead of waiting for a late-stage scan, Snyk runs checks in editors, source-control pull requests, and continuous-integration pipelines.

The platform groups its testing into four products. Snyk Open Source performs software composition analysis on third-party dependencies. Snyk Code performs static analysis on first-party source. Snyk Container inspects container images and their base layers. Snyk Infrastructure as Code checks declarative infrastructure definitions for misconfiguration.

Licence tier decides which products and which governance controls are in force. Entitlements such as reachability analysis, policy management, and reporting depth vary by plan. Confirm the active tier before you assume a capability is available to a given team.

## Architecture and how it works

Snyk is delivered as a hosted service with local components that run close to the code. Developers interact with it through integrated development environment plugins, a command-line interface, source-control integrations, and a web application for policy and reporting.

For Snyk Open Source, the platform reads a project's manifest and lockfile to build a dependency tree. It compares that tree against a vulnerability database maintained by Snyk. Direct and transitive dependencies are both considered, so a flaw introduced several layers deep is still reported.

Snyk Code applies static analysis to first-party source without needing a full build. It identifies patterns associated with common weakness classes, such as injection and insecure data handling. Results are presented with the file and line involved.

Snyk Container reads image layers and the packages inside them. It maps known vulnerabilities to those packages and ties findings back to the base image. Snyk Infrastructure as Code parses templates and configuration to flag insecure settings before they are applied.

Reachability analysis, where the tier supports it, narrows open-source findings to those whose vulnerable function the application actually calls. This helps teams prioritize dependencies that pose real exposure over ones that are present but never reached.

## Key capabilities

- Software composition analysis across direct and transitive open-source dependencies.
- Static analysis of first-party code for common weakness classes.
- Container image scanning that ties findings to base layers.
- Infrastructure-as-code checks for insecure declarative configuration.
- Pull-request checks that comment on the change under review.
- Continuous-integration gates that can fail a build on policy breach.
- Automated fix pull requests that propose a dependency upgrade.
- Base-image upgrade advice that suggests a lower-risk image.
- Reachability analysis to prioritize dependencies the code calls.
- Licence policy to flag open-source licences that violate program rules.

Fix pull requests and base-image advice reduce the manual work of remediation. Rather than only reporting a problem, Snyk proposes a specific version bump or image change that a developer can review and merge.

Licence policy is separate from vulnerability findings. Open-source components carry licence obligations, and Snyk can flag licences that conflict with an organization's stated policy so legal and engineering teams see them early.

## Deployment and operations

Snyk runs as a cloud service, so there is no scanner infrastructure for a team to host for the core platform. Onboarding a project means connecting a source-control organization, a registry, or a pipeline and letting Snyk import the relevant targets.

Day-to-day operation centers on the pull-request and pipeline integrations. Developers see findings where they already work, and security teams set the policies that decide what blocks a merge or a build. The web application holds reporting, project inventory, and policy configuration.

Operations work includes keeping integrations authorized, reviewing which projects are imported, and tuning gate severity so pipelines fail on the issues that matter without blocking on noise. Ignore handling is part of this: a finding can be suppressed with a reason and, where configured, an expiry.

Account structure matters at scale. Organizations and groups control who sees which projects and who can change policy. Keep that structure aligned with how engineering teams are organized so ownership of findings is clear.

## Integrations and data flow

Snyk connects to source control, continuous-integration and delivery systems, container registries, and ticketing tools. A typical flow starts in source control, where a pull request triggers a check and Snyk posts results back to the change.

In a pipeline, the command-line interface or a plugin runs a test and returns a pass or fail result against policy. Container findings flow from registry imports. Infrastructure-as-code findings flow from the repositories or pipelines that hold the templates.

Ticketing integration lets a finding become a tracked work item in the team's issue tracker. This keeps remediation visible in the same backlog as other engineering work rather than in a separate security queue.

Data flows from the scanned assets to the hosted platform for analysis and back to the developer surfaces. Because manifests, code snippets, and image metadata leave the local environment, scope the integration to the repositories and registries that the program intends to cover.

## Hardening and secure use

Treat Snyk's service accounts and API tokens as sensitive credentials. A token that can import projects and read source should be scoped to only what an integration needs. Hard-coding a token in a pipeline file or committing it to a repository risks exposure, a case of use of hard-coded credentials (CWE-798). Store tokens in a secrets manager and rotate them.

Govern the ignore and expiry workflow. An ignored finding is an accepted risk, so require a reason and, where the tier allows, an expiry date so suppressions are revisited rather than left open forever. Periodically review the list of active ignores.

Verify that a fix reached the deployed artifact, not only the default branch. A merged fix pull request closes the finding in source control, but the vulnerable version can still be running until the build is rebuilt and redeployed. Confirm remediation against what is actually shipped.

Use role-based access so that changing policy, managing ignores, and administering integrations are limited to the right people. Align Snyk organizations with engineering ownership so each team sees and acts on its own findings.

## Where it fits in the program

Snyk is the shift-left layer of the application security program. It catches dependency, code, container, and infrastructure issues during development, before they reach the environments that runtime scanners and the vulnerability-management process watch.

Its findings feed the broader vulnerability-management workflow. Open-source and container results describe software risk that belongs in the same prioritization and tracking process as findings from other scanners. Its code results reinforce secure-coding practice by showing developers concrete weaknesses in their own changes.

Snyk does not replace dynamic testing of running applications or network-level scanning. It complements them by addressing the source and build stages, where the earliest and cheapest fixes live.

## Resources

- Snyk Documentation
- Snyk User Docs
- Snyk CLI reference
- Snyk Open Source documentation
- Snyk Code documentation
- Snyk Container documentation
- Snyk Infrastructure as Code documentation

## Related pages

- [Platforms index](/platforms/README.md)
- [Scanner platforms reference](/SCANNER_PLATFORMS_REFERENCE.md)
- [Secure coding reference](/SECURE_CODING_REFERENCE.md)
- [Vulnerability management reference](/VULNERABILITY_MANAGEMENT_REFERENCE.md)
- [Invicti](/platforms/invicti.md)
- [HackerOne](/platforms/hackerone.md)
- [Wiz](/platforms/wiz.md)
