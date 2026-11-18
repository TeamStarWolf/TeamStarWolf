# Slide plan: NIST Zero Trust Architecture (SP 800-207)

- Study: case-studies/NIST_ZERO_TRUST_2020.md
- Cover title: Zero Trust Architecture / SP 800-207 / 2020
- Subtitle: A reference reading of NIST SP 800-207: the tenets, the policy decision and enforcement model, and why the label is not the property.
- Published: 18 November 2026
- Notes: The cover frames the deck as a reference study of a NIST Special Publication, not an incident report.

## FOUNDATION | A neutral language for access
- SP 800-207 provides technology-neutral terms for resource access, not a new appliance.
- Its scope is an abstract architecture, deployment models and use cases, not one plan.
- Value appears when a team names an unjustified access assumption and replaces it.
- For every action: what evidence justifies it, and which component enforces the answer.
Caption: Evidence grade: Confirmed (SP 800-207 stated scope)
Notes: Sets the thesis that the document is a shared vocabulary rather than a tool to install.

## CORRECTION | Zero trust is an approach, not a purchase
Left: What the publication is
- A NIST Special Publication giving architectural guidance.
- Seven tenets, logical components, deployment models and use cases.
Right: What it is not
- A product certification scheme or installable appliance.
- A blanket legal mandate binding on every organization.
Caption: Evidence grade: Confirmed (publication status and front matter)
Notes: Separates the architecture-and-tenets reading from the "zero trust is a product you buy" misreading.

## ARCHITECTURE | The 2020 model in four numbers
Stat: 7 | technology-neutral tenets in section 2.1
Stat: 3 | logical roles: engine, admin, enforcement
Stat: 2020 | final publication, after two drafts
Stat: 2 | planes separated: control and data
Caption: Evidence grade: Confirmed (sections 2.1 and 3)
Notes: Gives the structural scaffolding before the slides that unpack each number.

## TENETS | Goals read as design questions
NIST presents seven technology-neutral tenets in section 2.1; each becomes a concrete review question.

| Tenet (paraphrase) | Design question |
| --- | --- |
| Data and services are resources | What exactly is the resource and action? |
| Access is per-resource, per-session | What ends this permission? |
| Decisions use dynamic policy and context | Which observations are current enough? |
| Asset posture is monitored | Which conditions must be true now? |
| Authentication is revisited in session | When is the session reevaluated? |
Caption: Evidence grade: Confirmed (section 2.1 tenets), questions Inferred
Notes: Shows the tenets translated into workflow questions rather than recited as a slogan.

## COMPONENTS | Decision, administration, enforcement
- The policy engine evaluates rules and inputs to grant, deny or revoke access.
- The policy administrator carries that decision into connection setup or teardown.
- The policy enforcement point enables, monitors and ends the subject-to-resource link.
- These are logical responsibilities, not a requirement to buy three separate boxes.
Caption: Evidence grade: Confirmed (section 3)
Notes: Defines the policy decision and enforcement split so later failures can be diagnosed precisely.

## PLANES | The control path is its own resource
Left: Control plane
- Carries policy-related communication and decisions.
- Changing who is allowed through runs here.
Right: Data plane
- Carries application traffic between subject and resource.
- Protecting it does not protect the administrative channel.
Caption: Evidence grade: Confirmed (sections 3 and 3.4)
Notes: Makes clear that securing application traffic leaves the channel that rewrites policy untouched.

## TRUST ALGORITHM | A mechanism, not a moral score
- The trust algorithm is the process the engine uses to decide a specific request.
- Inputs include the request, subject, asset state, resource rules and threat data.
- NIST describes criteria-based and score-based styles, not one proprietary product.
- Define how missing, stale or contradictory inputs are handled, or the output is unexplainable.
Caption: Evidence grade: Confirmed (section 3.3)
Notes: Reframes "trust" as justification for an action under conditions, not a judgment of character.

## DEPLOYMENT | Each model is a tradeoff
NIST describes deployment variations that organize enforcement and evidence differently; several can coexist.

| Model | Strength | Cost |
| --- | --- | --- |
| Agent/gateway | Better managed-device visibility | Deployment and compatibility load |
| Portal | Accommodates less-controlled clients | Less posture visibility |
| Enclave | Protects grouped legacy resources | Larger internal trust zone |
| Sandbox | Constrains one application | Its own lifecycle obligations |
Caption: Evidence grade: Confirmed (sections 3.1-3.2)
Notes: Presents the models as choices driven by workflow, not a list where the newest option wins.

## ACTOR PATHS | Same model, three subjects
The logical model maps onto human, service and external subjects, each with a distinct design question.

| Subject | Resource | Key design question |
| --- | --- | --- |
| Analyst on managed laptop | Purchase-order application | What happens to a session on role change? |
| Order-processing service | Customer delivery data | Who owns the service identity lifecycle? |
| Partner or contractor | Limited project record | What authority expires at engagement end? |
Caption: Evidence grade: Demonstrated (original fictional workflows on NIST model)
Notes: Illustrates the decision and enforcement model across people, workloads and outside parties.

## DECISION SYSTEM | The control plane is a target
- NIST identifies subversion of the policy decision process as a named threat.
- Treat policy administration as a privileged business process with approved changes.
- Test the administrative path independently from ordinary user access.
- Keep policy history protected but readable by authorized reviewers.
Caption: Evidence grade: Confirmed (section 5.1), governance steps Inferred
Notes: Argues that the system built to constrain trust can itself concentrate excessive authority.

## AVAILABILITY | Design the failure mode first
Left: Risks NIST names
- Denial of service, network disruption, provider outages.
- A security control becomes a business availability dependency.
Right: Required design response
- Define degraded behavior per request sensitivity.
- Scoped emergency access: narrow, attributable, reviewed.
Caption: Evidence grade: Confirmed (section 5.2), degraded design Inferred
Notes: Rejects a universal fail-open or fail-closed slogan in favor of a scoped, consequence-based response.

## RESIDUAL RISK | Authorized misuse still exists
- NIST notes stolen credentials or an insider may still reach already-authorized resources.
- Zero trust reduces inappropriate reach and aids detection; it does not end risk.
- It cannot turn a bad business authorization into a good one by enforcing it consistently.
- Resource-level permissions, backups and governance remain necessary alongside it.
Caption: Evidence grade: Confirmed (section 5.3)
Notes: Keeps the aspirational principle distinct from any claim that the architecture prevents all harm.

## MIGRATION | Start from a workflow, not a list
- Section 7 describes a staged transition: identify actors and assets, then policy, then expand.
- Pick a pilot with a clear owner, manageable scope and observable outcomes.
- Map upstream and downstream dependencies before enforcing new restrictions.
- A reporting-only phase needs a defined purpose and an end condition.
Caption: Evidence grade: Confirmed (sections 7 and 7.3.6)
Notes: Frames adoption as incremental learning on a bounded workflow, not a single enterprise switch.

## EVIDENCE | Make the implementation claim specific
- Verify a permitted action, then alter one condition with a test identity and confirm the denial.
- Test adjacent resources separately so one approval does not grant silent access to another.
- Measure revocation, but define whether the interval starts at a business event or an enforcement command.
- Name the workflow, resource, subject, decision evidence and enforcement result.
Caption: Evidence grade: Demonstrated (original acceptance tests)
Notes: Closes on the strongest defensible claim: a tested boundary stated in terms evidence can support.
