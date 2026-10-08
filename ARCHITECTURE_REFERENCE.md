# General (Enterprise & Solution) Architecture

> **In one minute:** Architecture is the set of decisions that are expensive to change — the boundaries between parts of a system, the contracts across those boundaries, and the quality attributes (security, reliability, performance, cost) those boundaries are chosen to protect. This reference covers the whole arc: the four architecture domains (business, data, application, technology), the frameworks that structure the work (TOGAF 10 ADM, C4, arc42), how to record decisions (ADRs), how to reason about trade-offs (quality attributes, ATAM, well-architected thinking), the patterns you will actually reach for (layered, hexagonal, microservices, event-driven, CQRS, SOA, DDD), and how to weave security and privacy by design through all of it. Because this is a security library, every pattern is read partly as an attack-surface decision: good architecture is a vulnerability-reduction instrument, and bad architecture is a standing liability. Vendor-neutral throughout; cloud, AI, networking, and security each have their own companion references.

| Read this when… | Start at… |
|---|---|
| You are standing up an architecture practice or need a shared vocabulary | [Principles & drivers](#1-principles--drivers), [Standards & frameworks](#8-standards--frameworks) |
| You are choosing a structure for a new system | [Reference architectures & patterns](#2-reference-architectures--patterns), [Key design decisions & trade-offs](#5-key-design-decisions--trade-offs) |
| You are documenting an existing system | [Building blocks & domains](#3-building-blocks--domains), [C4 & arc42](#43-documenting-architecture-c4-arc42-adrs) |
| You need to justify or defend a decision | [ADRs](#43-documenting-architecture-c4-arc42-adrs), [Quality attributes & ATAM](#4-quality-attributes-nfrs--trade-off-analysis) |
| You are a security reviewer looking at a design | [Security-by-design integration](#6-security-by-design-integration), [Anti-patterns & pitfalls](#7-anti-patterns--pitfalls) |
| You want to score maturity or run a review | [Maturity & checklist](#9-maturity--checklist) |

---

## 1. Principles & drivers

### 1.1 What architecture is (and is not)

A workable definition, consistent with ISO/IEC/IEEE 42010: **architecture is the fundamental concepts or properties of a system in its environment, embodied in its elements, their relationships, and the principles of its design and evolution.** Three things fall out of that:

- **Architecture is about the hard-to-reverse.** A method signature is a day's rework; a service boundary, a data-ownership decision, or a trust boundary is a quarter's rework. Spend architectural attention proportional to the cost of being wrong.
- **Architecture is contextual.** The same design is excellent for a 3-person startup and negligent for a regulated bank. There is no architecture without a stated environment: load, team shape, compliance regime, threat model, budget.
- **Architecture is a set of trade-offs, not a set of best practices.** Every "best practice" buys one quality attribute by spending another (see §4). The architect's job is to make those trades explicit and defensible, not to collect patterns.

> **Conway corollary:** "Organizations design systems that mirror their own communication structure." You do not get to pick a module structure independently of your team structure — pick them together, or the org chart will silently win. The *Inverse Conway Maneuver* deliberately shapes teams to produce the architecture you want.

### 1.2 Architecture principles

Principles are durable, enforceable rules that constrain design decisions. A good principle has four parts (TOGAF form): **name, statement, rationale, implications.** Vague aspirations ("be scalable") are not principles. Examples of well-formed principles:

| Principle | Statement | Security implication |
|---|---|---|
| Single source of truth | Each data element is mastered in exactly one system; others hold read copies. | Shrinks the number of places PII must be protected and audited. |
| Secure by default | New components ship closed: deny-by-default authz, TLS on, no public exposure without explicit sign-off. | Eliminates the "temporary open port" class of incident. |
| Design for failure | Every remote call can fail, time out, or be slow; design the behavior for that case. | Degraded-mode behavior prevents a dependency outage from becoming a data-integrity or auth-bypass incident. |
| Loose coupling, high cohesion | Components depend on contracts, not internals; related change stays local. | A compromised component's blast radius is bounded by its contract, not its reach. |
| Automate the paved road | The easy way to build and deploy is the compliant, secure way. | Security that is the default path is the only security that survives schedule pressure. |

### 1.3 Drivers: business, constraint, quality

Every architecture is pushed by three force classes. Name them before you draw anything:

```
            BUSINESS GOALS                  CONSTRAINTS
      (grow to N users, enter               (budget, deadline, team
       EU market, 99.95% SLA,                skills, existing systems,
       cut per-txn cost 40%)                 regulation, data residency)
                 \                               /
                  \                             /
                   v                           v
                 +-------------------------------+
                 |     ARCHITECTURE DECISIONS     |
                 +-------------------------------+
                                 ^
                                 |
                      QUALITY ATTRIBUTES (NFRs)
             security, reliability, performance, scalability,
             maintainability, observability, cost, privacy
```

If you cannot trace an architectural decision back to a goal, a constraint, or a quality attribute, it is decoration — or worse, accidental complexity that becomes tomorrow's attack surface.

---

## 2. Reference architectures & patterns

Patterns are named, reusable structural solutions. Below are the ones a solution architect actually chooses between. Each entry: shape, when it fits, when it bites, and a one-line security read.

### 2.1 Layered (n-tier)

The default. Code is organized into horizontal layers; each layer depends only on the one below.

```
┌──────────────────────────────────────────┐
│  Presentation  (UI, API controllers)       │
├──────────────────────────────────────────┤
│  Application   (use cases, orchestration)   │
├──────────────────────────────────────────┤
│  Domain        (business rules, entities)    │
├──────────────────────────────────────────┤
│  Infrastructure(persistence, messaging, I/O) │
└──────────────────────────────────────────┘
          dependencies point downward
```

- **Fits:** most line-of-business apps; teams that want an obvious, teachable structure.
- **Bites:** layers leak (a "presentation" concern reaches into SQL); becomes a *big ball of mud* without discipline; the database often becomes the real integration point.
- **Security read:** the trust boundary is usually the top edge (authn/authz at the controller). Danger is *layer-skipping* — a path that reaches the data layer without passing the authz layer. Enforce authz in the domain/application layer, not only at the UI.

### 2.2 Hexagonal / Ports & Adapters (and Clean / Onion)

The domain sits at the center, knows nothing about the outside world, and talks through **ports** (interfaces). **Adapters** on the outside implement those ports for specific technologies (REST, gRPC, Postgres, Kafka).

```
            ┌─────────── adapters (driving) ───────────┐
            │  REST API   CLI   gRPC   message consumer  │
            └───────────────────┬───────────────────────┘
                                 │ ports (in)
                        ┌────────▼────────┐
                        │   DOMAIN CORE    │  (pure business logic,
                        │  no I/O, no deps │   no framework imports)
                        └────────┬────────┘
                                 │ ports (out)
            ┌───────────────────▼───────────────────────┐
            │  Postgres   S3   Kafka   payment gateway    │
            └─────────── adapters (driven) ──────────────┘
```

- **Fits:** systems with rich domain logic and a long life; anywhere you want to test business rules without a database or swap infrastructure.
- **Bites:** ceremony and indirection for CRUD-heavy apps with little logic; over-abstraction.
- **Security read:** adapters are the natural home for input validation, output encoding, and credential handling — the core stays pure. This isolation makes it straightforward to prove where tainted data is sanitized.

### 2.3 Monolith (modular monolith)

A single deployable unit. The *modular monolith* adds enforced internal module boundaries (compile-time or build-time) without the network between them.

- **Fits:** early-stage products, small teams, strong consistency needs, when you do not yet know the real seams. **The correct default for most new systems.**
- **Bites:** independent scaling and independent deploy are hard; a single bad dependency version blocks everyone; large-team contention.
- **Security read:** one process, one trust boundary — simpler to reason about, no internal network to secure, but no internal blast-radius containment either. A deserialization or RCE bug owns the whole process.

### 2.4 Microservices

Independently deployable services, each owning its data, communicating over the network. Choose this for *organizational* scaling (many teams shipping independently), not because it is modern.

```
   [API gateway / BFF]
      |      |       |
   [Orders][Pricing][Inventory]      each: own DB, own deploy,
      |      |       |                     own team, own release cadence
   [ Orders DB ][ Pricing DB ][ Inventory DB ]
      \________ async events via broker ________/
```

- **Fits:** many teams, differing scaling/availability needs per capability, polyglot requirements.
- **Bites:** distributed systems are *hard* — network partitions, partial failure, eventual consistency, distributed tracing, data duplication, versioned contracts. Operational and cognitive cost is high. Do not adopt without platform maturity (CI/CD, observability, service discovery).
- **Security read:** the network between services is now attack surface. Requires **zero-trust service-to-service** (mTLS, workload identity such as SPIFFE/SPIFFE-SVID), per-service least-privilege, and an authz model that survives the gateway (a request authenticated at the edge must not be implicitly trusted internally — defends against ATT&CK **Lateral Movement, T1021 / T1570**). Each service multiplies the number of secrets, certs, and patch targets.

### 2.5 Event-driven architecture (EDA)

Components communicate by producing and consuming **events** (facts about something that happened) through a broker. Two sub-styles: *event notification* (thin events, consumers call back for detail) and *event-carried state transfer* (fat events carrying the data).

```
  [Order Service] --OrderPlaced--> [ Broker ] --> [Email Svc]
                                        |-------> [Inventory Svc]
                                        |-------> [Analytics Svc]
         producers don't know who consumes; consumers added without touching producers
```

- **Fits:** decoupling in time and space, fan-out, reactive/streaming workloads, audit-by-design.
- **Bites:** eventual consistency; hard to reason about end-to-end flow; debugging requires correlation IDs and distributed tracing; **duplicate and out-of-order delivery are normal** — consumers must be idempotent; the broker is a critical dependency and a single point of failure if not clustered.
- **Security read:** the event log is often a *de facto* data store containing sensitive history — encrypt it, set retention, and apply topic-level authz. Poisoned or spoofed events are an injection vector (map to **Data Manipulation, T1565**); sign or schema-validate events and authenticate producers.

### 2.6 CQRS & Event Sourcing

**CQRS** (Command Query Responsibility Segregation) splits the write model from the read model so each is optimized independently. **Event sourcing** stores state as an append-only log of events and derives current state by replay. They are separable; event sourcing usually implies CQRS, but CQRS does not require event sourcing.

- **Fits:** complex domains with very different read vs write shapes; high-read systems; strong audit/temporal requirements ("what did this account look like on March 3?").
- **Bites:** significant complexity; eventual consistency between write and read sides confuses users ("I saved it but don't see it"); event schema evolution and replay are genuinely hard; **not a default** — most systems should not use it.
- **Security read:** the event store is immutable audit evidence (a forensic asset), but it also means PII cannot simply be deleted — reconcile with GDPR/CCPA erasure via crypto-shredding (delete the key, not the record) or tombstone+rebuild.

### 2.7 Service-Oriented Architecture (SOA)

The enterprise ancestor of microservices: coarse-grained, reusable business services, historically integrated through an **Enterprise Service Bus (ESB)**. Modern SOA favors *smart endpoints, dumb pipes* over a logic-heavy ESB.

- **Fits:** large enterprises integrating many heterogeneous systems; where governance and reuse across business units matter more than team autonomy.
- **Bites:** a logic-heavy ESB becomes a bottleneck and a single point of failure; governance can ossify into bureaucracy.
- **Security read:** the ESB is a high-value target holding routing and often credentials for every connected system — compromise is enterprise-wide.

### 2.8 API & integration architecture

How systems talk is an architectural decision of the first rank. The main styles:

| Style | Shape | Best for | Watch-outs |
|---|---|---|---|
| **REST** | Resource-oriented over HTTP | Public/partner APIs, broad compatibility | Over-/under-fetching; versioning discipline |
| **GraphQL** | Client-specified query graph | Rich frontends, many consumers, avoid round-trips | Query-depth/complexity DoS; authz per field; caching harder |
| **gRPC** | Contract-first RPC over HTTP/2 + protobuf | Internal low-latency service-to-service | Browser support needs a proxy; less human-debuggable |
| **Async / messaging** | Events/commands over a broker | Decoupling, resilience, streaming | Eventual consistency; idempotency required |
| **Webhooks** | Provider POSTs to consumer URL | Outbound notifications to third parties | Must verify signatures (HMAC); SSRF and replay risk |

Integration-pattern vocabulary worth knowing (from *Enterprise Integration Patterns*): message channel, router, translator, aggregator, saga (for distributed transactions), and the **anti-corruption layer** (a translation boundary that stops a legacy or external model from leaking into your domain — also a security boundary).

**API gateway vs service mesh vs BFF:** the gateway is the north-south edge (external clients → services: authn, rate limiting, routing); the **service mesh** handles east-west (service → service: mTLS, retries, traffic policy) via sidecars; a **Backend-for-Frontend (BFF)** is a per-client-type aggregation layer. They are complementary, not alternatives.

### 2.9 Choosing: the decision in one view

```
 Start here ─────────────────────────────────────────────┐
   Is the domain well understood and the team small? ─ yes → MODULAR MONOLITH
                     │ no / growing org                    │  (add seams later)
                     ▼                                     │
   Do independent teams need independent deploy cadence? ─ no → MODULAR MONOLITH
                     │ yes                                      with clear modules
                     ▼
   Do you have CI/CD + observability + on-call maturity? ─ no → FIX THAT FIRST
                     │ yes
                     ▼
   MICROSERVICES  ── + heavy fan-out / reactive? ── yes ─→ add EVENT-DRIVEN
                   ── + read/write shapes diverge wildly? ─ yes → consider CQRS
```

> **Default advice:** start with a well-structured modular monolith. Extract services only along seams that *have proven* they need independent scaling or deployment. "Microservices first" is the most common self-inflicted architecture wound of the last decade.

---

## 3. Building blocks & domains

Enterprise architecture is conventionally divided into four domains (the "BDAT" stack of TOGAF). Solution architecture instantiates these for one system.

```
┌───────────────────────────────────────────────────────────────┐
│  BUSINESS ARCHITECTURE                                           │
│  capabilities, value streams, processes, org, roles, KPIs        │
├───────────────────────────────────────────────────────────────┤
│  DATA (INFORMATION) ARCHITECTURE                                 │
│  entities, ownership, lineage, master data, classification       │
├───────────────────────────────────────────────────────────────┤
│  APPLICATION ARCHITECTURE                                        │
│  services/apps, their responsibilities, interfaces, dependencies  │
├───────────────────────────────────────────────────────────────┤
│  TECHNOLOGY ARCHITECTURE                                         │
│  compute, network, storage, platforms, runtime, infrastructure    │
└───────────────────────────────────────────────────────────────┘
   Security & privacy are NOT a fifth layer — they are a cross-cutting
   concern that must be expressed in every one of the four.
```

| Domain | Key artifacts | Primary questions | Security lens |
|---|---|---|---|
| **Business** | Capability map, value-stream map, process models, business-capability-to-app mapping | What does the organization do? Who does it? What is valuable? | Which capabilities are regulated / high-impact? Where does fraud/abuse live? |
| **Data** | Conceptual/logical/physical data models, data-flow diagrams, data-classification scheme, lineage, master-data map | What data exists, who owns it, where does it flow, how is it classified? | Data classification drives *every* control. DFDs are the raw material for threat modeling. |
| **Application** | Component/container diagrams, API catalog, service dependency map, sequence diagrams | What are the parts, what are their contracts, how do they depend on each other? | Trust boundaries, authz model, blast-radius containment. |
| **Technology** | Deployment/infrastructure diagrams, network topology, runtime platform, IaC | Where does it run, on what, over what network? | Network segmentation, hardening, patch surface, secrets management. |

**Data classification** is the single most leveraged architectural input to security. A typical scheme — *Public / Internal / Confidential / Restricted (PII, PHI, PCI, secrets)* — because the classification of the data a component touches determines its required controls (encryption, access, logging, residency, retention) and therefore its placement in the architecture. Draw the data-flow diagram first; the controls follow the data.

---

## 4. Quality attributes (NFRs) & trade-off analysis

### 4.1 Quality attributes are the real requirements

Functional requirements say *what* the system does; **quality attributes** (a.k.a. non-functional requirements, NFRs, "-ilities") say *how well*, and they are what architecture actually optimizes. The ISO/IEC 25010 product-quality model is the standard vocabulary:

| ISO 25010 characteristic | Includes | Architectural levers |
|---|---|---|
| Functional suitability | correctness, completeness | domain model, validation |
| Performance efficiency | time behavior, resource use, capacity | caching, async, data locality, CQRS |
| Compatibility | interoperability, co-existence | API contracts, standards |
| **Security** | confidentiality, integrity, non-repudiation, accountability, authenticity | trust boundaries, authz, crypto, audit |
| Reliability | availability, fault tolerance, recoverability | redundancy, bulkheads, circuit breakers |
| Maintainability | modularity, modifiability, testability | coupling/cohesion, hexagonal, ADRs |
| Portability | adaptability, installability | containerization, abstraction |
| Usability / Interaction | learnability, accessibility | UX, API ergonomics |

*(ISO/IEC 25010 was revised in 2023 — Security and the others remain top-level characteristics; verify exact sub-characteristic naming against the current standard if you cite it formally.)*

### 4.2 Make quality attributes testable with scenarios

An NFR that cannot be measured cannot be met. Use the **six-part quality-attribute scenario** (from SEI): *source → stimulus → artifact → environment → response → response measure.*

> "A credential-stuffing bot (**source**) submits 10k login attempts in 60s (**stimulus**) against the auth API (**artifact**) during normal operation (**environment**); the system rate-limits, locks the targeted accounts, and alerts the SOC (**response**) with no valid-user lockout exceeding 0.1% and detection within 30s (**response measure**)."

That is a testable security requirement *and* an architectural driver (it demands a rate-limiter, a WAF/bot-management tier, and a detection pipeline).

### 4.3 Documenting architecture: C4, arc42, ADRs

**C4 model** (Simon Brown) — four zoom levels, so each audience sees the right altitude:

```
Level 1  SYSTEM CONTEXT   your system + users + external systems   (exec / everyone)
Level 2  CONTAINER        apps, services, data stores, the big movable parts  (tech-wide)
Level 3  COMPONENT        inside one container: the major components  (developers)
Level 4  CODE             classes/functions — usually skip; let the IDE generate it
```
Supplementary diagrams: *system landscape* (many systems), *dynamic* (runtime sequence), *deployment* (mapping to infrastructure — the one security reviewers want). C4 is notation-independent; render it however you like (often with structurizr, Mermaid, or PlantUML).

**arc42** — a 12-section template for an architecture document: 1 Introduction & goals · 2 Constraints · 3 Context & scope · 4 Solution strategy · 5 Building-block view · 6 Runtime view · 7 Deployment view · 8 Cross-cutting concepts (security lives here) · 9 Architecture decisions · 10 Quality requirements · 11 Risks & technical debt · 12 Glossary. C4 supplies the diagrams for sections 3/5/6/7; arc42 supplies the surrounding narrative.

**Architecture Decision Records (ADRs)** — a short, immutable, versioned record of one significant decision, living *in the repo* next to the code. The canonical lightweight format (Michael Nygard):

```markdown
# ADR-017: Use event-carried state transfer for order→fulfillment

## Status
Accepted  (supersedes ADR-009)

## Context
Fulfillment needs order data but must keep running during order-service
outages. Synchronous calls coupled their availability and caused 3 incidents.

## Decision
Order service publishes a fat `OrderConfirmed` event carrying the fields
fulfillment needs. Fulfillment maintains a local read model. Events are
signed and schema-validated.

## Consequences
+ Fulfillment survives order-service outages (availability ↑).
+ Clear audit trail of order state changes.
− Eventual consistency; data duplicated across services.
− Event schema is now a contract requiring versioning discipline.
− Security: event bus now carries customer PII → topic encryption + ACLs (see ADR-018).
```

Rules that make ADRs worth keeping: one decision per record; never edit an accepted ADR (supersede it with a new one); record the *rejected* options and *why*; keep them in version control. ADRs are also the single best security-review artifact — they capture the reasoning a reviewer needs and show whether security was weighed at decision time. Tooling: `adr-tools`, MADR template, Log4brains.

### 4.4 Trade-off analysis: ATAM

Quality attributes conflict. Making something more secure often makes it slower, costlier, or less usable. The **Architecture Tradeoff Analysis Method (ATAM)** (SEI) is the structured way to surface those conflicts before you build. Core concepts:

- **Utility tree** — decompose "goodness" into quality attributes → refinements → concrete, prioritized scenarios (importance × difficulty).
- **Sensitivity point** — a decision that strongly affects one quality attribute.
- **Trade-off point** — a decision that is a sensitivity point for *two or more* attributes that pull in opposite directions (e.g., "encrypt all inter-service traffic" is a trade-off point between security ↑ and latency/cost ↓).
- **Risk / non-risk** — decisions that may/may not jeopardize a quality goal.

A lightweight version — gather stakeholders, build a utility tree, walk the top scenarios against the design, and record risks and trade-off points as ADRs — is worth running on any system where being wrong is expensive. The security value is explicit: it forces the question "what quality are we spending to get this security control, and is that trade defensible?"

### 4.5 Well-architected thinking

The cloud vendors converged on a useful checklist discipline. The **AWS Well-Architected Framework** has **six pillars**: Operational Excellence, Security, Reliability, Performance Efficiency, Cost Optimization, and **Sustainability** (the sixth, added late 2021). The **Azure Well-Architected Framework** has **five**: Reliability, Security, Cost Optimization, Operational Excellence, Performance Efficiency (no sustainability pillar). Google Cloud publishes an equivalent **Architecture Framework**. The pillar names differ, but the discipline is the same and is vendor-independent: periodically review a workload against each pillar's questions and track remediation. Security is a pillar in every one of them — treat the Security pillar's questions (identity, detection, data protection, incident response, infrastructure protection) as a recurring design review, not a one-time gate.

---

## 5. Key design decisions & trade-offs

The recurring architectural decisions, framed ADR-style (options → trade → security note). Use these as a checklist of decisions you *must* make consciously rather than by default.

### 5.1 Monolith vs microservices
- **Options:** modular monolith · microservices · hybrid (monolith + a few extracted services).
- **Trade:** microservices buy independent deploy/scale and team autonomy at the cost of distributed-systems complexity, operational burden, and new network attack surface. Monoliths buy simplicity at the cost of coupled deploy and coarse scaling.
- **Decision rule:** default monolith; extract only proven seams; never adopt microservices without CI/CD, observability, and on-call maturity.
- **Security note:** microservices demand zero-trust internally; monoliths have one big blast radius. More services = more secrets, certs, and patch targets.

### 5.2 Synchronous vs asynchronous integration
- **Options:** request/response (REST/gRPC) · messaging/events · hybrid.
- **Trade:** sync is simpler to reason about and gives immediate consistency but couples availability (a slow dependency slows you); async decouples availability and enables fan-out but forces eventual consistency and idempotency.
- **Security note:** async adds a broker to secure and audit; sync exposes more direct, abusable endpoints — rate-limit and authenticate both.

### 5.3 Consistency: strong vs eventual (CAP/PACELC)
- Under a network partition you must choose availability or consistency (**CAP**); even without a partition you trade latency against consistency (**PACELC**).
- **Decision rule:** demand strong consistency only where correctness requires it (money, inventory, authz decisions); accept eventual consistency elsewhere and design the UX for it.
- **Security note:** authorization and authentication state should be strongly consistent — a revoked token or disabled account that is "eventually" enforced is an access-control gap (ATT&CK **Valid Accounts, T1078**).

### 5.4 Data ownership & the shared-database trap
- **Options:** database-per-service · shared database · schema-per-service in one cluster.
- **Trade:** a shared database is the fastest way to couple "independent" services into a distributed monolith — a change by one team breaks another, and it becomes the real integration contract.
- **Decision rule:** one writer per data element; share by API or events, not by reaching into another service's tables.
- **Security note:** a shared DB means one over-privileged credential can read everyone's data — least-privilege is impossible. Per-service data enables per-service least-privilege (defends **Collection, T1213** / **Exfiltration**).

### 5.5 Build vs buy vs open-source
- **Trade:** building gives control and differentiation but costs engineering and ongoing maintenance; buying/OSS is fast but adds supply-chain and lock-in risk.
- **Decision rule:** build only your differentiators; buy/adopt commodity capability.
- **Security note:** every dependency is inherited attack surface — maintain an SBOM, use SCA, and treat third-party and OSS components as part of your threat model (ATT&CK **Supply Chain Compromise, T1195**; see the OSS build/sign guidance in SLSA).

### 5.6 Statelessness & session management
- **Decision rule:** push services toward statelessness (externalize session/state to a cache or store) so they scale horizontally and fail without data loss.
- **Security note:** stateless JWT sessions are hard to revoke — pair short token lifetimes with a revocation/introspection path; server-side sessions are revocable but need a shared, protected store.

### 5.7 Coupling at the edge: gateway, mesh, BFF
- Put cross-cutting concerns (authn, rate limiting, TLS termination) at the edge so services do not each reimplement them — but never make the edge the *only* line of defense (defense in depth; see §6).

---

## 6. Security-by-design integration

This is a security library, so security is not a section — it is the reading of every decision above. Here is how to operationalize "secure and private by design" as an architectural discipline.

### 6.1 The foundational principles

- **Saltzer & Schroeder (1975), still the bedrock:** economy of mechanism, fail-safe defaults (deny by default), complete mediation (check *every* access, no cached bypass), open design (no security through obscurity), separation of privilege, **least privilege**, least common mechanism, psychological acceptability.
- **Defense in depth:** no single control is trusted to be sufficient; the edge gateway, the service authz, the data-layer permissions, and the network segmentation each assume the others may fail.
- **Zero trust (NIST SP 800-207):** never trust based on network location; authenticate and authorize every request, continuously, with least privilege. This is why "authenticated at the gateway" is not enough inside a microservice mesh.
- **Secure/Privacy by design & by default (GDPR Art. 25; the "privacy by design" principles):** data protection is built in from the start and the default settings are the most protective, not bolted on before launch.
- **Shift left:** threat modeling and security review happen at design time (in the ADR), where fixes are an edit, not after deployment, where they are an incident.

### 6.2 Trust boundaries are an architectural artifact

A **trust boundary** is any point where data or control crosses between zones of differing trust (internet→DMZ, user→service, service→service, app→database, tenant→tenant). *Every trust boundary is where authentication, authorization, input validation, and output encoding must happen.* Draw them explicitly on the C4 container/deployment diagram:

```
   Internet  ══╗ (trust boundary: WAF, authn, TLS, rate limit)
               ▼
            [ API Gateway ]
               ║ (trust boundary: mTLS + workload identity — DO NOT trust
               ▼  "it came from the gateway")
            [ Order Service ] ──╗ (trust boundary: least-priv DB creds,
                                 ▼  parameterized queries)
                              [ Order DB ]  (encryption at rest, row-level
                                             access, audit logging)
```

### 6.3 Threat modeling woven into design

Threat modeling is the mechanism that turns a DFD into a set of controls. The four questions (Shostack): *What are we building? What can go wrong? What are we going to do about it? Did we do a good job?* Common techniques:

| Technique | Lens | Use when |
|---|---|---|
| **STRIDE** | per-element: Spoofing, Tampering, Repudiation, Information disclosure, DoS, Elevation of privilege | Decomposing a DFD element-by-element |
| **Attack trees** | attacker goal → sub-goals | Reasoning about a specific high-value target |
| **PASTA** | risk-centric, 7 stages | Aligning threats to business impact |
| **LINDDUN** | privacy threats | Privacy-by-design analysis of personal data flows |
| **MITRE ATT&CK mapping** | adversary TTPs against the design | Checking whether the architecture detects/mitigates real techniques |

Record the output as design constraints and ADRs. STRIDE maps cleanly onto security quality attributes (spoofing→authenticity, tampering→integrity, repudiation→non-repudiation, info disclosure→confidentiality, DoS→availability, elevation→authorization).

### 6.4 Tying design to controls and ATT&CK

Architecture is a control. The table shows how structural choices map to control frameworks and to the MITRE ATT&CK techniques/mitigations they blunt — this is the threat-informed reading a security reviewer applies to a design.

| Architectural choice | Control mapping (NIST SP 800-53 / CSF 2.0 / CIS v8.1) | ATT&CK technique mitigated | Mitigation (Mxxxx) |
|---|---|---|---|
| Network segmentation / microsegmentation | SC-7 Boundary Protection; CSF **PR.AA/PR.IR**; CIS Control 12 | Lateral Movement **T1021**, **T1570** | Network Segmentation **M1030** |
| Least-privilege service identities, no shared creds | AC-6; CSF **PR.AA**; CIS Control 5/6 | Valid Accounts **T1078**, Collection **T1213** | Privileged Account Mgmt **M1026**, User Acct Mgmt **M1018** |
| Centralized authn + MFA at every boundary | IA-2; CSF **PR.AA-02/03** | Brute Force **T1110**, Phishing **T1566** | Multi-factor Authentication **M1032** |
| Input validation / parameterized queries in adapters | SI-10; OWASP ASVS V5 | Exploit Public-Facing App **T1190** | — (secure coding) |
| Encryption in transit (mTLS) & at rest | SC-8, SC-28; CSF **PR.DS** | Adversary-in-the-Middle **T1557**, Exfil over C2 | Encrypt Sensitive Info **M1041** |
| Immutable, centralized audit logging | AU-2/AU-9; CSF **DE.AE/DE.CM** | Indicator Removal **T1070**, Impair Defenses **T1562** | Remote Data Storage **M1029** |
| SBOM + SCA + dependency pinning/signing | SR-3/SR-11; CSF **GV.SC**; CIS Control 2/16 | Supply Chain Compromise **T1195** | — (SLSA, Update SW **M1051**) |
| Secrets in a vault, short-lived, rotated | IA-5; CSF **PR.AA**; CIS Control 6 | Unsecured Credentials **T1552** | — (secrets management) |
| Rate limiting / bot management at edge | SC-5; CSF **PR.IR** | Endpoint DoS **T1499**, Brute Force **T1110** | Filter Network Traffic **M1037** |

> Note on currency: NIST CSF 2.0 (2024) added the **Govern (GV)** function — supply-chain risk now lives under **GV.SC**, and identity/access concepts cluster under **PR.AA**. CIS Controls v8.1 realigned to CSF 2.0 and added a Governance security function. Verify exact subcategory IDs against the live NIST/CIS sources before citing them formally; ATT&CK technique IDs drift across versions — confirm against the current ATT&CK release.

### 6.5 Privacy by design, concretely

Data classification (§3) drives placement, encryption, retention, residency, and access. Architectural moves that implement privacy: **data minimization** (don't collect/propagate fields a component doesn't need — fat events are a privacy liability), **purpose limitation** (separate stores/scopes per purpose), **pseudonymization/tokenization** at the boundary, **crypto-shredding** to satisfy erasure in immutable logs, and **data-residency-aware deployment** (region-pinned storage for GDPR/data-sovereignty). LINDDUN is the threat-modeling complement that makes these systematic.

---

## 7. Anti-patterns & pitfalls

The failures a senior architect is paid to prevent. Most are not technology failures — they are decisions made by default instead of on purpose.

| Anti-pattern | What it looks like | Why it hurts | Security angle |
|---|---|---|---|
| **Big ball of mud** | No discernible structure; everything depends on everything | Change is unpredictable; nobody can reason about impact | Impossible to locate trust boundaries or bound blast radius |
| **Distributed monolith** | "Microservices" that must deploy together and share a DB | All the cost of distribution, none of the independence | One shared credential reads everyone's data; no isolation |
| **Microservices premature adoption** | Splitting before you know the seams, or with a 3-person team | Operational burden crushes feature velocity | N× secrets, certs, patch surface for no isolation benefit |
| **Shared database** | Multiple services writing the same tables | The DB becomes the real contract; silent coupling | Over-privileged creds; least-privilege impossible |
| **Golden hammer** | One pattern/tech for every problem | Forces bad fits; accidental complexity | Unneeded complexity is unneeded attack surface |
| **Accidental complexity** | Layers/abstractions no requirement demanded | Slower, harder to secure and audit | More code and moving parts = more bugs and CVEs |
| **Security as a final gate** | Pen test the week before launch | Findings are architectural → unfixable on schedule → shipped anyway | Design flaws (missing authz model) can't be patched late |
| **Perimeter-only trust** | Hard shell, soft interior; internal services trust each other | One foothold → lateral movement everywhere | Classic breach amplifier (**T1021**); violates zero trust |
| **Over-trusting the gateway** | Internal services assume edge authn is enough | A smuggled/internal request is fully trusted | Authz bypass; SSRF pivot into trusted zone |
| **Chatty / N+1 integration** | Many fine-grained sync calls per operation | Latency and fragility compound | More endpoints to abuse; amplifies DoS |
| **Resume-driven / hype-driven design** | Choosing tech for novelty, not fit | Unproven ops and security posture | Immature tooling = unpatched, poorly understood risk |
| **No ADRs / tribal knowledge** | Decisions live in people's heads | Can't onboard, can't audit, decisions re-litigated | No record of whether security was ever considered |
| **Ignoring Conway's Law** | Architecture fights the org chart | Boundaries erode; coupling returns | Ownership gaps = unowned, unpatched components |
| **Fat events leaking PII** | Event-carried state transfer with full records | Privacy exposure across every consumer and the log | Broadens where PII must be protected (**T1565/T1213**) |

---

## 8. Standards & frameworks

A map of what to reach for, and for what. Vendor-neutral unless noted.

| Standard / framework | Owner | What it is / use for |
|---|---|---|
| **TOGAF Standard, 10th Edition** (2022) | The Open Group | Enterprise-architecture method; the **ADM** cycle (Preliminary → A Vision → B Business → C Information Systems → D Technology → E Opportunities & Solutions → F Migration → G Implementation Governance → H Change Mgmt, with **Requirements Management** central) |
| **Zachman Framework** | Zachman Intl. | EA ontology: a matrix of perspectives × interrogatives (what/how/where/who/when/why) — a taxonomy, not a method |
| **ArchiMate 3.2** | The Open Group | A modeling *language* for EA across business/application/technology layers (complements TOGAF) |
| **ISO/IEC/IEEE 42010** | ISO/IEC/IEEE | Standard for architecture description: views, viewpoints, stakeholders, concerns |
| **ISO/IEC 25010** (rev. 2023) | ISO/IEC | Product-quality model — the canonical quality-attribute vocabulary |
| **C4 model** | Simon Brown (community) | Lightweight diagramming at four zoom levels |
| **arc42** | Starke/Hruschka (community) | 12-section architecture-documentation template |
| **ATAM / quality-attribute scenarios** | SEI (CMU) | Structured trade-off analysis and testable NFRs |
| **ADRs (Nygard / MADR)** | community | Lightweight decision records in the repo |
| **Well-Architected Frameworks** | AWS (6 pillars) / Azure (5) / Google | Recurring workload review checklists (Security is a pillar in each) |
| **NIST CSF 2.0** (2024) | NIST | Govern/Identify/Protect/Detect/Respond/Recover — risk framing; **Govern** function added in 2.0 |
| **NIST SP 800-53 Rev. 5** | NIST | Control catalog (map architectural controls to it) |
| **NIST SP 800-207** | NIST | Zero Trust Architecture |
| **NIST SP 800-160 Vol. 1 (rev.)** | NIST | Systems security engineering — security designed into systems |
| **CIS Controls v8.1** | CIS | Prioritized, implementable safeguards; realigned to CSF 2.0 (added Governance function) |
| **MITRE ATT&CK** | MITRE | Adversary TTP knowledge base — map designs to real techniques/mitigations |
| **OWASP ASVS / Cheat Sheets / Proactive Controls** | OWASP | Application-security requirements and secure-design guidance |
| **SLSA / SBOM (SPDX, CycloneDX)** | OpenSSF / Linux Fdn | Software supply-chain integrity and inventory |
| **Enterprise Integration Patterns** | Hohpe/Woolf | Vocabulary for messaging/integration |
| **DDD (Evans / Vernon)** | community | Strategic & tactical domain modeling (see §A) |

*(Version/edition numbers above reflect the latest the author verified; confirm against the owning body's current publication before citing — standards revise, and ATT&CK/NIST identifiers in particular change between releases.)*

---

## 9. Maturity & checklist

### 9.1 Architecture-practice maturity (quick self-assessment)

| Level | Description | Tell-tale |
|---|---|---|
| 1 — Ad hoc | No shared method; decisions undocumented | "Why is it built this way?" → shrugs |
| 2 — Repeatable | Some diagrams/standards exist for big projects | Diagrams exist but are stale and no one trusts them |
| 3 — Defined | Consistent method (C4/arc42), ADRs in repos, principles published | New hires can read the architecture and find decision history |
| 4 — Managed | Quality attributes are measured; trade-offs analyzed (ATAM-style); security review at design time | NFRs have numbers; threat models exist per system |
| 5 — Optimizing | Architecture governance is lightweight and continuous; fitness functions enforce constraints in CI; feedback loops improve the practice | Dependency/coupling/security rules fail the build automatically |

### 9.2 Design-review checklist

**Drivers & scope**
- [ ] Business goals, constraints, and prioritized quality attributes are written down and traceable to decisions.
- [ ] Key NFRs are expressed as measurable scenarios (source→stimulus→…→measure), not adjectives.

**Structure**
- [ ] The structural pattern (monolith/microservices/EDA/…) is a *conscious* choice with recorded rationale, not a default.
- [ ] Coupling and cohesion are deliberate; no shared database across service boundaries; one writer per data element.
- [ ] Module/service boundaries align with team boundaries (Conway) and with domain boundaries (bounded contexts).

**Documentation**
- [ ] C4 context + container (+ deployment) diagrams exist and are current.
- [ ] Significant decisions are captured as ADRs with options, trade-offs, and consequences.
- [ ] Data-flow diagram with data classification exists.

**Security & privacy by design**
- [ ] Trust boundaries are drawn explicitly; authn/authz/validation/encoding happen at each.
- [ ] A threat model (STRIDE/LINDDUN/ATT&CK mapping) exists and its findings became constraints/ADRs.
- [ ] Least privilege for every identity (human and workload); no shared or long-lived credentials; secrets in a vault.
- [ ] Zero-trust internally — no implicit trust from network location or "it came from the gateway."
- [ ] Encryption in transit and at rest; data residency and retention handled per classification.
- [ ] Defense in depth — no single control is the only line.
- [ ] Immutable, centralized audit logging; detections mapped to relevant ATT&CK techniques.
- [ ] Supply chain: SBOM maintained, SCA in CI, dependencies pinned/signed.
- [ ] Degraded-mode behavior is defined for every external dependency (failure does not open an auth/integrity gap).

**Evolvability & governance**
- [ ] Architectural constraints are enforced as *fitness functions* in CI where possible (dependency rules, layering, forbidden calls, security policy-as-code).
- [ ] Technical debt and known risks are logged (arc42 §11) and reviewed.

### 9.3 Fitness functions (make the architecture self-enforcing)

An architectural rule that is only in a document will erode. Encode the ones you can as automated tests that fail the build:

- **Dependency/layering rules** — ArchUnit (JVM), dependency-cruiser (JS), import-linter (Python), `go vet`/custom linters: "the domain layer must not import infrastructure," "no service may import another's internals."
- **Security policy-as-code** — OPA/Conftest/Checkov/tfsec on IaC: "no security group open to 0.0.0.0/0 on 22," "all S3 buckets encrypted and private."
- **Supply chain** — SCA (dependency scanning), SBOM generation, signature verification in CI.
- **API contracts** — schema linting and backward-compatibility checks (Buf for protobuf, spectral for OpenAPI).

---

## Appendix A — Domain-Driven Design, briefly

DDD is the discipline that makes service/module boundaries principled rather than arbitrary — which is why it pairs with every pattern above.

**Strategic (the architecture part):**
- **Ubiquitous language** — one shared vocabulary per context, used in code, docs, and conversation.
- **Bounded context** — an explicit boundary within which a model is consistent; *the single most useful guide to where a microservice boundary should go.*
- **Context map** — how bounded contexts relate: *partnership, customer/supplier, conformist, anti-corruption layer* (ACL), *open-host service, published language, shared kernel.* The **ACL** is both a modeling and a **security** boundary — it stops an external/legacy model (and its assumptions) from leaking in.
- **Subdomains** — *core* (your differentiator — build it, model it richly), *supporting*, *generic* (buy/adopt).

**Tactical (inside a context):** entity, value object, aggregate (+ aggregate root — the consistency and transaction boundary), domain event, repository, domain service, factory.

> **The alignment that matters:** bounded context ≈ team ≈ deployable service ≈ data-ownership boundary ≈ trust boundary. When those five line up, the architecture is coherent, evolvable, and defensible. When they diverge, you get distributed monoliths, shared databases, ownership gaps, and lateral-movement paths. Getting that alignment right is most of the job.

## Appendix B — The one-page method

```
1. State drivers      business goals + constraints + prioritized quality attributes
2. Model the domain   bounded contexts, ubiquitous language, context map
3. Choose structure   pattern per the §2.9 decision flow (default: modular monolith)
4. Draw it            C4 context + container + deployment; mark TRUST BOUNDARIES
5. Threat model       STRIDE/LINDDUN on the DFD → controls (map to CSF/800-53/ATT&CK)
6. Analyze trade-offs ATAM-lite: utility tree, find sensitivity & trade-off points
7. Record decisions   ADRs — options, trade, consequences (incl. security)
8. Enforce            fitness functions in CI (layering, security policy, supply chain)
9. Review & evolve    well-architected review per pillar; log debt/risk; supersede ADRs
```
