# Ballerina

Ballerina is a statically typed, open-source language built for writing network services and integrations. It was created by WSO2 and first released around 2017, with network concepts (services, clients, remote calls, and resources) as language constructs rather than library add-ons. Its type system is structural, and its data handling treats JSON, XML, and tabular data as native values. It is used for microservices, API back ends, and integration code that connects systems together.

| Attribute | Value |
|---|---|
| Paradigm | Imperative and functional, concurrent, network-aware |
| Typing | Static, structural, with union types and a built-in `error` type |
| First appeared | 2017 |
| Memory model | Managed, garbage-collected (compiles to JVM bytecode; native images via GraalVM) |
| Reference implementation | [Ballerina](https://github.com/ballerina-platform/ballerina-lang) (the `bal` toolchain) |
| Typical uses | Microservices, API back ends, systems integration, cloud-native services |
| Governance | [WSO2](https://wso2.com/) and the Ballerina community |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Ballerina came from WSO2, a company whose products center on integration and APIs, as an attempt to make writing network-connected code feel first-class rather than bolted on through frameworks. The language reached a stable release (often called Ballerina Swan Lake) after several years of development and redesign. A recurring theme is that a Ballerina program's structure corresponds to a sequence diagram of the interactions it performs, so the code and the picture of the integration stay close.

The language compiles to Java bytecode and runs on the Java Virtual Machine, and it can also be built into a native executable with GraalVM for faster start-up and smaller footprint, which suits containers and serverless deployment.

## Paradigm and type system

Ballerina is statically and structurally typed: two types are compatible if their shapes match, not by name. It has the usual value types plus `json`, `xml`, `map`, and `table`, and records and tuples for structured data. Union types (`int|string`) and the built-in `error` type are central: a function that may fail returns a union with `error`, and the caller must handle the error path, which the type checker enforces. Optional values use `T?`, which is `T|()` where `()` is the nil value.

```ballerina
function parse(string s) returns int|error {
    return int:fromString(s);   // returns an int, or an error
}
```

Network interactions are typed too: `service` objects expose resources, `client` objects make remote calls, and the data crossing those boundaries is checked against record types.

## Toolchain and ecosystem

- Toolchain: the `bal` command builds, runs, tests, formats, and packages code; `bal new` scaffolds a package.
- Standard library: a set of modules under `ballerina/...` covers HTTP, gRPC, WebSockets, SQL and NoSQL clients, messaging, and data formats.
- Package repository: [Ballerina Central](https://central.ballerina.io/) distributes shared packages and connectors to third-party systems.
- Tooling: a language server powers editor support (notably a Visual Studio Code extension), and the compiler can generate OpenAPI definitions from services and vice versa.

```bash
bal new greeter        # scaffold a package
bal run                # compile and run
bal test               # run tests
bal build              # produce an executable artifact
```

## Syntax tour

```ballerina
import ballerina/http;

// A service listening on port 8080
service /greeting on new http:Listener(8080) {

    // A resource that handles GET /greeting/{name}
    resource function get [string name]() returns string {
        return string `Hello, ${name}`;
    }
}

// Records describe structured data by shape
type Order record {|
    string id;
    decimal total;
|};

function totalOf(Order[] orders) returns decimal {
    decimal sum = 0;
    foreach var o in orders {
        sum += o.total;
    }
    return sum;
}
```

## Idioms and different approaches

- Return `T|error` from anything that can fail and handle the error explicitly with `check`, `on fail`, or a type test, rather than throwing exceptions across the program.
- Model payloads as records and let the HTTP and data modules bind requests and responses to them, so malformed data is caught at the boundary.
- Use `service` and `resource` declarations to expose endpoints; the structure doubles as the API definition and can emit OpenAPI.
- Reach for `worker` blocks and asynchronous calls to express concurrency within a function, and let the runtime schedule them.
- Prefer the standard library's typed clients (HTTP, SQL, messaging) over hand-built socket code.

## Design principles

Ballerina's stated aim is to make integration and network programming part of the language, so that services, clients, resilience (timeouts, retries, circuit breakers), and data handling are expressed directly rather than assembled from frameworks. Making errors part of the type system, rather than unchecked exceptions, pushes failure handling to where it happens. The correspondence between code and sequence diagrams is a deliberate design choice meant to keep distributed interactions understandable.

## Standard library and notable packages

The standard library modules (published under the `ballerina` organization) include `http` and `graphql` for web APIs, `grpc` and `websocket` for streaming, `sql`, `mysql`, `postgresql`, and `redis` for data stores, `kafka` and `rabbitmq` for messaging, and `io`, `log`, and `crypto` for common needs. Beyond the standard library, [Ballerina Central](https://central.ballerina.io/) hosts connectors to third-party services (cloud providers, software-as-a-service products) that wrap their APIs as typed clients.

## Testing and packaging

Testing is built in: a `tests` directory with functions annotated `@test:Config` runs under `bal test`, with assertions, setup and teardown, data providers, and mocking. Code is organized into packages and modules; `bal pack` and `bal push` publish a package to Ballerina Central, and dependencies are declared in `Ballerina.toml` and pinned in `Dependencies.toml`.

```ballerina
import ballerina/test;

@test:Config
function testTotal() {
    Order[] orders = [{id: "a", total: 10}, {id: "b", total: 5}];
    test:assertEquals(totalOf(orders), <decimal>15);
}
```

## Performance and concurrency

Ballerina runs on the JVM, so it inherits just-in-time compilation and a mature garbage collector; GraalVM native images trade some peak throughput for faster start-up and lower memory, which matters for short-lived or scaled-to-zero workloads.

Concurrency is a language feature rather than a library:

- `worker` blocks within a function run concurrently and communicate through typed message passing, so a function can express parallel steps and their synchronization directly.
- Network calls are non-blocking under the hood; the runtime multiplexes many in-flight requests onto a pool of threads, which suits I/O-bound service workloads.
- Because services are a first-class construct, the runtime handles the listener, request dispatch, and concurrency for each resource, so per-request isolation is the default model.

CPU-bound work still competes for threads as on any JVM program, so heavy computation is offloaded or parallelized explicitly.

## Common pitfalls

- Ignoring the error path: using `check` to propagate an error without a plan for handling it higher up can turn a recoverable failure into a crashed request; decide where each error is handled.
- Confusing structural typing with name typing: a value matches a type by shape, so an unexpected extra or missing field may or may not be accepted depending on whether the record is open (`{ }`) or closed (`{| |}`).
- Treating `()` (nil) like other languages' null without using optional types and checks, which the compiler otherwise forces you to handle.
- Blocking a worker on heavy computation and starving I/O concurrency; offload CPU-bound work.
- Assuming broad third-party library availability as in older ecosystems; the connector set is growing but smaller than long-established platforms.

## Secure coding

Ballerina is used to build network services and integrations, so its security concerns are those of API and service code:

- Injection in data-store and external calls ([CWE-89](https://cwe.mitre.org/data/definitions/89.html) and related): build SQL with parameterized queries from the `sql` module rather than string concatenation, and validate data bound from requests. See [API Security Reference](/API_SECURITY_REFERENCE.md).
- Hardcoded credentials ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): database passwords, API keys, and tokens belong in configuration supplied at deployment (Ballerina's configurable variables, environment, or a secrets manager), not in source or committed config files.
- Authentication and authorization: the `http` module supports declarative auth (basic, JWT, OAuth2) on services; apply it rather than hand-rolling checks, and enforce least privilege on what each endpoint allows. Missing or misapplied checks map to [CWE-284](https://cwe.mitre.org/data/definitions/284.html).
- Transport security and input validation: enable TLS on listeners and clients, and validate and constrain incoming records so malformed or oversized payloads are rejected at the boundary.
- Supply chain: packages and connectors pulled from Ballerina Central run with your service's privileges; pin versions in `Dependencies.toml` and review third-party connectors. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

Tooling: enable the compiler's warnings, keep dependencies pinned, and apply the broader checks in the [Secure Coding Reference](/SECURE_CODING_REFERENCE.md) and [API Security Reference](/API_SECURITY_REFERENCE.md) to service designs.

## Learning resources

- [Ballerina documentation](https://ballerina.io/learn/), the language guide and standard-library reference.
- [Ballerina by Example](https://ballerina.io/learn/by-example/), runnable annotated snippets.
- [Ballerina Central](https://central.ballerina.io/), for packages and connectors.

## Related pages

- [API Security Reference](/API_SECURITY_REFERENCE.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
