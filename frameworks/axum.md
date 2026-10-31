# Axum

Axum is an async web framework for Rust built on Tokio for the runtime and Tower for middleware. It describes handlers as plain async functions whose arguments are extractors, so request parsing is driven by the type system. The framework stays small and composes with the broader Tokio and Tower ecosystem rather than replacing it.

## Overview and history

Axum is maintained by the Tokio project and reached 0.1 in 2021. It was designed to feel ergonomic without macros for routing, relying instead on traits and generics. The framework reached a 0.6 and later releases that stabilized its extractor and state model.

The goal was a framework that reuses Tower's middleware ecosystem directly. Any Tower `Service` or `Layer` works with Axum, so timeouts, tracing, and rate limiting come from shared crates. This keeps Axum focused on routing and request handling.

## Architecture

An Axum application is a `Router` that maps paths and methods to handlers. The router is itself a Tower `Service`, so it runs on a Hyper server through Tokio. Everything is async from the socket up.

Handlers are async functions. Their parameters implement the `FromRequest` or `FromRequestParts` traits, which makes them extractors. The return type implements `IntoResponse`, so the function body stays focused on logic.

Middleware are Tower layers applied with `.layer()`. A layer wraps the inner service to add behavior before and after the handler. State is shared through the `State` extractor, injected when the router is built.

## Routing, data, and key subsystems

Routing uses builder methods: `Router::new().route("/users/:id", get(handler))`. Path segments bind through the `Path` extractor, and query strings through `Query`. Nested routers and route merging compose larger applications.

Extractors turn request parts into typed values. `Json<T>` deserializes a body with serde, `Path<T>` reads path parameters, and `State<T>` provides shared application state. Extraction order matters, since body extractors consume the request and must come last.

Responses come from `IntoResponse`. Returning a tuple like `(StatusCode, Json(value))` sets status and body together. The `Result` type with an error that implements `IntoResponse` gives clean error paths.

Data access is independent of Axum. SQLx is a common choice, offering async, compile-time-checked queries. Shared pools live in router state and are extracted per handler.

## A minimal example

```rust
use axum::{routing::get, extract::Path, Router, Json};
use serde_json::{json, Value};

async fn get_user(Path(id): Path<String>) -> Json<Value> {
    Json(json!({ "id": id }))
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/users/:id", get(get_user));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Ecosystem and tooling

Axum builds with Cargo and the standard Rust toolchain. `cargo build`, `cargo test`, and `cargo clippy` cover building, testing, and linting. No framework-specific CLI is needed.

Tower and `tower-http` supply middleware: tracing, compression, CORS, timeouts, and request limits come as layers. `tokio` provides the runtime and async primitives, and `hyper` is the HTTP engine underneath. These crates are shared across the async Rust world.

SQLx and SeaORM handle databases asynchronously. `serde` and `serde_json` drive serialization through the `Json` extractor and response type. For testing, handlers can be called directly or exercised through the router with `tower::ServiceExt::oneshot`.

## Security model and common vulnerabilities

Type-driven extraction is Axum's first security property. A handler that takes `Json<CreateUser>` only runs if the body deserializes into that exact shape, which rejects malformed input early. Still validate semantic rules (ranges, formats) beyond deserialization, since type-correct input can be invalid; skipping this is CWE-20 (improper input validation). The `/SECURE_CODING_REFERENCE.md` covers validation.

SQLx offers compile-time-checked, parameterized queries through the `query!` macros. Values are always bound as parameters, so ordinary use resists CWE-89 (SQL injection). The risk returns only if you build query strings by hand and pass them to a dynamic query function; the `/API_SECURITY_REFERENCE.md` shows safe patterns.

Rust's memory safety removes a class of bugs: buffer overflows and use-after-free do not occur in safe code. This does not stop logic flaws, so authorization and output encoding still matter. Memory safety is a floor, not a full defense.

Output encoding is the developer's job for HTML responses. Axum does not template by default, so pair it with `askama` or a similar engine that escapes, or encode manually. Writing user input into HTML without escaping causes CWE-79 (cross-site scripting); see `/WEB_APPLICATION_SECURITY_REFERENCE.md`.

Authentication and authorization are built as extractors or middleware. An extractor that validates a token and yields the current user is the idiomatic pattern, often paired with a layer that rejects unauthenticated requests. Omitting a check on a route that needs one is CWE-862 (missing authorization); make protection explicit per route and avoid relying on ordering alone.

Security headers and CORS are manual through `tower-http`. Add `CorsLayer` with a narrow origin list rather than permissive defaults, and set headers like `Strict-Transport-Security` with a layer. Configure TLS at the server or a fronting proxy.

## Performance and scaling

Axum runs on Tokio's multi-threaded scheduler and Hyper, which places it among the faster web frameworks. Async handlers let one thread serve many in-flight requests while they await I/O. Throughput is high for I/O-bound workloads.

Avoid blocking the async runtime inside handlers. CPU-heavy or synchronous work belongs on `tokio::task::spawn_blocking` or a separate pool, or it stalls the scheduler. This is the main latency trap in async Rust.

Scaling horizontally means running stateless instances behind a load balancer, with pooled database connections in shared state. The compiled binary has a small memory footprint and predictable latency. Connection pools cap backend pressure under load.

## Common pitfalls

Ordering extractors wrong is a frequent error. A body-consuming extractor like `Json` must be the last argument, or compilation fails or extraction breaks. The compiler error points at the trait bound.

Blocking calls inside async handlers quietly degrade the whole service. Move file, crypto, or CPU work to `spawn_blocking`. Watch for synchronous library calls hidden in dependencies.

Assuming memory safety covers all security is a mistake. Logic, authorization, and encoding bugs are unaffected by Rust's guarantees. Review these as you would in any language.

Permissive CORS defaults copied from examples leak across origins. Set an explicit origin allowlist in `CorsLayer`. Never combine a wildcard origin with credentials.

## Resources

- The Axum documentation
- The Tokio and Tower documentation
- The OWASP Cheat Sheet Series

## Related pages

- Language: [Rust](/languages/rust.md)
- [Software frameworks](/frameworks/README.md)
- Security references: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)
- Siblings: [Gin](/frameworks/gin.md), [FastAPI](/frameworks/fastapi.md), [Express.js](/frameworks/express.md)
