# Gin

Gin is a lightweight HTTP web framework for Go built around a fast router and a middleware chain. It stays close to the standard library, adding routing, parameter binding, validation, and response rendering without imposing an ORM or application structure. Teams reach for it when they want speed and small dependencies over convention.

## Overview and history

Gin emerged around 2014 as a faster alternative to earlier Go web frameworks. It uses a radix-tree router, which keeps route matching quick even with many routes. The project stayed small and focused, which suited Go's preference for explicit code.

Gin does not try to be a full-stack framework. It gives request routing, a `Context` for handler work, and helpers for common tasks. Everything else, including data access and templating choices, is left to the developer and the wider Go ecosystem.

## Architecture

A Gin application centers on an `Engine`, usually created with `gin.Default()` or `gin.New()`. The engine holds the router and the global middleware stack. `gin.Default()` includes logger and recovery middleware; `gin.New()` starts bare.

Handlers are functions that take a `*gin.Context`. The context carries the request and response, path and query parameters, and helpers for binding and rendering. Middleware share the same signature and call `c.Next()` to pass control along the chain.

Gin sits directly on Go's `net/http`. The engine implements `http.Handler`, so it plugs into the standard server. This keeps the mental model simple and the surface area small.

## Routing, data, and key subsystems

Routes attach a method and path to a handler, for example `r.GET("/users/:id", handler)`. Path parameters come from `c.Param("id")`, and query values from `c.Query("q")`. Route groups share a prefix and middleware through `r.Group("/api")`.

Binding maps request bodies and parameters onto Go structs. `c.ShouldBindJSON(&input)` decodes JSON, and struct tags like `binding:"required"` drive validation through the `validator` library. Binding errors return to the handler for explicit handling.

Rendering helpers write typed responses. `c.JSON`, `c.XML`, `c.String`, and `c.HTML` set the content type and serialize the value. Middleware can wrap these to add headers or compression.

Gin has no data layer. Most projects use `database/sql` with a driver, or a library like `sqlx` or an ORM such as GORM. The choice and its query safety are the developer's responsibility.

## A minimal example

```go
package main

import "github.com/gin-gonic/gin"

func main() {
	r := gin.Default()
	r.GET("/users/:id", func(c *gin.Context) {
		c.JSON(200, gin.H{"id": c.Param("id")})
	})
	r.Run(":8080")
}
```

## Ecosystem and tooling

Gin relies on Go's own toolchain. `go build`, `go test`, and `go vet` cover building and testing, and modules handle dependencies. There is no separate CLI to learn.

Middleware exists for common needs: CORS, rate limiting, request IDs, and JWT verification are available as third-party packages. The `net/http/httptest` package drives handler tests without a live server. Gin's `Engine` works directly with `httptest.NewRecorder`.

The validator library ships with Gin's binding and covers field rules, formats, and cross-field checks. For data access, `database/sql` plus a driver is the baseline, with `sqlx` or GORM layered on when wanted.

## Security model and common vulnerabilities

Gin gives little automatic protection, so security is explicit. Input binding with the validator is the first control. Validate every bound struct and reject malformed input, since loose binding leads to CWE-20 (improper input validation). The `/SECURE_CODING_REFERENCE.md` covers input handling.

Because there is no ORM, SQL safety depends on `database/sql` usage. Always pass values as query parameters with placeholders, never by concatenating strings into the SQL text. String-built queries cause CWE-89 (SQL injection); the `/API_SECURITY_REFERENCE.md` and the Go `database/sql` docs show parameterized patterns.

Output rendering is where cross-site scripting enters. The `html/template` package, used behind `c.HTML`, escapes by default, so prefer it over building HTML strings. Writing user input into responses with `c.String` and a HTML content type, or disabling escaping, risks CWE-79 (cross-site scripting). See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for encoding rules.

Gin does not add CSRF protection. For cookie-authenticated browser apps, add CSRF middleware and verify tokens on state-changing requests, or the app is open to CWE-352 (cross-site request forgery). Token-authenticated APIs that avoid cookies sidestep this class.

Security headers are manual. Set `Content-Security-Policy`, `Strict-Transport-Security`, and related headers through middleware. Configure TLS at the server, prefer `http.Server` with explicit timeouts, and terminate TLS with modern settings.

Concurrency needs care in handlers. Each request runs in its own goroutine, so shared state must be protected with a mutex or confined to the request. Launching goroutines that outlive the request and touch the `Context` is a data-race and use-after-free hazard; copy what you need with `c.Copy()` first.

## Performance and scaling

Gin's radix-tree router and low per-request allocation make it one of the faster Go frameworks. The thin layer over `net/http` means little overhead beyond routing and middleware. Benchmarks reflect that, though real cost usually lives in handlers and the database.

Go's goroutine model scales request handling across cores without per-connection threads. Keep handlers non-blocking where possible and set server timeouts to shed slow clients. Connection pooling in `database/sql` caps backend load.

Horizontal scaling means running stateless instances behind a load balancer. Keep session state in a shared store rather than process memory. Gin itself holds no cross-request state beyond what you add.

## Common pitfalls

Using the `Context` in a goroutine after the handler returns is a common bug. The request may be recycled, so call `c.Copy()` before handing the context to a background task. Races here are hard to reproduce.

Ignoring binding errors silently accepts bad input. Always check the error from `ShouldBind*` and return a clear status. Unvalidated structs flow into business logic otherwise.

Relying on `gin.Default()` recovery as error handling hides real failures. Recovery catches panics but is not a substitute for returning proper status codes. Handle expected errors explicitly.

Forgetting security headers and CSRF middleware leaves browser apps exposed. Gin adds neither by default. Add them deliberately for any cookie-based session flow.

## Resources

- The Gin documentation
- The Go `net/http` and `database/sql` documentation
- The OWASP Go Secure Coding Practices guide

## Related pages

- Language: [Go](/languages/go.md)
- [Software frameworks](/frameworks/README.md)
- Security references: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)
- Siblings: [Axum](/frameworks/axum.md), [Express.js](/frameworks/express.md), [FastAPI](/frameworks/fastapi.md)
