# ASP.NET Core

ASP.NET Core is a cross-platform web framework from Microsoft for building APIs and server-rendered sites in C#. It runs on the .NET runtime across Windows, Linux, and macOS. Teams use it for its middleware pipeline, its built-in dependency injection, and the performance of the Kestrel server.

## Overview and history

ASP.NET Core launched in 2016 as a rewrite of the older ASP.NET framework. The original ran only on Windows and the .NET Framework. The rewrite targeted the new cross-platform .NET Core runtime and a modular, composable design.

The framework and runtime now share a yearly release cadence under the unified .NET brand, with long-term support versions every other year. Each release has narrowed the gap between older patterns and newer ones. Minimal APIs, introduced in .NET 6, let a small service be defined in a handful of lines.

Today ASP.NET Core supports several programming models in one framework. MVC and Razor Pages serve HTML, while controller-based and minimal APIs serve data. Blazor adds component-based UI. They share the same hosting, configuration, and dependency injection foundations.

## Architecture

An application is built with a host that configures services and the request pipeline. Program startup registers services into a dependency injection container, then composes a sequence of middleware. The host binds Kestrel, the default HTTP server, to listen for connections.

The request pipeline is an ordered chain of middleware components. Each component receives the request context, may act on it, and either passes control to the next component or short-circuits the chain. Ordering matters: authentication must run before authorization, and exception handling must wrap the components it protects. Routing, static files, and endpoint execution are themselves middleware.

Dependency injection is built into the framework rather than added by a library. Services register with a lifetime of singleton, scoped, or transient. Scoped services live for one request, which makes them the right choice for per-request state such as a database context. The container resolves constructor dependencies when it creates controllers and handlers.

Endpoint execution depends on the model. MVC routes to controller actions that return results. Minimal APIs map routes directly to handler delegates. Razor Pages pair a page template with a page model class. In all cases model binding fills parameters from the request, and the result is serialized or rendered back through the pipeline.

Entity Framework Core is the common data layer. A `DbContext` represents a session with the database and tracks changes to entities. LINQ queries translate to SQL, and migrations manage schema changes over time.

## Routing, data, and key subsystems

Routing matches a request to an endpoint. Attribute routing places templates such as `[HttpGet("items/{id}")]` on actions. Minimal APIs declare routes with `app.MapGet` and similar calls. Route parameters bind to handler arguments by name and type.

Model binding reads values from the route, query string, headers, and body, then constructs the parameters an action declares. Binding feeds validation: data annotations such as `[Required]` and `[Range]` run automatically, and `ModelState` reports failures.

Configuration composes from multiple providers: JSON files, environment variables, command-line arguments, and user secrets in development. The options pattern binds a configuration section to a typed class injected where needed. Settings layer by provider order, so environment variables can override file defaults.

Entity Framework Core handles persistence. The `DbContext` exposes `DbSet` collections that LINQ queries run against. Change tracking batches inserts and updates into a single `SaveChanges` call. Raw SQL is available through `FromSqlInterpolated` and related methods when LINQ is not enough.

## A minimal example

```csharp
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/items/{id}", (int id) => new { id, name = "widget" });

app.Run();
```

## Ecosystem and tooling

The `dotnet` command-line tool builds, runs, tests, and publishes applications and manages NuGet packages. NuGet is the package registry for .NET libraries. Visual Studio, Visual Studio Code, and JetBrains Rider are the common editors.

Serilog and the built-in logging abstractions handle structured logs. Testing uses xUnit, NUnit, or MSTest, often with the `WebApplicationFactory` for in-memory integration tests. Swashbuckle and the newer built-in OpenAPI support generate API documents.

ASP.NET Core Identity supplies user accounts, password hashing, and sign-in. For token and external login scenarios, teams integrate OpenID Connect and OAuth2 providers through the authentication middleware.

## Security model and common vulnerabilities

The data protection system supplies keyed encryption and signing for framework features such as cookies and tokens. It manages key rotation and storage. Antiforgery tokens build on it to defend against cross-site request forgery (CWE-352). Razor forms emit the token automatically, and `[ValidateAntiForgeryToken]` enforces it on actions. Pure token APIs that use no cookies rely on the token in the authorization header instead. See `/WEB_APPLICATION_SECURITY_REFERENCE.md` for CSRF guidance.

Authentication and authorization run as middleware and attributes. Identity handles the credential store, while `[Authorize]` and policy-based authorization gate access. Missing or misapplied `[Authorize]` leaves endpoints open (CWE-287, improper authentication). Apply authorization by default and opt specific endpoints out, rather than the reverse. See `/API_SECURITY_REFERENCE.md` for authentication patterns.

Model binding over-posting is a .NET-specific trap. If an action binds directly to an entity, a client can set properties it should not control, such as `IsAdmin` or `Balance` (CWE-915, improper restriction of object modification through user-controlled keys, often called mass assignment). Bind to a view model or DTO that lists only the editable fields, or use `[Bind]` to restrict them. See `/SECURE_CODING_REFERENCE.md` for input-handling guidance.

Entity Framework Core parameterizes LINQ queries, which prevents SQL injection by construction. Raw SQL built by string concatenation reopens the hole (CWE-89, SQL injection). Use `FromSqlInterpolated`, which turns interpolated values into parameters, and never concatenate user input into a query string.

Secrets in configuration leak when connection strings and API keys sit in `appsettings.json` committed to source control. Use user secrets in development and a managed secret store in production. CORS is configured with named policies: avoid `AllowAnyOrigin` combined with credentials, and list the exact origins a browser client needs.

## Performance and scaling

Kestrel is a high-throughput server written for the framework. It handles requests asynchronously, and `async`/`await` across the stack keeps threads free during I/O. Awaiting database and network calls rather than blocking is the main throughput lever.

The framework scales horizontally behind a load balancer or reverse proxy such as YARP, Nginx, or IIS. Scoped services and in-memory state are per-process, so shared session or cache state belongs in a distributed store like Redis. Response caching and output caching reduce repeated work.

Allocations matter at high request rates. Pooling, `Span`-based APIs, and source-generated JSON serialization cut garbage collection pressure. Ahead-of-time compilation and trimming reduce startup time and image size for container and serverless targets.

## Common pitfalls

Registering a scoped service as a singleton captures per-request state and corrupts data across requests. Match the lifetime to the use.

Ordering middleware wrong, such as placing authorization before authentication, silently breaks access control. Follow the documented order.

Binding actions straight to EF entities invites over-posting. Use DTOs.

Blocking on async calls with `.Result` or `.Wait()` can deadlock and starves the thread pool. Keep the call chain asynchronous.

## Resources

- ASP.NET Core documentation and its Security area on Microsoft Learn
- OWASP .NET Security Cheat Sheet
- OWASP Top 10
- *Pro ASP.NET Core* by Adam Freeman

## Related pages

- /languages/csharp.md
- /frameworks/README.md
- /SECURE_CODING_REFERENCE.md
- /WEB_APPLICATION_SECURITY_REFERENCE.md
- /API_SECURITY_REFERENCE.md
- /frameworks/spring-boot.md
- /frameworks/django.md
- /frameworks/express.md
