# NestJS

NestJS is a server-side TypeScript framework for building scalable Node.js applications. It borrows its module system, dependency injection, and decorator style from Angular, then runs on top of an HTTP layer provided by Express or Fastify. The result is a structured, opinionated layer over Node that favors testable, loosely coupled components.

## Overview and history

NestJS appeared in 2017, created by Kamil Mysliwiec. It set out to give Node a consistent application architecture, since Express alone imposes almost no structure. The framework is written in TypeScript but supports plain JavaScript as well.

Nest aims at a predictable layout across teams. The same module, controller, and provider concepts apply whether the project is a small REST API or a large microservice fleet. This consistency is the main reason teams adopt it over bare Express.

## Architecture

Nest organizes code into modules. A module groups related controllers and providers, and declares what it exports to other modules. The root module bootstraps the application and pulls in feature modules.

Controllers handle incoming requests and return responses. Providers (often called services) hold business logic and are injected into controllers or other providers. The dependency injection container wires these together based on constructor types and decorators.

Decorators carry most of the configuration. `@Module()`, `@Controller()`, `@Injectable()`, and route decorators like `@Get()` describe structure and routing without separate config files. This metadata is read at startup to build the injector graph.

## Routing, data, and key subsystems

Routes come from controller decorators. A `@Controller('users')` class with a `@Get(':id')` method maps to `GET /users/:id`. Parameter decorators such as `@Param()`, `@Query()`, and `@Body()` pull values out of the request.

Three request-lifecycle constructs shape behavior. Guards decide whether a request may proceed, which makes them the natural place for authentication and authorization. Interceptors wrap handler execution to transform results, add logging, or manage timeouts. Pipes transform and validate input before it reaches the handler.

Data access is not prescribed. Teams commonly use TypeORM, Prisma, or Mongoose through dedicated modules. Nest provides thin integration packages, but the ORM choice and its query safety remain the developer's responsibility.

Nest runs on Express by default and can swap in Fastify through `@nestjs/platform-fastify`. The adapter pattern keeps controller code the same while changing the underlying HTTP engine. Fastify generally offers higher throughput.

## A minimal example

```typescript
import { Controller, Get, Param, Module } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';

@Controller('users')
class UsersController {
  @Get(':id')
  findOne(@Param('id') id: string): { id: string } {
    return { id };
  }
}

@Module({ controllers: [UsersController] })
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
bootstrap();
```

## Ecosystem and tooling

The `@nestjs/cli` scaffolds projects, modules, controllers, and providers. It wires new files into the module graph and enforces the standard layout. Generated test stubs come with each component.

First-party packages cover common needs. `@nestjs/config` reads environment configuration, `@nestjs/jwt` and `@nestjs/passport` handle tokens and strategies, and `@nestjs/swagger` generates OpenAPI documents from decorators. `@nestjs/testing` builds isolated module contexts for unit and integration tests.

Microservice transports (TCP, Redis, NATS, Kafka, gRPC) ship as adapters. GraphQL support comes through `@nestjs/graphql` with a code-first or schema-first flow. These packages keep the DI model consistent across transport types.

## Security model and common vulnerabilities

Input validation centers on the `ValidationPipe` combined with `class-validator` and `class-transformer`. DTO classes declare decorators like `@IsEmail()` or `@IsInt()`, and the pipe rejects requests that fail them. Missing or loosely configured validation leads to CWE-20 (improper input validation). See `/SECURE_CODING_REFERENCE.md` for input-handling guidance.

Mass assignment is a real risk with DTOs. If a DTO accepts arbitrary properties and the service passes it straight to an ORM `save`, clients can set fields they should not, such as `isAdmin`. Set `whitelist: true` and `forbidNonWhitelisted: true` on the `ValidationPipe` to strip unknown properties, which guards against CWE-915 (improper modification of object attributes). The `/API_SECURITY_REFERENCE.md` covers over-posting in detail.

Authentication and authorization run through guards. A guard that reads a JWT and populates the request user is the standard pattern, often with role checks in a second guard. Weak or absent guards cause CWE-287 (improper authentication); treat every route as protected unless explicitly marked public.

JWT handling needs care. Verify the signature with a known algorithm and reject tokens whose `alg` header does not match, since accepting attacker-chosen algorithms is CWE-347 (improper verification of cryptographic signature). Use `@nestjs/jwt` with an explicit `algorithms` option and never trust unsigned tokens.

Nest inherits the risks of its HTTP layer. On Express, add `helmet` for security headers and configure `cors` narrowly rather than allowing all origins. CORS set to a wildcard with credentials exposes session data across sites; the `/WEB_APPLICATION_SECURITY_REFERENCE.md` describes safe origin policies. Rate limiting through `@nestjs/throttler` blunts brute-force and abuse.

Error handling can leak internals. The default exception filter returns stack traces in development mode; keep production responses generic so implementation details stay private.

## Performance and scaling

Fastify as the adapter raises request throughput over Express for JSON-heavy APIs. Switching adapters is a configuration change, not a rewrite, because controllers stay the same. Measure before and after, since serialization often dominates.

Dependency injection resolves at startup, so request-time cost is low. Providers default to singleton scope; request-scoped providers add overhead and should be used only when per-request state demands it. Avoid request scope on hot paths.

Nest scales horizontally like any Node service. Run multiple instances behind a load balancer and keep handlers stateless. For microservices, the transport adapters let one codebase expose both HTTP and message-based entry points.

## Common pitfalls

Circular dependencies between modules or providers break the injector. Use `forwardRef()` sparingly and prefer restructuring to remove the cycle. The CLI error messages name the offending token.

Forgetting to apply the `ValidationPipe` globally leaves individual routes unvalidated. Register it once in `main.ts` with `app.useGlobalPipes()` so coverage is uniform. Per-route pipes are easy to omit.

Request-scoped providers can silently slow a service. They force Nest to rebuild part of the injector per request. Confirm scope settings when latency rises unexpectedly.

Blocking the event loop inside a provider stalls the whole process. Keep CPU-heavy work in worker threads or a separate service. Node concurrency assumes handlers yield quickly.

## Resources

- The NestJS documentation
- The OWASP Node.js Security Cheat Sheet
- The OWASP API Security Top 10

## Related pages

- Language: [TypeScript](/languages/typescript.md), [JavaScript](/languages/javascript.md)
- [Software frameworks](/frameworks/README.md)
- Security references: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)
- Siblings: [Express.js](/frameworks/express.md), Fastify, [Spring Boot](/frameworks/spring-boot.md), [ASP.NET Core](/frameworks/aspnet-core.md)
