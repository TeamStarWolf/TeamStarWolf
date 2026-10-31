# Express.js

Express.js is a minimal, unopinionated web framework for Node.js. It provides routing and a middleware pipeline over the built-in HTTP server, and leaves most other choices to the developer. Express is the base layer under many higher-level Node frameworks. It is written in JavaScript and used widely with TypeScript.

## Overview and history

TJ Holowaychuk released Express in 2010, inspired by the Sinatra framework. It became the de facto standard web layer for Node.js. The project is now maintained under the OpenJS Foundation.

Express stays small by design. It does not bundle an ORM, a template engine, or built-in security defenses. You assemble those from the npm ecosystem, which gives flexibility and places more responsibility on the developer.

## Architecture

An Express application is an ordered chain of middleware functions. Each function receives the request, the response, and a `next` callback. A function either ends the request by sending a response or calls `next` to pass control along the chain.

Routing is itself middleware. Route handlers match a method and path, then run the handler functions registered for them. Router instances group related routes into mountable units.

Errors flow to error-handling middleware, which takes four arguments starting with the error. Because order matters, placement of middleware and routes determines behavior. This explicit model is simple but easy to misconfigure.

## Routing, data, and key subsystems

Routes bind an HTTP method and path pattern to one or more handlers. Path parameters such as `/users/:id` populate `req.params`. Query strings populate `req.query`, and parsed bodies populate `req.body` once a body parser runs.

The `req` object exposes the incoming request, and the `res` object builds the response. Methods such as `res.json`, `res.send`, and `res.status` write output. Body parsing uses the built-in `express.json` and `express.urlencoded` middleware.

Express integrates with templating engines such as EJS and Pug through the view layer. Persistence is external: common choices include the Prisma or Sequelize ORMs and the MongoDB driver. Express supplies the hooks under frameworks such as NestJS, which runs on Express by default.

## A minimal example

```javascript
const express = require('express');
const app = express();

app.get('/users/:id', (req, res) => {
  res.json({ id: req.params.id });
});

app.listen(3000);
```

## Ecosystem and tooling

The npm registry supplies most functionality. Common middleware includes `morgan` for logging, `cors` for cross-origin rules, and `cookie-session` or `express-session` for sessions. TypeScript users add `@types/express` for type definitions.

Testing uses runners such as Jest or Mocha with `supertest` for HTTP assertions. Process managers such as `pm2` and container runtimes handle deployment. Validation libraries and security middleware fill the gaps the core leaves open.

## Security model and common vulnerabilities

Express provides no security defenses by default. Every protection is opt-in, so an application is only as safe as the middleware you add. Treat the checklist below as required, not optional. See `/WEB_APPLICATION_SECURITY_REFERENCE.md`.

Use `helmet` to set security response headers, including a content security policy that limits cross-site scripting (CWE-79). Escape or encode any user data rendered into HTML templates. Set cookies as `httpOnly`, `secure`, and `sameSite` to reduce token theft and cross-site request forgery.

Express has no built-in CSRF protection. Add a double-submit cookie pattern or a maintained CSRF middleware for state-changing routes that use cookie sessions (CWE-352). Token-based APIs that never rely on cookies have a different threat model.

Injection is a core risk. Use parameterized queries or an ORM to avoid SQL injection (CWE-89), and avoid building queries by string concatenation. NoSQL injection (CWE-943) occurs when request objects reach query filters, letting operators such as `$gt` pass through, so validate and coerce input types. `/SECURE_CODING_REFERENCE.md` and `/API_SECURITY_REFERENCE.md` cover query safety and API authorization.

Body parsers can enable prototype pollution when attacker keys such as `__proto__` reach object merges (CWE-1321). Validate input against a schema with a library such as `zod` or `joi`, and avoid unsafe deep-merge of request data. Add rate limiting with `express-rate-limit` to blunt brute force and denial of service. User-supplied values in route patterns and regular expressions can trigger regular-expression denial of service (CWE-400), so avoid untrusted input in patterns and cap request sizes.

## Performance and scaling

Node runs on a single-threaded event loop, so blocking work starves all requests. Keep handlers asynchronous and move CPU-bound work to worker threads or separate services. Avoid synchronous file and crypto calls on the request path.

Scale across cores with the `cluster` module or a process manager, and scale out with stateless instances behind a load balancer. Store sessions in a shared backend such as Redis rather than in process memory. Enable gzip or brotli compression at the proxy layer.

## Common pitfalls

Skipping input validation is the root of most Express vulnerabilities. Add schema validation at the boundary. Forgetting error-handling middleware lets rejections crash the process or leak stack traces.

Middleware order bugs cause silent failures, such as reading `req.body` before the parser runs. Trusting `req.body` shape invites prototype pollution and NoSQL injection. Leaving `helmet`, CORS rules, and rate limiting out ships an application with no baseline defenses.

## Resources

- The Express documentation and its Security Best Practices page
- OWASP Node.js Security Cheat Sheet
- OWASP Cheat Sheet Series
- OWASP Top 10

## Related pages

- `/languages/javascript.md`
- `/languages/typescript.md`
- `/frameworks/README.md`
- `/SECURE_CODING_REFERENCE.md`
- `/WEB_APPLICATION_SECURITY_REFERENCE.md`
- `/API_SECURITY_REFERENCE.md`
- `/frameworks/nestjs.md`
- `/frameworks/fastapi.md`
