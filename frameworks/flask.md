# Flask

Flask is a microframework for web development in Python. It provides routing, request handling, and templating, and leaves most other choices to the developer. Teams use it when they want a small core they can extend only where needed, rather than a full stack of defaults. It builds on two libraries from the same author: Werkzeug for WSGI and Jinja2 for templates.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers who build with Flask, and the reviewers and application security engineers who assess what they build

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 6 min (1,383 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You are building or reviewing a Flask application, you need its security model and common vulnerabilities before a code review, or you want to see how its architecture and ecosystem fit together

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Architecture](#architecture), [Security model and common vulnerabilities](#security-model-and-common-vulnerabilities), [Common pitfalls](#common-pitfalls)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Python](/languages/python.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [API Security Reference](/API_SECURITY_REFERENCE.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## Overview and history

Armin Ronacher released Flask in 2010, initially as an April Fools joke that became a real project. It is deliberately minimal: the core stays small, and features arrive through extensions. The Pallets Projects organization now maintains Flask and its dependencies.

Flask does not bundle an ORM, a form library, or authentication. You add those as you need them. This keeps small services lean and gives larger applications freedom to pick their own components.

The tradeoff is that Flask leaves architecture to you. Small apps fit in one file, while larger ones adopt the application factory and blueprints. That flexibility is the main reason teams choose it over an opinionated framework.

## Architecture

Flask is a WSGI application. A request from the server enters through Werkzeug, which parses it into a request object. Flask matches the URL to a view function using its URL map. The view returns a response, which Werkzeug converts back to a WSGI result.

Flask uses context objects to expose per-request state. The request context holds the incoming `request`, and the application context holds the current `app` and `g`. These are available as thread-local proxies, so view code can import `request` directly. The contexts are pushed at the start of handling and popped when the response is ready.

A view function is registered with a URL rule, usually through the `@app.route` decorator. The function returns a string, a template render, a tuple with a status code, or a response object. Error handlers and before- and after-request hooks let you run shared logic. Flask dispatches to the matching view and applies these hooks around it.

The application factory pattern wraps creation in a function that returns a configured app. This supports multiple instances, cleaner testing, and deferred extension setup. Extensions are initialized against the app inside the factory.

## Routing, data, and key subsystems

Routing maps URL rules to view functions. Rules support typed converters, such as `<int:post_id>`, and HTTP method lists. The `url_for` function builds URLs from endpoint names so links survive route changes.

Flask has no built-in data layer. Flask-SQLAlchemy is the common choice, wrapping the SQLAlchemy ORM and session for Flask. Migrations come from Flask-Migrate, which wraps Alembic. You can also use any database client directly.

Jinja2 renders templates and autoescapes HTML output. Blueprints group related routes, templates, and static files into components that register onto an app. Extensions add features: Flask-Login for sessions and user loading, Flask-WTF for forms and CSRF, and Flask-RESTful or Flask-Smorest for APIs. Middleware is standard WSGI middleware wrapped around the application.

## A minimal example

```python
from flask import Flask, render_template, abort

def create_app():
    app = Flask(__name__)

    @app.route("/articles/<int:article_id>")
    def article_detail(article_id):
        article = load_article(article_id)
        if article is None:
            abort(404)
        return render_template("article.html", article=article)

    return app
```

## Ecosystem and tooling

Packages install from PyPI with `pip` inside a virtual environment. The `flask` command runs the development server and shell, reading the app from `FLASK_APP`. Testing uses `pytest` with the built-in test client.

SQLAlchemy and Flask-SQLAlchemy cover data access, and Marshmallow handles serialization and validation. Celery runs background tasks. Gunicorn or uWSGI serves the app in production behind Nginx. `pip-audit` and Bandit check dependencies and code for known issues.

## Security relevance

This section is the threat-facing view of Flask: how it appears to an attacker or an auditor in the field, and which weakness classes shape its record. The defensive controls and the per-flaw fixes are in the "Security model and common vulnerabilities" section that follows.

### Where it appears

- Internet-facing web applications, small services, and JSON APIs. Flask is often recognizable from a `Server: Werkzeug` header, the signed session cookie format, and above all the Werkzeug interactive debugger page, a styled traceback with an in-browser console, served when `debug=True` is left on.
- Offensive interest centers on template injection and the debugger. Server-side template injection is the signature Flask finding, and tplmap automates detection and exploitation of it; Burp Suite handles manual request tampering.
- Audit and defensive tooling is general Python rather than Flask-specific: Bandit scans the source for dangerous calls such as `render_template_string` on user input, and pip-audit checks the dependency tree against the PyPA advisory database.
- The dependency surface is PyPI, since most features arrive as extensions. A compromised or typosquatted package runs with full application privilege, the pattern covered in [the supply chain security reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).

### Dominant weakness classes

Flask runs on [Python](/languages/python.md), a memory-managed language, so the dominant classes are logic and injection flaws rather than memory corruption. The fixes for each are detailed in the section below.

- Server-side template injection ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)), where `render_template_string` on attacker input evaluates template expressions and reaches Python objects, leading to code execution.
- Exposed debug mode ([CWE-94](https://cwe.mitre.org/data/definitions/94.html)), since the Werkzeug debugger console is remote code execution when reachable on a public host.
- Exposure of the signing secret ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)), because `SECRET_KEY` signs the client-side session cookie, so a leaked value lets an attacker forge sessions.
- Missing cross-site request forgery protection ([CWE-352](https://cwe.mitre.org/data/definitions/352.html)), which Flask does not enable on its own, leaving state-changing form routes open until an extension adds token checks.

### Why it matters

Flask ships almost no defaults, so an auditor treats every protection as opt-in and checks whether it was actually added rather than assuming the framework supplied it. Recognizing Flask in the field tells a tester to probe for template injection and a left-on debugger first, the two findings that turn a web bug into code execution. Bandit is the static analyzer to reach for on the source side. See [the web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md) for the cross-cutting review method.

## Security model and common vulnerabilities

Flask gives you safe defaults in a few places and leaves the rest to you and your extensions. See `/SECURE_CODING_REFERENCE.md`, `/WEB_APPLICATION_SECURITY_REFERENCE.md`, and `/API_SECURITY_REFERENCE.md` for shared guidance.

Jinja2 autoescapes HTML, which blocks most cross-site scripting (CWE-79). Rendering a template from user-controlled source text instead causes server-side template injection (CWE-1336, often classed as CWE-94 code injection). Calling `render_template_string` on attacker input lets them execute template expressions and reach Python objects. Always render fixed template files and pass untrusted data only as values.

The `SECRET_KEY` signs the session cookie. Flask sessions are client-side and signed, not encrypted, so anyone can read the contents, and a leaked key lets an attacker forge sessions. Set a long random key, keep it out of source control, and do not store secrets in the session itself.

Debug mode is dangerous in production (CWE-215). The Werkzeug debugger runs an interactive console in the browser on errors, which is remote code execution if exposed. The debugger PIN reduces but does not remove that risk, and `debug=True` must never run on a public host. Turn debug off and let a real logger record errors.

Flask does not enable CSRF protection on its own (CWE-352). Add Flask-WTF, which issues and validates a token for forms. For APIs consumed by browsers, configure CORS explicitly with Flask-CORS rather than allowing every origin. A wildcard origin with credentials defeats the browser's protections.

## Performance and scaling

Flask runs behind a WSGI server such as Gunicorn with several workers. The development server is single-threaded and for local use only. The N+1 query problem applies when using an ORM; eager-load related rows.

Cache expensive results with Flask-Caching backed by Redis. Scale horizontally by running more worker processes behind a load balancer, with the database and cache as shared state. Move slow work to Celery so requests return quickly. Async views and ASGI servers help with long-lived connections.

## Common pitfalls

Rendering templates from user input is the signature Flask vulnerability. Shipping with `debug=True` or a hardcoded `SECRET_KEY` is a frequent mistake. Forgetting CSRF protection because it is not on by default leaves forms open.

Global state and import-time side effects make testing and multiple instances harder; prefer the application factory. Circular imports between blueprints and models trip up growing projects. Allowing all CORS origins with credentials exposes authenticated endpoints.

## Resources

- Flask documentation, the official reference
- Flask Security Considerations page, the official security notes
- Jinja2 documentation, the official template reference
- OWASP Cheat Sheet Series
- OWASP Top 10

## Related pages

- [Python](/languages/python.md)
- [Frameworks index](/frameworks/README.md)
- [Secure coding reference](/SECURE_CODING_REFERENCE.md)
- [Web application security reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [API security reference](/API_SECURITY_REFERENCE.md)
- [Django](/frameworks/django.md)
- [FastAPI](/frameworks/fastapi.md)
- [Express](/frameworks/express.md)
