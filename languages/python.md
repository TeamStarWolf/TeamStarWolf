# Python

Python is a dynamically typed, garbage-collected, multi-paradigm language created by Guido van Rossum and first released in 1991. It favors readable syntax, significant indentation, and a large standard library, and it runs on an interpreter (the reference implementation is CPython). It is used for scripting, automation, web back ends, data analysis, machine learning, scientific computing, and security tooling.

| Attribute | Value |
|---|---|
| Paradigm | Multi-paradigm: imperative, object-oriented, functional |
| Typing | Dynamic, strong, with optional static type hints checked by external tools |
| First appeared | 1991 (Python 3 in 2008) |
| Memory model | Automatic: reference counting plus a cyclic garbage collector |
| Reference implementation | [CPython](https://github.com/python/cpython) |
| Typical uses | Automation, web, data science, machine learning, security tooling |
| Governance | [PEP process](https://peps.python.org/) under the Python Software Foundation |

Related: [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Python emerged from the ABC language and Amoeba project work at CWI in the Netherlands. The language reached a deliberate break with Python 3.0 (2008), which fixed long-standing text and integer issues at the cost of source compatibility; Python 2 reached end of life on January 1, 2020, per the [official sunset notice](https://www.python.org/doc/sunset-python-2/). Current development follows a yearly release cadence defined in [PEP 602](https://peps.python.org/pep-0602/), with each feature release supported for several years.

The language is defined by the [Python Language Reference](https://docs.python.org/3/reference/), and its evolution is governed by Python Enhancement Proposals. The reference interpreter is CPython; alternative implementations include [PyPy](https://www.pypy.org/) (a tracing just-in-time compiler), and historically Jython and IronPython for the JVM and .NET.

## Paradigm and type system

Python is dynamically typed: a name is a reference to an object, and types are checked at run time. Typing is strong, so the interpreter does not silently coerce unrelated types (adding a string to an integer raises `TypeError`). Since [PEP 484](https://peps.python.org/pep-0484/), source can carry optional type annotations that the interpreter ignores at run time but that external checkers such as [mypy](https://mypy-lang.org/) and [pyright](https://github.com/microsoft/pyright) enforce.

```python
def total(prices: list[float], tax: float = 0.0) -> float:
    return sum(prices) * (1 + tax)
```

Annotations are available at run time through the `__annotations__` attribute, which libraries such as `dataclasses` and `pydantic` read to generate behavior.

## Toolchain and ecosystem

- Interpreter: `python3` runs scripts and an interactive read-eval-print loop.
- Packaging: distributions publish to the [Python Package Index](https://pypi.org/); `pip` installs them. Dependency and environment managers include the standard-library `venv`, plus [uv](https://github.com/astral-sh/uv), [Poetry](https://python-poetry.org/), and [p-env/conda](https://docs.conda.io/) for scientific stacks.
- Project metadata lives in `pyproject.toml`, standardized by [PEP 621](https://peps.python.org/pep-0621/).
- Formatting and linting: [Black](https://black.readthedocs.io/) formats code; [Ruff](https://docs.astral.sh/ruff/) lints and formats quickly.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install requests
```

## Syntax tour

```python
# Variables and f-strings
name = "world"
print(f"hello, {name}")

# Collections
squares = [n * n for n in range(5)]          # list comprehension
lookup = {"a": 1, "b": 2}                     # dict
unique = {1, 2, 2, 3}                         # set -> {1, 2, 3}

# Functions, defaults, keyword args
def greet(who, *, excited=False):
    end = "!" if excited else "."
    return f"hi {who}{end}"

# Classes and dataclasses
from dataclasses import dataclass

@dataclass
class Point:
    x: int
    y: int

# Context managers release resources deterministically
with open("data.txt", encoding="utf-8") as fh:
    rows = fh.read().splitlines()

# Exceptions
try:
    value = int("not a number")
except ValueError as err:
    value = 0
```

## Idioms and different approaches

- Prefer iteration over index arithmetic: `for item in items` rather than `for i in range(len(items))`.
- Use comprehensions and generator expressions for transformations; reach for explicit loops when the logic has side effects or does not fit on a line.
- "Easier to ask forgiveness than permission" (`try`/`except`) is idiomatic where a check would race or duplicate work; a `if key in mapping` guard is clearer for simple membership.
- Use the standard-library `pathlib.Path` for file-system paths rather than string concatenation.
- For concurrency, pick the model that fits the workload (see Performance and concurrency below).

## Design principles

The language's stated aesthetics are collected in [PEP 20, "The Zen of Python"](https://peps.python.org/pep-0020/): readability counts, explicit is better than implicit, and there should be one obvious way to do a thing. Style conventions live in [PEP 8](https://peps.python.org/pep-0008/), which formatters encode so teams do not argue about layout.

## Standard library and notable packages

The standard library ships modules for the file system (`pathlib`, `os`), serialization (`json`, `csv`, `pickle`), concurrency (`threading`, `multiprocessing`, `asyncio`), and testing (`unittest`). Widely used third-party packages include [requests](https://requests.readthedocs.io/) for HTTP, [NumPy](https://numpy.org/) and [pandas](https://pandas.pydata.org/) for numerical and tabular data, [Django](https://www.djangoproject.com/) and [FastAPI](https://fastapi.tiangolo.com/) for the web, and [PyTorch](https://pytorch.org/) for machine learning.

## Testing and packaging

The standard library provides `unittest`; [pytest](https://docs.pytest.org/) is a common third-party runner with terse assertions and fixtures.

```python
def add(a, b):
    return a + b

def test_add():
    assert add(2, 3) == 5
```

A distributable package declares its metadata in `pyproject.toml` and builds a wheel with `python -m build`, then uploads with [twine](https://twine.readthedocs.io/).

## Performance and concurrency

CPython runs bytecode on a stack machine and, through its 3.x line, serializes bytecode execution with a global interpreter lock (GIL), so threads do not run Python bytecode in parallel. The practical consequences:

- I/O-bound work scales with `threading` or `asyncio`, because threads release the lock while waiting on I/O.
- CPU-bound work scales with `multiprocessing` (separate processes, separate locks) or by moving hot loops into C extensions, NumPy, or a just-in-time compiler.
- [PEP 703](https://peps.python.org/pep-0703/) adds an experimental build that can disable the GIL; treat it as not yet the default.

When raw speed matters, PyPy or native extensions (Cython, or bindings to C and Rust) often close the gap.

## Common pitfalls

- Mutable default arguments (`def f(x=[])`) are created once and shared across calls; use `None` and create the value inside the function.
- Late binding in closures: a lambda inside a loop captures the variable, not its value at creation; bind with a default argument.
- `==` compares value, `is` compares identity; use `is` only for singletons such as `None`.
- Floating-point arithmetic is binary; use `decimal.Decimal` for money.

## Secure coding

Language-specific risks and the safe patterns that address them:

- Code and command injection: never pass untrusted input to `eval`, `exec`, or `os.system`, and never call `subprocess` with `shell=True` on assembled strings. Pass an argument list instead, which maps to [CWE-78](https://cwe.mitre.org/data/definitions/78.html). See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Insecure deserialization: `pickle` and `yaml.load` without a safe loader execute arbitrary objects. Use `json` for untrusted data, or `yaml.safe_load`. This is [CWE-502](https://cwe.mitre.org/data/definitions/502.html).
- Dependency supply chain: pin and hash-lock dependencies, and scan them. Typosquatting on PyPI is a recurring vector; see [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Template and path handling: enable autoescaping in Jinja2 to avoid [CWE-79](https://cwe.mitre.org/data/definitions/79.html), and validate that joined paths stay within an intended root to avoid [CWE-22](https://cwe.mitre.org/data/definitions/22.html).

Tooling: [Bandit](https://bandit.readthedocs.io/) is a static analyzer for common Python security issues; [pip-audit](https://github.com/pypa/pip-audit) checks installed packages against advisory databases.

## Learning resources

- [The Python Tutorial](https://docs.python.org/3/tutorial/) and [Language Reference](https://docs.python.org/3/reference/), the primary documentation.
- [PEP index](https://peps.python.org/), the design-decision record.
- [Real Python](https://realpython.com/) tutorials for applied topics.

## Related pages

- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Web Application Security Reference](/WEB_APPLICATION_SECURITY_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
