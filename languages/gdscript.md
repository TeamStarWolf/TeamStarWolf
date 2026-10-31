# GDScript

GDScript is a dynamically typed scripting language built into the Godot game engine. Its syntax resembles Python (significant indentation, familiar keywords), but it is a separate language designed to work directly with Godot's scene and node model. Scripts attach to nodes, respond to the engine's lifecycle callbacks, and reach engine objects and signals without a binding layer. It is used mainly for game logic, tools, and prototypes inside Godot, and first shipped with the engine around 2014.

| Attribute | Value |
|---|---|
| Paradigm | Imperative, object-oriented, event-driven |
| Typing | Dynamic by default, with optional static type hints |
| First appeared | 2014 (with the public release of Godot) |
| Memory model | Automatic: reference counting for `RefCounted` objects; the engine owns the node tree |
| Reference implementation | Interpreter built into the [Godot engine](https://github.com/godotengine/godot) |
| Typical uses | Game logic, editor tools, rapid prototyping within Godot |
| Governance | [Godot Engine project](https://godotengine.org/) (community, under the Godot Foundation) |

Related: [Haxe](/languages/haxe.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

GDScript was created for Godot so that game code would integrate tightly with the engine's design rather than through a general-purpose language and a binding layer. Its Python-like surface makes it quick to read and write, and because the interpreter is part of the engine, scripts have direct access to nodes, resources, and signals with fast iteration (edit, run, see the result). GDScript 2.0, which shipped with Godot 4 in 2023, reworked the language with better optional typing, first-class functions (lambdas), and other changes, so examples written for Godot 3 may not run unchanged on Godot 4.

Godot also supports C# and a native interface for C and C++, so GDScript is the default but not the only choice. It is favored for game logic and editor tooling, where its coupling to the engine is a benefit.

## Paradigm and type system

A GDScript file defines a class (implicitly, from the file) that usually extends an engine class such as `Node`, `Node2D`, or `Resource`. Code is imperative and object-oriented, and much of it is event-driven: the engine calls lifecycle methods (`_ready`, `_process`, `_physics_process`, `_input`) and emits signals that scripts connect to.

Typing is dynamic by default: a variable can hold any type, checked at run time. Optional static type hints let you annotate variables, parameters, and return types, which the engine uses to catch mistakes earlier and to speed up some operations. Inferred typing with `:=` gives a static type without writing it out.

```gdscript
var speed: float = 200.0        # explicitly typed
var score := 0                   # inferred as int
func damage(amount: int) -> void:
    health -= amount
```

## Toolchain and ecosystem

- Editor: Godot's built-in script editor, debugger, and profiler are the primary environment; the engine and editor are one download.
- Running: scripts run inside the engine; there is no separate GDScript interpreter to install.
- Assets and plugins: the [Godot Asset Library](https://godotengine.org/asset-library/asset) distributes reusable scripts, plugins, and editor tools.
- External editors: Visual Studio Code and others work through community extensions that talk to Godot's language server.
- Formatting and linting: community tools such as [gdtoolkit](https://github.com/Scony/godot-gdscript-toolkit) provide `gdformat` and `gdlint`.

```bash
# Run a project headless (useful for tests and continuous integration)
godot --headless --path . --script res://run_tests.gd
```

## Syntax tour

```gdscript
extends Node2D

# A signal this node can emit
signal died

@export var max_health: int = 100     # shown in the editor inspector
var health: int

func _ready() -> void:
    health = max_health

func _process(delta: float) -> void:
    position.x += 100 * delta          # move right over time

func take_damage(amount: int) -> void:
    health -= amount
    if health <= 0:
        died.emit()                    # notify listeners
        queue_free()                   # remove this node safely
```

## Idioms and different approaches

- Use signals to decouple nodes: a node emits a signal and does not need to know who listens, which keeps game objects independent.
- Prefer `@onready` variables and `_ready` for setup that needs the node tree to exist, rather than running it in the constructor.
- Reach other nodes with exported `NodePath` or scene-unique names instead of hardcoding tree paths, which break when the scene changes.
- Add optional type hints to code that matters for correctness or performance; keep quick prototype code dynamic if that is faster to iterate.
- Call `queue_free()` to remove nodes rather than freeing them immediately mid-frame, which can invalidate references the engine is still using.

## Design principles

GDScript is designed to fit Godot: a small language that maps cleanly onto nodes, scenes, signals, and the engine's object model, with fast iteration and a gentle syntax so that designers and programmers can both use it. The optional typing reflects a deliberate balance, keeping the quick, dynamic feel for prototyping while letting teams tighten types where reliability or speed warrants. Being built into the engine, rather than bound to it, keeps the edit-run loop short and the integration direct.

## Standard library and notable classes

GDScript's "standard library" is the Godot engine API: the class hierarchy rooted at `Object`, with `Node` and its subclasses for the scene tree, `Resource` for saved data, and built-in types such as `Vector2`, `Vector3`, `Color`, `Transform2D`, `Array`, and `Dictionary`. Global helpers (`print`, math functions, `randi`, `lerp`) and singletons (autoloads such as `Input`, `Engine`, `OS`) round it out. Reusable code and plugins come through the Asset Library rather than a package manager, since the engine provides most of what game code needs.

## Testing and packaging

Godot does not ship a unit-test framework, so teams use community ones such as [GUT (Godot Unit Testing)](https://github.com/bitwes/Gut) or [gdUnit](https://github.com/MikeSchulze/gdUnit4), running tests through the engine, often headless in continuous integration. "Packaging" means exporting the project: Godot's export templates build runnable binaries for desktop, mobile, web, and consoles from the same project, bundling scripts and assets. There is no language-level package registry; shared code is distributed as assets or as git-tracked files.

```gdscript
# A GUT test
extends GutTest

func test_damage_reduces_health():
    var p = preload("res://player.gd").new()
    p.health = 100
    p.take_damage(30)
    assert_eq(p.health, 70)
```

## Performance and concurrency

GDScript is interpreted by the engine, so raw numeric throughput is lower than compiled C# or native code; for most game logic this is not the bottleneck, because the heavy work (rendering, physics) happens in the engine's native code. Where script-side performance matters:

- Adding static type hints lets the interpreter take faster paths and avoids some run-time type resolution.
- Hot inner loops that dominate a frame can be moved to C# or to a native extension (GDExtension), keeping GDScript for the glue.
- Per-frame work lives in `_process` and `_physics_process`; keeping those methods light and avoiding per-frame allocation prevents frame-rate dips.

For concurrency, GDScript offers coroutines through `await`, which suspends until a signal or a called coroutine completes without blocking the frame, and Godot provides threads for background work, with the caveat that most engine and scene-tree operations must happen on the main thread. The evaluation model is frame-driven: the engine calls into scripts each frame rather than scripts running a loop of their own.

## Common pitfalls

- Porting Godot 3 code to Godot 4 unchanged: GDScript 2.0 renamed methods and changed signal, `await`, and export syntax, so older snippets often need updates.
- Freeing nodes immediately (`free()`) during signal handling or iteration, which can invalidate references the engine still uses; prefer `queue_free()`.
- Hardcoded node paths that break when a scene is restructured; use exported paths or unique names.
- Heavy work in `_process` every frame, including allocations, causing stutter.
- Assuming thread safety: touching the scene tree from a background thread leads to crashes or corruption; marshal back to the main thread.

## Secure coding

GDScript runs game and tool logic inside Godot, so its security concerns are those of client-side game code and of any content a game loads:

- Loading untrusted content: `load`/`preload` and resource files can reference scripts and scenes; opening a project or resource pack from an untrusted source can run code you did not write. Treat downloaded projects, mods, and save files as untrusted, and do not load executable resources from them without review. This relates to code-inclusion weaknesses such as [CWE-494](https://cwe.mitre.org/data/definitions/494.html) (download of code without integrity check).
- Deserializing save data ([CWE-502](https://cwe.mitre.org/data/definitions/502.html)): loading a saved game that can instantiate arbitrary objects or scripts lets a crafted save run code; prefer plain data formats (`JSON`, typed dictionaries) for saves and validate their contents rather than restoring full engine objects from untrusted files.
- Network input in multiplayer: data from peers is untrusted; validate remote procedure calls and state, authorize actions server-side, and never trust a client's reported position or score. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).
- Hardcoded secrets ([CWE-798](https://cwe.mitre.org/data/definitions/798.html)): API keys or server credentials embedded in a shipped game are extractable from the exported binary; keep secrets on a server the game talks to, not in the client.

Tooling: lint with [gdtoolkit](https://github.com/Scony/godot-gdscript-toolkit) (`gdlint`) for code issues, and review any third-party assets or plugins before adding them, since they run with the game's privileges. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [Godot documentation](https://docs.godotengine.org/), including the GDScript reference and style guide.
- [GDScript basics](https://docs.godotengine.org/en/stable/tutorials/scripting/gdscript/gdscript_basics.html), the language introduction.
- [Godot Asset Library](https://godotengine.org/asset-library/asset), for reusable scripts and plugins.

## Related pages

- [Haxe](/languages/haxe.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [All languages](/languages/README.md)
