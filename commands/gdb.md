# GDB Command Reference

GDB, the GNU Debugger, inspects a running program or a crashed one. It can start a process under control, stop it at breakpoints, step line by line, read and change memory and registers, and analyze core dumps after a crash. Developers use it to find bugs; security engineers use it for crash triage and authorized exploit development. This page covers the commands that cover both.

<!-- meta:start (written by scripts/build_doc_meta.py from data/doc_meta.yaml; do not edit) -->

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Who this is for</th><td>

Developers, reverse engineers and exploit developers who debug compiled programs

</td></tr>
<tr><th scope="row" align="left" valign="top">Level</th><td>

Intermediate

</td></tr>
<tr><th scope="row" align="left" valign="top">Reading time</th><td>

About 5 min (1,065 words at 230 words a minute)

</td></tr>
<tr><th scope="row" align="left" valign="top">Read this when</th><td>

You need the GDB commands for a task at hand, you want a common workflow to copy and adapt, you are looking up a flag or option worth knowing, or you need the security notes that go with them

</td></tr>
<tr><th scope="row" align="left" valign="top">Start at</th><td>

[Core commands](#core-commands), [Common workflows](#common-workflows), [Security notes](#security-notes)

</td></tr>
</table>

<details class="tsw-meta-more"><summary>More about this page (pairs with, last reviewed)</summary>

<table class="tsw-meta-card">
<tr><th scope="row" align="left" valign="top">Pairs with</th><td>

[Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [Metasploit Framework Reference](/commands/metasploit.md), [Linux Command Reference](/commands/linux-commands.md), [Vim Command Reference](/commands/vim.md)

</td></tr>
<tr><th scope="row" align="left" valign="top">Last reviewed</th><td>

No review recorded yet

</td></tr>
</table>

</details>

<!-- meta:end -->

## What it is and where it runs

GDB debugs programs written in C, C++, and other compiled languages. It runs on Linux and other Unix-like systems and understands the standard ELF and DWARF debug formats; compile with `-g` to get symbols and source-level debugging. Start it with `gdb ./program`, attach it to a running process, or point it at a core file. On macOS, `lldb` fills a similar role, and `gef`, `pwndbg`, and `peda` are common GDB extensions for low-level analysis.

## Core commands

### Starting and controlling execution

```
run [args]      start the program (alias r)
start           run and stop at main
continue        resume after a stop (alias c)
kill            stop the running program
```

| Command | Action |
| --- | --- |
| `step` / `s` | Execute one source line, entering calls |
| `next` / `n` | Execute one source line, stepping over calls |
| `stepi` / `si` | Execute one machine instruction |
| `finish` | Run until the current function returns |
| `until` | Run until a line past the current one |

### Breakpoints and watchpoints

```
break main          break at a function (alias b)
break file.c:42     break at a line
tbreak main         one-shot (temporary) breakpoint
watch var           stop when var changes
```

| Command | Action |
| --- | --- |
| `info breakpoints` | List breakpoints and watchpoints |
| `delete N` | Remove breakpoint N |
| `disable N` / `enable N` | Toggle a breakpoint |
| `condition N expr` | Break only when `expr` is true |
| `rwatch var` | Stop when `var` is read |

### Inspecting state

```
print expr      show a value (alias p)
p/x var         print in hexadecimal
backtrace       show the call stack (alias bt)
bt full         call stack with local variables
```

| Command | Action |
| --- | --- |
| `info registers` | All register values |
| `info locals` | Local variables in the current frame |
| `info args` | Arguments to the current function |
| `frame N` | Select stack frame N |
| `list` | Show source around the current line |

### Examining memory and code

The `x` command examines memory with a count, format, and size, as in `x/16xw $sp` to show sixteen hexadecimal words from the stack pointer.

```
x/8xb &buf          8 bytes in hex
x/s ptr             a C string
x/16i $pc           16 instructions at the program counter
disassemble main    disassemble a function
```

### Changing state

```
set var count = 0       assign to a variable
set $rax = 0x1          assign to a register
return                  force the current function to return
call func(arg)          invoke a function in the inferior
```

### Attach, detach, and core files

```
gdb -p 1234             attach by PID at launch
attach 1234             attach from inside gdb
detach                  release the process, leaving it running
gdb ./prog core         open a core dump
core-file core          load a core after starting gdb
```

### TUI mode

The text user interface shows source, assembly, and registers alongside the command line. Toggle it with `Ctrl-x a`, or start with `gdb -tui`. `layout src`, `layout asm`, and `layout regs` pick a view; `Ctrl-x o` switches the active window.

## Common workflows

### Find why a program crashes

Run under GDB, let it stop at the fault, and read the stack.

```
gdb ./app
run
# program hits a segfault
bt full
info registers
list
```

### Analyze a core dump after the fact

Open the saved core and inspect the state at the crash.

```
ulimit -c unlimited       enable core dumps in the shell first
./app                     crashes, writes a core file
gdb ./app core
bt
frame 1
info locals
```

### Watch a value change

Stop the moment a variable is modified to catch unexpected writes.

```
gdb ./app
break main
run
watch global_counter
continue
# stops when global_counter changes, showing old and new values
```

### Inspect a crash at the instruction level

Step through machine code with registers and memory in view.

```
gdb -tui ./app
layout asm
break *0x4011a6
run
stepi
x/16xw $sp
info registers rax rbx rsp rip
```

## Flags and options worth knowing

| Flag | Effect |
| --- | --- |
| `gdb ./prog` | Load a program for debugging |
| `gdb -p PID` | Attach to a running process |
| `gdb ./prog core` | Open a program with its core dump |
| `gdb -tui` | Start in TUI mode |
| `gdb -batch -ex "..."` | Run commands non-interactively and exit |
| `gdb -x script.gdb` | Run commands from a script file |
| `gdb --args ./prog a b` | Pass program arguments on the command line |

Set `set pagination off` and `set confirm off` in a `~/.gdbinit` or script to keep batch runs from stopping for prompts.

## Security relevance

This section is the threat-facing view of GDB and where it sits in vulnerability research; authorized use only is assumed. The authorization, ASLR, and secret-handling guidance for safe use is in the "Security notes" section that follows.

### Where it appears

- Crash triage. After a fuzzer or a report produces a fault, GDB shows the faulting instruction, registers, and stack so a researcher can decide whether the crash is exploitable.
- Exploit development. Examining memory layout, controlling the instruction pointer, and building ROP chains all happen under a debugger before a working proof of concept exists.
- Reverse engineering. Dynamic analysis of a closed binary or a malware sample, with disassembly and single-stepping, complements static review.
- Defensive research. The same workflow verifies that a patch removes the faulty code path.

### Dominant weakness classes

Unlike most tools here, GDB's whole subject is memory corruption: it is the lens through which these classes are studied.

- Stack-based buffer overflow ([CWE-121](https://cwe.mitre.org/data/definitions/121.html)).
- Heap-based buffer overflow ([CWE-122](https://cwe.mitre.org/data/definitions/122.html)).
- Use after free ([CWE-416](https://cwe.mitre.org/data/definitions/416.html)).
- Out-of-bounds write ([CWE-787](https://cwe.mitre.org/data/definitions/787.html)).

### Why it matters

Dynamic debugging is how a researcher proves a crash is a controllable vulnerability rather than a benign fault, and how a reliable exploit is built or a sample's behavior is understood. That evidence drives both offensive proof of concept and the defensive fix. See [the exploit development reference](/EXPLOIT_DEVELOPMENT_REFERENCE.md) and [the reverse engineering reference](/REVERSE_ENGINEERING_REFERENCE.md).

## Security notes

GDB is a legitimate tool for debugging, crash and core analysis, reverse engineering, and exploit development within authorized testing and research. Use it only on software you own or have written permission to analyze. Attaching to a process reads and can alter its memory, so attach only to processes you are authorized to inspect; unauthorized attachment or memory tampering can violate policy and law, and relates to CWE-863 (incorrect authorization). The kernel's `ptrace` scope (`/proc/sys/kernel/yama/ptrace_scope`) governs which processes you may attach to and exists to limit this.

Address space layout randomization (ASLR) and position-independent executables (PIE) move code and data to different addresses on each run, so addresses you observe in one session will not match the next. GDB disables ASLR for its child by default; `set disable-randomization on` (the default) keeps addresses stable for analysis, and `set disable-randomization off` reproduces the randomized production layout. Do not carry a hardcoded address from a debugging session into any assumption about a live process, and remember that disabling these mitigations is for analysis only, never a configuration to ship. Overreliance on fixed addresses connects to CWE-121 (stack-based buffer overflow) research where defeating these protections is the point of study.

Core dumps and the memory of an attached process can contain secrets: passwords, keys, tokens, and personal data held in buffers at the time of capture. Treat a core file as sensitive. Store it with restrictive permissions, do not commit it to a repository, and delete it when the analysis is done. On shared hosts, a world-readable core is an information-exposure problem under CWE-532. See `/SECURE_CODING_REFERENCE.md` for handling of secrets and sensitive artifacts.

## Resources

- The GDB manual, "Debugging with GDB", from the GNU Project
- The `gdb` man page, `man gdb`
- The in-tool help system, reached with `help` and `help {command}`
- "The Art of Debugging with GDB, DDD, and Eclipse" by Norman Matloff and Peter Jay Salzman

## Related pages

- [Command reference](/commands/README.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Metasploit Framework Reference](/commands/metasploit.md)
- [Linux Command Reference](/commands/linux-commands.md)
- [Vim Command Reference](/commands/vim.md)
