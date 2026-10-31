# SystemVerilog

SystemVerilog is a hardware description and verification language standardized by the IEEE as IEEE 1800. It extends Verilog with stronger types, object-oriented features, assertions, and constrained-random verification, so one language covers both designing hardware and building the testbenches that verify it. First released in 2005 and merged with the Verilog standard in 2009, it is the common language for register-transfer-level design and for verification environments built on the Universal Verification Methodology (UVM).

| Attribute | Value |
|---|---|
| Paradigm | Concurrent hardware description plus object-oriented, constrained-random verification |
| Typing | Static; adds two-state and strong types, enums, structs, and classes on top of Verilog |
| First appeared | 2005 (IEEE 1800; merged Verilog in 2009) |
| Memory model | Hardware model for design; garbage-collected class objects in the verification (testbench) layer |
| Reference standard / toolchain | [IEEE 1800](https://standards.ieee.org/ieee/1800/7743/); simulators VCS, Questa, Xcelium; partial support in [Verilator](https://www.veripool.org/verilator/) |
| Typical uses | FPGA and ASIC design, functional verification, assertion-based verification |
| Governance | [IEEE Standards Association](https://standards.ieee.org/) (IEEE 1800 working group) |

Related: [Verilog](/languages/verilog.md), [VHDL](/languages/vhdl.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

SystemVerilog started as donations to the Accellera standards group, building on the Superlog language and the OpenVera and PSL assertion work. The IEEE published it as IEEE 1800-2005, and the 2009 revision merged the IEEE 1364 Verilog standard into IEEE 1800, making SystemVerilog a single standard that contains Verilog. Later revisions appeared in 2012, 2017, and 2023.

The language serves two audiences from one base. Designers use the synthesizable subset, which is Verilog plus conveniences such as `logic`, `always_ff`, and `always_comb`. Verification engineers use the testbench features: classes, randomization, functional coverage, and assertions, which are not synthesized but run in simulation to drive and check a design.

## Paradigm and type system

For design, SystemVerilog keeps Verilog's concurrent model and adds a stronger type layer. The `logic` type replaces the ambiguous `reg`/`wire` choice in most places, `always_ff`, `always_comb`, and `always_latch` state the designer's intent so tools can check it, and `enum`, `struct`, and `union` give structured data.

For verification, the language adds a dynamic, object-oriented layer. Classes support inheritance and polymorphism, objects are created at run time and reclaimed by the simulator's garbage collector, and `rand`/`randc` members with `constraint` blocks generate constrained-random stimulus. Dynamic arrays, queues, and associative arrays model flexible test data.

```systemverilog
typedef enum logic [1:0] { IDLE, RUN, DONE } state_t;

class Packet;
  rand bit [7:0] addr;
  rand bit [7:0] data;
  constraint valid_addr { addr inside {[0:127]}; }
endclass
```

## Toolchain and ecosystem

- Simulation: Synopsys VCS, Siemens Questa, and Cadence Xcelium support the full language including the verification layer; [Verilator](https://www.veripool.org/verilator/) supports a growing synthesizable and assertion subset for fast cycle-based simulation.
- Synthesis: vendor and ASIC tools (Vivado, Quartus, Synopsys Design Compiler, open-source [Yosys](https://yosyshq.net/yosys/) with plugins) accept the synthesizable subset.
- Verification: the [UVM](https://www.accellera.org/downloads/standards/uvm) class library structures reusable testbenches; it is itself written in SystemVerilog.
- Linting and style: [Verible](https://github.com/chipsalliance/verible) and commercial linters check style and catch design mistakes.

```bash
verilator --lint-only --sv design.sv
# A full-featured simulator is typically invoked through a vendor flow
```

## Syntax tour

```systemverilog
module counter (
  input  logic       clk,
  input  logic       reset,
  output logic [7:0] count
);
  // always_ff states sequential intent; tools flag accidental latches
  always_ff @(posedge clk) begin
    if (reset)
      count <= '0;
    else
      count <= count + 1'b1;
  end
endmodule

// An immediate assertion checks a condition during simulation
module checker (input logic clk, input logic [7:0] count);
  // Concurrent assertion: count must never reach 255 while enabled
  assert property (@(posedge clk) count != 8'hFF)
    else $error("counter overflowed");
endmodule
```

## Idioms and different approaches

- Use `logic` instead of `reg`/`wire`, and `always_ff`/`always_comb`/`always_latch` instead of bare `always`, so the tool checks that the hardware matches the stated intent.
- Keep a firm line between the synthesizable design subset and the verification subset; classes, randomization, and dynamic arrays belong in testbenches, not in synthesized modules.
- Build verification environments on UVM rather than ad hoc testbenches for anything reused across blocks.
- Write properties as SystemVerilog Assertions (SVA) to capture protocol rules once and check them in simulation and formal tools alike.
- Use `interface` constructs to bundle related signals and reduce port-list errors.

## Design principles

SystemVerilog was designed to unify design and verification in one language so teams did not maintain separate tools and languages for each. The design additions make a designer's intent explicit and checkable; the verification additions bring software-engineering constructs (classes, constrained randomization, coverage) to the problem of exercising a design thoroughly. Assertions let specification rules live in the code and be checked continuously rather than in separate documents.

## Standard library and notable packages

The language's reusable layer is the verification methodology rather than a general standard library. [UVM](https://www.accellera.org/downloads/standards/uvm) provides base classes for test components, sequences, drivers, monitors, and scoreboards, plus a configuration and factory mechanism. Built-in system tasks (`$display`, `$finite`, `$urandom`, `$assertoff`, and others) and the assertion and coverage constructs are part of the language. Design reuse is by source, packages (`package`/`import`), and shared IP (intellectual property) blocks.

## Testing and packaging

Verification is the language's second purpose, so testing is first-class: constrained-random stimulus, functional coverage to measure what has been exercised, and assertions to check behavior. There is no software-style registry; reuse is by source files, SystemVerilog `package`s, and IP blocks, with UVM as the structuring convention.

```systemverilog
class Driver;
  task run(virtual dut_if vif);
    Packet p = new();
    assert (p.randomize());   // generate a constrained-random packet
    vif.addr <= p.addr;
    vif.data <= p.data;
  endtask
endclass
```

## Performance and concurrency

Hardware is concurrent, and SystemVerilog models it directly, so performance has two faces as with the other hardware description languages.

- Simulation speed depends on the simulator and what the testbench uses: constrained-random and class-based environments add run-time overhead, and functional coverage collection costs time, so regressions are planned around simulator throughput. Verilator's compiled approach is fast for the synthesizable and assertion subset but does not run the full dynamic verification layer.
- Synthesis results, the real circuit's clock frequency, area, and power, come from the synthesis and place-and-route tools on the synthesizable subset, not from the language.

Simulation and synthesis can still diverge. The `always_ff`/`always_comb` forms exist precisely so tools can warn when code would synthesize to something other than the designer intended. Treat the verified artifact as the netlist, and run gate-level and formal checks for high-assurance parts.

## Common pitfalls

- Writing non-synthesizable constructs (classes, dynamic arrays, `fork`/`join` in odd places) inside a design module; keep those in the testbench.
- Assuming two-state types (`bit`) behave like four-state (`logic`) during reset and on uninitialized nets; `x` values can be masked by two-state optimization.
- Incomplete constraints that let randomization produce illegal stimulus, or over-constraints that silently exclude cases, so coverage looks done when it is not.
- Confusing an immediate assertion (checked once, procedurally) with a concurrent assertion (checked on a clock); they fire differently.
- Relying on simulator-specific support; tools differ in which SystemVerilog features they accept, especially the newer ones.

## Secure coding

SystemVerilog describes hardware and the tests that check it, so the secure-coding focus is trust, the simulation-to-synthesis gap, and verification gaps that let flawed hardware pass:

- Simulation-versus-synthesis mismatch: code that simulates correctly can synthesize differently through latch inference or non-synthesizable constructs, shipping unverified hardware. Use `always_ff`/`always_comb`, lint, and run gate-level simulation of the netlist; treat unverified synthesis output as untrusted. This correctness-and-trust gap relates to hardware-behavior weaknesses such as [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html).
- Verification gaps as a security risk: incomplete constraints or coverage can leave security-relevant states (debug modes, privilege transitions) unexercised, so a flaw reaches silicon unseen. Treat security properties as assertions and track their coverage.
- Hardware trojans and supply chain: third-party IP, verification IP, and the tools themselves can carry hidden logic; verify provenance and simulate third-party blocks. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Debug access and hardcoded secrets: JTAG and scan paths left enabled expose internal state, and keys written into RTL become fixed in silicon, matching [CWE-798](https://cwe.mitre.org/data/definitions/798.html); gate debug access and provision secrets outside the source.

Tooling: run [Verible](https://github.com/chipsalliance/verible) or a commercial linter and heed synthesis warnings as a first pass; use assertion-based and formal verification for security properties, and formal equivalence checking between RTL and netlist. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [IEEE 1800 standard](https://standards.ieee.org/ieee/1800/7743/), the formal definition.
- [UVM](https://www.accellera.org/downloads/standards/uvm) from Accellera, for the verification methodology.
- [Verilator](https://www.veripool.org/verilator/) and [Verible](https://github.com/chipsalliance/verible) documentation, for open-source simulation and linting.

## Related pages

- [Verilog](/languages/verilog.md)
- [VHDL](/languages/vhdl.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
