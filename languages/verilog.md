# Verilog

Verilog is a hardware description language for modeling, simulating, and synthesizing digital electronic systems. It was created in 1984 at Gateway Design Automation and standardized by the IEEE as IEEE 1364 in 1995. Its C-like syntax is terser than VHDL, and the same source can be simulated to verify behavior and synthesized into gates for an FPGA or ASIC. Later work folded Verilog into SystemVerilog, so new designs often target that superset, but the Verilog core remains in wide use.

| Attribute | Value |
|---|---|
| Paradigm | Concurrent hardware description; dataflow, behavioral, and structural styles |
| Typing | Static, weak: bit vectors with implicit width and sign rules |
| First appeared | 1984 (IEEE 1364 in 1995) |
| Memory model | Hardware model: nets and registers, not heap-allocated memory |
| Reference standard / toolchain | [IEEE 1364](https://standards.ieee.org/ieee/1364/3641/); simulators [Icarus Verilog](https://github.com/steveicarus/iverilog), [Verilator](https://www.veripool.org/verilator/), commercial VCS and Questa |
| Typical uses | FPGA and ASIC design, digital logic modeling, hardware verification |
| Governance | [IEEE Standards Association](https://standards.ieee.org/) (merged into IEEE 1800) |

Related: [VHDL](/languages/vhdl.md), [SystemVerilog](/languages/systemverilog.md), [Secure Coding Reference](/SECURE_CODING_REFERENCE.md), [languages index](/languages/README.md).

## Overview and history

Phil Moorby designed Verilog at Gateway Design Automation, which Cadence acquired in 1989. Cadence placed the language in the public domain, and the IEEE standardized it as IEEE 1364-1995, revised in 2001 and 2005. The 2001 revision added features such as generate blocks, signed arithmetic, and named port connections that designers rely on today.

In 2005 the IEEE also published SystemVerilog (IEEE 1800) as a superset aimed at both design and verification. The 2009 revision merged the Verilog 1364 standard into IEEE 1800, so Verilog is now formally a subset of SystemVerilog, though the name stays in common use for the classic design language.

## Paradigm and type system

A Verilog module describes concurrent hardware. Continuous assignments (`assign`) model combinational logic, and `always` blocks model either combinational or clocked logic depending on their sensitivity. The pieces run together, not in program order.

Typing is deliberately low level and weak compared with VHDL. The main data objects are nets (`wire`), which are driven continuously, and variables (`reg`, which despite the name does not always mean a register), which hold a value until reassigned. Values are bit vectors with four states (`0`, `1`, `x` unknown, `z` high-impedance). Widths and signedness follow implicit rules, and mismatches are often silently extended or truncated rather than flagged.

```verilog
wire        ready;            // single net
reg  [7:0]  count;            // 8-bit variable
localparam  WIDTH = 8;        // compile-time constant
```

## Toolchain and ecosystem

- Simulation: [Icarus Verilog](https://github.com/steveicarus/iverilog) is an open-source event-driven simulator; [Verilator](https://www.veripool.org/verilator/) compiles synthesizable Verilog to fast C++ for cycle-based simulation. Commercial options include Synopsys VCS, Siemens Questa, and Cadence Xcelium.
- Synthesis: vendor tools such as AMD/Xilinx Vivado and Intel Quartus map a synthesizable subset to a device; for ASICs, tools such as Synopsys Design Compiler and the open-source [Yosys](https://yosyshq.net/yosys/) are used.
- Waveform viewing: [GTKWave](https://gtkwave.sourceforge.net/) reads the value-change dump a simulation writes.
- Linting: [Verilator](https://www.veripool.org/verilator/) run with `--lint-only` catches width mismatches and unintended latches; [Verible](https://github.com/chipsalliance/verible) adds style checks.

```bash
iverilog -o sim counter.v tb_counter.v
vvp sim                      # run the compiled simulation
verilator --lint-only counter.v
```

## Syntax tour

```verilog
module counter (
  input  wire       clk,
  input  wire       reset,
  output reg  [7:0] count
);
  // Clocked process: a register updated on the rising edge
  always @(posedge clk) begin
    if (reset)
      count <= 8'd0;         // non-blocking assignment for sequential logic
    else
      count <= count + 1'b1;
  end
endmodule

module top;
  // Combinational logic with a continuous assignment
  wire [7:0] doubled;
  reg  [7:0] in;
  assign doubled = in << 1;
endmodule
```

## Idioms and different approaches

- Use non-blocking assignments (`<=`) in clocked `always` blocks and blocking assignments (`=`) in combinational ones; mixing them is a frequent source of simulation-versus-hardware bugs.
- Describe a register with `always @(posedge clk)` and combinational logic with `always @(*)`, which builds the sensitivity list automatically.
- Size literals explicitly (`8'd0`, `4'b1010`) so width and base are unambiguous.
- Use `parameter` and `generate` to build width- and count-parameterized modules rather than copying code.
- Keep testbench-only constructs (delays, `$display`, file reads) out of synthesizable modules.

## Design principles

Verilog was designed for fast, readable modeling of digital hardware with a syntax familiar to C programmers, trading VHDL's strict typing for brevity. The four-value logic captures the unknown and high-impedance states that real circuits exhibit during reset and on shared buses. The language favors getting a simulation running quickly, which is also why its weak typing puts more of the burden of correctness on the designer and the linter.

## Standard library and notable packages

Verilog has no package system in the software sense. System tasks and functions built into simulators (names beginning with `$`, such as `$display`, `$monitor`, `$readmemh`, and `$finish`) provide output, memory loading, and control during simulation. Reuse happens through source files and shared IP (intellectual property) blocks. Verification libraries and methodologies, including the Universal Verification Methodology (UVM), are written in SystemVerilog rather than classic Verilog.

## Testing and packaging

A testbench is a module with no ports that instantiates the design under test, drives stimulus, and checks results. Distribution is by source files and IP blocks, not a registry. The open-source [cocotb](https://www.cocotb.org/) framework lets you write testbenches in Python that drive a Verilog simulation, which many teams prefer for complex stimulus.

```verilog
module tb_counter;
  reg clk = 0, reset = 1;
  wire [7:0] count;
  counter dut (.clk(clk), .reset(reset), .count(count));

  always #5 clk = ~clk;      // 10 ns clock
  initial begin
    #20 reset = 0;
    #100;
    if (count == 8'd0) $error("counter did not advance");
    $finish;
  end
endmodule
```

## Performance and concurrency

Hardware is concurrent, and Verilog models that directly, so performance splits into two questions.

- Simulation speed is how fast a simulator runs the model on a workstation. Event-driven simulators (Icarus, Questa) schedule updates as signals change; cycle-based compiled simulators (Verilator) are much faster for synchronous designs but model only two states and the synthesizable subset.
- Synthesis results are the real circuit's clock frequency, gate count, and power, produced by the synthesis and place-and-route tools under timing constraints you supply, not by the language.

As with any hardware description language, simulation and synthesis can diverge. Blocking-versus-non-blocking misuse, incomplete sensitivity lists, and non-synthesizable constructs are classic ways to get hardware that does not match the simulation. Keep to the synthesizable subset for anything built, and confirm with gate-level simulation of the netlist.

## Common pitfalls

- Using blocking assignments (`=`) in sequential logic, or non-blocking (`<=`) in combinational logic, makes simulation disagree with the synthesized hardware.
- Incomplete sensitivity lists in `always` blocks cause missed updates in simulation; use `always @(*)` for combinational logic.
- Unintended latches appear when a combinational block does not assign an output on every branch.
- Width mismatches are silently extended or truncated; a linter catches these where the language does not.
- `reg` does not mean a hardware register by itself; what it synthesizes to depends on how it is assigned.

## Secure coding

Describing hardware carries risks that software review alone does not catch, so the focus is trust, supply chain, and the simulation-to-synthesis gap:

- Simulation-versus-synthesis mismatch: assignment-style mistakes, incomplete sensitivity lists, or non-synthesizable code can ship a circuit that differs from what was simulated and verified. Keep to the synthesizable subset, lint, and run gate-level simulation of the synthesized netlist; treat unverified synthesis output as untrusted. This correctness-and-trust gap is in the spirit of hardware-behavior weaknesses such as [CWE-1037](https://cwe.mitre.org/data/definitions/1037.html).
- Hardware trojans and supply chain: third-party IP cores, encrypted vendor blocks, and the synthesis tools themselves can carry logic that no source review reveals. Verify provenance, simulate third-party blocks, and track them as dependencies. See [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md).
- Debug and test access left active: JTAG and scan chains that remain enabled in production expose internal state and can bypass access controls; disable or gate them in shipped devices.
- Hardcoded secrets in RTL: keys written into source become fixed in silicon and extractable, matching [CWE-798](https://cwe.mitre.org/data/definitions/798.html); provision secrets at manufacture or in a secure element.

Tooling: run [Verilator](https://www.veripool.org/verilator/) in lint mode and heed synthesis-tool warnings (latch and multi-driver reports) as a first pass; use formal equivalence checking between RTL and netlist for high-assurance parts. See [Secure Coding Reference](/SECURE_CODING_REFERENCE.md).

## Learning resources

- [IEEE 1364 standard](https://standards.ieee.org/ieee/1364/3641/), the formal definition (now folded into IEEE 1800).
- [Icarus Verilog](https://github.com/steveicarus/iverilog) and [Verilator](https://www.veripool.org/verilator/) documentation, for the open-source simulators.
- [cocotb](https://www.cocotb.org/), for Python-driven testbenches.

## Related pages

- [VHDL](/languages/vhdl.md)
- [SystemVerilog](/languages/systemverilog.md)
- [Secure Coding Reference](/SECURE_CODING_REFERENCE.md)
- [Supply Chain Security Reference](/SUPPLY_CHAIN_SECURITY_REFERENCE.md)
- [All languages](/languages/README.md)
