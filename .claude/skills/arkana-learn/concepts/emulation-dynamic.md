# Concept Reference: Emulation & Dynamic Analysis

Advanced tier reference for Module 3.2. This file is drawn from by the teaching
skill during guided analysis — it is not shown directly to learners.

---

## Core Concept

Emulation executes binary code in a controlled, instrumented environment rather
than on real hardware with a real operating system. The binary "thinks" it is
running normally, but every instruction, memory access, and API call passes
through the emulation engine, giving the analyst full visibility and control
without any risk of the malware actually performing its intended actions.

### Emulation vs Real Execution

| Aspect | Emulation | Real execution (sandbox/VM) |
|---|---|---|
| Side effects | None — all I/O is simulated | Real — files created, network traffic sent |
| Control | Instruction-level, pause/inspect anywhere | Process-level, limited introspection |
| Fidelity | Approximate — not all APIs supported | Full — real OS handles everything |
| Speed | Slower (interpreting each instruction) | Native speed |
| Safety | Completely safe | Requires isolation (VM, network segmentation) |
| Best for | Targeted analysis of specific functions | Full behavioural observation |

Key teaching point: emulation trades fidelity for control. You will not get a
perfect reproduction of the binary's behaviour, but you can inspect and
manipulate every detail of what the emulator does simulate.

## Emulation Engines in Arkana

### Qiling Framework

Qiling is a cross-platform binary emulation framework built on Unicorn Engine.
It emulates the CPU and provides OS-level abstractions (file system, registry,
network) through a rootfs — a directory structure that mimics the target OS.

**Strengths**:
- Cross-platform: supports Windows, Linux, macOS, and more
- Full API hooking: intercept any OS call with custom Python handlers
- Memory inspection: read/write any address at any point during emulation
- Rootfs support: provides DLLs and system files the binary expects to find
- Trace execution: log every API call with arguments and return values

**When to use**: Runtime behaviour analysis, unpacking (execute to OEP and dump),
API call tracing, memory search for decrypted data, shellcode analysis.

```
Tool: emulate_binary_with_qiling()

Example output:
  Emulation started at entry point 0x00401000
  API calls traced:
    VirtualAlloc(0, 0x10000, MEM_COMMIT, PAGE_READWRITE) => 0x00500000
    memcpy(0x00500000, 0x00403000, 0x8000)
    VirtualProtect(0x00500000, 0x8000, PAGE_EXECUTE_READ, &old)
  Emulation completed: 45,231 instructions executed
```

```
Tool: qiling_hook_api_calls(hooks=["VirtualAlloc", "WriteProcessMemory"])

Provides custom interception of specific API calls, logging arguments and
return values for targeted monitoring.
```

```
Tool: qiling_memory_search(pattern="http")

Searches the emulator's memory space after execution completes — ideal for
finding decrypted strings, unpacked code, or C2 URLs that only exist at runtime.
```

```
Tool: qiling_trace_execution()

Detailed trace of all API calls during emulation, providing a complete
behavioural timeline.
```

### Interactive Debugger (Persistent Qiling)

The interactive debugger is a persistent Qiling subprocess that survives across
multiple MCP calls. Unlike the fire-and-forget tools above (which run to
completion and return all results at once), the debugger lets you start
emulation, pause at breakpoints, inspect registers and memory, modify state,
and resume — exactly like using a real debugger (GDB, x64dbg) but within the
emulation environment.

**How it differs from fire-and-forget Qiling**:

| Aspect | Fire-and-forget | Interactive debugger |
|---|---|---|
| State persistence | Gone after tool returns | Persists across MCP calls |
| Control granularity | Run to completion | Step, breakpoint, continue |
| Input handling | Pre-configured args only | Queue input mid-execution |
| Memory inspection | Only via qiling_memory_search after | Read any address at any point |
| API monitoring | Full trace returned at end | Filter and query trace incrementally |
| State comparison | Not possible | Snapshot save/restore/diff |

**I/O stubs**: By default (`stub_io=True`), the debugger hooks Win32 console
APIs (GetStdHandle, WriteConsoleA/W, ReadConsoleA, SetConsoleMode, etc.) so that
printf, cout, cin, and similar calls work without crashing the emulator on
unmapped memory. Output text is captured and retrievable. Input can be queued
before the binary tries to read it.

**API tracing**: All Windows API calls are logged automatically with their
arguments and return values. You can query the trace with a filter (e.g.,
`filter="Crypt"` to see only crypto-related calls) or set a whitelist to limit
what gets recorded.

**Memory search**: After stepping through code (e.g., past a decryption loop),
search all mapped memory for strings (UTF-8 and UTF-16LE) or hex byte patterns
(with `??` wildcards for unknown bytes).

**Snapshots**: Save the full emulation state at any point, restore it later, or
diff two snapshots to see exactly what changed (registers and memory) between
two execution points.

```
Workflow: Stepping through a decryption function

1. debug_start(file_path="/samples/malware.exe")
   → Session created, paused at entry point 0x00401000

2. debug_set_breakpoint(address="0x00401500")
   → Breakpoint set at the decryption function

3. debug_set_input(text="password123")
   → Input queued for when the binary reads from console

4. debug_continue()
   → Hit breakpoint at 0x00401500
   → API trace shows: GetStdHandle, ReadConsoleA (consumed "password123")

5. debug_snapshot_save(name="before_decrypt")
   → State saved

6. debug_step_over()  (repeat several times or debug_run_until)
   → Steps through the decryption logic

7. debug_snapshot_save(name="after_decrypt")
8. debug_snapshot_diff(name_a="before_decrypt", name_b="after_decrypt")
   → Shows which memory regions changed (the output buffer)

9. debug_read_memory(address="0x00500000", length=256)
   → Read the decrypted data from the output buffer

10. debug_search_memory(pattern="http", pattern_type="string")
    → Find any decrypted URLs in memory

11. debug_get_output()
    → Read any text the binary printed to console

12. debug_stop()
    → Session ended
```

```
Tool: debug_get_api_trace(filter="VirtualAlloc")

Returns only API trace entries matching the filter. Example output:
  entries:
    - type: ENTER, api: VirtualAlloc, args: [0, 65536, 0x3000, 0x40]
    - type: EXIT, api: VirtualAlloc, return_value: 0x00500000
  total_entries: 2
  filter_applied: "VirtualAlloc"
```

### Speakeasy (Windows PE Emulation)

Speakeasy is a Windows-focused emulator designed specifically for PE analysis.
It simulates Windows APIs at a higher level than Qiling, providing realistic
return values for common API patterns without needing a rootfs.

**Strengths**:
- Windows API simulation: handles hundreds of common Windows APIs out of the box
- Lighter weight: no rootfs directory required
- PE-aware: understands PE loading, imports, TLS callbacks, DLL dependencies
- Shellcode support: can emulate raw shellcode with a simulated environment

**When to use**: Quick PE behavioural analysis when you want API-level behaviour
without the overhead of setting up a full Qiling rootfs. Particularly good for
Windows-specific malware that makes heavy use of Win32 APIs.

```
Tool: emulate_pe_with_windows_apis()

Example output:
  Entry point: 0x00401000
  TLS callbacks executed: 1
  API trace:
    GetModuleHandleA("kernel32.dll") => 0x7FFE0000
    GetProcAddress(0x7FFE0000, "VirtualAlloc") => 0x7FFE1234
    VirtualAlloc(0, 0x5000, 0x3000, 0x40) => 0x00600000
    CreateFileA("C:\\config.dat", ...) => 0x80
    ReadFile(0x80, 0x00600000, 0x5000, ...) => TRUE
```

### angr Emulation (Symbolic Execution)

angr provides symbolic execution — instead of running with concrete values, it
uses symbolic variables and constraint solving to explore multiple execution
paths simultaneously. This is fundamentally different from Qiling/Speakeasy.

**Strengths**:
- Path exploration: can explore all possible execution paths, not just one
- Constraint solving: find inputs that satisfy specific conditions
- Target-directed: "find me an input that reaches address X"
- Function-level: can emulate individual functions with symbolic arguments

**When to use**: Finding inputs that trigger specific code paths (reaching a
decryption routine, bypassing a license check), exploring all branches of a
command dispatcher, understanding what conditions lead to specific behaviour.

```
Tool: find_path_to_address(target_address)

Example: "Find an input that reaches the decryption function at 0x00401500"
Result:
  Path found! Input constraints:
    argv[1][0] == 0x41  ('A')
    argv[1][1] == 0x42  ('B')
    argv[1][2:6] == "KEY1"
  Input that reaches target: "ABKEY1"
```

```
Tool: emulate_function_execution(function_address, args)

Emulates a single function with concrete arguments. Useful for testing what
a decryption function produces with known inputs.
```

```
Tool: emulate_with_watchpoints(watchpoints)

Sets memory or register watchpoints that trigger during emulation, reporting
when specific addresses are read, written, or executed.
```

## Choosing the Right Engine

| Task | Recommended engine | Why |
|---|---|---|
| Full runtime API trace | Qiling or Speakeasy | Need API simulation |
| Quick PE behaviour check | Speakeasy | Lighter, no rootfs needed |
| Shellcode analysis | Qiling or Speakeasy | Both support raw shellcode |
| Find decrypted data in memory | Qiling (`qiling_memory_search`) | Best memory inspection |
| Unpack to OEP and dump | Qiling (`qiling_dump_unpacked_binary`) | Full memory dump support |
| Find input that reaches target | angr (`find_path_to_address`) | Symbolic execution required |
| Test a single function | angr (`emulate_function_execution`) | Function-level emulation |
| Monitor specific memory writes | angr (`emulate_with_watchpoints`) | Watchpoint support |
| Cross-platform (ELF) analysis | Qiling | Multi-platform support |
| Step through code instruction by instruction | Debugger (`debug_start` + `debug_step`) | Persistent state, pause/resume |
| Supply stdin input during emulation | Debugger (`debug_set_input`) | I/O stubs queue input for ReadConsole |
| Compare state before/after a call | Debugger (`debug_snapshot_diff`) | Save and diff emulation snapshots |
| Inspect memory at arbitrary points | Debugger (`debug_read_memory`) | Read any mapped address mid-execution |
| Search for decrypted data mid-execution | Debugger (`debug_search_memory`) | Search while paused, before data is overwritten |
| Fire-and-forget crashed, need control | Debugger (`debug_start` with breakpoints) | Step past crash point manually |

## Socratic Questions

- "We can see the decryption function in the decompiler, but we do not know the
  key. How could we get the decrypted output without finding the key ourselves?"
  (Leads to: emulate the function and read the result from memory)
- "The binary checks for a debugger before decrypting its config. How can we
  get past this check without modifying the binary?"
  (Leads to: hook IsDebuggerPresent to return 0 during emulation)
- "We need to know which input makes the binary take the 'success' path. Testing
  every possible input would take forever. Is there a smarter approach?"
  (Leads to: symbolic execution with find_path_to_address)
- "After emulation, the API trace shows VirtualAlloc followed by large memcpy.
  What might be happening?" (Leads to: unpacking or payload staging, search
  the allocated memory for PE headers or decrypted content)
- "Fire-and-forget emulation crashed at instruction 5,000 with an unmapped read.
  We need to see what happened just before the crash. How can we get more
  control?" (Leads to: interactive debugger — set a breakpoint just before the
  crash address, inspect registers and memory, understand the root cause)
- "The binary reads a password from the console and uses it as a decryption key.
  How can we supply that password during emulation?" (Leads to: interactive
  debugger with debug_set_input to queue the password, I/O stubs handle the
  ReadConsoleA call)
- "We want to know exactly what changes in memory when the decryption function
  runs. How can we capture that difference?" (Leads to: snapshot before the
  function, step over it, snapshot after, then diff the two snapshots)
- "The malware decrypts a URL in memory but overwrites it shortly after. How
  can we catch it before it disappears?" (Leads to: set a breakpoint right
  after decryption, search memory while paused, before execution continues)

## Common Mistakes

### Expecting perfect emulation

No emulator supports every API, every edge case, or every OS quirk. Emulation
will often terminate early with "unsupported API" or "unmapped memory access."
This does not mean the analysis failed — partial results are still valuable. An
API trace that covers the first 30 API calls before crashing may reveal the
decryption routine, C2 setup, or persistence mechanism.

### Not setting execution limits

Emulation without a timeout or instruction limit can run indefinitely if the
binary enters a loop or sleep call. Always work with the default limits Arkana
sets, and examine partial results if emulation is terminated early.

### Ignoring partial results

When emulation stops early (unsupported syscall, unmapped read), the results
up to that point are still available. Check the API trace, search memory for
decrypted data, and examine the state at the point of failure. The failure
point itself is often informative — it may indicate anti-emulation checks.

### Using symbolic execution for everything

Symbolic execution is powerful but expensive. It suffers from path explosion in
complex binaries (too many branches to explore). Use it for targeted questions
("find input reaching address X") rather than full program exploration. For
general behavioural analysis, concrete emulation with Qiling or Speakeasy is
faster and more practical.

### Forgetting to search memory after emulation

The most valuable data from emulation is often not in the API trace but in
memory. After emulation completes (or even after early termination), use
`qiling_memory_search` to look for decrypted strings, URLs, IP addresses,
PE headers ("MZ"), or other indicators that only exist at runtime.

### Using the interactive debugger when fire-and-forget would suffice

The interactive debugger requires multiple MCP round-trips (start, set
breakpoints, continue, inspect, ...). If you just need a full API trace or a
memory search after execution, fire-and-forget tools (`emulate_binary_with_qiling`,
`qiling_memory_search`) are faster and simpler. Use the debugger only when you
need to pause, inspect, and resume — not as a default replacement for the
simpler tools.

### Forgetting to queue input before continuing

If the binary reads from stdin/console, it will block (or fail) if no input is
queued. Always call `debug_set_input()` before `debug_continue()` when you
know the binary expects user input. The I/O stubs consume from the input queue
in order — queue all expected inputs before running past those read points.

### Not using snapshots for experimentation

When you want to try different inputs or explore alternative code paths, use
`debug_snapshot_save()` before the branch point. If the path is a dead end,
`debug_snapshot_restore()` brings you back instantly without restarting the
entire session. This is far more efficient than stopping and restarting.
