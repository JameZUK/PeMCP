# Interactive Debugger Guide (Tier 3b)

The interactive debugger provides a persistent Qiling subprocess that survives
across MCP calls — you can start emulation, set breakpoints, step through code,
inspect state, queue input, and search memory incrementally. Unlike Tier 3
fire-and-forget tools that run to completion and return results, the debugger
lets you pause, inspect, modify, and resume at will.

## When to Use the Debugger

Use the debugger instead of fire-and-forget emulation when:
- You need to step through a decryption loop and inspect memory after each iteration
- The binary reads user input (stdin/console) and you need to supply specific values
- You want to compare state before and after a specific function call (snapshots)
- Fire-and-forget emulation crashed or stalled and you need finer control
- You want to set breakpoints at specific API calls and inspect arguments live
- You need to watch memory regions for writes (e.g., detect when a buffer is filled)

## Core Workflow

1. `debug_start(file_path)` — starts the debugger (I/O stubs enabled by default)
2. `debug_set_breakpoint(address)` — set breakpoints at addresses of interest
3. `debug_set_input(text)` — queue input the binary will read from stdin/console
4. `debug_continue()` — run until breakpoint or completion
5. `debug_read_state()` — inspect registers and current instruction
6. `debug_read_memory(address, length)` — read memory at any address
7. `debug_get_api_trace()` — review all Windows API calls made so far
8. `debug_get_output()` — read text the binary wrote to stdout/console
9. `debug_search_memory(pattern)` — find decrypted strings/data in memory
10. `debug_stop()` — end the session

## Stubbing

**CRT stubs** (`stub_crt=True`, default): Hooks ~47 Windows APIs needed for MSVC
CRT initialization (GetSystemTimeAsFileTime, GetCurrentProcessId, GetProcessHeap,
critical sections, TLS/FLS, EncodePointer, etc.) to prevent crashes before user code runs.

**I/O stubs** (`stub_io=True`, default): Hooks Win32 console APIs (GetStdHandle,
WriteConsoleA/W, ReadConsoleA, etc.) so printf/cout/cin calls work without
crashing. Output is captured and retrievable via `debug_get_output()`. Input is
consumed from a queue populated by `debug_set_input()`.

**Custom API stubs** — extend stubbing at runtime:
- `debug_stub_api(api_name, return_value, num_params, writes, set_last_error)` — create a stub
- `debug_list_stubs()` — show all stubs (builtin I/O, builtin CRT, user-defined)
- `debug_remove_stub(api_name)` — remove a user-defined stub

**GetLastError() anti-emulation bypass** — many packers (TA505, etc.) call a Windows API with
invalid parameters, then check `GetLastError()` for the expected error code. Use `set_last_error`
to make the stub set the correct error code before returning:
```
debug_stub_api(api_name="GetWindowContextHelpId", return_value="0x0",
               set_last_error="0x578")   # ERROR_INVALID_WINDOW_HANDLE
debug_stub_api(api_name="SetClassLongA", return_value="0x0",
               set_last_error="0x578")   # ERROR_INVALID_WINDOW_HANDLE
```
GetLastError and SetLastError are dynamic CRT stubs — they read/write a shared `_last_error_code`
variable, so `set_last_error` on any stub automatically affects subsequent `GetLastError()` calls.

## API Tracing

Enabled by default. Logs all Windows API calls with arguments and return values.
- `debug_get_api_trace(filter="Crypt")` — retrieve only matching calls (simple name filter)
- `debug_get_api_trace(query="api=VirtualAlloc,args.p3=0x40")` — structured query with argument filtering
- `debug_get_api_trace(query="api~Write,retval!=0x0")` — substring match + not-equal
- `debug_get_api_trace(query="seq>10,seq<50")` — range filtering on sequence numbers
- `debug_get_api_trace(sequence="VirtualAlloc;WriteProcessMemory;CreateRemoteThread")` — find ordered API call patterns
- `debug_get_api_trace(sequence="VirtualAlloc;memcpy", gap_max=5)` — sequence with max gap between steps
- `debug_set_trace_filter(whitelist=["VirtualAlloc", "memcpy"])` — limit what gets traced

Query operators: `=` (exact), `!=`, `~` (substring), `>`, `<`, `>=`, `<=`. Fields: `api`, `args.<key>`, `retval`, `address`, `seq`, `timestamp`. Hex values (e.g. `0x40`) are auto-coerced for numeric comparison.

## Snapshots

Save and compare state at different execution points:
- `debug_snapshot_save(name)` — save full emulation state (includes trace_seq for attribution)
- `debug_snapshot_restore(name)` — revert to a saved state
- `debug_snapshot_diff(id_a, id_b)` — compare register and memory differences
- `debug_snapshot_diff(id_a, id_b, attribute_changes=True)` — also correlate memory changes with API calls between snapshots (shows which VirtualAlloc/WriteProcessMemory/ReadFile calls caused which changes, plus unattributed change count)

## Memory Search

Find data in mapped memory regions:
- `debug_search_memory(pattern="http", pattern_type="string")` — string search (UTF-8 + UTF-16LE)
- `debug_search_memory(pattern="4D5A90", pattern_type="hex")` — hex pattern with `??` wildcards

## Execution Control

- `debug_step()` — single instruction step (into calls)
- `debug_step_over()` — step over calls
- `debug_continue()` — run to next breakpoint or limit
- `debug_run_until(address)` — run to a specific address
- `debug_set_watchpoint(address, length, type)` — break on memory read/write/access

## Limits

Max 3 concurrent sessions, 1800s TTL, 10M instruction cap, 1MB max memory read,
100 breakpoints, 50 watchpoints, 10 snapshots.

## Timeout Behaviour — Pause, Don't Kill

Execution commands (`debug_continue`, `debug_step`, `debug_step_over`,
`debug_run_until`) have a **runner-side timeout** (`DEBUG_COMMAND_TIMEOUT`, 300s
by default, env: `ARKANA_DEBUG_COMMAND_TIMEOUT`).

When the timeout fires, the runner calls `_ql.emu_stop()` (Unicorn's thread-safe
stop API) which causes the current `_ql.run()` to return cleanly. The session is
**paused, not killed** — all CPU state, memory, hooks, breakpoints, and watchpoints
are fully preserved.

After a timeout you can:
- `debug_read_state()` — see registers, PC, next instructions
- `debug_read_memory(address, length)` — dump memory regions
- `debug_search_memory(pattern)` — find decrypted strings/data
- `debug_get_api_trace()` — review API calls made so far
- `debug_continue()` / `debug_step()` — **resume execution** from exactly where it stopped

The response includes `stop_reason: "timeout"` with a hint explaining the session
is still alive and resumable.

**Example — unpacking a packed binary:**
```
debug_continue(max_instructions=10000000)
  → timeout after 300s, stop_reason="timeout", instructions_executed=8234521

debug_search_memory(pattern="MZ", pattern_type="string")
  → found at 0x5003000 (unpacked PE in heap)

debug_read_memory(address="0x5003000", length=4096)
  → dump the unpacked payload

debug_continue(max_instructions=10000000)
  → resumes from where it paused, hits connect() breakpoint
```

## Known Limitations and Workarounds

### 1. Register writes do not redirect execution

Unicorn's `emu_start()` uses its own start address parameter and does not honour
EIP/RIP changes made via `debug_write_register`.

**Workaround — code patching**: Use `debug_write_memory` to patch a `JMP` instruction
at the current execution point. Calculate the relative offset
(`target - (patch_addr + 5)`) and write `E9 xx xx xx xx` (x86 near jump).
To halt execution at a target, patch `EB FE` (jump-to-self infinite loop)
and use `max_instructions` to stop, then read memory for results.

### 2. Unresolved imports crash emulation

Qiling may fail to resolve imports from certain DLLs (commonly MSVCRT CRT functions
like `_initterm_e`, `_initterm`, `__getmainargs`, `__set_app_type`), leaving IAT
entries pointing to invalid addresses in the 0x5xxx range.

**Workaround — IAT patching**: Write a `xor eax, eax; ret` stub (`31 C0 C3`) to a
code cave, then patch all unresolved IAT entries to point to the stub address.
Check the IAT region for entries with suspiciously low addresses (< 0x10000).

### 3. Threading not supported

`CreateThread`, `WaitForMultipleObjects`, and other synchronisation APIs must be
stubbed. Thread functions will not execute. To analyse thread functions, redirect
the main execution flow into them via code patching (see workaround 1).

### 4. Breakpoints may not fire after code patches

When combining code patching with breakpoints, breakpoints set at the *original*
target address may not trigger. Use the infinite-loop-trap technique instead:
patch `EB FE` at the desired stop point, run with sufficient `max_instructions`,
and read memory after the emulator stops.

### 5. CRT stubs cover ~47 APIs but not all MSVCRT functions

If emulation crashes during CRT init, check `debug_get_api_trace` and the crash PC
to identify the missing API, then use `debug_stub_api` or IAT patching to add coverage.

## Decision Matrix — When to Use Tier 3b

| Scenario | Approach |
|----------|----------|
| Stepping through decryption loop instruction-by-instruction | `debug_start` + `debug_step` + `debug_read_memory` |
| Supplying specific stdin input during emulation | `debug_set_input` + `debug_continue` |
| Comparing state before/after a function call | `debug_snapshot_save`/`restore`/`diff` |
| Understanding what caused memory changes between snapshots | `debug_snapshot_diff(attribute_changes=True)` — correlates with API calls |
| Finding decrypted data after stepping past crypto | `debug_search_memory` |
| Fire-and-forget emulation crashed, need finer control | `debug_start` with breakpoints |
| Monitoring specific API calls with live argument inspection | `debug_get_api_trace` with filter |
| Filtering API trace by argument values (e.g. PAGE_EXECUTE_READWRITE) | `debug_get_api_trace(query="api=VirtualAlloc,args.p3=0x40")` |
| Detecting process injection API sequence | `debug_get_api_trace(sequence="VirtualAlloc;WriteProcessMemory;CreateRemoteThread")` |
| Binary with unresolved MSVCRT imports crashing at CRT init | IAT patching + code-cave stubs |
| Extracting encrypted data from a function you can't call directly | Code patching: JMP to target + EB FE trap + memory read |
| Multi-threaded binary where threads don't execute under emulation | Stub `CreateThread` + code-patch main flow into thread funcs |
