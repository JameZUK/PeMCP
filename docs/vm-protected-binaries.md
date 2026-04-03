# Analysing VM-Protected Binaries with Arkana

Commercial protectors like **VMProtect**, **Themida**, and **Enigma** convert original x86/x64 code into custom bytecode executed by an embedded virtual machine. This makes static analysis nearly impossible -- decompilers see the interpreter loop, not the original logic. The binaries often include anti-VM detection to prevent analysis in virtual environments.

Rather than attempting to reverse the VM bytecode (an unsolved research problem), Arkana focuses on **recovering what the binary does** through comprehensive behavioural monitoring using [Frida](https://frida.re/). The pipeline has four stages: **characterise, instrument, execute, analyse**.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Stage 1: Static Characterisation](#stage-1-static-characterisation)
- [Stage 2: Frida Script Generation](#stage-2-frida-script-generation)
- [Stage 3: Execution on Windows](#stage-3-execution-on-windows)
- [Stage 4: Import and Analyse](#stage-4-import-and-analyse)
- [Frida Reference](#frida-reference)
  - [Installation](#frida-installation)
  - [Running Scripts](#running-frida-scripts)
  - [Script Types](#script-types)
  - [Output Formats](#output-formats)
  - [Troubleshooting Frida](#troubleshooting-frida)
- [Complete Workflow Example](#complete-workflow-example)
- [Limitations](#limitations)

---

## Prerequisites

| Requirement | Where | Purpose |
|---|---|---|
| Arkana MCP server | Analysis host (Docker or local) | Stages 1, 2, and 4 |
| Windows VM | Isolated environment | Stage 3 -- running the protected binary |
| [Frida](https://frida.re/) | Windows VM | Dynamic instrumentation |
| [Python 3.x](https://python.org/) | Windows VM | Frida CLI tools |

**Install Frida on the Windows VM:**

```powershell
pip install frida-tools
```

> **Safety**: Always run malware in an isolated VM with snapshots. Revert after each run.

---

## Stage 1: Static Characterisation

Before executing anything, identify the protector and its configuration.

### Detect the Protector

```
detect_vm_protection()
```

This analyses the loaded binary without execution and reports:

- **Protector identity** -- VMProtect, Themida, Enigma, Code Virtualizer -- with confidence score
- **Active protection options** -- which features are enabled:
  - *Themida*: `anti_debug`, `api_wrapping`, `vm_code`, `string_encryption`
  - *VMProtect*: `virtualization`, `mutation`, `import_protection`
  - *Enigma*: `anti_vm`, `virtualization`
- **Import obfuscation score** (0.0--1.0) -- how heavily imports are hidden
- **Analysis recommendations** -- protector-specific guidance

### Assess the Binary

```
get_triage_report(compact=True)
classify_binary_purpose()
```

Even with protection active, triage reveals file metadata, section structure, entropy patterns, and whatever imports survive obfuscation. This context helps interpret the dynamic results later.

---

## Stage 2: Frida Script Generation

Arkana generates ready-to-run Frida JavaScript files tailored to the loaded binary. Three scripts work together to provide complete behavioural coverage:

### Anti-VM Bypass Script

```
generate_frida_stalker_script(script_type="anti_vm", output_path="/output/anti_vm_bypass.js")
```

Hooks four categories of VM detection APIs:

| Detection Method | APIs Hooked | Bypass |
|---|---|---|
| Registry checks | `RegOpenKeyExA/W` | Blocks access to VM-indicator keys (VMware, VirtualBox, QEMU, Hyper-V) |
| Firmware queries | `GetSystemFirmwareTable` | Scrubs SMBIOS strings containing VM vendor identifiers |
| Process enumeration | `Process32FirstW/NextW` | Hides VM-related processes (vmtoolsd, VBoxService, qemu-ga) |
| Network fingerprinting | `GetAdaptersInfo` | Masks VM MAC address prefixes (00:0C:29, 08:00:27, etc.) |

### Coverage Collection Script

```
generate_frida_stalker_script(
    script_type="coverage",
    output_format="drcov",
    output_path="/output/coverage.js"
)
```

Uses Frida's [Stalker](https://frida.re/docs/stalker/) engine to record every basic block the CPU executes. Outputs in **DynamoRIO drcov** format, compatible with:

- [Lighthouse](https://github.com/gaasedelen/lighthouse) (IDA Pro / Binary Ninja)
- [dragondance](https://github.com/0ffffffffh/dragondance) (Ghidra)
- Arkana's own `import_coverage_data()`

Set `output_format="json"` for a JSON alternative that includes timestamps and thread IDs.

### API Logger Script

```
generate_frida_stalker_script(
    script_type="api_logger",
    apis=["VirtualAlloc", "VirtualProtect", "CreateFileW", "WriteFile",
          "RegSetValueExW", "InternetOpenA", "HttpSendRequestA",
          "CreateProcessW", "WinExec"],
    output_path="/output/api_logger.js"
)
```

Logs every call to the specified APIs with:

- Full argument values (type-aware resolution for 50+ common Windows APIs)
- Return values
- Timestamps
- Call stack addresses
- Structured JSON output, one event per line

Choose APIs based on the triage results. Common selections:

| Capability | APIs to Monitor |
|---|---|
| File I/O | `CreateFileA/W`, `WriteFile`, `ReadFile`, `DeleteFileA/W` |
| Registry | `RegSetValueExA/W`, `RegCreateKeyExA/W`, `RegDeleteValueA/W` |
| Network | `InternetOpenA`, `HttpSendRequestA/W`, `connect`, `send`, `WSASend` |
| Process | `CreateProcessA/W`, `WinExec`, `ShellExecuteA/W` |
| Memory | `VirtualAlloc`, `VirtualProtect`, `VirtualAllocEx`, `WriteProcessMemory` |
| Crypto | `CryptEncrypt`, `CryptDecrypt`, `BCryptEncrypt`, `BCryptDecrypt` |

### Save All Scripts

The `output_path` parameter saves each script to disk. Use the `/output` directory (mapped to your host) so you can copy them to the Windows VM.

---

## Stage 3: Execution on Windows

Copy the three generated scripts and the malware sample to your Windows VM.

### Running with Frida

**Spawn mode** (recommended -- catches initialisation):

```powershell
frida -l anti_vm_bypass.js -l coverage.js -l api_logger.js -f sample.exe
```

This spawns the process suspended, injects all three scripts, then resumes. The anti-VM bypass activates before the protector's detection code runs.

**Attach mode** (for already-running processes):

```powershell
frida -l coverage.js -l api_logger.js -p <PID>
```

### Collecting Output

**Coverage data** -- when the process exits or you're ready to collect:

```
# In the Frida REPL:
rpc.exports.dump()
```

This writes the drcov file to the current directory (filename printed to console).

**API logs** -- written continuously to `api_trace.json` in the current directory.

**Let the binary run** long enough to exercise its main functionality. For malware, 30-60 seconds is often sufficient for initial C2 communication, persistence setup, and credential harvesting. Use multiple runs with different inputs to improve coverage.

### Copy Results Back

Copy the output files from the Windows VM to a location accessible to Arkana:

- `coverage.drcov` (or `coverage.json`)
- `api_trace.json`

If using Docker, place them in the samples or output directory.

---

## Stage 4: Import and Analyse

### Import Coverage Data

```
import_coverage_data(file_path="/output/coverage.drcov")
get_coverage_summary()
```

Coverage is overlaid onto Arkana's function map, revealing:

- **Executed functions** -- what the binary actually did during the run
- **Uncovered functions** -- potential dormant capabilities, kill switches, time-bombs, or alternate code paths that weren't triggered
- **Coverage percentage** -- how much of the binary was exercised

### Analyse the API Trace

```
analyze_instruction_trace(file_path="/output/api_trace.json")
```

The trace is analysed for:

- Execution patterns and API call sequences
- Mnemonic/operation frequency
- Temporal ordering of operations

### Investigate Findings

From here, use Arkana's standard analysis tools to dig deeper:

```
# Decompile uncovered functions -- may contain dormant capabilities
decompile_function_with_angr("0x401000")

# Try to reach unexplored code paths symbolically
find_path_to_address("0x402500")

# Check for mixed Boolean-arithmetic obfuscation
detect_mba_obfuscation()

# Rapid triage of all discovered functions
batch_decompile(digest=True)

# Generate a complete report
generate_cti_report()
```

---

## Frida Reference

### Frida Installation

**Windows (in the analysis VM):**

```powershell
# Install Frida CLI tools
pip install frida-tools

# Verify installation
frida --version
```

Frida requires matching versions between the CLI tools and the frida-server (if used). For spawn mode (`-f`), no separate server is needed.

**Specific Python version:**

```powershell
python -m pip install frida-tools
```

### Running Frida Scripts

| Mode | Command | Use Case |
|---|---|---|
| Spawn | `frida -l script.js -f binary.exe` | Start new process with hooks from the beginning |
| Attach by name | `frida -l script.js -n process.exe` | Hook a running process |
| Attach by PID | `frida -l script.js -p 1234` | Hook a specific process instance |
| Multiple scripts | `frida -l a.js -l b.js -l c.js -f binary.exe` | Load several scripts at once |
| No REPL | `frida -l script.js -f binary.exe --no-pause` | Spawn and immediately resume (no interactive console) |

### Script Types

Arkana generates four types of Frida scripts via `generate_frida_stalker_script()`:

| `script_type` | Purpose | Output |
|---|---|---|
| `coverage` | Record every basic block executed via Stalker | `.drcov` or `.json` file |
| `anti_vm` | Bypass user-mode VM detection | Console log of blocked checks |
| `injection_detector` | Detect process injection sequences | Alert via `send()` |
| `api_logger` | Log specified API calls with arguments | `.json` file (one event per line) |

Additional Frida tools:

| Tool | Purpose |
|---|---|
| `generate_frida_hook_script()` | Hook specific functions by address or name |
| `generate_frida_bypass_script()` | Bypass anti-debug techniques (IsDebuggerPresent, etc.) |
| `generate_frida_trace_script()` | Trace function entry/exit with arguments |

### Output Formats

**drcov format** (coverage):

Binary format used by DynamoRIO. Each entry records a basic block address and size. Compatible with Lighthouse, dragondance, and Arkana's `import_coverage_data()`.

**JSON format** (coverage):

```json
{"type": "bb", "address": "0x401000", "size": 15, "thread_id": 1234, "timestamp": 1712345678.123}
```

**API logger JSON** (one event per line):

```json
{"api": "CreateFileW", "args": {"lpFileName": "C:\\Users\\...\\config.dat", "dwDesiredAccess": "0x80000000", "dwShareMode": "0x1"}, "retval": "0x1a4", "timestamp": 1712345678.456, "tid": 1234}
```

### Troubleshooting Frida

| Problem | Solution |
|---|---|
| "Failed to spawn" | Run as Administrator. Some protectors require elevated privileges. |
| "Script crashed on load" | Check Frida version matches (CLI and core). Update with `pip install --upgrade frida-tools`. |
| Protector detects Frida | Try `--runtime=v8` flag. Some protectors scan for the default Frida runtime. |
| Process exits immediately | The anti-VM bypass may not cover all checks. Check console output for which detection fired. Add custom hooks. |
| No coverage data | Ensure `rpc.exports.dump()` is called before the process exits. For short-lived processes, add a delay or use `--no-pause` with a timer. |
| drcov file empty | Stalker may not have been attached to the right thread. Try `target_module` parameter to scope coverage. |
| "Access denied" | Disable Windows Defender / antivirus in the VM. It may block Frida injection. |

---

## Complete Workflow Example

This example analyses a Themida-protected stealer.

**Stage 1 -- Characterise (Arkana):**

```
open_file("/samples/protected_stealer.exe")

detect_vm_protection()
# → Themida 3.x detected (confidence: 95%)
# → Options: anti_debug=True, api_wrapping=True, vm_code=True
# → Import obfuscation: 0.85

get_triage_report(compact=True)
# → PE32, 2.1MB, entropy 7.4, 3 sections, signed=False
```

**Stage 2 -- Generate Scripts (Arkana):**

```
generate_frida_stalker_script(script_type="anti_vm", output_path="/output/bypass.js")
generate_frida_stalker_script(script_type="coverage", output_format="drcov", output_path="/output/coverage.js")
generate_frida_stalker_script(script_type="api_logger",
    apis=["CreateFileW", "WriteFile", "RegSetValueExW", "InternetOpenA",
          "HttpSendRequestA", "CryptDecrypt", "VirtualAlloc", "VirtualProtect"],
    output_path="/output/logger.js")
```

**Stage 3 -- Execute (Windows VM):**

```powershell
# Copy scripts and sample to VM, then:
frida -l bypass.js -l coverage.js -l logger.js -f protected_stealer.exe

# Wait 60 seconds for the malware to initialise and phone home
# Then in the Frida REPL:
rpc.exports.dump()
# → Saved coverage to coverage_1712345678.drcov
```

**Stage 4 -- Analyse (Arkana):**

```
import_coverage_data(file_path="/output/coverage_1712345678.drcov")
get_coverage_summary()
# → 2,847 basic blocks executed across 156 functions
# → 89 functions never executed (potential dormant capabilities)

analyze_instruction_trace(file_path="/output/api_trace.json")
# → 423 API calls logged
# → CreateFileW: 12 calls (credential files, browser databases)
# → InternetOpenA: 1 call (C2 initialisation)
# → HttpSendRequestA: 3 calls (data exfiltration)
# → CryptDecrypt: 8 calls (config/string decryption)

# Investigate uncovered functions
batch_decompile(digest=True)

# Generate the final report
generate_cti_report()
```

---

## Limitations

- **Windows VM required** -- Stage 3 requires a Windows environment with Frida. Arkana handles Stages 1, 2, and 4.
- **User-mode only** -- The anti-VM bypass covers user-mode detection (registry, firmware, process enumeration, MAC addresses). Kernel-mode detection (e.g., CPUID leaf interception, MSR checks) is not addressed.
- **Coverage is input-dependent** -- Code coverage reflects only the execution paths triggered during the run. Unexplored paths require additional runs with different inputs, or use `find_path_to_address()` for symbolic exploration.
- **Bytecode is not devirtualised** -- The VM interpreter's custom bytecode is not reversed. Code-level understanding of virtualised functions requires manual analysis of the VM dispatcher. Arkana helps you understand *what the binary does* without needing to understand *how the VM works*.
- **Anti-Frida detection** -- Some protectors detect Frida itself. Mitigations include the `--runtime=v8` flag and custom Frida builds, but this is an arms race.
- **Timing-based detection** -- Stalker adds overhead that may trigger timing checks (`QueryPerformanceCounter`, `rdtsc`). Arkana's Qiling-based `anti_vm_bypass=True` handles RDTSC normalisation for emulated execution, but Frida does not.

---

*See also: [Analysis Methodology](methodology.md) | [Tools Reference](tools-reference.md) | [Configuration](configuration.md)*
