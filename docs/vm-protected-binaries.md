# Analysing VM-Protected Binaries with Arkana

Commercial protectors like **VMProtect**, **Themida**, and **Enigma** convert original x86/x64 code into custom bytecode executed by an embedded virtual machine. This makes static analysis nearly impossible -- decompilers see the interpreter loop, not the original logic. The binaries also include multi-layered anti-analysis: anti-VM detection, anti-debug, code integrity checks, and timing verification.

Rather than attempting to reverse the VM bytecode (an unsolved research problem), Arkana focuses on **recovering what the binary does** through comprehensive behavioural monitoring using [Frida](https://frida.re/). The pipeline has four stages: **characterise, instrument, execute, analyse**.

This guide is based on real-world testing against a Themida/WinLicense 3.x-protected Rust binary running on a QEMU/KVM virtual machine (Proxmox). Every technique described here was validated end-to-end.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Stage 1: Static Characterisation](#stage-1-static-characterisation)
- [Stage 2: Frida Script Generation](#stage-2-frida-script-generation)
- [Stage 3: Execution on Windows](#stage-3-execution-on-windows)
- [Stage 4: Import and Analyse](#stage-4-import-and-analyse)
- [Hypervisor Configuration](#hypervisor-configuration)
- [Detection Layers and Bypass Hierarchy](#detection-layers-and-bypass-hierarchy)
- [Frida Reference](#frida-reference)
  - [Installation](#frida-installation)
  - [Frida 17.x API Changes](#frida-17x-api-changes)
  - [Running Scripts](#running-frida-scripts)
  - [Script Types](#script-types)
  - [Output Formats](#output-formats)
  - [Troubleshooting Frida](#troubleshooting-frida)
- [Complete Workflow Example](#complete-workflow-example)
- [Alternative Approaches](#alternative-approaches)
- [Limitations](#limitations)

---

## Prerequisites

| Requirement | Where | Purpose |
|---|---|---|
| Arkana MCP server | Analysis host (Docker or local) | Stages 1, 2, and 4 |
| Windows VM | Isolated environment (QEMU/KVM, Proxmox, or bare metal) | Stage 3 -- running the protected binary |
| [Frida](https://frida.re/) | Windows VM | Dynamic instrumentation |
| [Python 3.x](https://python.org/) | Windows VM | Frida CLI tools |
| Hypervisor with CPUID masking | Host (Proxmox, libvirt, or QEMU) | Hide VM from CPUID-based detection |

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

- **Protector identity** -- VMProtect, Themida/WinLicense, Enigma, Code Virtualizer -- with confidence score
- **Active protection options** -- which features are enabled:
  - *Themida*: `anti_debug`, `api_wrapping`, `vm_code`, `string_encryption`
  - *VMProtect*: `virtualization`, `mutation`, `import_protection`
  - *Enigma*: `anti_vm`, `virtualization`
- **Import obfuscation score** (0.0--1.0) -- how heavily imports are hidden
- **Analysis recommendations** -- protector-specific guidance

**Real output from a Themida-protected Rust binary:**

```
vm_protection_detected: true
protector: WinLicense
confidence: 95
protection_options:
  - anti_dump: true
  - api_wrapping: true (0 direct kernel32/ntdll APIs)
  - vm_code: true (entry point in .winlice section)
  - string_encryption: true (0 strings relative to binary size)
import_obfuscation_score: 0.82
```

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
generate_frida_stalker_script(script_type="anti_vm", output_path="/output/bypass.js")
```

Hooks four categories of VM detection APIs:

| Detection Method | APIs Hooked | Bypass |
|---|---|---|
| Registry checks | `RegOpenKeyExA/W` | Blocks access to VM-indicator keys (VMware, VirtualBox, QEMU, Hyper-V) |
| Firmware queries | `GetSystemFirmwareTable` | Scrubs SMBIOS strings containing VM vendor identifiers |
| Process enumeration | `Process32FirstW/NextW` | Hides VM-related processes (vmtoolsd, VBoxService, qemu-ga) |
| Network fingerprinting | `GetAdaptersInfo` | Masks VM MAC address prefixes (00:0C:29, 08:00:27, etc.) |

> **Important**: The generated scripts use `Module.getExportByName(null, ...)` which was removed in Frida 17.x. See [Frida 17.x API Changes](#frida-17x-api-changes) for the required fix.

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

> **Note**: Stalker adds significant overhead. For protectors with timing checks (RDTSC), this may trigger detection. Use the API logger alone for timing-sensitive binaries.

### API Logger Script

```
generate_frida_stalker_script(
    script_type="api_logger",
    apis=["VirtualAlloc", "VirtualProtect", "CreateFileW", "WriteFile",
          "RegSetValueExW", "InternetOpenA", "HttpSendRequestA",
          "CreateProcessW", "WinExec"],
    output_path="/output/logger.js"
)
```

Logs every call to the specified APIs with full argument values, return values, and timestamps as structured JSON.

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

Copy the generated scripts and the malware sample to your Windows VM.

### Running with Frida

**Spawn mode** (recommended -- catches initialisation):

```powershell
frida -l bypass.js -l coverage.js -l logger.js -f sample.exe
```

This spawns the process suspended, injects all three scripts, then resumes. The anti-VM bypass activates before the protector's detection code runs.

For a Python-based runner with structured output handling, use the `run_frida.py` helper (generated alongside the scripts):

```powershell
python run_frida.py sample.exe --timeout 60
```

### Collecting Output

**API logs** -- events are captured by the `on_message` handler in the Python runner and saved to `api_trace.json`.

**Coverage data** -- when the process exits or you're ready to collect:

```
# In the Frida REPL:
rpc.exports.dump()
```

**Let the binary run** long enough to exercise its main functionality. For malware, 30-60 seconds is often sufficient for initial C2 communication, persistence setup, and credential harvesting.

### Copy Results Back

Copy the output files from the Windows VM to a location accessible to Arkana:

- `api_trace.json`
- `coverage_*.drcov` (if coverage was collected)

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

### Record Dynamic Findings

Save the API trace analysis as a conclusion note for the binary:

```
add_note(content="Frida API trace: 40 calls captured. Themida init sequence: DLL loading → API resolution → anti-VM checks (bypassed) → code unpacking (VirtualProtect RWX) → Rust runtime init → application logic.", category="conclusion", tool_name="frida_dbi_analysis")
```

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

## Hypervisor Configuration

**This is critical.** Commercial protectors use `CPUID` instructions to detect hypervisors. CPUID is a CPU instruction -- it cannot be intercepted from userspace by Frida, Pin, DynamoRIO, or any other DBI tool. The bypass must happen at the hypervisor level.

### Proxmox / QEMU / KVM

One-line configuration change:

```bash
# On the Proxmox host:
qm set <VMID> --cpu host,hidden=1
```

Or edit `/etc/pve/qemu-server/<VMID>.conf`:

```
cpu: host,hidden=1
```

This tells KVM to:
- Clear CPUID leaf 1 ECX bit 31 (hypervisor present)
- Zero CPUID leaf 0x40000000 (hypervisor vendor string "KVMKVMKVM")
- Hide the KVM paravirt interface

**Restart the VM after changing this setting.**

### libvirt / virt-manager

```xml
<cpu mode='host-passthrough'>
  <feature policy='disable' name='hypervisor'/>
</cpu>
```

### Direct QEMU Command Line

```bash
qemu-system-x86_64 -cpu host,-hypervisor ...
```

### VMware Workstation / ESXi

Add to the VM's `.vmx` file:

```
hypervisor.cpuid.v0 = "FALSE"
```

### VirtualBox

```bash
VBoxManage modifyvm "VMName" --paravirtprovider none
```

### Why This Is Necessary

Without CPUID masking, Themida's `SECheckVirtualPC()` detects the hypervisor and enters an infinite loop. Our testing confirmed:
- With `hidden=0`: binary hangs after 12 API calls (Themida's init phase), never reaches user code
- With `hidden=1`: binary runs to completion, all protected code blocks execute normally

No amount of usermode API hooking can bypass CPUID detection. This is a hardware instruction that executes directly on the CPU.

---

## Detection Layers and Bypass Hierarchy

Commercial protectors use multiple detection layers. Understanding which tools address which layers is essential:

### Themida/WinLicense Detection Layers (Tested)

| Layer | Detection Method | Bypass | Tool Level |
|---|---|---|---|
| 1. CPUID | Hypervisor present bit, vendor string | `cpu: host,hidden=1` | Hypervisor config |
| 2. SMBIOS | Firmware table VM vendor strings | `GetSystemFirmwareTable` hook (Frida) | Usermode API |
| 3. Registry | VM-indicator keys (VBOX, VMware) | `RegOpenKeyExA/W`, `RegOpenKeyA` hooks | Usermode API |
| 4. Device enumeration | `CM_Get_Device_IDA` for VM hardware | Hook + scrub device strings | Usermode API |
| 5. Network | MAC address prefixes | `GetAdaptersInfo` hook | Usermode API |
| 6. Process enumeration | VM tools processes | `Process32FirstW/NextW` hook | Usermode API |
| 7. Anti-debug (API) | `IsDebuggerPresent`, `NtQueryInformationProcess` | Return fake values | Usermode API |
| 8. Anti-debug (PEB) | `BeingDebugged` flag, `NtGlobalFlag` | Direct memory patch | Usermode |
| 9. Anti-debug (thread) | `NtSetInformationThread(ThreadHideFromDebugger)` | Swallow the call | Usermode API |
| 10. Sandbox DLLs | `GetModuleHandleA` for known DLL names | Return NULL for blacklisted names | Usermode API |
| 11. Monitor windows | `FindWindowA` for analysis tool windows | Return NULL for blacklisted windows | Usermode API |
| 12. Code integrity | CRC check on code sections | Cannot bypass without timing tricks | Protected |
| 13. Memory scanning | Scan for DBI tool signatures | Rename/rebuild Frida from source | Build-time |

Layers 1-11 are bypassed by the combination of hypervisor CPUID masking + Frida API hooks. Layer 12 (code integrity) is bypassed by not modifying the binary's code sections. Layer 13 (Frida memory scanning) is bypassed by using standard Frida spawn-mode injection rather than frida-gadget sideloading.

### Tool Capabilities Comparison

| Detection | Frida (API hooks) | Frida (Stalker) | x64dbg + ScyllaHide | HyperDbg | Intel PT |
|---|---|---|---|---|---|
| API-level checks | Yes | Yes | Yes | Yes | N/A |
| CPUID | No | Too slow | Manual BP | Yes (VT-x exit) | Records only |
| RDTSC timing | No | No (adds overhead) | No | Yes (VT-x exit) | N/A |
| IN port (VMware) | No | No | No | Yes (I/O exit) | N/A |
| Code integrity (CRC) | No (don't patch code) | No | No | Yes (EPT hooks) | N/A |
| Memory scanning | Detectable | Detectable | Less detectable | Invisible | Invisible |

### Recommended Approach by Protector

| Protector | Minimum Setup | Full Bypass |
|---|---|---|
| **Themida/WinLicense 3.x** | CPUID hidden + Frida API hooks | + ScyllaHide for advanced anti-debug |
| **VMProtect 3.x** | CPUID hidden + Frida API hooks | + Unlicense for memory dump |
| **Enigma Protector** | Frida API hooks (weaker VM detection) | Usually sufficient |
| **Code Virtualizer** | Frida API hooks | Usually sufficient |

---

## Frida Reference

### Frida Installation

**Windows (in the analysis VM):**

```powershell
pip install frida-tools

# Verify installation
frida --version
```

For spawn mode (`-f`), no separate frida-server is needed.

### Frida 17.x API Changes

**Critical**: Frida 17.x removed the static `Module.getExportByName(null, "ApiName")` API. Scripts generated by Arkana may use this pattern. The fix:

```javascript
// OLD (broken in Frida 17.x):
var p = Module.getExportByName(null, "GetProcAddress");

// NEW (works in Frida 17.x):
var p = Process.getModuleByName("KERNEL32.DLL").getExportByName("GetProcAddress");
```

Helper function for cross-module resolution:

```javascript
function findExport(name) {
    var dlls = ["KERNEL32.DLL", "KERNELBASE.dll", "ntdll.dll",
                "ADVAPI32.dll", "IPHLPAPI.DLL", "ucrtbase.dll"];
    for (var i = 0; i < dlls.length; i++) {
        try {
            var addr = Process.getModuleByName(dlls[i]).getExportByName(name);
            if (addr) return addr;
        } catch(e) {}
    }
    return null;
}
```

### Running Frida Scripts

| Mode | Command | Use Case |
|---|---|---|
| Spawn | `frida -l script.js -f binary.exe` | Start new process with hooks from the beginning |
| Attach by name | `frida -l script.js -n process.exe` | Hook a running process |
| Attach by PID | `frida -l script.js -p 1234` | Hook a specific process instance |
| Multiple scripts | `frida -l a.js -l b.js -l c.js -f binary.exe` | Load several scripts at once |
| No REPL | `frida -l script.js -f binary.exe --no-pause` | Spawn and immediately resume |

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
{"api": "CreateFileW", "call_index": 16, "args": {"file": "C:\\ProgramData\\rtpeskt"}, "retval": "0x348", "timestamp": "2026-04-04T13:34:49.930Z"}
```

### Troubleshooting Frida

| Problem | Solution |
|---|---|
| "Failed to spawn" | Run as Administrator. Some protectors require elevated privileges. |
| `TypeError: not a function` on `Module.getExportByName` | Frida 17.x API change. Use `Process.getModuleByName("DLL").getExportByName("Name")` instead. See [API Changes](#frida-17x-api-changes). |
| "process refused to load frida-agent" | Protector's anti-injection detected Frida. Ensure CPUID is hidden at hypervisor level. With `hidden=1`, standard spawn mode often works. |
| Process hangs after ~12 API calls | CPUID detection. Configure hypervisor to hide the hypervisor bit. See [Hypervisor Configuration](#hypervisor-configuration). |
| frida-gadget detected by protector | Themida scans process memory for Frida signatures. Use standard spawn-mode injection instead of gadget sideloading. |
| Stalker causes hang/slowdown | Stalker JIT-recompiles every basic block -- too heavy for complex VM interpreters. Use API logging alone. |
| "Access denied" | Disable Windows Defender / antivirus in the VM. It may block Frida injection. |

---

## Complete Workflow Example

This example is from real testing against `Themida_Protected_Rust.exe` -- a Rust binary protected with Themida/WinLicense 3.x featuring code virtualisation, mutation, code integrity checks, debugger detection, and VM detection. The test environment was a Windows VM on Proxmox/QEMU/KVM.

### Stage 1 -- Characterise (Arkana)

```
open_file("/samples/Protect/Themida_Protected_Rust.exe")

detect_vm_protection()
# → WinLicense detected (confidence: 95%)
# → Options: anti_dump, api_wrapping, vm_code, string_encryption
# → Entry point in .winlice section
# → Import obfuscation: 0.82

get_triage_report(compact=True)
# → CRITICAL risk, Themida packer confirmed via capa
# → Anti-debug instructions: CPUID, INT 2Dh, RDTSC
# → VM/sandbox indicator strings detected
# → 9 imports across 9 DLLs (heavily obfuscated)
```

### Stage 2 -- Generate Scripts (Arkana)

```
generate_frida_stalker_script(script_type="anti_vm", output_path="/output/bypass.js")
generate_frida_stalker_script(script_type="api_logger",
    apis=["VirtualAlloc", "VirtualProtect", "CreateFileW", "WriteFile",
          "GetProcAddress", "LoadLibraryA", "WriteConsoleW", "WriteConsoleA",
          "IsDebuggerPresent", "NtQueryInformationProcess"],
    output_path="/output/logger.js")
```

### Pre-Stage 3 -- Configure Hypervisor

```bash
# On the Proxmox host (CRITICAL — without this, the binary hangs):
qm set 100 --cpu host,hidden=1
qm stop 100 && qm start 100
```

### Stage 3 -- Execute (Windows VM)

```python
# run_clean.py — Python runner with structured output
import frida, json, time

api_calls = []
def on_message(msg, data):
    if msg['type'] == 'send' and 'api' in msg.get('payload', {}):
        api_calls.append(msg['payload'])
        p = msg['payload']
        print(f"  [{len(api_calls):4d}] {p['api']} => {p['retval']}")

pid = frida.spawn(['Themida_Protected_Rust.exe'])
session = frida.attach(pid)
with open('all_hooks.js') as f:
    script = session.create_script(f.read())
script.on('message', on_message)
script.load()
frida.resume(pid)

time.sleep(30)

with open('api_trace.json', 'w') as f:
    for c in api_calls:
        f.write(json.dumps(c) + '\n')
print(f'{len(api_calls)} API calls saved')
```

**Actual output (40 API calls captured):**

```
[   1] LoadLibraryA lib=user32.dll => 0x7ffdca4b0000
[   2] LoadLibraryA lib=advapi32.dll => 0x7ffdcb4a0000
[   3] LoadLibraryA lib=ntdll.dll => 0x7ffdcbe40000
[   4] LoadLibraryA lib=shell32.dll => 0x7ffdcad20000
[   5] LoadLibraryA lib=shlwapi.dll => 0x7ffdca370000
[   6] GetProcAddress proc=SetLastError => 0x7ffdca408db0
[   7] GetProcAddress proc=GetLastError => 0x7ffdca3f8640
...
[BYPASS] Scrubbed SMBIOS
[BYPASS] Blocked RegOpenKeyA: HARDWARE\ACPI\DSDT\VBOX__
...
[  18] VirtualProtect addr=0x140022354 => 1      # Code decryption
[  19] VirtualProtect addr=0x14001a000 => 1       # Section unpacking
...
[BYPASS] NtQueryInfoProcess(DebugPort) -> 0       # Anti-debug bypassed
[BYPASS] CheckRemoteDebuggerPresent -> false
[BYPASS] Blocked NtSetInformationThread(ThreadHideFromDebugger)
...
[  40] VirtualProtect addr=0x7ffdc8b08000 => 1    # Final init
```

The binary completed successfully -- all VM-protected and mutated code blocks executed.

### Stage 4 -- Analyse (Arkana)

```
# Save findings
add_note(content="40 API calls captured via Frida DBI. Themida init: DLL loading → anti-VM (bypassed) → code unpacking → Rust runtime → application logic. All 4 protected blocks executed.", category="conclusion", tool_name="frida_dbi_analysis")

# Continue analysis
get_analysis_digest()
generate_cti_report()
```

### What The Trace Reveals (Without Source Code)

From 40 API calls alone, we can reconstruct the binary's execution:

1. **Calls 1-5**: Themida loads DLLs for anti-analysis (user32, advapi32, shell32, SETUPAPI, Iphlpapi)
2. **Calls 6-15**: Dynamic API resolution -- SetLastError, GetLastError, IsUserAnAdmin, CM_Get_Device_IDA, GetAdaptersInfo -- preparation for VM detection checks
3. **Calls 16-17**: Themida temp file `C:\ProgramData\rtpeskt` created/accessed
4. **Calls 18-32**: Code unpacking -- VirtualProtect changing memory to RWX at binary addresses (0x140000000 range), VirtualAlloc for new regions -- Themida decrypting the original code
5. **Calls 33-40**: Rust runtime initialisation -- SetThreadDescription, VirtualProtect on ntdll ranges, anti-debug checks (all bypassed)

---

## Alternative Approaches

### x64dbg + ScyllaHide + Themidie

The standard reverse engineering approach for Themida. ScyllaHide handles anti-debug, Themidie handles Themida-specific checks (sandbox DLL detection, monitor window detection, VM registry queries). Requires manual interaction but gives full debugger control.

### Unlicense (Dynamic Unpacking)

[Unlicense](https://github.com/ergrelet/unlicense) is a Python 3 dynamic unpacker for Themida/WinLicense 2.x and 3.x. It lets Themida fully unpack itself, then dumps the memory image with reconstructed imports. The resulting dump can be loaded into IDA/Ghidra for static analysis. Virtualized code sections remain opaque. See [Unpacking and Repairing the TERA Executable](https://alexrp.substack.com/p/unpacking-and-repairing-the-tera-executable) for a detailed walkthrough.

### CAPEv2 Sandbox

For teams with existing sandbox infrastructure, [CAPEv2](https://github.com/kevoreilly/CAPEv2) provides kernel-level API monitoring that is less detectable than Frida. Arkana can import CAPE reports via `import_sandbox_report(format="cape")`. However, CAPE requires significant infrastructure to maintain.

### HyperDbg (Hypervisor-Level Debugging)

[HyperDbg](https://hyperdbg.org/) provides completely invisible instrumentation using Intel VT-x. It intercepts CPUID, RDTSC, and I/O port access at the hardware level. Use EPT hooks for invisible breakpoints. Requires a physical machine with Intel VT-x (not nested inside another VM).

---

## Limitations

- **Hypervisor configuration required** -- CPUID detection cannot be bypassed from userspace. You must configure your hypervisor to hide the hypervisor bit (`hidden=1` on Proxmox/KVM, `hypervisor.cpuid.v0 = FALSE` on VMware). Without this, the binary hangs during Themida's initialisation.
- **Frida memory scanning** -- Themida scans process memory for Frida signatures. Standard spawn-mode injection works (the agent loads after Themida's memory scan), but frida-gadget sideloading via DLL proxy does not (the gadget is present during Themida's init). If spawn mode fails, you may need to build Frida from source with signature strings removed.
- **Coverage vs timing** -- Frida's Stalker engine adds 10-100x overhead per basic block. Protectors with RDTSC timing checks (Themida, VMProtect) will detect this slowdown. Use API logging alone for timing-sensitive binaries.
- **Code integrity checks** -- Themida's `SECheckCodeIntegrity()` verifies CRC checksums of code sections. Do not modify the binary's code sections (no import table patching, no CPUID byte patching). Use API hooks and hypervisor config instead.
- **Bytecode is not devirtualised** -- The VM interpreter's custom bytecode is not reversed. Code-level understanding of virtualised functions requires manual analysis of the VM dispatcher. Arkana helps you understand *what the binary does* without needing to understand *how the VM works*.
- **Frida 17.x API change** -- `Module.getExportByName(null, "Name")` was removed. Use `Process.getModuleByName("DLL").getExportByName("Name")`. See [Frida 17.x API Changes](#frida-17x-api-changes).

---

*See also: [Analysis Methodology](methodology.md) | [Tools Reference](tools-reference.md) | [Configuration](configuration.md)*
