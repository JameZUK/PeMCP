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
- [Protector Comparison: Static vs Dynamic Analysis](#protector-comparison-static-vs-dynamic-analysis)
  - [Test Binaries](#test-binaries)
  - [Static Analysis Results](#static-analysis-results-arkana)
  - [Dynamic Analysis Results](#dynamic-analysis-results-frida)
  - [Combined Effectiveness Ranking](#combined-effectiveness-ranking)
  - [Analysis](#analysis)
  - [Practical Recommendations](#practical-recommendations)
  - [Reproducing These Tests](#reproducing-these-tests)
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

> **Important**: Arkana's generated scripts may use `Module.getExportByName(null, ...)` which was removed in Frida 17.x. The `protect_hooks.js` test script (see [Protector Comparison](#protector-comparison-static-vs-dynamic-analysis)) already uses the corrected `Process.getModuleByName("DLL").getExportByName("Name")` pattern. See [Frida 17.x API Changes](#frida-17x-api-changes) for details.

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

QEMU/KVM exposes many VM indicators beyond just CPUID. A complete stealth configuration requires multiple settings. Edit `/etc/pve/qemu-server/<VMID>.conf`:

```
# Core anti-detection
cpu: host,hidden=1
balloon: 0
agent: 0
vmgenid: 0

# Use non-VirtIO devices (VirtIO PCI vendor 0x1AF4 = Red Hat)
scsihw: lsi
vga: std
net0: e1000=D4:BE:D9:12:34:56,bridge=vmbr0

# QEMU args: ACPI + SMBIOS + disk spoofing
args: -smbios type=0,vendor=Dell\ Inc.,version=1.14.0,date=10/20/2022,release=1.14,uefi=on -smbios type=1,manufacturer=Dell,product=Latitude-5520 -global scsi-hd.vendor=WDC -global scsi-hd.product=WD10EZEX -machine x-oem-id=ALASKA,x-oem-table-id=A_M_I___
```

**What each setting hides:**

| Setting | Hides |
|---|---|
| `cpu: host,hidden=1` | CPUID hypervisor bit, KVM vendor string |
| `balloon: 0` | VirtIO balloon device |
| `agent: 0` | QEMU guest agent channel |
| `vmgenid: 0` | VM Generation ID ACPI device |
| `scsihw: lsi` | VirtIO SCSI (replaces with real LSI chip emulation) |
| `vga: std` | VirtIO GPU |
| `net0: e1000=D4:BE:D9:...` | VirtIO NIC + QEMU MAC prefix (52:54:00) |
| `-smbios type=0,...` | BIOS manufacturer, version (replaces "QEMU/Bochs") |
| `-smbios type=1,...` | System manufacturer (replaces "QEMU") |
| `-global scsi-hd.vendor=WDC` | Disk model (replaces "QEMU HARDDISK") |
| `-machine x-oem-id=ALASKA` | ACPI OEM ID (replaces "BOCHS") |

**Restart the VM after changing settings.**

> **OVMF firmware branding**: Proxmox's OVMF firmware embeds "Proxmox distribution of EDK II" as a compile-time constant. This cannot be changed via QEMU arguments. Options: install vanilla Debian `ovmf` package, build custom `pve-edk2-firmware` from source, or use the [proxmox-ve-anti-detection](https://github.com/zhaodice/proxmox-ve-anti-detection) patched QEMU build. See [Remaining Indicators](#remaining-indicators) below.

> **For deeper hardening** (device names, audio vendor IDs, EDID monitor info, USB device strings, RDTSC timing): the [proxmox-ve-anti-detection](https://github.com/zhaodice/proxmox-ve-anti-detection) project patches 60+ detection strings in the QEMU binary. Pre-built `.deb` packages are available for each Proxmox version.

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
| **Themida/WinLicense 3.x** | CPUID hidden + Frida API hooks | Fully working (tested, 40 API calls captured) |
| **VMProtect 3.x** | CPUID hidden + full Proxmox hardening + patched OVMF | Uses direct syscalls — API hooks alone insufficient. Needs [proxmox-ve-anti-detection](https://github.com/zhaodice/proxmox-ve-anti-detection) or custom OVMF build |
| **Enigma Protector** | Frida API hooks (weaker VM detection) | Usually sufficient |
| **Code Virtualizer** | Frida API hooks | Usually sufficient |

### Remaining Indicators (Proxmox)

Even with full configuration hardening, some indicators require patched QEMU or custom firmware:

| Indicator | Source | Fix |
|---|---|---|
| "Proxmox distribution of EDK II" in BIOS version | OVMF firmware compile-time PCD | Build custom pve-edk2-firmware or install vanilla Debian `ovmf` |
| VirtIO PCI vendor 0x1AF4 (Red Hat) | Any remaining VirtIO devices | Avoid VirtIO devices, or use patched QEMU |
| "QEMU Monitor" in EDID display info | QEMU display emulation | `vga: none` with GPU passthrough, or patched QEMU |
| "QEMU USB Tablet" in device names | QEMU input devices | Pass through real USB devices, or patched QEMU |
| RDTSC timing anomalies | KVM VM-exit overhead | `hv_time` CPU flag (partial), or kernel RDTSC handler patch |
| fw_cfg ACPI device "QEMU0002" | QEMU firmware config | Patched QEMU only |

For the most thorough solution, use [zhaodice/proxmox-ve-anti-detection](https://github.com/zhaodice/proxmox-ve-anti-detection) which patches all of these in a single QEMU build. Pre-built packages available for Proxmox 8.x.

### VMProtect vs Themida: Why VMProtect Is Harder

Our testing revealed a fundamental difference:

- **Themida** uses Windows API calls for VM detection (`GetSystemFirmwareTable`, `RegOpenKeyEx`, `GetAdaptersInfo`). Frida's API hooks intercept these successfully.
- **VMProtect** makes **direct syscalls** — it has its own `syscall` instruction stubs that bypass ntdll.dll entirely. No usermode API hook can intercept these. VMProtect reads SMBIOS/ACPI data through raw `NtQuerySystemInformation` syscalls, finding VM strings that must be eliminated at the hypervisor level.

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

## Protector Comparison: Static vs Dynamic Analysis

To quantify what each protector hides (and leaks), we tested 8 protected binaries built from **identical Rust source code** performing 10 known Windows API operations. Each binary was compiled with a different commercial protector, then analysed statically with Arkana and dynamically with Frida on a Windows VM (Proxmox/QEMU/KVM, `cpu: host,hidden=1`).

This is a controlled experiment: because we have the source code, we know exactly what the binary *should* do, and can measure precisely what each analysis technique recovers.

### Test Binaries

All binaries are 64-bit Rust console applications calling these 10 operations in sequence:

1. `GetEnvironmentVariableW("COMPUTERNAME")`
2. `GetUserNameW`
3. `GetEnvironmentVariableW("TEMP")`
4. `GetCurrentProcessId` + `GetCurrentThreadId`
5. `GetDiskFreeSpaceExW("C:\\")`
6. `SHGetKnownFolderPath(FOLDERID_Documents)`
7. `GetSystemInfo`
8. `RegCreateKeyExW` + `RegSetValueExW` (`HKCU\Software\EmeritaDemo`)
9. `RegOpenKeyExW` + `RegQueryValueExW`
10. `CreateFileW` + `WriteFile` + `ReadFile` (`emerita_demo.txt`)

Each binary wraps these operations in its protector's VM/mutation markers. Two additional binaries (`Themida_Protected_Rust.exe` and `vmprotect_rust.vmp.exe`) use the same protectors but with different source code and protection options.

| Binary | Protector | Size | Source VM Markers |
|---|---|---|---|
| `frida_test_codevirt_protected.exe` | Code Virtualizer (Oreans) | 5.5 MB | `VirtualizerStart/End`, LION_BLACK custom VM, stealth .data zone |
| `frida_test_enigma.exe` | Enigma Protector | 3.7 MB | `enigma::vm_risc_begin/end` |
| `frida_test_obsidium.exe` | Obsidium | 375 KB | `obs::vm_start!/vm_end!` |
| `frida_test_vmprotect.vmp.exe` | VMProtect 3.x | 14.7 MB | `VMProtectBeginVirtualization/End` |
| `frida_test_vxlang.vxm.exe` | VXLang | 982 KB | `VxVirtualizationBegin/End` |
| `frida_test_winlicense_protected.exe` | WinLicense (Oreans) | 5.2 MB | `VM_TIGER_WHITE_START/END` with mid-function splits |
| `Themida_Protected_Rust.exe` | Themida/SecureEngine | 6.1 MB | `VMStart/End`, `MutateStart/End`, `SECheckDebugger`, `SECheckVirtualPC`, `SECheckCodeIntegrity` |
| `vmprotect_rust.vmp.exe` | VMProtect 3.x | 12.6 MB | `VMProtectBeginVirtualization/Mutation`, `VMProtectIsDebuggerPresent`, `VMProtectIsVirtualMachinePresent`, `VMProtectIsValidImageCRC`, `VMProtectDecryptStringA` |

### Static Analysis Results (Arkana)

Arkana tools used: `open_file`, `get_triage_report`, `detect_vm_protection`, `rust_analyze`, `get_focused_imports`, `get_strings_summary`, `classify_binary_purpose`.

| Protector | Entropy | Imports (DLLs/funcs) | Import Obfuscation | Protector ID'd | Rust Detected | Source Strings Visible | Dev Identity Leaked |
|---|---|---|---|---|---|---|---|
| **Code Virtualizer** | 6.82 | 14 / 98 | 0.00 | No | Partial | Yes (all) | Yes (`ChadM`) |
| **Enigma** | 7.99 | 17 / 20 | 0.60 | **Enigma** (90%) | No | No | No |
| **Obsidium** | 7.98 | 4 / 4 | 0.92 | No | No | No | No |
| **VMProtect** | 7.77 | 14 / 14 | 0.72 | No | No | No | No |
| **VXLang** | 6.98 | 1 / 1 | 0.98 | No | No | No | No |
| **WinLicense** | 7.89 | 13 / 13 | 0.74 | **WinLicense** (90%) | No | No | No |

**Key static findings:**

- **Code Virtualizer** uses a "stealth mode" that only virtualises marked code regions. Everything else — imports, strings, Rust panic handlers, Cargo dependency paths, rustc commit hash, developer username — survives intact. Import obfuscation score: 0.00.
- **VXLang** is the most aggressive: only 1 import from 1 DLL. No strings, no Rust markers. Import obfuscation: 0.98.
- **Enigma** and **WinLicense** self-identify via strings (`enigmaprotector.com` URLs) and section names (`.winlice`), respectively.
- All protectors except Code Virtualizer successfully hide Rust origin (panic handlers, mangled symbols, cargo paths).

### Dynamic Analysis Results (Frida)

A combined Frida script (`protect_hooks.js`) hooked: anti-debug APIs (IsDebuggerPresent, NtQueryInformationProcess, NtSetInformationThread, CheckRemoteDebuggerPresent), anti-VM APIs (RegOpenKeyExA/W, GetSystemFirmwareTable), all 10 source APIs with full argument/return parsing, import resolution tracking (GetProcAddress, LoadLibrary\*), console output (WriteConsoleW/A), and protector overhead (VirtualAlloc, VirtualProtect).

#### Source Operation Visibility

| Protector | Ops Detected | Console Output | Notes |
|---|---|---|---|
| **Code Virtualizer** | **10/10** | Visible via SSH | Clean exit 0.5s, zero bypasses needed |
| **VMProtect (frida_test)** | **10/10** | Visible via SSH | Clean exit 0.5s, zero bypasses needed |
| **Obsidium** | **10/10** | Visible via SSH | 5 anti-debug bypasses triggered but all defeated |
| **Enigma** | **9/10** | Visible via SSH | Missing SHGetKnownFolderPath |
| **WinLicense** | **9/10** | Visible via SSH | Missing SHGetKnownFolderPath, 7 bypasses triggered |
| **Themida (full)** | **1/10** | Visible via SSH | Only GetCurrentProcessId. Anti-hook blocked app ops |
| **VMProtect (vmprotect_rust)** | **1/10** | "VM detected!" then exit | `VMProtectIsVirtualMachinePresent()` not bypassed |
| **VXLang** | **0/10** | None | Zero Frida events. Complete evasion |

#### Import Resolution

| Protector | Dynamically Resolved | Notable |
|---|---|---|
| **Enigma** | **905** | Embedded Delphi VCL framework (user32: 194, GDI32: 109, uxtheme: 73). Own license-check registry key exposed |
| **WinLicense** | 40 | user32, advapi32, ntdll, SETUPAPI, Iphlpapi. HW fingerprinting (network adapter enumeration) |
| **Themida (full)** | 29 | Same DLL pattern as WinLicense |
| **Obsidium** | 16 | KERNELBASE APIs (IsWow64Process2, FlsAlloc), VCRUNTIME140 |
| **Code Virtualizer** | 4 | SetThreadDescription, GetTempPath2W, sspicli.dll |
| **VMProtect (frida_test)** | 4 | Identical to Code Virtualizer |
| **VMProtect (vmprotect_rust)** | 1 | Only SetThreadDescription |
| **VXLang** | 0 | Nothing observable |

#### Anti-Analysis Bypasses Triggered

| Protector | Total | Anti-Debug | Anti-VM |
|---|---|---|---|
| **WinLicense** | 7 | NtSetInformationThread(HideFromDebugger), NtQueryInfoProcess(DebugPort x2, DebugObjectHandle) | RegOpenKeyExA(VBOX__), GetSystemFirmwareTable scrubbed x2 |
| **Themida (full)** | 7 | Same anti-debug as WinLicense | Same anti-VM as WinLicense |
| **Obsidium** | 5 | NtQueryInfoProcess(DebugPort x2, DebugObjectHandle, DebugFlags), NtSetInformationThread(HideFromDebugger) | None |
| **Enigma** | 2 | NtSetInformationThread(HideFromDebugger) x2 | None |
| **Code Virtualizer** | 0 | — | — |
| **VMProtect** | 0 | — | — |
| **VXLang** | 0 | — | — |

#### Protector Memory Overhead

| Protector | VirtualAlloc | VirtualProtect | Total Events |
|---|---|---|---|
| **Enigma** | 19 | 13 | 1,491 |
| **WinLicense** | 17 | 23 | 259 |
| **Themida (full)** | 4 | 13 | 168 |
| **Obsidium** | 5 | 47 | 145 |
| **VMProtect (frida_test)** | 0 | 2 | 72 |
| **Code Virtualizer** | 0 | 2 | 70 |
| **VMProtect (vmprotect_rust)** | 0 | 0 | 3 |
| **VXLang** | 0 | 0 | 0 |

### Combined Effectiveness Ranking

| Rank | Protector | Static Evasion | Dynamic Evasion | Overall |
|---|---|---|---|---|
| 1 | **VXLang** | Strong (1 import, no strings) | **Total** (0 events) | Best — opaque to both |
| 2 | **VMProtect** (with anti-VM) | Strong (no leaks) | **High** (own VM detection beat bypasses) | Strong — requires VM-level bypass |
| 3 | **Themida** (full, with SE macros) | Moderate (identifiable) | **High** (anti-hook blocked 9/10 ops) | Strong dynamic, moderate static |
| 4 | **Obsidium** | Strong (no leaks) | Weak (all 10 ops exposed) | Anti-debug defeated by Frida |
| 5 | **WinLicense** | Moderate (identifiable) | Weak (9/10 ops exposed) | Identifiable and hookable |
| 6 | **VMProtect** (without anti-VM) | Strong (no static leaks) | **None** (10/10 transparent) | VM bytecode alone insufficient |
| 7 | **Code Virtualizer** | None (everything visible) | None (10/10 transparent) | Stealth mode leaks everything |
| 8 | **Enigma** | None (self-identifies) | None (9/10 + 905 imports) | Leaks in every dimension |

### Analysis

**Code virtualisation alone does not prevent API-level hooking.** Code Virtualizer and the frida_test VMProtect binary both virtualise the code, but the VM interpreter still calls the real Windows APIs. Frida hooks at the API boundary, so the VM is irrelevant — all 10 operations captured with full arguments and return values.

**Anti-debug and anti-hook layers are what block dynamic observation.** Compare the two Themida variants: Code Virtualizer (virtualisation only) achieved 10/10 visibility, while full Themida (with `SECheckDebugger`, `SECheckCodeIntegrity`, `SECheckVirtualPC`) achieved only 1/10. Same vendor, same VM engine, completely different outcomes. The `SE*` anti-analysis macros in the source code made the difference.

**VMProtect's `VMProtectIsVirtualMachinePresent()` uses internal checks that bypass our hooks.** The vmprotect_rust binary printed "VM detected!" and exited. This API likely uses CPUID-level or direct-syscall checks baked into VMProtect's VM bytecode — not the standard registry/firmware APIs that Frida can intercept. Despite `cpu: host,hidden=1` in Proxmox, VMProtect found additional indicators (likely OVMF firmware branding or other Proxmox-specific strings).

**VXLang achieved complete evasion.** Zero events across all Frida hook categories. The binary either detected Frida injection before hooks loaded (TLS callback), uses direct syscalls bypassing ntdll, or employs an anti-hook mechanism that prevents Interceptor.attach from working. Further investigation would require kernel-level instrumentation (HyperDbg, Intel PT).

**Console output was not captured by WriteConsoleW/A hooks.** Despite all binaries producing visible console output over SSH, zero `println!` lines were captured by Frida. Rust's `println!` macro routes through the CRT (`__acrt_iob_func`) to `WriteFile` on a console handle, not through `WriteConsoleW`. Hooking `WriteFile` and filtering by handle type would capture this.

**Enigma is the leakiest protector in both dimensions.** Statically: self-identifying URLs and strings. Dynamically: 905 resolved imports from an embedded Delphi VCL framework, plus its own license-checking registry key (`Software\Enigma Protector\...`). It exposes more about itself than about the protected application.

### Practical Recommendations

| If you encounter... | Approach |
|---|---|
| Code Virtualizer (stealth mode) | Static analysis alone recovers nearly everything. Import table, strings, and debug info are intact. |
| Enigma Protector | Frida hooks with basic anti-debug bypass are sufficient. The embedded VCL runtime creates noise — filter for application-specific APIs. |
| Obsidium | Frida with anti-debug bypass recovers all behaviour. Expect heavy VirtualProtect overhead. |
| WinLicense / Themida (code-virt only) | Frida API hooks recover all behaviour. Zero bypasses needed if no SE* macros used. |
| Themida (full, with SE macros) | Requires CPUID hiding + full Frida anti-debug/anti-VM bypass suite. May still block application-level hooks. |
| VMProtect (with anti-VM) | Requires full Proxmox hardening including patched OVMF firmware. `VMProtectIsVirtualMachinePresent()` checks beyond standard APIs. Consider bare-metal analysis. |
| VXLang | Frida is insufficient. Use kernel-level instrumentation (HyperDbg, Intel PT) or sandbox-based analysis (CAPEv2). |

### Reproducing These Tests

The test scripts are in the repository at `output/protect_test/`:

```
output/protect_test/
├── protect_hooks.js      # Combined Frida script (bypass + 10 API hooks + import tracking)
├── run_protect_test.py   # Python runner (iterates binaries, collects JSON results)
├── deploy.sh             # SCP deployment helper
└── results/              # Per-binary JSON + comparison.json
```

Run on the Windows VM:

```powershell
cd C:\Malware\protect_test
python run_protect_test.py --samples-dir C:\Malware\Protect --timeout 30
```

The runner spawns each binary under Frida, loads `protect_hooks.js`, waits for exit or timeout, then saves structured results to `results/<binary>.json` with a comparison report at the end.

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

- **Hypervisor configuration required** -- CPUID detection cannot be bypassed from userspace. You must configure your hypervisor to hide the hypervisor bit and spoof SMBIOS/ACPI data. Without this, binaries hang or exit during the protector's initialisation. See [Hypervisor Configuration](#hypervisor-configuration) for the full Proxmox setup.
- **VMProtect direct syscalls** -- VMProtect makes direct `syscall` instructions that bypass ntdll.dll entirely. Frida's API hooks on ntdll functions never fire. VMProtect requires VM indicators to be eliminated at the hypervisor level (SMBIOS, ACPI, disk model, OVMF firmware branding). Proxmox's OVMF embeds "Proxmox distribution of EDK II" as a compile-time constant that cannot be changed via configuration — requires a custom firmware build or the [proxmox-ve-anti-detection](https://github.com/zhaodice/proxmox-ve-anti-detection) patched QEMU.
- **Frida memory scanning** -- Themida scans process memory for Frida signatures. Standard spawn-mode injection works (the agent loads after Themida's memory scan), but frida-gadget sideloading via DLL proxy does not (the gadget is present during Themida's init). If spawn mode fails, you may need to build Frida from source with signature strings removed.
- **Coverage vs timing** -- Frida's Stalker engine adds 10-100x overhead per basic block. Protectors with RDTSC timing checks (Themida, VMProtect) will detect this slowdown. Use API logging alone for timing-sensitive binaries.
- **Code integrity checks** -- Themida's `SECheckCodeIntegrity()` verifies CRC checksums of code sections. Do not modify the binary's code sections (no import table patching, no CPUID byte patching). Use API hooks and hypervisor config instead.
- **Bytecode is not devirtualised** -- The VM interpreter's custom bytecode is not reversed. Code-level understanding of virtualised functions requires manual analysis of the VM dispatcher. Arkana helps you understand *what the binary does* without needing to understand *how the VM works*.
- **Frida 17.x API change** -- `Module.getExportByName(null, "Name")` was removed. Use `Process.getModuleByName("DLL").getExportByName("Name")`. See [Frida 17.x API Changes](#frida-17x-api-changes).

---

*See also: [Analysis Methodology](methodology.md) | [Tools Reference](tools-reference.md) | [Configuration](configuration.md)*
