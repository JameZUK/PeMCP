# Malware Analysis Report: CrySome RAT — Full-Featured .NET RAT with Factory Reset Survival

**Analyst:** Arkana Automated Analysis
**Date:** 2026-03-31
**Classification:** Remote Access Trojan (RAT) / .NET / Modular
**Risk Level:** CRITICAL (83/100)
**Source:** VirusTotal (CYFIRMA IOC, 51/76 detections)

---

## 1. Executive Summary

This report documents the analysis of **CrySome RAT**, a full-featured **.NET 4.7.2 Remote Access Trojan** written in C# with an unusually aggressive anti-removal and persistence architecture. The sample was sourced from VirusTotal using IOC hashes published in CYFIRMA's original research disclosure (first observed 2026-03-20).

The binary is **completely unobfuscated** -- `detect_dotnet_obfuscation` found zero protections, and full ILSpy decompilation recovered **124 C# source files** with clean, readable class and method names across well-organised namespaces (`Crysome.Client`, `Crysome.Common.Network`, `Crysome.Client.Handlers`). Dependencies are embedded via **Costura.Fody** (NAudio for audio capture, AForge for webcam, Microsoft.Win32.Registry), which inflated entropy to 7.46 in the `.text` section and triggered a false-positive PEiD match for "ASProtect v1.32" -- the .NET metadata was fully intact beneath.

CrySome implements **18 modular capabilities** controlled by feature flags in a JSON configuration: remote desktop, HVNC (hidden VNC for 6 browsers), webcam capture, audio surveillance, keylogging, credential theft via DLL injection, file management, process control, SOCKS proxy, reverse proxy, command execution, and chat. The C2 address defaults to `127.0.0.1:7777` and is patched at build time via marker strings (`##CRYCFG##` / `##CRYCONFIG##`).

The most significant finding is the **5-layer persistence and anti-removal system**: scheduled tasks, RunOnce registry, a Windows service (`WindowsHealthMonitor`), mutual watchdog processes, and -- most notably -- **Windows Recovery partition persistence** that copies the binary to `C:\Recovery\OEM\` and modifies `ResetConfig.xml` to survive factory resets. The self-protection module marks the process as **critical via `RtlSetProcessIsCritical`** (killing it causes a BSOD), applies **DACL protection** denying termination rights, and masquerades as `RuntimeBroker.exe` and `conhost.exe`.

The **AV killer** module simultaneously deploys 5 attack vectors against 114+ security products: PowerShell Defender neutralisation, IFEO traps for 34 AV executables, service disabling for 41 AV services, hosts file poisoning of 33 update domains, and a continuous process kill loop with AV installer interception.

---

## 2. Sample Information

| Property | Value |
|----------|-------|
| **Filename** | Crysome.Client.exe |
| **SHA-256** | `f30f32937999abe4fa6e90234773e0528a4b2bd1d6de5323d59ac96cdb58f25d` |
| **MD5** | `03898be29fb6c5464b28ae0239713b7b` |
| **SHA-1** | `a89158fe7d762dca8f136498a4120e3597933cab` |
| **ssdeep** | `12288:zhoUZeviEqMeV89bROjl/1yJIRHqPuCA6H4pD0ai95WQHlTt:GUkn7eWBR5JIRR16zxvWaTt` |
| **File Size** | 520,704 bytes (509 KB) |
| **Format** | PE32, .NET CIL, Windows GUI |
| **Runtime** | CLR v2.5, metadata v4.0.30319 (.NET Framework 4.7.2) |
| **Signed** | No |
| **Sections** | 3 (.text 7.46 entropy, .rsrc 4.12, .reloc 0.08) |
| **Imports** | 1 function from 1 DLL (mscoree.dll `_CorExeMain`) |
| **Obfuscation** | None (type name entropy 3.39, method name entropy 2.88) |
| **Packing** | Costura.Fody (dependency embedding only) |
| **PDB Path** | `C:\Users\ztz\Desktop\pace-main\pace-main\src\Crysome.Client\obj\Release\net472\Crysome.Client.pdb` |
| **Developer** | Username `ztz`, project `pace-main` |
| **VT Detection** | 51/76 (`trojan.msil/barys`) |
| **VT First Seen** | 2026-03-20 |
| **VT Names** | `Crysome.Client.exe`, `RuntimeBroker.exe`, `conhost.exe`, `DMMDJJ37FUYD.exe` |

### PEiD False Positive

PEiD matched "ASProtect v1.32" and `classify_binary_purpose` reported `has_dotnet: false` due to the Costura.Fody resource embedding inflating `.text` section entropy to 7.46. However, VirusTotal TrID correctly identified it as "Generic CIL Executable (.NET)" at 70.4% probability, and `dotnet_analyze` confirmed full CLR metadata with 173 types, 954 methods, and 13 assembly references. The .NET metadata was never encrypted -- only the embedded dependency DLLs (NAudio, AForge) are Deflate-compressed as resources.

---

## 3. C2 Configuration

### 3.1 Configuration System (`ClientConfiguration.cs`)

CrySome uses a three-tier configuration loading chain with build-time patching:

| Priority | Source | Marker | Description |
|----------|--------|--------|-------------|
| 1 | Embedded string | `##CRYCFG##` | Builder patches a 500-char padded field in the binary |
| 2 | EXE tail | `##CRYCONFIG##` | Appended to last 1024 bytes of the executable |
| 3 | JSON file | `config.json` | Falls back to file in same directory as executable |

**Default configuration** (pre-builder patch):
```json
{
  "host": "127.0.0.1",
  "port": 7777,
  "group": "",
  "persistence": false,
  "feat": null,
  "parent": ""
}
```

### 3.2 Feature Flags

The `feat` field controls which modules are loaded. When `null` (default), **all 18 features are enabled**:

| Flag | Module | Capability |
|------|--------|------------|
| `protect` | SelfProtect | Watchdog, BSOD protection, DACL, file lock, relocation |
| `avkill` | AVKiller | 5-vector AV neutralisation |
| `survival` | Survival | Service + recovery partition persistence |
| `cmd` | CommandHandlers | Arbitrary command execution |
| `direct` | DirectLinkHandlers | URL download and execute |
| `file` | FileTransferHandlers | Bidirectional file transfer |
| `screen` | SystemHandlers | On-demand screenshots |
| `restart` | SystemHandlers | Remote reboot |
| `filemgr` | FileHandlers | Drive enum, directory browse, read/delete/upload |
| `proxy` | ProxyHandlers | Forward SOCKS proxy |
| `proc` | ProcessHandlers | Process list and kill |
| `audio` | AudioHandlers | Microphone streaming (NAudio) |
| `cam` | CameraHandlers | Webcam capture (AForge) |
| `rdp` | RemoteDesktopHandlers | Screen streaming + mouse/keyboard input |
| `hvnc` | HvncHandlers | Hidden desktop per-browser |
| `cred` | CredentialsHandlers | Browser credential theft via DLL injection |
| `keylog` | KeyloggerHandlers | Low-level keyboard hook |
| `chat` | ChatHandlers | Operator-to-victim popup chat |

### 3.3 Network Protocol

| Property | Value |
|----------|-------|
| **Transport** | Raw TCP socket |
| **Framing** | 4-byte little-endian length prefix + payload |
| **Max Frame** | 200 MB (209,715,200 bytes) |
| **Serialization** | Custom binary via `PacketSerializer` (type byte + `BinaryWriter` fields) |
| **Compression** | QuickLZ (embedded implementation) |
| **Reconnect** | 5-second main loop, 10-second connect retry |
| **Thread Safety** | `_sendLock` object for serialised writes |
| **Identifier** | `Crysome-01` (default, configurable) |

### 3.4 Registration Beacon

On connection, sends `ClientInfoResponsePacket` with:
- Configured identifier and group
- Remote/local IP addresses and port
- Username, computer name, operating system
- Active window title
- System uptime
- Country code

---

## 4. Persistence & Anti-Removal (5 Layers)

### 4.1 Scheduled Task (`Persistence.cs`)

```
schtasks /create /tn "CrysomeLoader" /tr "{exe_path}" /sc minute /mo 5 /f
```

Runs every 5 minutes. Only installed when `ClientConfiguration.Persistence` is `true`.

### 4.2 Registry RunOnce (`SelfProtect.cs`)

Writes to `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`:
- **Value name**: `RuntimeBroker`
- **Value data**: Path to primary or current executable

### 4.3 Windows Service (`Survival.cs`)

| Property | Value |
|----------|-------|
| **Service Name** | `WindowsHealthMonitor` |
| **Display Name** | "Windows System Health Monitor" |
| **Description** | "Monitors system health and performance diagnostics." |
| **Start Type** | Automatic |
| **Failure Action** | Restart after 60 seconds (3 attempts) |

### 4.4 Mutual Watchdog (`SelfProtect.cs`)

The most sophisticated persistence mechanism -- a **bidirectional process monitoring system**:

1. **Main process** spawns a **watcher** via `--watcher {pid}` argument using the backup executable
2. **Watcher** monitors main process every 2.5 seconds; if it exits, waits 800ms then restarts from best available copy
3. **Main process** monitors watcher every 3 seconds; if it exits, respawns it
4. Both processes continuously verify backup copies exist (`EnsureBackups()`)

File locations:
- **Primary**: `%APPDATA%\Microsoft\Windows\RuntimeBroker.exe`
- **Backup**: `%LOCALAPPDATA%\Microsoft\CLR\conhost.exe`
- Both marked Hidden + System attributes; directories also hidden

### 4.5 Recovery Partition Persistence (`Survival.cs`)

The most noteworthy finding -- **survives Windows factory reset**:

1. Copies binary to `C:\Recovery\OEM\{12-char-random}.exe`
2. Creates or modifies `C:\Recovery\OEM\ResetConfig.xml`
3. Injects `<Run>` elements for both `BasicReset_AfterImageApply` and `FactoryReset_AfterImageApply` phases
4. The batch script loads the offline registry hive (`HKLM\SOFTWARE`) and writes a `RunOnce` key
5. On factory reset, Windows executes the batch → registers the malware for first-boot autorun

```batch
reg load HKLM\{random} %TARGETOSDRIVE%\windows\system32\config\SOFTWARE
reg add HKLM\{random}\Microsoft\Windows\CurrentVersion\RunOnce /v {random} /t REG_SZ /d "{payload}" /f
reg unload HKLM\{random}
```

If `ResetConfig.xml` already exists with legitimate reset scripts, the malware **preserves the original entries** and appends its own payload to the existing scripts -- avoiding detection by not replacing the file.

---

## 5. Self-Protection

### 5.1 Critical Process Flag

```csharp
RtlSetProcessIsCritical(bNew: true, ref pbOld, bNeedScb: false);
```

Calls `ntdll!RtlSetProcessIsCritical` to mark the process as system-critical. **Killing the process causes a Blue Screen of Death** (BSOD with `CRITICAL_PROCESS_DIED`). Requires `SeDebugPrivilege` via `Process.EnterDebugMode()`.

### 5.2 DACL Protection

```csharp
ConvertStringSecurityDescriptorToSecurityDescriptor("D:(D;;0x0001;;;WD)", ...);
SetKernelObjectSecurity(handle, 4, securityDescriptor);
```

Applies a **Deny ACE** for `PROCESS_TERMINATE` (0x0001) to the **World SID** (`WD` = Everyone). Task Manager and other tools cannot terminate the process.

### 5.3 File Lock

Opens own executable with `FileShare.Read` -- prevents deletion, modification, or exclusive access by AV scanners while the process is running.

### 5.4 Parent PID Spoofing (`ParentSpoof.cs`)

Uses `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` with `CreateProcess(EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW)` to spawn under a configurable parent process (e.g., `explorer.exe`). This makes the RAT appear as a child of a legitimate system process in tools like Process Explorer.

---

## 6. AV Killer (5 Attack Vectors)

### 6.1 Windows Defender Neutralisation

**PowerShell** (single command):
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true
  -DisableBehaviorMonitoring $true -DisableScriptScanning $true
  -DisableBlockAtFirstSeen $true
```

**Registry** (8 keys set in parallel):
- `DisableAntiSpyware = 1`
- `DisableRealtimeMonitoring = 1`
- `DisableBehaviorMonitoring = 1`
- `DisableOnAccessProtection = 1`
- `DisableScanOnRealtimeEnable = 1`
- `TamperProtection = 0`
- `SpyNetReporting = 0`
- `SubmitSamplesConsent = 2`

**Scheduled tasks disabled**: Windows Defender Scheduled Scan, Cache Maintenance, Verification.

### 6.2 Image File Execution Options (IFEO) Traps

Sets `Debugger` registry value to `cmd.exe /c echo` for **34 AV executables**:

| Vendor | Targeted Executables |
|--------|---------------------|
| Kaspersky | `avp.exe`, `avpui.exe` |
| ESET | `ekrn.exe`, `egui.exe` |
| Bitdefender | `bdagent.exe`, `vsserv.exe`, `bdservicehost.exe` |
| Avast | `AvastSvc.exe`, `AvastUI.exe`, `afwServ.exe` |
| AVG | `AVGSvc.exe`, `AVGUI.exe` |
| Malwarebytes | `MBAMService.exe`, `mbamtray.exe` |
| CrowdStrike | `CSFalconService.exe`, `csagent.exe` |
| SentinelOne | `SentinelAgent.exe`, `SentinelServiceHost.exe` |
| Cylance | `CylanceSvc.exe`, `CylanceUI.exe` |
| Norton/Symantec | `NortonSecurity.exe`, `ccSvcHst.exe` |
| McAfee | `McShield.exe`, `masvc.exe` |
| F-Secure | `fshoster.exe`, `FSMA32.exe` |
| Sophos | `SavService.exe`, `SAVAdminService.exe` |
| Webroot | `WRSA.exe`, `WRCoreService.exe` |
| Emsisoft | `a2service.exe`, `a2guard.exe` |
| Panda | `PSANHost.exe`, `PSUAMain.exe` |

When any of these executables launches, Windows instead executes `cmd.exe /c echo` -- silently preventing the AV from starting.

### 6.3 Service Disabling

Stops and disables **41 AV services** using both `sc.exe stop/config` and `net.exe stop`:

Targets include: `WinDefend`, `WdNisSvc`, `SecurityHealthService`, `wscsvc`, `Sense`, `McShield`, `masvc`, `AVP`, `kavfsgt`, `VSSERV`, `avast! Antivirus`, `ekrn`, `EsetService`, `MBAMService`, `ntrtscan`, `SAVService`, `CSFalconService`, `SentinelAgent`, `CylanceSvc`, `CbDefense`, and 21 more.

Enables `SeDebugPrivilege` first via `AdjustTokenPrivileges` for elevated service access.

### 6.4 Hosts File Poisoning

Appends **33 AV update domains** redirected to `0.0.0.0` in the hosts file (marker: `# avk-block`):

```
0.0.0.0 update.nai.com
0.0.0.0 download.mcafee.com
0.0.0.0 dnl-01.geo.kaspersky.com
0.0.0.0 download.eset.com
0.0.0.0 download.bitdefender.com
0.0.0.0 download.sophos.com
0.0.0.0 definitions.symantec.com
0.0.0.0 downloads.malwarebytes.com
...
```

### 6.5 Continuous Process Kill Loop

Runs every **2 seconds** with `Parallel.ForEach`:
- Kills **114 AV process names** (MsMpEng, avp, ekrn, bdagent, AvastSvc, AVGUI, MBAMService, CSFalconService, SentinelAgent, CylanceSvc, etc.)
- **Intercepts AV installers**: Monitors for `msiexec`, processes containing "setup" or "install" -- checks command line and file path against 42 AV keywords, kills matching processes and their entire process tree

---

## 7. Credential Theft (`CredentialsHandlers.cs`)

### 7.1 DLL Injection into Browsers

The credential module uses **classic DLL injection** to steal browser credentials:

1. Server sends `RequestCredentialsPacket` containing `abe_decrypt.dll` bytes
2. Client kills all browser processes (Chrome, Brave, Edge)
3. Writes DLL to `%TEMP%\abe_decrypt.dll`
4. For each browser:
   - Creates process **suspended** with `--headless=new --disable-gpu --no-sandbox`
   - Allocates memory in target process via `VirtualAllocEx`
   - Writes DLL path via `WriteProcessMemory`
   - Creates remote thread calling `LoadLibraryW` via `CreateRemoteThread`
   - Waits for injection, then resumes main thread
5. After injection settles (5-8 seconds), reads `passwords.json` and `cookies.json` from output directory
6. Sends `CredentialsResponsePacket` with passwords and cookies back to C2

| Browser | Registry Path | Wait Time |
|---------|--------------|-----------|
| Chrome | `App Paths\chrome.exe` | 5 seconds |
| Brave | `App Paths\brave.exe` | 5 seconds |
| Edge | `App Paths\msedge.exe` | 8 seconds |

---

## 8. HVNC — Hidden Virtual Network Computing

### 8.1 Architecture

The HVNC module creates a **hidden Windows desktop** and runs browser instances on it, invisible to the victim:

- **`HvncProcessHandler.cs`**: Manages browser processes on the hidden desktop, supports Chrome, Edge, Firefox, Opera, OperaGX, and Brave with dedicated `--user-data-dir` paths
- **`HvncImagingHandler.cs`**: Captures screen frames from the hidden desktop for the operator
- **`HvncInputHandler.cs`**: Relays mouse clicks, key presses, and scrolling to the hidden desktop

### 8.2 Browser Launch Profiles

Each browser is launched with isolation flags to avoid interfering with the victim's real browser sessions:

| Browser | User Data Directory | Extra Flags |
|---------|-------------------|-------------|
| Chrome | `C:\ChromeAutomationData` | `--no-sandbox --allow-no-sandbox-job --disable-gpu` |
| Edge | `C:\EdgeAutomationData` | `--no-sandbox --allow-no-sandbox-job --disable-gpu` |
| Firefox | `C:\FirefoxAutomationData` | `-no-remote -profile` |
| Opera | `C:\OperaAutomationData` | `--no-sandbox --allow-no-sandbox-job --disable-gpu` |
| OperaGX | `C:\OperaGXAutomationData` | `--no-sandbox --allow-no-sandbox-job --disable-gpu` |
| Brave | `C:\BraveAutomationData` | `--no-sandbox --allow-no-sandbox-job --disable-gpu` |

This allows the operator to perform banking fraud, session hijacking, or account takeover on the victim's machine while the victim sees nothing unusual on their own desktop.

---

## 9. Surveillance Capabilities

### 9.1 Keylogger (`KeyloggerHandlers.cs`)

- **Hook type**: `WH_KEYBOARD_LL` (ID 13) via `SetWindowsHookEx`
- **Buffer**: 500 characters or 2-second flush interval
- **Key mapping**: Alphanumeric, punctuation, space, enter, backspace, tab
- **Exfiltration**: `KeylogDataPacket` sent to C2 on buffer flush
- **Message pump**: Background thread with `PeekMessage`/`TranslateMessage`/`DispatchMessage` loop (20ms polling)

### 9.2 Audio Capture

Uses **NAudio** library (7 embedded DLLs: NAudio, NAudio.Core, NAudio.WinMM, NAudio.WinForms, NAudio.Wasapi, NAudio.Asio, NAudio.Midi):
- Device enumeration via `GetAudioDevicesPacket`
- Streaming capture via `StartAudioStreamPacket` / `StopAudioStreamPacket`
- One-shot recording via `RequestAudioPacket`

### 9.3 Webcam Capture

Uses **AForge.Video.DirectShow** (2 embedded DLLs):
- Camera enumeration via `GetCameraDevicesPacket`
- Frame-by-frame capture via `RequestCameraFramePacket`

### 9.4 Remote Desktop

- Screen enumeration via `GetScreensRequestPacket` (multi-monitor support)
- Continuous frame streaming via `StartRemoteDesktopPacket`
- Mouse and keyboard input relay via `RemoteInputPacket`

---

## 10. Embedded Dependencies (Costura.Fody)

| Resource | Version | Purpose |
|----------|---------|---------|
| `costura.naudio.dll.compressed` | 2.2.1.0 | Audio framework |
| `costura.naudio.core.dll.compressed` | 2.2.1.0 | NAudio core |
| `costura.naudio.winmm.dll.compressed` | 2.2.1.0 | WinMM audio backend |
| `costura.naudio.wasapi.dll.compressed` | 2.2.1.0 | WASAPI audio backend |
| `costura.naudio.winforms.dll.compressed` | 2.2.1.0 | WinForms audio controls |
| `costura.naudio.asio.dll.compressed` | 2.2.1.0 | ASIO audio backend |
| `costura.naudio.midi.dll.compressed` | 2.2.1.0 | MIDI support |
| `costura.aforge.video.dll.compressed` | 2.2.0.0 | Video framework |
| `costura.aforge.video.directshow.dll.compressed` | 2.2.0.0 | DirectShow webcam |
| `costura.microsoft.win32.registry.dll.compressed` | 4.1.3.0 | Registry access |
| `costura.system.security.accesscontrol.dll.compressed` | 4.1.3.0 | ACL manipulation |
| `costura.system.security.principal.windows.dll.compressed` | 4.1.3.0 | Windows identity |
| `costura.system.diagnostics.diagnosticsource.dll.compressed` | — | Diagnostics |
| `costura.costura.dll.compressed` | 5.7.0.0 | Costura runtime loader |

---

## 11. MITRE ATT&CK Mapping

| Tactic | ID | Technique | Source |
|--------|-----|-----------|--------|
| Execution | T1059.001 | PowerShell | AVKiller: Defender disable commands |
| Execution | T1053.005 | Scheduled Task | Persistence: `CrysomeLoader` every 5 min |
| Persistence | T1543.003 | Windows Service | Survival: `WindowsHealthMonitor` auto-start |
| Persistence | T1547.001 | Registry Run Keys | SelfProtect: `RunOnce\RuntimeBroker` |
| Persistence | T1547.014 | Active Setup | Survival: Recovery partition `ResetConfig.xml` |
| Defense Evasion | T1562.001 | Disable Security Tools | AVKiller: 5 simultaneous attack vectors |
| Defense Evasion | T1562.004 | Indicator Blocking | AVKiller: hosts file poisoning (33 domains) |
| Defense Evasion | T1546.012 | IFEO Injection | AVKiller: 34 AV executables redirected |
| Defense Evasion | T1134.004 | Parent PID Spoofing | ParentSpoof: `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` |
| Defense Evasion | T1564.001 | Hidden Files/Directories | SelfProtect: Hidden + System attributes |
| Defense Evasion | T1036.005 | Match Legitimate Name | SelfProtect: `RuntimeBroker.exe`, `conhost.exe` |
| Credential Access | T1555.003 | Credentials from Browsers | CredentialsHandlers: DLL injection + `abe_decrypt.dll` |
| Collection | T1056.001 | Keylogging | KeyloggerHandlers: `WH_KEYBOARD_LL` hook |
| Collection | T1113 | Screen Capture | SystemHandlers: screenshot + remote desktop |
| Collection | T1125 | Video Capture | CameraHandlers: AForge DirectShow webcam |
| Collection | T1123 | Audio Capture | AudioHandlers: NAudio microphone streaming |
| Discovery | T1057 | Process Discovery | ProcessHandlers: process list enumeration |
| Discovery | T1082 | System Information | SystemInformation: OS, uptime, country code |
| Command and Control | T1095 | Non-Application Layer Protocol | Custom TCP with length-prefixed binary framing |
| Command and Control | T1090 | Proxy | ProxyHandlers: SOCKS + reverse proxy |
| Impact | T1489 | Service Stop | AVKiller: 41 AV services stopped and disabled |

---

## 12. Indicators of Compromise

### File System

| Indicator | Path |
|-----------|------|
| Primary binary | `%APPDATA%\Microsoft\Windows\RuntimeBroker.exe` |
| Backup binary | `%LOCALAPPDATA%\Microsoft\CLR\conhost.exe` |
| Recovery stub | `C:\Recovery\OEM\{random12}.exe` |
| Recovery backup | `C:\Recovery\OEM\CrysomeBackup\` |
| Recovery config | `C:\Recovery\OEM\ResetConfig.xml` |
| Debug log | `%TEMP%\Crysome_debug.log` |
| Credential DLL | `%TEMP%\abe_decrypt.dll` |
| HVNC data | `C:\ChromeAutomationData\`, `C:\EdgeAutomationData\`, etc. |

### Registry

| Key | Value |
|-----|-------|
| `HKCU\...\RunOnce\RuntimeBroker` | Path to primary executable |
| `HKLM\...\Image File Execution Options\{34 AV exes}\Debugger` | `cmd.exe /c echo` |
| `HKLM\...\Windows Defender\*` | 8 keys disabling protections |

### Services & Tasks

| Name | Type |
|------|------|
| `WindowsHealthMonitor` | Windows Service (auto-start) |
| `CrysomeLoader` | Scheduled Task (every 5 minutes) |

### Process Indicators

| Indicator | Value |
|-----------|-------|
| Mutex | `Global\CrysomeClient.InstanceMutex` |
| Watcher argument | `--watcher {pid}` |
| Spoofed argument | `--spoofed` |
| Critical process | `RtlSetProcessIsCritical` call |

### Network

| Type | Value |
|------|-------|
| Default C2 | `127.0.0.1:7777` (builder-patched) |
| Hosts marker | `# avk-block` in hosts file |
| 33 AV domains | Redirected to `0.0.0.0` (see Section 6.4) |

### File Hashes

| Algorithm | Hash |
|-----------|------|
| SHA-256 | `f30f32937999abe4fa6e90234773e0528a4b2bd1d6de5323d59ac96cdb58f25d` |
| MD5 | `03898be29fb6c5464b28ae0239713b7b` |
| SHA-1 | `a89158fe7d762dca8f136498a4120e3597933cab` |

---

## 13. Detection Guidance

### Behavioural Indicators

1. **Hosts file modification** with `# avk-block` marker
2. **IFEO registry writes** with `Debugger = cmd.exe /c echo` for AV executables
3. **`RtlSetProcessIsCritical`** API call from non-system process
4. **`ResetConfig.xml` modification** outside of Windows setup context
5. **Service creation** named `WindowsHealthMonitor` from user-mode process
6. **Browser processes** launched with `--headless=new --no-sandbox` from non-browser parent
7. **Mutual process monitoring** pattern: parent spawns child with `--watcher {pid}`

### YARA Rule

A YARA detection rule was auto-generated and validated against the sample. Key string indicators include the PDB path (`C:\Users\ztz\Desktop\pace-main\...`), Costura resource names, and namespace strings (`Crysome.Common.Network`, `Crysome.Client.Network`). The rule is available as an artifact.

---

## 14. Conclusion

CrySome RAT is a well-engineered, full-featured .NET RAT that stands out from commodity RATs primarily through its **anti-removal architecture**. While the capabilities themselves (HVNC, keylogger, credential theft, remote desktop) are standard for modern RATs, the combination of **mutual watchdog processes**, **critical process BSOD protection**, **DACL termination denial**, and especially **Windows factory reset survival** via Recovery partition hijacking represents an unusually hardened persistence model.

The complete absence of obfuscation is noteworthy -- either the developer prioritises rapid development over stealth, or this is a "cracked" version that has had protections stripped. VirusTotal names support the latter interpretation: `CrySome RAT Cracked/Crysome.Client.exe` appears in submission paths.

The AV killer's breadth (114 process names, 41 services, 34 IFEO targets, 33 update domains) suggests active maintenance and awareness of the current security product landscape. The 5-vector simultaneous approach -- disabling, killing, trapping, blocking updates, and intercepting installers -- is designed to be resilient against any single countermeasure.
