"""Frida JS template generation — pure data and string builders, no MCP dependency."""
from typing import Dict, List, Optional, Any


# =====================================================================
#  API Signature Database (for argument formatting in hooks)
# =====================================================================

FRIDA_API_SIGNATURES: Dict[str, Dict[str, Any]] = {
    # --- Process Injection ---
    "CreateRemoteThread": {
        "args": ["hProcess:HANDLE", "lpThreadAttributes:ptr", "dwStackSize:uint",
                 "lpStartAddress:ptr", "lpParameter:ptr", "dwCreationFlags:uint", "lpThreadId:ptr"],
        "return": "HANDLE",
        "category": "process_injection",
    },
    "WriteProcessMemory": {
        "args": ["hProcess:HANDLE", "lpBaseAddress:ptr", "lpBuffer:ptr",
                 "nSize:uint", "lpNumberOfBytesWritten:ptr"],
        "return": "BOOL",
        "category": "process_injection",
    },
    "VirtualAllocEx": {
        "args": ["hProcess:HANDLE", "lpAddress:ptr", "dwSize:uint",
                 "flAllocationType:uint", "flProtect:uint"],
        "return": "ptr",
        "category": "process_injection",
    },
    "NtWriteVirtualMemory": {
        "args": ["ProcessHandle:HANDLE", "BaseAddress:ptr", "Buffer:ptr",
                 "BufferSize:uint", "NumberOfBytesWritten:ptr"],
        "return": "NTSTATUS",
        "category": "process_injection",
    },
    "QueueUserAPC": {
        "args": ["pfnAPC:ptr", "hThread:HANDLE", "dwData:uint"],
        "return": "BOOL",
        "category": "process_injection",
    },
    "NtQueueApcThread": {
        "args": ["ThreadHandle:HANDLE", "ApcRoutine:ptr", "ApcArgument1:ptr",
                 "ApcArgument2:ptr", "ApcArgument3:ptr"],
        "return": "NTSTATUS",
        "category": "process_injection",
    },
    # --- Process Creation ---
    "CreateProcessA": {
        "args": ["lpApplicationName:str", "lpCommandLine:str", "lpProcessAttributes:ptr",
                 "lpThreadAttributes:ptr", "bInheritHandles:BOOL", "dwCreationFlags:uint",
                 "lpEnvironment:ptr", "lpCurrentDirectory:str", "lpStartupInfo:ptr",
                 "lpProcessInformation:ptr"],
        "return": "BOOL",
        "category": "process_creation",
    },
    "CreateProcessW": {
        "args": ["lpApplicationName:wstr", "lpCommandLine:wstr", "lpProcessAttributes:ptr",
                 "lpThreadAttributes:ptr", "bInheritHandles:BOOL", "dwCreationFlags:uint",
                 "lpEnvironment:ptr", "lpCurrentDirectory:wstr", "lpStartupInfo:ptr",
                 "lpProcessInformation:ptr"],
        "return": "BOOL",
        "category": "process_creation",
    },
    "WinExec": {
        "args": ["lpCmdLine:str", "uCmdShow:uint"],
        "return": "uint",
        "category": "process_creation",
    },
    "ShellExecuteA": {
        "args": ["hwnd:HANDLE", "lpOperation:str", "lpFile:str",
                 "lpParameters:str", "lpDirectory:str", "nShowCmd:int"],
        "return": "HANDLE",
        "category": "process_creation",
    },
    "ShellExecuteW": {
        "args": ["hwnd:HANDLE", "lpOperation:wstr", "lpFile:wstr",
                 "lpParameters:wstr", "lpDirectory:wstr", "nShowCmd:int"],
        "return": "HANDLE",
        "category": "process_creation",
    },
    # --- Memory Operations ---
    "VirtualAlloc": {
        "args": ["lpAddress:ptr", "dwSize:uint", "flAllocationType:uint", "flProtect:uint"],
        "return": "ptr",
        "category": "memory",
    },
    "VirtualProtect": {
        "args": ["lpAddress:ptr", "dwSize:uint", "flNewProtect:uint", "lpflOldProtect:ptr"],
        "return": "BOOL",
        "category": "memory",
    },
    "HeapCreate": {
        "args": ["flOptions:uint", "dwInitialSize:uint", "dwMaximumSize:uint"],
        "return": "HANDLE",
        "category": "memory",
    },
    # --- Networking ---
    "InternetOpenA": {
        "args": ["lpszAgent:str", "dwAccessType:uint", "lpszProxy:str",
                 "lpszProxyBypass:str", "dwFlags:uint"],
        "return": "HANDLE",
        "category": "networking",
    },
    "InternetOpenUrlA": {
        "args": ["hInternet:HANDLE", "lpszUrl:str", "lpszHeaders:str",
                 "dwHeadersLength:uint", "dwFlags:uint", "dwContext:uint"],
        "return": "HANDLE",
        "category": "networking",
    },
    "HttpOpenRequestA": {
        "args": ["hConnect:HANDLE", "lpszVerb:str", "lpszObjectName:str",
                 "lpszVersion:str", "lpszReferrer:str", "lplpszAcceptTypes:ptr",
                 "dwFlags:uint", "dwContext:uint"],
        "return": "HANDLE",
        "category": "networking",
    },
    "send": {
        "args": ["s:SOCKET", "buf:ptr", "len:int", "flags:int"],
        "return": "int",
        "category": "networking",
    },
    "recv": {
        "args": ["s:SOCKET", "buf:ptr", "len:int", "flags:int"],
        "return": "int",
        "category": "networking",
    },
    "connect": {
        "args": ["s:SOCKET", "name:ptr", "namelen:int"],
        "return": "int",
        "category": "networking",
    },
    "WSAStartup": {
        "args": ["wVersionRequested:uint", "lpWSAData:ptr"],
        "return": "int",
        "category": "networking",
    },
    # --- File Operations ---
    "CreateFileA": {
        "args": ["lpFileName:str", "dwDesiredAccess:uint", "dwShareMode:uint",
                 "lpSecurityAttributes:ptr", "dwCreationDisposition:uint",
                 "dwFlagsAndAttributes:uint", "hTemplateFile:HANDLE"],
        "return": "HANDLE",
        "category": "file_io",
    },
    "CreateFileW": {
        "args": ["lpFileName:wstr", "dwDesiredAccess:uint", "dwShareMode:uint",
                 "lpSecurityAttributes:ptr", "dwCreationDisposition:uint",
                 "dwFlagsAndAttributes:uint", "hTemplateFile:HANDLE"],
        "return": "HANDLE",
        "category": "file_io",
    },
    "WriteFile": {
        "args": ["hFile:HANDLE", "lpBuffer:ptr", "nNumberOfBytesToWrite:uint",
                 "lpNumberOfBytesWritten:ptr", "lpOverlapped:ptr"],
        "return": "BOOL",
        "category": "file_io",
    },
    "ReadFile": {
        "args": ["hFile:HANDLE", "lpBuffer:ptr", "nNumberOfBytesToRead:uint",
                 "lpNumberOfBytesRead:ptr", "lpOverlapped:ptr"],
        "return": "BOOL",
        "category": "file_io",
    },
    "DeleteFileA": {
        "args": ["lpFileName:str"],
        "return": "BOOL",
        "category": "file_io",
    },
    # --- Registry ---
    "RegOpenKeyExA": {
        "args": ["hKey:HANDLE", "lpSubKey:str", "ulOptions:uint",
                 "samDesired:uint", "phkResult:ptr"],
        "return": "LONG",
        "category": "registry",
    },
    "RegSetValueExA": {
        "args": ["hKey:HANDLE", "lpValueName:str", "Reserved:uint",
                 "dwType:uint", "lpData:ptr", "cbData:uint"],
        "return": "LONG",
        "category": "registry",
    },
    "RegCreateKeyExA": {
        "args": ["hKey:HANDLE", "lpSubKey:str", "Reserved:uint",
                 "lpClass:str", "dwOptions:uint", "samDesired:uint",
                 "lpSecurityAttributes:ptr", "phkResult:ptr", "lpdwDisposition:ptr"],
        "return": "LONG",
        "category": "registry",
    },
    # --- Crypto ---
    "CryptEncrypt": {
        "args": ["hKey:HANDLE", "hHash:HANDLE", "Final:BOOL", "dwFlags:uint",
                 "pbData:ptr", "pdwDataLen:ptr", "dwBufLen:uint"],
        "return": "BOOL",
        "category": "crypto",
    },
    "CryptDecrypt": {
        "args": ["hKey:HANDLE", "hHash:HANDLE", "Final:BOOL", "dwFlags:uint",
                 "pbData:ptr", "pdwDataLen:ptr"],
        "return": "BOOL",
        "category": "crypto",
    },
    "CryptHashData": {
        "args": ["hHash:HANDLE", "pbData:ptr", "dwDataLen:uint", "dwFlags:uint"],
        "return": "BOOL",
        "category": "crypto",
    },
    "BCryptEncrypt": {
        "args": ["hKey:HANDLE", "pbInput:ptr", "cbInput:uint", "pPaddingInfo:ptr",
                 "pbIV:ptr", "cbIV:uint", "pbOutput:ptr", "cbOutput:uint",
                 "pcbResult:ptr", "dwFlags:uint"],
        "return": "NTSTATUS",
        "category": "crypto",
    },
    # --- Anti-Debug ---
    "IsDebuggerPresent": {
        "args": [],
        "return": "BOOL",
        "category": "anti_debug",
    },
    "CheckRemoteDebuggerPresent": {
        "args": ["hProcess:HANDLE", "pbDebuggerPresent:ptr"],
        "return": "BOOL",
        "category": "anti_debug",
    },
    "NtQueryInformationProcess": {
        "args": ["ProcessHandle:HANDLE", "ProcessInformationClass:uint",
                 "ProcessInformation:ptr", "ProcessInformationLength:uint",
                 "ReturnLength:ptr"],
        "return": "NTSTATUS",
        "category": "anti_debug",
    },
    "GetTickCount": {
        "args": [],
        "return": "uint",
        "category": "anti_debug",
    },
    "QueryPerformanceCounter": {
        "args": ["lpPerformanceCount:ptr"],
        "return": "BOOL",
        "category": "anti_debug",
    },
    "OutputDebugStringA": {
        "args": ["lpOutputString:str"],
        "return": "void",
        "category": "anti_debug",
    },
    # --- Service ---
    "OpenSCManagerA": {
        "args": ["lpMachineName:str", "lpDatabaseName:str", "dwDesiredAccess:uint"],
        "return": "HANDLE",
        "category": "service",
    },
    "CreateServiceA": {
        "args": ["hSCManager:HANDLE", "lpServiceName:str", "lpDisplayName:str",
                 "dwDesiredAccess:uint", "dwServiceType:uint", "dwStartType:uint",
                 "dwErrorControl:uint", "lpBinaryPathName:str", "lpLoadOrderGroup:str",
                 "lpdwTagId:ptr", "lpDependencies:str", "lpServiceStartName:str",
                 "lpPassword:str"],
        "return": "HANDLE",
        "category": "service",
    },
    # --- Thread ---
    "CreateThread": {
        "args": ["lpThreadAttributes:ptr", "dwStackSize:uint",
                 "lpStartAddress:ptr", "lpParameter:ptr", "dwCreationFlags:uint",
                 "lpThreadId:ptr"],
        "return": "HANDLE",
        "category": "thread",
    },
    "ResumeThread": {
        "args": ["hThread:HANDLE"],
        "return": "uint",
        "category": "thread",
    },
    "SuspendThread": {
        "args": ["hThread:HANDLE"],
        "return": "uint",
        "category": "thread",
    },
}


# =====================================================================
#  Anti-Debug Bypass Templates
# =====================================================================

ANTI_DEBUG_BYPASSES: Dict[str, str] = {
    "IsDebuggerPresent": """    // Bypass IsDebuggerPresent — always return FALSE
    Interceptor.attach(Module.getExportByName(null, "IsDebuggerPresent"), {
        onLeave: function(retval) {
            retval.replace(0);
            console.log("[BYPASS] IsDebuggerPresent -> FALSE");
        }
    });""",

    "CheckRemoteDebuggerPresent": """    // Bypass CheckRemoteDebuggerPresent — set output to FALSE
    Interceptor.attach(Module.getExportByName(null, "CheckRemoteDebuggerPresent"), {
        onEnter: function(args) {
            this.pbDebuggerPresent = args[1];
        },
        onLeave: function(retval) {
            if (this.pbDebuggerPresent && !this.pbDebuggerPresent.isNull()) {
                this.pbDebuggerPresent.writeU32(0);
            }
            console.log("[BYPASS] CheckRemoteDebuggerPresent -> FALSE");
        }
    });""",

    "NtQueryInformationProcess": """    // Bypass NtQueryInformationProcess (ProcessDebugPort=7, ProcessDebugObjectHandle=30, ProcessDebugFlags=31)
    var pNtQueryInformationProcess = Module.getExportByName("ntdll.dll", "NtQueryInformationProcess");
    if (pNtQueryInformationProcess) {
        Interceptor.attach(pNtQueryInformationProcess, {
            onEnter: function(args) {
                this.infoClass = args[1].toInt32();
                this.pInfo = args[2];
            },
            onLeave: function(retval) {
                if (this.infoClass === 7 && this.pInfo && !this.pInfo.isNull()) {
                    this.pInfo.writePointer(ptr(0));
                    console.log("[BYPASS] NtQueryInformationProcess(ProcessDebugPort) -> 0");
                }
                if (this.infoClass === 30) {
                    retval.replace(0xC0000353); // STATUS_PORT_NOT_SET
                    console.log("[BYPASS] NtQueryInformationProcess(ProcessDebugObjectHandle) -> STATUS_PORT_NOT_SET");
                }
                if (this.infoClass === 31 && this.pInfo && !this.pInfo.isNull()) {
                    this.pInfo.writeU32(1); // 1 = no debugger
                    console.log("[BYPASS] NtQueryInformationProcess(ProcessDebugFlags) -> 1");
                }
            }
        });
    }""",

    "NtSetInformationThread": """    // Bypass NtSetInformationThread(ThreadHideFromDebugger=17)
    var pNtSetInformationThread = Module.getExportByName("ntdll.dll", "NtSetInformationThread");
    if (pNtSetInformationThread) {
        Interceptor.attach(pNtSetInformationThread, {
            onEnter: function(args) {
                if (args[1].toInt32() === 17) {
                    args[1] = ptr(0); // change class to 0 (nop)
                    console.log("[BYPASS] NtSetInformationThread(ThreadHideFromDebugger) -> NOP");
                }
            }
        });
    }""",

    "OutputDebugStringA": """    // Bypass OutputDebugString-based detection (checks GetLastError)
    Interceptor.attach(Module.getExportByName(null, "OutputDebugStringA"), {
        onLeave: function(retval) {
            // Anti-debug technique: if OutputDebugString succeeds, debugger is present
            // We don't need to do anything special here, but logging helps visibility
            console.log("[BYPASS] OutputDebugStringA called");
        }
    });""",

    "GetTickCount": """    // Bypass timing-based anti-debug (GetTickCount)
    var baseTime = null;
    Interceptor.attach(Module.getExportByName(null, "GetTickCount"), {
        onLeave: function(retval) {
            if (baseTime === null) {
                baseTime = retval.toInt32();
            }
            // Cap elapsed time to prevent timing detection
            var elapsed = retval.toInt32() - baseTime;
            if (elapsed > 1000) {
                retval.replace(baseTime + 500);
                console.log("[BYPASS] GetTickCount clamped (elapsed would be " + elapsed + "ms)");
            }
        }
    });""",

    "QueryPerformanceCounter": """    // Bypass timing-based anti-debug (QueryPerformanceCounter)
    var basePerfCount = null;
    Interceptor.attach(Module.getExportByName(null, "QueryPerformanceCounter"), {
        onLeave: function(retval) {
            // Let it run normally but log for visibility
            console.log("[BYPASS] QueryPerformanceCounter called");
        }
    });""",

    "NtClose": """    // Bypass NtClose anti-debug (invalid handle check triggers exception under debugger)
    var pNtClose = Module.getExportByName("ntdll.dll", "NtClose");
    if (pNtClose) {
        Interceptor.attach(pNtClose, {
            onEnter: function(args) {
                this.handle = args[0];
            },
            onLeave: function(retval) {
                if (retval.toInt32() < 0) {
                    retval.replace(0); // STATUS_SUCCESS
                    console.log("[BYPASS] NtClose(invalid handle) -> STATUS_SUCCESS");
                }
            }
        });
    }""",

    "BlockInput": """    // Bypass BlockInput (prevents UI lockout during analysis)
    Interceptor.attach(Module.getExportByName(null, "BlockInput"), {
        onEnter: function(args) {
            args[0] = ptr(0); // fBlockIt = FALSE
            console.log("[BYPASS] BlockInput -> disabled");
        }
    });""",

    "NtQuerySystemInformation": """    // Bypass NtQuerySystemInformation (SystemKernelDebuggerInformation=35)
    var pNtQuerySystemInformation = Module.getExportByName("ntdll.dll", "NtQuerySystemInformation");
    if (pNtQuerySystemInformation) {
        Interceptor.attach(pNtQuerySystemInformation, {
            onEnter: function(args) {
                this.infoClass = args[0].toInt32();
                this.pInfo = args[1];
            },
            onLeave: function(retval) {
                if (this.infoClass === 35 && this.pInfo && !this.pInfo.isNull()) {
                    // SYSTEM_KERNEL_DEBUGGER_INFORMATION: both booleans to FALSE
                    this.pInfo.writeU8(0);
                    this.pInfo.add(1).writeU8(0);
                    console.log("[BYPASS] NtQuerySystemInformation(KernelDebugger) -> FALSE");
                }
            }
        });
    }""",
}


# Known anti-debug API names for auto-detection
ANTI_DEBUG_APIS = frozenset({
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "NtSetInformationThread",
    "OutputDebugStringA", "OutputDebugStringW",
    "GetTickCount", "GetTickCount64",
    "QueryPerformanceCounter", "QueryPerformanceFrequency",
    "NtClose", "BlockInput",
    "NtQuerySystemInformation",
    "FindWindowA", "FindWindowW",  # debugger window detection
    "EnumWindows",  # debugger window enumeration
})


# =====================================================================
#  JS Generation Functions
# =====================================================================

def _format_arg_reader(idx: int, arg_spec: str) -> str:
    """Generate JS to read a single Frida hook argument."""
    parts = arg_spec.split(":", 1)
    name = parts[0]
    atype = parts[1] if len(parts) > 1 else "ptr"

    if atype == "str":
        return f'        var {name} = args[{idx}].isNull() ? "(null)" : args[{idx}].readAnsiString();'
    elif atype == "wstr":
        return f'        var {name} = args[{idx}].isNull() ? "(null)" : args[{idx}].readUtf16String();'
    elif atype in ("uint", "int", "BOOL", "LONG", "NTSTATUS", "SOCKET"):
        return f"        var {name} = args[{idx}].toInt32();"
    elif atype == "HANDLE":
        return f"        var {name} = args[{idx}];"
    else:
        return f"        var {name} = args[{idx}];"


def _format_arg_log(arg_spec: str) -> str:
    """Generate JS log expression for an argument."""
    name = arg_spec.split(":")[0]
    return name


def generate_hook_js(
    api_name: str,
    module: Optional[str] = None,
    include_backtrace: bool = True,
    include_args: bool = True,
) -> str:
    """Generate Frida hook JS for a single API."""
    sig = FRIDA_API_SIGNATURES.get(api_name)
    resolve = (
        f'Module.getExportByName("{module}", "{api_name}")'
        if module else
        f'Module.getExportByName(null, "{api_name}")'
    )

    lines = [f"    // Hook: {api_name}"]
    lines.append(f'    var p{api_name} = {resolve};')
    lines.append(f"    if (p{api_name}) {{")
    lines.append(f"        Interceptor.attach(p{api_name}, {{")

    # onEnter
    lines.append("            onEnter: function(args) {")
    if include_args and sig:
        for i, arg_spec in enumerate(sig["args"]):
            lines.append(f"    {_format_arg_reader(i, arg_spec)}")
        arg_names = [_format_arg_log(a) for a in sig["args"]]
        log_parts = ", ".join(f'{n}=" + {n} + "' for n in arg_names)
        lines.append(f'                console.log("[HOOK] {api_name}({log_parts})");')
    else:
        lines.append(f'                console.log("[HOOK] {api_name} called");')

    if include_backtrace:
        lines.append("                console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));")

    lines.append("            },")

    # onLeave
    lines.append("            onLeave: function(retval) {")
    if sig:
        ret_type = sig.get("return", "ptr")
        if ret_type in ("BOOL", "uint", "int", "LONG", "NTSTATUS"):
            lines.append(f'                console.log("[HOOK] {api_name} returned: " + retval.toInt32());')
        elif ret_type == "HANDLE" or ret_type == "ptr":
            lines.append(f'                console.log("[HOOK] {api_name} returned: " + retval);')
        else:
            lines.append(f'                console.log("[HOOK] {api_name} returned: " + retval);')
    else:
        lines.append(f'                console.log("[HOOK] {api_name} returned: " + retval);')
    lines.append("            }")

    lines.append("        });")
    lines.append("    }")

    return "\n".join(lines)


def generate_hook_for_address(
    address: str,
    include_backtrace: bool = True,
) -> str:
    """Generate Frida hook for a raw address."""
    bt_line = (
        "            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)"
        ".map(DebugSymbol.fromAddress).join('\\n'));"
    ) if include_backtrace else ""
    lines = [
        f"    // Hook raw address: {address}",
        f'    Interceptor.attach(ptr("{address}"), {{',
        "        onEnter: function(args) {",
        f'            console.log("[HOOK] Hit address {address}");',
        '            console.log("  arg0=" + args[0] + " arg1=" + args[1] + " arg2=" + args[2]);',
    ]
    if bt_line:
        lines.append(bt_line)
    lines.extend([
        "        },",
        "        onLeave: function(retval) {",
        f'            console.log("[HOOK] {address} returned: " + retval);',
        "        }",
        "    });",
    ])
    return "\n".join(lines)


def generate_bypass_js(techniques: List[str]) -> str:
    """Generate combined bypass script from a list of technique names."""
    parts = [
        '"use strict";',
        "",
        "// ============================================",
        "// Arkana Anti-Debug Bypass Script (Frida)",
        "// ============================================",
        "",
    ]

    bypassed = []
    for tech in techniques:
        template = ANTI_DEBUG_BYPASSES.get(tech)
        if template:
            parts.append(template)
            parts.append("")
            bypassed.append(tech)

    parts.append(f'console.log("[ARKANA] Anti-debug bypasses active: {", ".join(bypassed)}");')
    return "\n".join(parts)


def generate_trace_js(
    apis: List[Dict[str, Any]],
    categories: Optional[List[str]] = None,
) -> str:
    """Generate a comprehensive tracing script for a list of APIs.

    Each entry in `apis` should have at least 'name' and optionally 'module', 'category'.
    """
    parts = [
        '"use strict";',
        "",
        "// ============================================",
        "// Arkana API Trace Script (Frida)",
        "// ============================================",
        "",
        "var traceLog = [];",
        "",
    ]

    traced_count = 0
    for api_info in apis:
        name = api_info.get("name", "")
        if not name:
            continue
        cat = api_info.get("category", "")
        if categories and cat not in categories:
            continue
        module = api_info.get("module")
        parts.append(generate_hook_js(name, module=module, include_backtrace=False, include_args=True))
        parts.append("")
        traced_count += 1

    parts.append(f'console.log("[ARKANA] Tracing {traced_count} APIs");')
    return "\n".join(parts)


# =====================================================================
#  Stalker Coverage Script
# =====================================================================

def generate_stalker_coverage_js(
    target_module: Optional[str] = None,
    output_format: str = "drcov",
) -> str:
    """Generate a Frida Stalker script that collects basic-block coverage.

    Args:
        target_module: Module name to restrict coverage to (e.g. 'sample.exe').
            If None, covers the main binary module.
        output_format: 'drcov' for drcov-compatible binary format, 'json' for JSON.
    """
    if output_format not in ("drcov", "json"):
        output_format = "drcov"

    mod_resolve = (
        f'var targetMod = Process.getModuleByName("{target_module}");'
        if target_module else
        "var targetMod = Process.enumerateModules()[0];"
    )

    lines = [
        '"use strict";',
        "",
        "// ============================================",
        "// Arkana Stalker Coverage Script (Frida)",
        "// ============================================",
        "",
        mod_resolve,
        'console.log("[COVERAGE] Target module: " + targetMod.name + " base=" + targetMod.base + " size=" + targetMod.size);',
        "",
        "var modBase = targetMod.base;",
        "var modEnd = modBase.add(targetMod.size);",
        "var coveredBlocks = [];  // {start: offset, size: length}",
        "var seen = {};",
        "",
        "Stalker.follow(Process.getCurrentThreadId(), {",
        "    events: { compile: true },",
        "    onReceive: function(events) {",
        "        var parsed = Stalker.parse(events, { stringify: false, annotate: false });",
        "        for (var i = 0; i < parsed.length; i++) {",
        "            var ev = parsed[i];",
        "            // compile events: [type, start, end]",
        "            if (ev.length >= 3) {",
        "                var blockStart = ptr(ev[1]);",
        "                var blockEnd = ptr(ev[2]);",
        "                if (blockStart.compare(modBase) >= 0 && blockStart.compare(modEnd) < 0) {",
        "                    var offset = blockStart.sub(modBase).toInt32();",
        "                    var size = blockEnd.sub(blockStart).toInt32();",
        "                    var key = offset.toString();",
        "                    if (!seen[key]) {",
        "                        seen[key] = true;",
        "                        coveredBlocks.push({ start: offset, size: size });",
        "                    }",
        "                }",
        "            }",
        "        }",
        "    }",
        "});",
        "",
    ]

    if output_format == "drcov":
        lines.extend([
            "function dumpDrcov() {",
            '    console.log("[COVERAGE] Dumping drcov format: " + coveredBlocks.length + " basic blocks");',
            "",
            "    // drcov header",
            '    var header = "DRCOV VERSION: 2\\n";',
            '    header += "DRCOV FLAVOR: frida\\n";',
            '    header += "Module Table: version 2, count 1\\n";',
            '    header += "Columns: id, base, end, entry, checksum, timestamp, path\\n";',
            '    header += " 0, " + modBase + ", " + modEnd + ", 0x0, 0x0, 0x0, " + targetMod.path + "\\n";',
            '    header += "BB Table: " + coveredBlocks.length + " bbs\\n";',
            "",
            "    // Build binary BB entries (8 bytes each: u32 start, u16 size, u16 mod_id)",
            "    var bbBuf = Memory.alloc(coveredBlocks.length * 8);",
            "    for (var i = 0; i < coveredBlocks.length; i++) {",
            "        bbBuf.add(i * 8).writeU32(coveredBlocks[i].start);",
            "        bbBuf.add(i * 8 + 4).writeU16(coveredBlocks[i].size);",
            "        bbBuf.add(i * 8 + 6).writeU16(0);  // module id",
            "    }",
            "",
            "    send({ type: 'drcov', header: header, bb_count: coveredBlocks.length }, bbBuf.readByteArray(coveredBlocks.length * 8));",
            "}",
        ])
    else:
        lines.extend([
            "function dumpDrcov() {",
            '    console.log("[COVERAGE] Dumping JSON format: " + coveredBlocks.length + " basic blocks");',
            "    send({",
            "        type: 'coverage',",
            "        module: targetMod.name,",
            "        module_base: modBase.toString(),",
            "        module_size: targetMod.size,",
            "        module_path: targetMod.path,",
            "        bb_count: coveredBlocks.length,",
            "        basic_blocks: coveredBlocks",
            "    });",
            "}",
        ])

    lines.extend([
        "",
        "// Dump on exit or signal",
        "Process.setExceptionHandler(function(details) {",
        "    dumpDrcov();",
        "    return false;",
        "});",
        "",
        "// Periodic flush every 30 seconds",
        "setInterval(function() {",
        '    console.log("[COVERAGE] Blocks so far: " + coveredBlocks.length);',
        "}, 30000);",
        "",
        "// Call dumpDrcov() via RPC or on detach",
        "rpc.exports = {",
        "    dump: function() { dumpDrcov(); },",
        "    count: function() { return coveredBlocks.length; }",
        "};",
        "",
        f'console.log("[ARKANA] Stalker coverage active — format={output_format}, module=" + targetMod.name);',
    ])

    return "\n".join(lines)


# =====================================================================
#  Anti-VM Bypass Script
# =====================================================================

# VM registry keys that malware commonly checks
_VM_REGISTRY_KEYS = [
    r"SOFTWARE\\VMware, Inc.\\VMware Tools",
    r"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
    r"SYSTEM\\CurrentControlSet\\Services\\vmtools",
    r"SYSTEM\\CurrentControlSet\\Services\\vmhgfs",
    r"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest",
    r"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse",
    r"SYSTEM\\CurrentControlSet\\Services\\VBoxSF",
    r"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo",
    r"SYSTEM\\CurrentControlSet\\Services\\vmci",
    r"SYSTEM\\CurrentControlSet\\Services\\vmx86",
    r"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters",
    r"HARDWARE\\ACPI\\DSDT\\VBOX__",
    r"HARDWARE\\ACPI\\FADT\\VBOX__",
    r"HARDWARE\\ACPI\\RSDT\\VBOX__",
    r"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD",
    r"SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE",
    r"SOFTWARE\\Wine",
    r"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum\\0",  # VBOX HARDDISK / VMWARE
]

# VM process names to hide from enumeration
_VM_PROCESS_NAMES = [
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
    "VBoxService.exe", "VBoxTray.exe",
    "xenservice.exe", "qemu-ga.exe",
    "prl_tools.exe", "prl_cc.exe",
    "SharedIntApp.exe", "vmusrvc.exe", "vmsrvc.exe",
    "joeboxcontrol.exe", "joeboxserver.exe",
    "wireshark.exe", "procmon.exe", "procmon64.exe",
    "procexp.exe", "procexp64.exe", "ollydbg.exe",
    "x64dbg.exe", "x32dbg.exe", "idaq.exe", "idaq64.exe",
]

# VM MAC address prefixes (OUI)
_VM_MAC_PREFIXES = [
    "00:05:69",  # VMware
    "00:0C:29",  # VMware
    "00:1C:14",  # VMware
    "00:50:56",  # VMware
    "08:00:27",  # VirtualBox
    "00:03:FF",  # Microsoft Hyper-V
    "00:15:5D",  # Microsoft Hyper-V
    "00:1A:4A",  # QEMU
    "52:54:00",  # QEMU/KVM
    "00:16:3E",  # Xen
    "00:1C:42",  # Parallels
]

# VM vendor strings to scrub from SMBIOS firmware tables
_VM_SMBIOS_STRINGS = [
    "VMware", "VMWARE", "vmware",
    "VirtualBox", "VIRTUALBOX", "VBOX",
    "QEMU", "Bochs", "Xen", "innotek",
    "Parallels", "Virtual Machine", "Microsoft Corporation",
    "Hyper-V", "Red Hat", "KVM",
]


def generate_anti_vm_bypass_js() -> str:
    """Generate a Frida script that bypasses common VM detection techniques."""

    # Build JS array literals
    vm_keys_js = ", ".join(f'"{k}"' for k in _VM_REGISTRY_KEYS)
    vm_procs_js = ", ".join(f'"{p.lower()}"' for p in _VM_PROCESS_NAMES)
    vm_macs_js = ", ".join(f'"{m.upper()}"' for m in _VM_MAC_PREFIXES)
    vm_smbios_js = ", ".join(f'"{s}"' for s in _VM_SMBIOS_STRINGS)

    lines = [
        '"use strict";',
        "",
        "// ============================================",
        "// Arkana Anti-VM Bypass Script (Frida)",
        "// ============================================",
        "",
        "// VM registry keys to block",
        f"var vmRegKeys = [{vm_keys_js}];",
        "",
        "// VM process names to hide (lowercase for comparison)",
        f"var vmProcessNames = [{vm_procs_js}];",
        "",
        "// VM MAC prefixes to mask",
        f"var vmMacPrefixes = [{vm_macs_js}];",
        "",
        "// VM SMBIOS vendor strings to scrub",
        f"var vmSmbiosStrings = [{vm_smbios_js}];",
        "",
        "// ---- Registry Key Bypass (RegOpenKeyExA/W) ----",
        "",
        '["RegOpenKeyExA", "RegOpenKeyExW"].forEach(function(apiName) {',
        "    var pApi = Module.getExportByName(null, apiName);",
        "    if (pApi) {",
        "        Interceptor.attach(pApi, {",
        "            onEnter: function(args) {",
        "                var subKey;",
        '                if (apiName.endsWith("W")) {',
        "                    subKey = args[1].isNull() ? '' : args[1].readUtf16String();",
        "                } else {",
        "                    subKey = args[1].isNull() ? '' : args[1].readAnsiString();",
        "                }",
        "                this.block = false;",
        "                if (subKey) {",
        "                    for (var i = 0; i < vmRegKeys.length; i++) {",
        "                        if (subKey.indexOf(vmRegKeys[i]) !== -1) {",
        "                            this.block = true;",
        '                            console.log("[ANTI-VM] Blocked " + apiName + ": " + subKey);',
        "                            break;",
        "                        }",
        "                    }",
        "                }",
        "            },",
        "            onLeave: function(retval) {",
        "                if (this.block) {",
        "                    retval.replace(2);  // ERROR_FILE_NOT_FOUND",
        "                }",
        "            }",
        "        });",
        "    }",
        "});",
        "",
        "// ---- SMBIOS Firmware Table Scrub (GetSystemFirmwareTable) ----",
        "",
        'var pGetSystemFirmwareTable = Module.getExportByName(null, "GetSystemFirmwareTable");',
        "if (pGetSystemFirmwareTable) {",
        "    Interceptor.attach(pGetSystemFirmwareTable, {",
        "        onEnter: function(args) {",
        "            this.pBuffer = args[2];",
        "            this.bufSize = args[3].toInt32();",
        "        },",
        "        onLeave: function(retval) {",
        "            var bytesWritten = retval.toInt32();",
        "            if (bytesWritten > 0 && this.pBuffer && !this.pBuffer.isNull()) {",
        "                try {",
        "                    var buf = this.pBuffer.readByteArray(bytesWritten);",
        "                    var view = new Uint8Array(buf);",
        "                    var str = '';",
        "                    for (var i = 0; i < view.length; i++) {",
        "                        str += String.fromCharCode(view[i]);",
        "                    }",
        "                    var modified = false;",
        "                    for (var j = 0; j < vmSmbiosStrings.length; j++) {",
        "                        if (str.indexOf(vmSmbiosStrings[j]) !== -1) {",
        "                            // Replace with spaces to preserve offsets",
        "                            var pattern = vmSmbiosStrings[j];",
        "                            var replacement = '';",
        "                            for (var k = 0; k < pattern.length; k++) { replacement += ' '; }",
        "                            while (str.indexOf(pattern) !== -1) {",
        "                                str = str.replace(pattern, replacement);",
        "                            }",
        "                            modified = true;",
        "                        }",
        "                    }",
        "                    if (modified) {",
        "                        var outView = new Uint8Array(bytesWritten);",
        "                        for (var m = 0; m < bytesWritten; m++) {",
        "                            outView[m] = str.charCodeAt(m);",
        "                        }",
        "                        this.pBuffer.writeByteArray(outView.buffer);",
        '                        console.log("[ANTI-VM] Scrubbed VM strings from SMBIOS table");',
        "                    }",
        "                } catch(e) {",
        '                    console.log("[ANTI-VM] SMBIOS scrub error: " + e);',
        "                }",
        "            }",
        "        }",
        "    });",
        "}",
        "",
        "// ---- Process Enumeration Filter (Process32FirstW / Process32NextW) ----",
        "",
        '["Process32FirstW", "Process32NextW"].forEach(function(apiName) {',
        "    var pApi = Module.getExportByName(null, apiName);",
        "    if (pApi) {",
        "        Interceptor.attach(pApi, {",
        "            onEnter: function(args) {",
        "                this.pEntry = args[1];  // PROCESSENTRY32W*",
        "            },",
        "            onLeave: function(retval) {",
        "                if (retval.toInt32() !== 0 && this.pEntry && !this.pEntry.isNull()) {",
        "                    try {",
        "                        // szExeFile is at offset 44 in PROCESSENTRY32W (after dwSize + 10 DWORDs)",
        "                        var exeName = this.pEntry.add(44).readUtf16String();",
        "                        if (exeName) {",
        "                            var lower = exeName.toLowerCase();",
        "                            for (var i = 0; i < vmProcessNames.length; i++) {",
        "                                if (lower === vmProcessNames[i]) {",
        "                                    // Skip this entry by calling the API again",
        '                                    console.log("[ANTI-VM] Hiding process: " + exeName);',
        "                                    // Zero out the process name to make it appear empty",
        "                                    this.pEntry.add(44).writeUtf16String('svchost.exe');",
        "                                    break;",
        "                                }",
        "                            }",
        "                        }",
        "                    } catch(e) {}",
        "                }",
        "            }",
        "        });",
        "    }",
        "});",
        "",
        "// ---- MAC Address Masking (GetAdaptersInfo) ----",
        "",
        'var pGetAdaptersInfo = Module.getExportByName(null, "GetAdaptersInfo");',
        "if (pGetAdaptersInfo) {",
        "    Interceptor.attach(pGetAdaptersInfo, {",
        "        onEnter: function(args) {",
        "            this.pInfo = args[0];  // PIP_ADAPTER_INFO",
        "        },",
        "        onLeave: function(retval) {",
        "            if (retval.toInt32() === 0 && this.pInfo && !this.pInfo.isNull()) {",
        "                try {",
        "                    var adapter = this.pInfo;",
        "                    while (!adapter.isNull()) {",
        "                        // Address field offset 404, AddressLength at offset 400",
        "                        var addrLen = adapter.add(400).readU32();",
        "                        if (addrLen >= 3) {",
        "                            var b0 = adapter.add(404).readU8();",
        "                            var b1 = adapter.add(405).readU8();",
        "                            var b2 = adapter.add(406).readU8();",
        "                            var macPrefix = ('0' + b0.toString(16)).slice(-2).toUpperCase() + ':' +",
        "                                           ('0' + b1.toString(16)).slice(-2).toUpperCase() + ':' +",
        "                                           ('0' + b2.toString(16)).slice(-2).toUpperCase();",
        "                            for (var i = 0; i < vmMacPrefixes.length; i++) {",
        "                                if (macPrefix === vmMacPrefixes[i]) {",
        '                                    console.log("[ANTI-VM] Masking VM MAC: " + macPrefix);',
        "                                    // Replace with a common Dell OUI",
        "                                    adapter.add(404).writeU8(0xD4);",
        "                                    adapter.add(405).writeU8(0xBE);",
        "                                    adapter.add(406).writeU8(0xD9);",
        "                                    break;",
        "                                }",
        "                            }",
        "                        }",
        "                        // Next adapter pointer at offset 0",
        "                        adapter = adapter.readPointer();",
        "                    }",
        "                } catch(e) {",
        '                    console.log("[ANTI-VM] GetAdaptersInfo scrub error: " + e);',
        "                }",
        "            }",
        "        }",
        "    });",
        "}",
        "",
        'console.log("[ARKANA] Anti-VM bypasses active: registry, SMBIOS, process enum, MAC masking");',
    ]

    return "\n".join(lines)


# =====================================================================
#  Injection Detector Script
# =====================================================================

def generate_injection_detector_js() -> str:
    """Generate a Frida script that monitors for process injection patterns."""

    lines = [
        '"use strict";',
        "",
        "// ============================================",
        "// Arkana Process Injection Detector (Frida)",
        "// ============================================",
        "",
        "// Track injection sequences: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread",
        "var injectionState = {};  // keyed by target process handle",
        "var alertCount = 0;",
        "",
        "function getTimestamp() {",
        "    return new Date().toISOString();",
        "}",
        "",
        "function sendAlert(msg) {",
        "    alertCount++;",
        "    msg.alert_id = alertCount;",
        "    msg.timestamp = getTimestamp();",
        "    send(msg);",
        "}",
        "",
        "// ---- VirtualAllocEx ----",
        "",
        'var pVirtualAllocEx = Module.getExportByName(null, "VirtualAllocEx");',
        "if (pVirtualAllocEx) {",
        "    Interceptor.attach(pVirtualAllocEx, {",
        "        onEnter: function(args) {",
        "            this.hProcess = args[0];",
        "            this.lpAddress = args[1];",
        "            this.dwSize = args[2].toInt32();",
        "            this.flAllocationType = args[3].toInt32();",
        "            this.flProtect = args[4].toInt32();",
        "        },",
        "        onLeave: function(retval) {",
        "            var hKey = this.hProcess.toString();",
        "            sendAlert({",
        "                type: 'injection_api',",
        "                api: 'VirtualAllocEx',",
        "                target_process: hKey,",
        "                requested_address: this.lpAddress.toString(),",
        "                size: this.dwSize,",
        "                allocation_type: '0x' + (this.flAllocationType >>> 0).toString(16),",
        "                protection: '0x' + (this.flProtect >>> 0).toString(16),",
        "                returned_address: retval.toString()",
        "            });",
        "",
        "            // Track state for sequence detection",
        "            if (!injectionState[hKey]) {",
        "                injectionState[hKey] = { stages: [] };",
        "            }",
        "            injectionState[hKey].stages.push('VirtualAllocEx');",
        "            injectionState[hKey].alloc_addr = retval.toString();",
        "            injectionState[hKey].alloc_size = this.dwSize;",
        "        }",
        "    });",
        "}",
        "",
        "// ---- WriteProcessMemory ----",
        "",
        'var pWriteProcessMemory = Module.getExportByName(null, "WriteProcessMemory");',
        "if (pWriteProcessMemory) {",
        "    Interceptor.attach(pWriteProcessMemory, {",
        "        onEnter: function(args) {",
        "            this.hProcess = args[0];",
        "            this.lpBaseAddress = args[1];",
        "            this.lpBuffer = args[2];",
        "            this.nSize = args[3].toInt32();",
        "        },",
        "        onLeave: function(retval) {",
        "            var hKey = this.hProcess.toString();",
        "",
        "            // Capture first 64 bytes of written data",
        "            var preview = '';",
        "            try {",
        "                var readLen = Math.min(this.nSize, 64);",
        "                var bytes = this.lpBuffer.readByteArray(readLen);",
        "                var arr = new Uint8Array(bytes);",
        "                for (var i = 0; i < arr.length; i++) {",
        "                    preview += ('0' + arr[i].toString(16)).slice(-2);",
        "                }",
        "            } catch(e) { preview = '(unreadable)'; }",
        "",
        "            sendAlert({",
        "                type: 'injection_api',",
        "                api: 'WriteProcessMemory',",
        "                target_process: hKey,",
        "                base_address: this.lpBaseAddress.toString(),",
        "                size: this.nSize,",
        "                data_preview_hex: preview,",
        "                success: retval.toInt32() !== 0",
        "            });",
        "",
        "            // Track state",
        "            if (!injectionState[hKey]) {",
        "                injectionState[hKey] = { stages: [] };",
        "            }",
        "            injectionState[hKey].stages.push('WriteProcessMemory');",
        "            injectionState[hKey].write_addr = this.lpBaseAddress.toString();",
        "            injectionState[hKey].write_size = this.nSize;",
        "        }",
        "    });",
        "}",
        "",
        "// ---- CreateRemoteThread ----",
        "",
        'var pCreateRemoteThread = Module.getExportByName(null, "CreateRemoteThread");',
        "if (pCreateRemoteThread) {",
        "    Interceptor.attach(pCreateRemoteThread, {",
        "        onEnter: function(args) {",
        "            this.hProcess = args[0];",
        "            this.lpStartAddress = args[3];",
        "            this.lpParameter = args[4];",
        "        },",
        "        onLeave: function(retval) {",
        "            var hKey = this.hProcess.toString();",
        "",
        "            sendAlert({",
        "                type: 'injection_api',",
        "                api: 'CreateRemoteThread',",
        "                target_process: hKey,",
        "                start_address: this.lpStartAddress.toString(),",
        "                parameter: this.lpParameter.toString(),",
        "                thread_handle: retval.toString()",
        "            });",
        "",
        "            // Track state and check for full injection sequence",
        "            if (!injectionState[hKey]) {",
        "                injectionState[hKey] = { stages: [] };",
        "            }",
        "            injectionState[hKey].stages.push('CreateRemoteThread');",
        "",
        "            var stages = injectionState[hKey].stages;",
        "            if (stages.indexOf('VirtualAllocEx') !== -1 &&",
        "                stages.indexOf('WriteProcessMemory') !== -1 &&",
        "                stages.indexOf('CreateRemoteThread') !== -1) {",
        "                sendAlert({",
        "                    type: 'injection_sequence_detected',",
        "                    severity: 'critical',",
        "                    technique: 'VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread',",
        "                    target_process: hKey,",
        "                    alloc_address: injectionState[hKey].alloc_addr || '(unknown)',",
        "                    alloc_size: injectionState[hKey].alloc_size || 0,",
        "                    write_address: injectionState[hKey].write_addr || '(unknown)',",
        "                    write_size: injectionState[hKey].write_size || 0,",
        "                    thread_start: this.lpStartAddress.toString()",
        "                });",
        '                console.log("[INJECTION] *** CLASSIC INJECTION SEQUENCE DETECTED *** target=" + hKey);',
        "                // Reset state for this handle",
        "                injectionState[hKey] = { stages: [] };",
        "            }",
        "        }",
        "    });",
        "}",
        "",
        "// ---- NtMapViewOfSection ----",
        "",
        'var pNtMapViewOfSection = Module.getExportByName("ntdll.dll", "NtMapViewOfSection");',
        "if (pNtMapViewOfSection) {",
        "    Interceptor.attach(pNtMapViewOfSection, {",
        "        onEnter: function(args) {",
        "            this.sectionHandle = args[0];",
        "            this.processHandle = args[1];",
        "            this.pBaseAddress = args[2];",
        "        },",
        "        onLeave: function(retval) {",
        "            var mappedAddr = '(unknown)';",
        "            try {",
        "                if (this.pBaseAddress && !this.pBaseAddress.isNull()) {",
        "                    mappedAddr = this.pBaseAddress.readPointer().toString();",
        "                }",
        "            } catch(e) {}",
        "",
        "            sendAlert({",
        "                type: 'injection_api',",
        "                api: 'NtMapViewOfSection',",
        "                section_handle: this.sectionHandle.toString(),",
        "                target_process: this.processHandle.toString(),",
        "                mapped_address: mappedAddr,",
        "                status: '0x' + (retval.toInt32() >>> 0).toString(16)",
        "            });",
        "        }",
        "    });",
        "}",
        "",
        'console.log("[ARKANA] Injection detector active — monitoring VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, NtMapViewOfSection");',
    ]

    return "\n".join(lines)


# =====================================================================
#  Structured API Logger Script
# =====================================================================

def generate_api_logger_js(
    apis: List[str],
    include_args: bool = True,
    include_backtrace: bool = False,
) -> str:
    """Generate a Frida script that logs API calls as structured JSON lines.

    Args:
        apis: List of API names to hook.
        include_args: Include resolved argument values. Default True.
        include_backtrace: Include call stack backtrace. Default False.
    """
    if not apis:
        return '// No APIs specified for logging.\nconsole.log("[ARKANA] No APIs to log.");'

    lines = [
        '"use strict";',
        "",
        "// ============================================",
        "// Arkana Structured API Logger (Frida)",
        "// ============================================",
        "",
        "var callIndex = 0;",
        "",
    ]

    for api_name in apis:
        sig = FRIDA_API_SIGNATURES.get(api_name)
        resolve_expr = f'Module.getExportByName(null, "{api_name}")'

        lines.append(f"// Logger: {api_name}")
        lines.append(f'var p_{api_name} = {resolve_expr};')
        lines.append(f"if (p_{api_name}) {{")
        lines.append(f"    Interceptor.attach(p_{api_name}, {{")

        # onEnter
        lines.append("        onEnter: function(args) {")
        lines.append("            this._callIdx = ++callIndex;")

        if include_args and sig:
            # Read each argument according to its type
            for i, arg_spec in enumerate(sig["args"]):
                lines.append(f"    {_format_arg_reader(i, arg_spec)}")
            # Build the args object
            arg_names = [a.split(":")[0] for a in sig["args"]]
            obj_parts = ", ".join(f'"{n}": ' + (f"String({n})" if True else n) for n in arg_names)
            lines.append(f"            this._args = {{ {obj_parts} }};")
        else:
            # Generic: capture first 4 args as pointers
            lines.append("            this._args = {")
            lines.append('                arg0: args[0].toString(),')
            lines.append('                arg1: args[1].toString(),')
            lines.append('                arg2: args[2].toString(),')
            lines.append('                arg3: args[3].toString()')
            lines.append("            };")

        if include_backtrace:
            lines.append("            this._backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)")
            lines.append("                .map(DebugSymbol.fromAddress).map(function(s) { return s.toString(); });")

        lines.append("        },")

        # onLeave
        lines.append("        onLeave: function(retval) {")

        # Build retval formatting
        if sig:
            ret_type = sig.get("return", "ptr")
            if ret_type in ("BOOL", "uint", "int", "LONG", "NTSTATUS"):
                lines.append("            var retStr = retval.toInt32();")
            else:
                lines.append("            var retStr = retval.toString();")
        else:
            lines.append("            var retStr = retval.toString();")

        lines.append("            var entry = {")
        lines.append(f'                api: "{api_name}",')
        lines.append("                call_index: this._callIdx,")
        lines.append("                args: this._args,")
        lines.append("                retval: retStr,")
        lines.append("                timestamp: new Date().toISOString()")
        lines.append("            };")
        if include_backtrace:
            lines.append("            if (this._backtrace) {")
            lines.append("                entry.backtrace = this._backtrace;")
            lines.append("            }")
        lines.append("            send(entry);")
        lines.append("        }")
        lines.append("    });")
        lines.append("}")
        lines.append("")

    lines.append(f'console.log("[ARKANA] API logger active — {len(apis)} APIs hooked");')

    return "\n".join(lines)
