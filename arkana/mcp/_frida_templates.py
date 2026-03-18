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
