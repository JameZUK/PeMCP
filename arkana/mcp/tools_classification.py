"""MCP tools for binary purpose classification."""
from typing import Dict, Any, List
from arkana.config import state, logger, Context, ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE, YARA_AVAILABLE
from arkana.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size
from arkana.state import AnalyzerState


# Import-to-behavior mapping for behavioral indicators
_IMPORT_BEHAVIORS: Dict[str, str] = {
    "CreateNamedPipe": "IPC (named pipes)",
    "ConnectNamedPipe": "IPC (named pipes)",
    "CreatePipe": "IPC (pipes)",
    "TerminateProcess": "Process management",
    "OpenProcess": "Process management",
    "CreateRemoteThread": "Code injection",
    "WriteProcessMemory": "Code injection",
    "VirtualAllocEx": "Remote memory allocation",
    "NtUnmapViewOfSection": "Process hollowing",
    "SetWindowsHookEx": "Input hooking",
    "GetAsyncKeyState": "Keystroke monitoring",
    "QueryPerformanceCounter": "Anti-debug (timing)",
    "GetTickCount": "Anti-debug (timing)",
    "IsDebuggerPresent": "Anti-debug (detection)",
    "CheckRemoteDebuggerPresent": "Anti-debug (detection)",
    "NtQueryInformationProcess": "Anti-debug (detection)",
    "CreateService": "Service installation",
    "RegSetValueEx": "Registry modification",
    "RegCreateKeyEx": "Registry modification",
    "InternetOpen": "HTTP networking",
    "HttpSendRequest": "HTTP networking",
    "URLDownloadToFile": "File download",
    "WinExec": "Process execution",
    "ShellExecute": "Process execution",
    "CryptEncrypt": "Encryption",
    "CryptDecrypt": "Decryption",
    "BCryptEncrypt": "Encryption",
}


def _classify_internal(current_state: AnalyzerState) -> Dict[str, Any]:
    """Classify binary purpose synchronously. No MCP overhead.

    Callable from enrichment or directly. Reads from the given state.
    """
    from arkana.state import set_current_state
    set_current_state(current_state)
    return _classify_core()


def _classify_core() -> Dict[str, Any]:
    """Core classification logic using the current state proxy."""
    # L11-v10: Guard against pe_data being None
    if state.pe_data is None:
        return {"error": "No file loaded. Call open_file() first."}

    classifications = []
    evidence = []

    mode = state.pe_data.get('mode', 'pe')

    # Non-PE formats
    if mode in ('elf', 'macho', 'shellcode'):
        return {
            "primary_type": mode.upper(),
            "classifications": [mode.upper()],
            "evidence": [f"File loaded in {mode} mode"],
            "note": "Detailed classification is PE-specific. Use format-specific tools for analysis.",
        }

    pe_data = state.pe_data
    sections_data = pe_data.get('sections', [])
    imports_data = pe_data.get('imports', [])
    version_info = pe_data.get('version_info', {})
    nt_headers = pe_data.get('nt_headers', {})
    com_descriptor = pe_data.get('com_descriptor', {})

    file_header = nt_headers.get('file_header', {})
    optional_header = nt_headers.get('optional_header', {})
    characteristics = file_header.get('characteristics', file_header.get('Characteristics', 0))
    subsystem = optional_header.get('subsystem', optional_header.get('Subsystem', 0))

    if isinstance(characteristics, dict):
        characteristics = characteristics.get('Value', 0)
    if isinstance(subsystem, dict):
        subsystem = subsystem.get('Value', 0)

    all_import_names = set()
    all_dll_names = set()
    for dll_entry in imports_data:
        if isinstance(dll_entry, dict):
            dll_name = dll_entry.get('dll_name', '').lower()
            all_dll_names.add(dll_name)
            for sym in dll_entry.get('symbols', []):
                name = sym.get('name', '')
                if name:
                    all_import_names.add(name)

    is_dll = False
    if isinstance(characteristics, int):
        is_dll = bool(characteristics & 0x2000)
    elif isinstance(characteristics, str) and 'DLL' in characteristics.upper():
        is_dll = True

    if is_dll:
        classifications.append("DLL/Library")
        evidence.append("FILE_HEADER.Characteristics has IMAGE_FILE_DLL flag")

    subsystem_val = subsystem
    if isinstance(subsystem, str):
        if 'GUI' in subsystem.upper():
            subsystem_val = 2
        elif 'CONSOLE' in subsystem.upper():
            subsystem_val = 3
        elif 'NATIVE' in subsystem.upper():
            subsystem_val = 1
        elif 'EFI' in subsystem.upper():
            subsystem_val = 10

    if subsystem_val == 2:
        classifications.append("GUI Application")
        evidence.append("Subsystem: Windows GUI")
    elif subsystem_val == 3:
        classifications.append("Console Application")
        evidence.append("Subsystem: Windows Console")
    elif subsystem_val == 1:
        classifications.append("Native/Kernel-mode")
        evidence.append("Subsystem: Native (kernel-mode driver or boot program)")
    elif isinstance(subsystem_val, int) and 10 <= subsystem_val <= 13:
        classifications.append("EFI Application")
        evidence.append(f"Subsystem: EFI ({subsystem_val})")

    if com_descriptor and isinstance(com_descriptor, dict) and com_descriptor.get('cb', com_descriptor.get('size', 0)):
        classifications.append(".NET Assembly")
        evidence.append("COM/.NET descriptor (IMAGE_COR20_HEADER) present")

    driver_dlls = {'ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'wdm.sys', 'ntdll.dll'}
    driver_imports = {'IoCreateDevice', 'IoDeleteDevice', 'IoCreateSymbolicLink',
                      'KeInitializeDpc', 'MmMapIoSpace', 'ExAllocatePool',
                      'ObReferenceObjectByHandle', 'PsCreateSystemThread'}
    if all_dll_names & driver_dlls or all_import_names & driver_imports:
        classifications.append("Device Driver")
        evidence.append(f"Driver DLLs/imports detected: {(all_dll_names & driver_dlls) | (all_import_names & driver_imports)}")

    service_imports = {'StartServiceCtrlDispatcherA', 'StartServiceCtrlDispatcherW',
                       'RegisterServiceCtrlHandlerA', 'RegisterServiceCtrlHandlerW',
                       'RegisterServiceCtrlHandlerExA', 'RegisterServiceCtrlHandlerExW'}
    if all_import_names & service_imports:
        classifications.append("Windows Service")
        evidence.append(f"Service dispatcher imports: {all_import_names & service_imports}")

    installer_indicators = []
    for sec in sections_data:
        if isinstance(sec, dict):
            name = sec.get('name', '').strip()
            if name in ('.ndata', '.nsis'):
                installer_indicators.append(f"NSIS section: {name}")
    if isinstance(version_info, dict):
        for key in ('FileDescription', 'ProductName', 'InternalName', 'OriginalFilename'):
            val = str(version_info.get(key, '')).lower()
            if any(kw in val for kw in ('setup', 'install', 'uninstall', 'updater')):
                installer_indicators.append(f"Version info '{key}' contains installer keyword: {val}")
    overlay = pe_data.get('overlay_data', {})
    if isinstance(overlay, dict) and overlay.get('size', 0) > 100000:
        installer_indicators.append(f"Large overlay ({overlay.get('size')} bytes) — common in SFX archives")

    if installer_indicators:
        classifications.append("Installer/SFX")
        evidence.extend(installer_indicators)

    net_dlls = {'ws2_32.dll', 'winhttp.dll', 'wininet.dll', 'urlmon.dll', 'mswsock.dll'}
    if len(all_dll_names & net_dlls) >= 2:
        classifications.append("Networking-Heavy")
        evidence.append(f"Multiple networking DLLs: {all_dll_names & net_dlls}")

    crypto_funcs = {'CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt',
                    'CryptDeriveKey', 'CryptGenKey', 'CryptAcquireContext'}
    if all_import_names & crypto_funcs:
        classifications.append("Crypto-Heavy")
        evidence.append(f"Cryptographic API imports: {all_import_names & crypto_funcs}")

    gui_dlls = {'user32.dll', 'gdi32.dll', 'comctl32.dll', 'comdlg32.dll', 'uxtheme.dll'}
    gui_funcs = {'CreateWindowExA', 'CreateWindowExW', 'ShowWindow', 'MessageBoxA',
                 'MessageBoxW', 'DialogBoxParamA', 'DialogBoxParamW', 'GetDC'}
    if len(all_dll_names & gui_dlls) >= 2 or all_import_names & gui_funcs:
        if "GUI Application" not in classifications:
            classifications.append("GUI Application")
        evidence.append(f"GUI DLLs: {all_dll_names & gui_dlls}")

    priority_order = ["Device Driver", "Native/Kernel-mode", "Windows Service",
                      ".NET Assembly", "Installer/SFX", "DLL/Library",
                      "GUI Application", "Console Application", "EFI Application"]
    primary = "Unknown PE"
    for p in priority_order:
        if p in classifications:
            primary = p
            break

    behavioral_indicators: List[str] = []
    triage = getattr(state, '_cached_triage', None)
    risk_level = None

    if triage:
        risk_level = triage.get("risk_level")
        sus_caps = triage.get("suspicious_capabilities", [])
        if isinstance(sus_caps, list):
            for cap in sus_caps:
                if isinstance(cap, dict):
                    ns = cap.get("namespace", "")
                    name = cap.get("name", cap.get("capability", ""))
                    if ns and name:
                        behavioral_indicators.append(f"{ns}: {name}")
                    elif name:
                        behavioral_indicators.append(str(name))
                elif isinstance(cap, str):
                    behavioral_indicators.append(cap)

        for func_name in all_import_names:
            for api_pattern, behavior in _IMPORT_BEHAVIORS.items():
                if api_pattern in func_name:
                    indicator = f"{behavior} ({func_name})"
                    if indicator not in behavioral_indicators:
                        behavioral_indicators.append(indicator)
                    break

    result: Dict[str, Any] = {
        "primary_type": primary,
        "classifications": classifications,
        "evidence": evidence,
        "is_dll": is_dll,
        "subsystem": subsystem,
        "has_overlay": bool(overlay.get('size', 0) > 0) if isinstance(overlay, dict) else False,
        "has_dotnet": ".NET Assembly" in classifications,
        "import_dll_count": len(all_dll_names),
        "import_function_count": len(all_import_names),
    }

    if behavioral_indicators:
        result["behavioral_indicators"] = behavioral_indicators[:20]
        if len(behavioral_indicators) > 20:
            result["behavioral_indicators_pagination"] = {"total": len(behavioral_indicators), "returned": 20, "has_more": True}
    if risk_level:
        result["risk_level"] = risk_level

    return result


@tool_decorator
async def classify_binary_purpose(ctx: Context) -> Dict[str, Any]:
    """
    [Phase: triage] Classifies the loaded binary by purpose and type using PE header
    analysis, import patterns, section characteristics, and resource presence.

    When to use: After get_triage_report() to understand what kind of binary you
    are dealing with before deep-dive analysis.

    Categories: GUI Application, Console Application, DLL/Library, System Service,
    Device Driver, Installer/SFX, .NET Assembly, and more.

    Typical next steps based on classification:
      - DLL/Library → get_focused_imports(), get_pe_data(key='exports')
      - .NET Assembly → dotnet_analyze(), dotnet_disassemble_method()
      - Installer/SFX → scan_for_embedded_files(), extract_resources()
      - Device Driver → get_load_config_details(), get_section_permissions()

    Returns:
        A dictionary with the primary classification, confidence indicators,
        and supporting evidence.
    """
    await ctx.info("Classifying binary purpose...")
    _check_pe_loaded("classify_binary_purpose")

    # Return cached result if enrichment already ran classification
    if state._cached_classification:
        return state._cached_classification

    result = _classify_core()
    state._cached_classification = result
    return result
