"""MCP tools for binary purpose classification."""
from typing import Dict, Any
from pemcp.config import state, logger, Context, ANGR_AVAILABLE, CAPA_AVAILABLE, FLOSS_AVAILABLE, YARA_AVAILABLE
from pemcp.mcp.server import tool_decorator, _check_pe_loaded, _check_mcp_response_size


@tool_decorator
async def classify_binary_purpose(ctx: Context) -> Dict[str, Any]:
    """
    Classifies the loaded binary by purpose and type using PE header analysis,
    import patterns, section characteristics, and resource presence.

    Categories: GUI Application, Console Application, DLL/Library, System Service,
    Device Driver, Installer/SFX, .NET Assembly, and more.

    Returns:
        A dictionary with the primary classification, confidence indicators,
        and supporting evidence.
    """
    await ctx.info("Classifying binary purpose...")
    _check_pe_loaded("classify_binary_purpose")

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

    # Extract key header fields
    file_header = nt_headers.get('file_header', {})
    optional_header = nt_headers.get('optional_header', {})
    characteristics = file_header.get('characteristics', file_header.get('Characteristics', 0))
    subsystem = optional_header.get('subsystem', optional_header.get('Subsystem', 0))

    # Extract Value from nested dicts returned by dump_dict()
    if isinstance(characteristics, dict):
        characteristics = characteristics.get('Value', 0)
    if isinstance(subsystem, dict):
        subsystem = subsystem.get('Value', 0)

    # Gather all import function names
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

    # ---- DLL Check ----
    is_dll = False
    if isinstance(characteristics, int):
        is_dll = bool(characteristics & 0x2000)  # IMAGE_FILE_DLL
    elif isinstance(characteristics, str) and 'DLL' in characteristics.upper():
        is_dll = True

    if is_dll:
        classifications.append("DLL/Library")
        evidence.append("FILE_HEADER.Characteristics has IMAGE_FILE_DLL flag")

    # ---- Subsystem Check ----
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

    # ---- .NET Assembly ----
    if com_descriptor and isinstance(com_descriptor, dict) and com_descriptor.get('cb', com_descriptor.get('size', 0)):
        classifications.append(".NET Assembly")
        evidence.append("COM/.NET descriptor (IMAGE_COR20_HEADER) present")

    # ---- Driver Detection ----
    driver_dlls = {'ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'wdm.sys', 'ntdll.dll'}
    driver_imports = {'IoCreateDevice', 'IoDeleteDevice', 'IoCreateSymbolicLink',
                      'KeInitializeDpc', 'MmMapIoSpace', 'ExAllocatePool',
                      'ObReferenceObjectByHandle', 'PsCreateSystemThread'}
    if all_dll_names & driver_dlls or all_import_names & driver_imports:
        classifications.append("Device Driver")
        evidence.append(f"Driver DLLs/imports detected: {(all_dll_names & driver_dlls) | (all_import_names & driver_imports)}")

    # ---- System Service Detection ----
    service_imports = {'StartServiceCtrlDispatcherA', 'StartServiceCtrlDispatcherW',
                       'RegisterServiceCtrlHandlerA', 'RegisterServiceCtrlHandlerW',
                       'RegisterServiceCtrlHandlerExA', 'RegisterServiceCtrlHandlerExW'}
    if all_import_names & service_imports:
        classifications.append("Windows Service")
        evidence.append(f"Service dispatcher imports: {all_import_names & service_imports}")

    # ---- Installer/SFX Detection ----
    installer_indicators = []
    # Check for NSIS/InnoSetup/InstallShield sections or resources
    for sec in sections_data:
        if isinstance(sec, dict):
            name = sec.get('name', '').strip()
            if name in ('.ndata', '.nsis'):
                installer_indicators.append(f"NSIS section: {name}")
    # Check version info
    if isinstance(version_info, dict):
        for key in ('FileDescription', 'ProductName', 'InternalName', 'OriginalFilename'):
            val = str(version_info.get(key, '')).lower()
            if any(kw in val for kw in ('setup', 'install', 'uninstall', 'updater')):
                installer_indicators.append(f"Version info '{key}' contains installer keyword: {val}")
    # Check for large overlay (common in SFX)
    overlay = pe_data.get('overlay_data', {})
    if isinstance(overlay, dict) and overlay.get('size', 0) > 100000:
        installer_indicators.append(f"Large overlay ({overlay.get('size')} bytes) — common in SFX archives")

    if installer_indicators:
        classifications.append("Installer/SFX")
        evidence.extend(installer_indicators)

    # ---- Networking Tool Detection ----
    net_dlls = {'ws2_32.dll', 'winhttp.dll', 'wininet.dll', 'urlmon.dll', 'mswsock.dll'}
    if len(all_dll_names & net_dlls) >= 2:
        classifications.append("Networking-Heavy")
        evidence.append(f"Multiple networking DLLs: {all_dll_names & net_dlls}")

    # ---- Crypto-Heavy Detection ----
    crypto_funcs = {'CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt', 'BCryptDecrypt',
                    'CryptDeriveKey', 'CryptGenKey', 'CryptAcquireContext'}
    if all_import_names & crypto_funcs:
        classifications.append("Crypto-Heavy")
        evidence.append(f"Cryptographic API imports: {all_import_names & crypto_funcs}")

    # ---- GUI Evidence ----
    gui_dlls = {'user32.dll', 'gdi32.dll', 'comctl32.dll', 'comdlg32.dll', 'uxtheme.dll'}
    gui_funcs = {'CreateWindowExA', 'CreateWindowExW', 'ShowWindow', 'MessageBoxA',
                 'MessageBoxW', 'DialogBoxParamA', 'DialogBoxParamW', 'GetDC'}
    if len(all_dll_names & gui_dlls) >= 2 or all_import_names & gui_funcs:
        if "GUI Application" not in classifications:
            classifications.append("GUI Application")
        evidence.append(f"GUI DLLs: {all_dll_names & gui_dlls}")

    # ---- Primary Classification ----
    # Prioritize: Driver > Service > .NET > DLL > Installer > GUI > Console > Unknown
    priority_order = ["Device Driver", "Native/Kernel-mode", "Windows Service",
                      ".NET Assembly", "Installer/SFX", "DLL/Library",
                      "GUI Application", "Console Application", "EFI Application"]
    primary = "Unknown PE"
    for p in priority_order:
        if p in classifications:
            primary = p
            break

    return {
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
