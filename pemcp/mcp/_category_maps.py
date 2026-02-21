"""Shared import/function category mappings for AI-friendly analysis tools.

Used by get_focused_imports, get_function_map, auto_note_function, and
get_cross_reference_map to provide consistent semantic grouping.
"""

# Risk level + category for each suspicious API.
# Format: {api_name: (risk_level, category)}
CATEGORIZED_IMPORTS_DB = {
    # --- Process injection / code execution ---
    "CreateRemoteThread": ("CRITICAL", "process_injection"),
    "NtCreateThreadEx": ("CRITICAL", "process_injection"),
    "RtlCreateUserThread": ("CRITICAL", "process_injection"),
    "WriteProcessMemory": ("CRITICAL", "process_injection"),
    "NtWriteVirtualMemory": ("CRITICAL", "process_injection"),
    "VirtualAllocEx": ("CRITICAL", "process_injection"),
    "NtAllocateVirtualMemory": ("CRITICAL", "process_injection"),
    "QueueUserAPC": ("CRITICAL", "process_injection"),
    "NtQueueApcThread": ("CRITICAL", "process_injection"),
    "SetWindowsHookEx": ("CRITICAL", "process_injection"),
    "NtMapViewOfSection": ("CRITICAL", "process_injection"),
    "NtUnmapViewOfSection": ("CRITICAL", "process_injection"),
    "ZwMapViewOfSection": ("CRITICAL", "process_injection"),
    "LdrLoadDll": ("CRITICAL", "process_injection"),

    # --- Credential theft / privilege escalation ---
    "MiniDumpWriteDump": ("CRITICAL", "credential_theft"),
    "LsaEnumerateLogonSessions": ("CRITICAL", "credential_theft"),
    "AdjustTokenPrivileges": ("CRITICAL", "privilege_escalation"),
    "ImpersonateLoggedOnUser": ("CRITICAL", "privilege_escalation"),
    "OpenProcessToken": ("CRITICAL", "privilege_escalation"),
    "DuplicateToken": ("CRITICAL", "privilege_escalation"),

    # --- Anti-analysis / evasion ---
    "IsDebuggerPresent": ("HIGH", "anti_analysis"),
    "CheckRemoteDebuggerPresent": ("HIGH", "anti_analysis"),
    "NtQueryInformationProcess": ("HIGH", "anti_analysis"),
    "OutputDebugString": ("HIGH", "anti_analysis"),
    "GetTickCount": ("HIGH", "anti_analysis"),
    "QueryPerformanceCounter": ("HIGH", "anti_analysis"),
    "NtSetInformationThread": ("HIGH", "anti_analysis"),

    # --- Networking (C2 potential) ---
    "InternetOpen": ("HIGH", "networking"),
    "InternetConnect": ("HIGH", "networking"),
    "HttpOpenRequest": ("HIGH", "networking"),
    "HttpSendRequest": ("HIGH", "networking"),
    "URLDownloadToFile": ("HIGH", "networking"),
    "URLDownloadToCacheFile": ("HIGH", "networking"),
    "WinHttpOpen": ("HIGH", "networking"),
    "WinHttpConnect": ("HIGH", "networking"),

    # --- Process / service manipulation ---
    "OpenProcess": ("HIGH", "process_manipulation"),
    "TerminateProcess": ("HIGH", "process_manipulation"),
    "CreateService": ("HIGH", "persistence"),
    "StartService": ("HIGH", "persistence"),
    "ShellExecute": ("HIGH", "execution"),
    "WinExec": ("HIGH", "execution"),
    "CreateProcess": ("HIGH", "execution"),

    # --- Registry / persistence ---
    "RegSetValueEx": ("MEDIUM", "registry"),
    "RegCreateKeyEx": ("MEDIUM", "registry"),
    "RegDeleteKey": ("MEDIUM", "registry"),
    "RegDeleteValue": ("MEDIUM", "registry"),

    # --- Crypto (ransomware indicators) ---
    "CryptEncrypt": ("MEDIUM", "crypto"),
    "CryptDecrypt": ("MEDIUM", "crypto"),
    "CryptAcquireContext": ("MEDIUM", "crypto"),
    "BCryptEncrypt": ("MEDIUM", "crypto"),
    "CryptDeriveKey": ("MEDIUM", "crypto"),
    "CryptGenKey": ("MEDIUM", "crypto"),

    # --- File operations (dropper indicators) ---
    "CreateFileMapping": ("MEDIUM", "file_io"),
    "MapViewOfFile": ("MEDIUM", "file_io"),
    "VirtualProtect": ("MEDIUM", "memory"),
    "SetFileAttributes": ("MEDIUM", "file_io"),

    # --- Socket-level networking ---
    "WSAStartup": ("MEDIUM", "networking"),
    "connect": ("MEDIUM", "networking"),
    "send": ("MEDIUM", "networking"),
    "recv": ("MEDIUM", "networking"),
    "socket": ("MEDIUM", "networking"),
    "bind": ("MEDIUM", "networking"),
    "listen": ("MEDIUM", "networking"),
    "accept": ("MEDIUM", "networking"),
}

# Category display names and descriptions for AI output
CATEGORY_DESCRIPTIONS = {
    "process_injection": "Process Injection — code injection into other processes",
    "credential_theft": "Credential Theft — dumping/stealing credentials",
    "privilege_escalation": "Privilege Escalation — elevating process privileges",
    "anti_analysis": "Anti-Analysis — debugger detection, timing checks",
    "networking": "Networking — HTTP, sockets, C2 communication",
    "process_manipulation": "Process Manipulation — opening/terminating processes",
    "persistence": "Persistence — services, autorun, scheduled tasks",
    "execution": "Execution — launching processes, shell commands",
    "registry": "Registry — reading/writing registry keys",
    "crypto": "Cryptography — encryption/decryption operations",
    "file_io": "File I/O — file mapping, attribute manipulation",
    "memory": "Memory — virtual memory protection changes",
}

# Risk level ordering (for sorting)
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# String categorization patterns (compiled on first use)
import re as _re

STRING_CATEGORY_PATTERNS = {
    "urls": _re.compile(r'(?:https?|ftp)://[^\s\'"<>]+', _re.IGNORECASE),
    "ip_addresses": _re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domains": _re.compile(
        r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|su|onion)\b',
        _re.IGNORECASE,
    ),
    "file_paths": _re.compile(r'[A-Z]:\\[^\s\'"<>]{3,}', _re.IGNORECASE),
    "registry_keys": _re.compile(
        r'(?:HKLM|HKCU|HKCR|HKU|HKCC|Software)\\[^\s\'"]+', _re.IGNORECASE,
    ),
    "mutex_names": _re.compile(r'(?:Global|Local)\\[^\s\'"]+'),
    "email_addresses": _re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "base64_blobs": _re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
}

# Well-known benign IPs to exclude from IOC extraction
BENIGN_IP_PREFIXES = {0, 10, 127, 255}  # first octet
