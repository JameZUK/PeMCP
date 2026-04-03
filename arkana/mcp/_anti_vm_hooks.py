"""Anti-VM bypass hooks for Qiling emulation instances.

Provides instruction-level hooks (CPUID, RDTSC, IN) and data sets (registry
keys, process names, MAC prefixes, firmware strings) used by Qiling runners
to defeat anti-VM checks in malware samples.

Based on techniques from:
  Lee et al., "Bypassing Anti-Analysis of Commercial Protector Methods
  Using DBI Tools", IEEE Access, 2021.

Design constraints:
  - No Qiling import at module level (may not be available).
  - Instruction hooks use Qiling's ``hook_code`` callback signature:
    ``callback(ql, address, size)``.
  - Triggered bypasses are tracked in a caller-supplied list (pass by ref).
  - Trigger list capped at ``MAX_BYPASS_TRIGGERS`` to prevent memory growth.
"""
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
#  Constants
# ---------------------------------------------------------------------------

# Maximum number of bypass trigger records to keep per session.
MAX_BYPASS_TRIGGERS = 10_000

# x86/x64 instruction opcodes
_CPUID_OPCODE = b"\x0f\xa2"       # CPUID
_RDTSC_OPCODE = b"\x0f\x31"       # RDTSC
_IN_AL_DX = b"\xec"               # IN AL, DX  (1-byte form)
_IN_EAX_DX = b"\xed"              # IN EAX, DX (1-byte form)

# VMware backdoor I/O port
_VMWARE_BACKDOOR_PORT = 0x5658

# VMware backdoor magic value (VMXh)
_VMWARE_MAGIC = 0x564D5868

# CPUID hypervisor present bit (ECX bit 31 when EAX=1)
_CPUID_HYPERVISOR_BIT = 1 << 31

# CPUID leaf for hypervisor vendor string
_CPUID_HYPERVISOR_VENDOR_LEAF = 0x40000000

# RDTSC realistic delta range (cycles between consecutive reads)
_RDTSC_MIN_DELTA = 100
_RDTSC_MAX_DELTA = 5000

# Initial TSC value (roughly plausible boot TSC for a modern processor)
_RDTSC_INITIAL_TSC = 0x0000_0100_0000_0000


# ---------------------------------------------------------------------------
#  VM registry key substrings (for RegOpenKeyExA/W interception)
# ---------------------------------------------------------------------------

_VM_REGISTRY_KEYS = frozenset({
    # VMware
    r"SOFTWARE\VMware, Inc.\VMware Tools",
    r"SYSTEM\CurrentControlSet\Services\VMTools",
    r"SYSTEM\CurrentControlSet\Services\vmci",
    r"SYSTEM\CurrentControlSet\Services\vmhgfs",
    r"SYSTEM\CurrentControlSet\Services\vmmouse",
    r"SYSTEM\CurrentControlSet\Services\vmrawdsk",
    r"SYSTEM\CurrentControlSet\Services\vmusbmouse",
    r"SYSTEM\CurrentControlSet\Services\vmx86",
    r"SYSTEM\CurrentControlSet\Services\vmnet",
    # VirtualBox
    r"SOFTWARE\Oracle\VirtualBox Guest Additions",
    r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
    r"SYSTEM\CurrentControlSet\Services\VBoxMouse",
    r"SYSTEM\CurrentControlSet\Services\VBoxSF",
    r"SYSTEM\CurrentControlSet\Services\VBoxVideo",
    r"HARDWARE\ACPI\DSDT\VBOX__",
    r"HARDWARE\ACPI\FADT\VBOX__",
    # QEMU
    r"SYSTEM\CurrentControlSet\Services\QEMU",
    r"HARDWARE\Description\System\QEMU",
    # Hyper-V
    r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    r"SYSTEM\CurrentControlSet\Services\vmbus",
    r"SYSTEM\CurrentControlSet\Services\vmicheartbeat",
    r"SYSTEM\CurrentControlSet\Services\vmicshutdown",
    r"SYSTEM\CurrentControlSet\Services\vmickvpexchange",
    r"SYSTEM\CurrentControlSet\Services\storvsc",
    r"SYSTEM\CurrentControlSet\Services\netvsc",
})


# ---------------------------------------------------------------------------
#  VM process names (for process enumeration interception)
# ---------------------------------------------------------------------------

_VM_PROCESS_NAMES = frozenset({
    # VMware
    "vmwareservice.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
    "vmtoolsd.exe",
    "vmacthlp.exe",
    # VirtualBox
    "vboxservice.exe",
    "vboxtray.exe",
    "vboxcontrol.exe",
    # QEMU
    "qemu-ga.exe",
    # Hyper-V
    "vmicheartbeat.exe",
    # Parallels
    "prl_tools.exe",
    "prl_cc.exe",
    # Sandbox
    "sbiectrl.exe",
    "sbiesvc.exe",
    # Analysis tools (sometimes checked by malware)
    "wireshark.exe",
    "procmon.exe",
    "procexp.exe",
    "ollydbg.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "idaq.exe",
    "idaq64.exe",
    "ida.exe",
    "ida64.exe",
    "fiddler.exe",
})


# ---------------------------------------------------------------------------
#  VM MAC address OUI prefixes
# ---------------------------------------------------------------------------

_VM_MAC_PREFIXES = frozenset({
    # VMware
    "00:0C:29",
    "00:50:56",
    "00:05:69",
    # VirtualBox
    "08:00:27",
    # QEMU/KVM
    "52:54:00",
    # Hyper-V
    "00:15:5D",
    # Xen
    "00:16:3E",
    # Parallels
    "00:1C:42",
})


# ---------------------------------------------------------------------------
#  VM firmware/SMBIOS vendor strings to scrub
# ---------------------------------------------------------------------------

_VM_FIRMWARE_STRINGS = frozenset({
    # VMware
    "VMware",
    "VMware, Inc.",
    "VMware Virtual Platform",
    "VMware7,1",
    "VMwareVMware",
    # VirtualBox
    "VirtualBox",
    "innotek GmbH",
    "Oracle Corporation",
    "VBOX",
    "VBOX HARDDISK",
    "VBOX CD-ROM",
    # QEMU
    "QEMU",
    "QEMU HARDDISK",
    "QEMU DVD-ROM",
    "Bochs",
    "BOCHS",
    "SeaBIOS",
    # Xen
    "Xen",
    "XenVMMXenVMM",
    "xen",
    # KVM
    "KVMKVMKVM",
    "KVM",
    # Hyper-V
    "Microsoft Hv",
    "Microsoft Corporation",
    "Virtual Machine",
    "Virtual HD",
    # Parallels
    "Parallels",
    "Parallels Software International",
    "Parallels Virtual Platform",
})


# ---------------------------------------------------------------------------
#  Public data accessors
# ---------------------------------------------------------------------------

def get_vm_registry_keys() -> frozenset:
    """Return registry key substrings that indicate VM presence.

    Used by the Qiling runner to intercept ``RegOpenKeyExA``/``RegOpenKeyExW``
    and return ``ERROR_FILE_NOT_FOUND`` for matching paths.
    """
    return _VM_REGISTRY_KEYS


def get_vm_process_names() -> frozenset:
    """Return lowercase process names associated with VM tools.

    Used to filter results from ``CreateToolhelp32Snapshot`` /
    ``Process32First`` / ``Process32Next`` enumeration hooks.
    """
    return _VM_PROCESS_NAMES


def get_vm_mac_prefixes() -> frozenset:
    """Return known VM MAC address OUI prefixes (colon-separated).

    Prefixes cover VMware, VirtualBox, QEMU/KVM, Hyper-V, Xen, and
    Parallels.  Used to spoof ``GetAdaptersInfo`` / ``GetAdaptersAddresses``
    results.
    """
    return _VM_MAC_PREFIXES


def get_vm_firmware_strings() -> frozenset:
    """Return strings to scrub from SMBIOS/firmware table responses.

    Covers vendor, product, and version strings for VMware, VirtualBox,
    QEMU, Xen, KVM, Hyper-V, and Parallels.  Used to intercept
    ``GetSystemFirmwareTable`` results.
    """
    return _VM_FIRMWARE_STRINGS


# ---------------------------------------------------------------------------
#  Instruction-level bypass hooks
# ---------------------------------------------------------------------------

def _record_trigger(
    triggers: List[Dict[str, Any]],
    bypass_type: str,
    address: int,
    detail: str,
) -> None:
    """Append a bypass trigger record if under the cap.

    Args:
        triggers: Mutable list to append to (passed by reference).
        bypass_type: Category string (e.g. ``"cpuid"``, ``"rdtsc"``).
        address: Instruction address where the bypass fired.
        detail: Human-readable description of what was spoofed.
    """
    if len(triggers) >= MAX_BYPASS_TRIGGERS:
        return
    triggers.append({
        "type": bypass_type,
        "address": address,
        "detail": detail,
    })


def install_cpuid_bypass(
    ql: "Any",
    triggers: List[Dict[str, Any]],
) -> bool:
    """Install a CPUID spoofing hook on a Qiling instance.

    Intercepts the ``CPUID`` instruction (``0F A2``) and modifies results:

    - **EAX=1** (feature flags): Clears ECX bit 31 (hypervisor present).
    - **EAX=0x40000000** (hypervisor vendor): Zeros EBX/ECX/EDX to hide
      the hypervisor brand string.

    Args:
        ql: Qiling instance to hook.
        triggers: Mutable list for recording triggered bypasses.

    Returns:
        True if the hook was installed, False on failure.
    """
    # Deferred hook pattern: pre-hook saves the CPUID leaf (EAX before
    # execution), then installs a one-shot hook_address at the next
    # instruction to modify registers AFTER CPUID has written its results.
    cpuid_pending: Dict[str, Any] = {"leaf": None, "addr": 0}
    cpuid_fixup_addrs: set = set()

    def _cpuid_pre_hook(ql_inst: "Any", address: int, size: int) -> None:
        if size < 2:
            return
        try:
            insn_bytes = bytes(ql_inst.mem.read(address, min(size, 4)))
        except Exception:
            return
        if not insn_bytes.startswith(_CPUID_OPCODE):
            return
        # Save leaf BEFORE cpuid overwrites EAX
        try:
            cpuid_pending["leaf"] = ql_inst.arch.regs.eax & 0xFFFFFFFF
            cpuid_pending["addr"] = address
            next_addr = address + size
            if next_addr not in cpuid_fixup_addrs:
                cpuid_fixup_addrs.add(next_addr)
                ql_inst.hook_address(_cpuid_fixup, next_addr)
        except Exception:
            pass

    def _cpuid_fixup(ql_inst: "Any") -> None:
        """Fix CPUID results after the instruction has executed."""
        try:
            leaf = cpuid_pending.get("leaf")
            orig_addr = cpuid_pending.get("addr", 0)
            cpuid_pending["leaf"] = None
            if leaf is None:
                return
            if leaf == 1:
                ecx = ql_inst.arch.regs.ecx & 0xFFFFFFFF
                if ecx & _CPUID_HYPERVISOR_BIT:
                    ql_inst.arch.regs.ecx = ecx & ~_CPUID_HYPERVISOR_BIT
                    _record_trigger(
                        triggers, "cpuid", orig_addr,
                        "Cleared hypervisor-present bit (ECX.31) for CPUID leaf 1",
                    )
            elif leaf == _CPUID_HYPERVISOR_VENDOR_LEAF:
                ql_inst.arch.regs.ebx = 0
                ql_inst.arch.regs.ecx = 0
                ql_inst.arch.regs.edx = 0
                _record_trigger(
                    triggers, "cpuid", orig_addr,
                    "Zeroed hypervisor vendor string (EBX/ECX/EDX) for "
                    "CPUID leaf 0x40000000",
                )
        except Exception:
            pass

    try:
        ql.hook_code(_cpuid_pre_hook)
        return True
    except Exception:
        return False


def install_rdtsc_bypass(
    ql: "Any",
    triggers: List[Dict[str, Any]],
) -> bool:
    """Install an RDTSC timing normalisation hook on a Qiling instance.

    Intercepts the ``RDTSC`` instruction (``0F 31``) and replaces the
    timestamp counter value with small realistic deltas (100--5000 cycles)
    to defeat timing-based VM/debugger detection.

    The hook maintains a monotonically increasing counter starting from
    ``_RDTSC_INITIAL_TSC``, incrementing by a deterministic amount derived
    from the instruction address to produce reproducible results.

    Args:
        ql: Qiling instance to hook.
        triggers: Mutable list for recording triggered bypasses.

    Returns:
        True if the hook was installed, False on failure.
    """
    # Deferred hook pattern: detect RDTSC pre-execution, apply spoofed
    # values post-execution via one-shot hook_address.
    tsc_state = {"last_tsc": _RDTSC_INITIAL_TSC}
    rdtsc_pending: Dict[str, Any] = {"active": False, "addr": 0}
    rdtsc_fixup_addrs: set = set()

    def _rdtsc_pre_hook(ql_inst: "Any", address: int, size: int) -> None:
        if size < 2:
            return
        try:
            insn_bytes = bytes(ql_inst.mem.read(address, min(size, 4)))
        except Exception:
            return
        if not insn_bytes.startswith(_RDTSC_OPCODE):
            return
        rdtsc_pending["active"] = True
        rdtsc_pending["addr"] = address
        try:
            next_addr = address + size
            if next_addr not in rdtsc_fixup_addrs:
                rdtsc_fixup_addrs.add(next_addr)
                ql_inst.hook_address(_rdtsc_fixup, next_addr)
        except Exception:
            pass

    def _rdtsc_fixup(ql_inst: "Any") -> None:
        """Replace RDTSC result with spoofed timestamp."""
        try:
            if not rdtsc_pending.get("active"):
                return
            rdtsc_pending["active"] = False
            orig_addr = rdtsc_pending.get("addr", 0)
            delta = _RDTSC_MIN_DELTA + (orig_addr % (_RDTSC_MAX_DELTA - _RDTSC_MIN_DELTA))
            new_tsc = tsc_state["last_tsc"] + delta
            tsc_state["last_tsc"] = new_tsc
            ql_inst.arch.regs.eax = new_tsc & 0xFFFFFFFF
            ql_inst.arch.regs.edx = (new_tsc >> 32) & 0xFFFFFFFF
            _record_trigger(
                triggers, "rdtsc", orig_addr,
                f"Spoofed RDTSC: delta={delta}, TSC=0x{new_tsc:016x}",
            )
        except Exception:
            pass

    try:
        ql.hook_code(_rdtsc_pre_hook)
        return True
    except Exception:
        return False


def install_io_port_bypass(
    ql: "Any",
    triggers: List[Dict[str, Any]],
) -> bool:
    """Install an IN instruction hook to block VMware backdoor port access.

    Intercepts ``IN AL, DX`` (``EC``) and ``IN EAX, DX`` (``ED``)
    instructions.  When DX contains the VMware backdoor port (``0x5658``),
    clears EBX to remove the VMXh magic signature (``0x564D5868``).

    Args:
        ql: Qiling instance to hook.
        triggers: Mutable list for recording triggered bypasses.

    Returns:
        True if the hook was installed, False on failure.
    """
    def _io_port_hook(ql_inst: "Any", address: int, size: int) -> None:
        if size < 1:
            return
        try:
            insn_bytes = bytes(ql_inst.mem.read(address, min(size, 4)))
        except Exception:
            return

        # Check for IN AL, DX or IN EAX, DX
        if insn_bytes[:1] not in (_IN_AL_DX, _IN_EAX_DX):
            return

        # Check if DX holds the VMware backdoor port
        try:
            dx = ql_inst.arch.regs.dx & 0xFFFF
        except AttributeError:
            # Some Qiling versions expose dx via edx
            try:
                dx = ql_inst.arch.regs.edx & 0xFFFF
            except Exception:
                return

        if dx != _VMWARE_BACKDOOR_PORT:
            return

        # Clear EBX to remove VMXh signature
        try:
            ql_inst.arch.regs.ebx = 0
            _record_trigger(
                triggers, "io_port", address,
                f"Cleared EBX (VMXh signature) on IN instruction to "
                f"VMware backdoor port 0x{_VMWARE_BACKDOOR_PORT:04X}",
            )
        except Exception:
            pass

    try:
        ql.hook_code(_io_port_hook)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
#  Master installer
# ---------------------------------------------------------------------------

def install_anti_vm_hooks(
    ql: "Any",
    triggers: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Install all instruction-level anti-VM bypass hooks on a Qiling instance.

    Installs CPUID spoofing, RDTSC timing normalisation, and VMware
    backdoor port (IN instruction) bypass hooks.  Does NOT install
    API-level hooks (registry, process enumeration, firmware queries) --
    those are handled by the Qiling runner's stub system.

    Args:
        ql: Qiling instance to hook.
        triggers: Optional mutable list for recording triggered bypasses.
            If None, an empty list is created internally.

    Returns:
        Dict with ``installed`` (list of hook names), ``failed`` (list of
        hook names that could not be installed), and ``triggers`` (the
        trigger list reference for later inspection).
    """
    if triggers is None:
        triggers = []

    installed = []
    failed = []

    hooks = [
        ("cpuid_bypass", install_cpuid_bypass),
        ("rdtsc_bypass", install_rdtsc_bypass),
        ("io_port_bypass", install_io_port_bypass),
    ]

    for name, installer in hooks:
        if installer(ql, triggers):
            installed.append(name)
        else:
            failed.append(name)

    return {
        "installed": installed,
        "failed": failed,
        "triggers": triggers,
    }


# ---------------------------------------------------------------------------
#  Bypass report
# ---------------------------------------------------------------------------

def check_anti_vm_triggers(
    triggers: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Summarise anti-VM bypass triggers collected during emulation.

    Args:
        triggers: List of trigger dicts populated by the bypass hooks.

    Returns:
        Summary dict with ``total_triggers``, ``by_type`` breakdown,
        ``capped`` flag, and ``unique_addresses`` count.
    """
    if not triggers:
        return {
            "total_triggers": 0,
            "by_type": {},
            "unique_addresses": 0,
            "capped": False,
            "summary": "No anti-VM bypass triggers recorded.",
        }

    by_type: Dict[str, int] = {}
    unique_addrs: set = set()

    for trigger in triggers:
        bypass_type = trigger.get("type", "unknown")
        by_type[bypass_type] = by_type.get(bypass_type, 0) + 1
        addr = trigger.get("address")
        if addr is not None:
            unique_addrs.add(addr)

    total = len(triggers)
    capped = total >= MAX_BYPASS_TRIGGERS

    # Build human-readable summary
    parts = []
    for btype, count in sorted(by_type.items(), key=lambda x: -x[1]):
        parts.append(f"{btype}: {count}")
    type_summary = ", ".join(parts)

    summary = (
        f"{total} anti-VM bypass{'es' if total != 1 else ''} triggered "
        f"at {len(unique_addrs)} unique address{'es' if len(unique_addrs) != 1 else ''}"
    )
    if capped:
        summary += f" (capped at {MAX_BYPASS_TRIGGERS})"
    summary += f". Breakdown: {type_summary}."

    return {
        "total_triggers": total,
        "by_type": by_type,
        "unique_addresses": len(unique_addrs),
        "capped": capped,
        "summary": summary,
    }
