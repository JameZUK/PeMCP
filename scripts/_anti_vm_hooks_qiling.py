"""Anti-VM bypass hooks for Qiling emulation — runner-side bridge.

Lightweight wrapper that installs instruction-level hooks (CPUID, RDTSC, IN)
on a Qiling instance to bypass common VM detection techniques.  Used by
qiling_runner.py when anti_vm_bypass=True.

This file lives in scripts/ alongside qiling_runner.py and runs inside the
Qiling venv.  It is self-contained (no imports from arkana.*).

Based on techniques from:
    Lee et al., "Bypassing Anti-Analysis of Commercial Protector Methods
    Using DBI Tools" (IEEE Access, 2021)
"""
import struct

# Maximum triggers before we stop recording (prevent unbounded memory growth)
_MAX_TRIGGERS = 10_000

# VMware backdoor I/O port
_VMWARE_PORT = 0x5658
_VMWARE_MAGIC = 0x564D5868  # "VMXh"


def _record_trigger(triggers, bypass_type, address):
    """Record a triggered bypass if under the cap."""
    if len(triggers) < _MAX_TRIGGERS:
        triggers.append({"type": bypass_type, "address": hex(address)})


def install_anti_vm_hooks_qiling(ql, triggers):
    """Install all anti-VM instruction hooks on a Qiling instance.

    Args:
        ql: Qiling instance (already initialised).
        triggers: Mutable list to record triggered bypasses.

    Returns:
        Dict with installation summary.
    """
    installed = []
    failed = []

    # Determine if 64-bit
    is_64 = hasattr(ql, 'arch') and '64' in str(getattr(ql.arch, 'type', ''))

    # State for RDTSC spoofing
    rdtsc_state = {"last_tsc": 0x100000000}

    # --- CPUID bypass ---
    # Strategy: pre-hook saves the leaf number (EAX before CPUID), then
    # installs a one-shot hook at the next instruction (address + size) to
    # modify registers AFTER CPUID has written its results.
    try:
        cpuid_pending = {"leaf": None, "addr": 0}
        cpuid_fixup_hooks = set()  # Track installed one-shot addresses

        def _cpuid_pre_hook(ql, address, size):
            try:
                code = ql.mem.read(address, min(size, 4))
                if len(code) >= 2 and code[0] == 0x0F and code[1] == 0xA2:
                    # Save leaf number BEFORE cpuid overwrites EAX
                    leaf = ql.arch.regs.rax & 0xFFFFFFFF if is_64 else ql.arch.regs.eax & 0xFFFFFFFF
                    cpuid_pending["leaf"] = leaf
                    cpuid_pending["addr"] = address
                    # Install one-shot post-hook at next instruction
                    next_addr = address + size
                    if next_addr not in cpuid_fixup_hooks:
                        cpuid_fixup_hooks.add(next_addr)
                        ql.hook_address(_cpuid_fixup, next_addr)
            except Exception:
                pass

        def _cpuid_fixup(ql):
            """Fix CPUID results after the instruction has executed."""
            try:
                leaf = cpuid_pending.get("leaf")
                orig_addr = cpuid_pending.get("addr", 0)
                cpuid_pending["leaf"] = None
                if leaf is None:
                    return
                if leaf == 1:
                    ecx = ql.arch.regs.rcx if is_64 else ql.arch.regs.ecx
                    if ecx & (1 << 31):
                        new_ecx = ecx & ~(1 << 31)
                        if is_64:
                            ql.arch.regs.rcx = new_ecx
                        else:
                            ql.arch.regs.ecx = new_ecx
                        _record_trigger(triggers, "cpuid_hypervisor_bit", orig_addr)
                elif leaf == 0x40000000:
                    if is_64:
                        ql.arch.regs.rbx = 0
                        ql.arch.regs.rcx = 0
                        ql.arch.regs.rdx = 0
                    else:
                        ql.arch.regs.ebx = 0
                        ql.arch.regs.ecx = 0
                        ql.arch.regs.edx = 0
                    _record_trigger(triggers, "cpuid_vendor_string", orig_addr)
            except Exception:
                pass

        ql.hook_code(_cpuid_pre_hook)
        installed.append("cpuid")
    except Exception as e:
        failed.append(f"cpuid: {e}")

    # --- RDTSC bypass ---
    # Same strategy: detect RDTSC pre-execution, fix registers post-execution
    # via one-shot hook_address at the next instruction.
    try:
        rdtsc_pending = {"active": False, "addr": 0}
        rdtsc_fixup_hooks = set()

        def _rdtsc_pre_hook(ql, address, size):
            try:
                code = ql.mem.read(address, min(size, 4))
                if len(code) >= 2 and code[0] == 0x0F and code[1] == 0x31:
                    rdtsc_pending["active"] = True
                    rdtsc_pending["addr"] = address
                    next_addr = address + size
                    if next_addr not in rdtsc_fixup_hooks:
                        rdtsc_fixup_hooks.add(next_addr)
                        ql.hook_address(_rdtsc_fixup, next_addr)
            except Exception:
                pass

        def _rdtsc_fixup(ql):
            """Replace RDTSC result with spoofed timestamp."""
            try:
                if not rdtsc_pending.get("active"):
                    return
                rdtsc_pending["active"] = False
                orig_addr = rdtsc_pending.get("addr", 0)
                delta = 100 + ((orig_addr & 0xFFF) % 4900)
                rdtsc_state["last_tsc"] += delta
                tsc = rdtsc_state["last_tsc"]
                low = tsc & 0xFFFFFFFF
                high = (tsc >> 32) & 0xFFFFFFFF
                if is_64:
                    ql.arch.regs.rax = low
                    ql.arch.regs.rdx = high
                else:
                    ql.arch.regs.eax = low
                    ql.arch.regs.edx = high
                _record_trigger(triggers, "rdtsc", orig_addr)
            except Exception:
                pass

        ql.hook_code(_rdtsc_pre_hook)
        installed.append("rdtsc")
    except Exception as e:
        failed.append(f"rdtsc: {e}")

    # --- IN instruction bypass (VMware backdoor port) ---
    try:
        def _in_hook(ql, address, size):
            try:
                code = ql.mem.read(address, min(size, 4))
                # IN AL, DX = EC; IN EAX, DX = ED
                if len(code) >= 1 and code[0] in (0xEC, 0xED):
                    # Check if DX == VMware port
                    if is_64:
                        dx = ql.arch.regs.rdx & 0xFFFF
                    else:
                        dx = ql.arch.regs.edx & 0xFFFF
                    if dx == _VMWARE_PORT:
                        # Clear VMXh magic from EBX
                        if is_64:
                            ql.arch.regs.rbx = 0
                        else:
                            ql.arch.regs.ebx = 0
                        _record_trigger(triggers, "vmware_io_port", address)
            except Exception:
                pass

        ql.hook_code(_in_hook)
        installed.append("io_port")
    except Exception as e:
        failed.append(f"io_port: {e}")

    return {
        "installed": installed,
        "failed": failed,
        "trigger_list": triggers,
    }


def check_anti_vm_triggers(triggers):
    """Produce a summary of triggered anti-VM bypasses.

    Args:
        triggers: List of trigger dicts from install_anti_vm_hooks_qiling.

    Returns:
        Summary dict.
    """
    by_type = {}
    unique_addrs = set()
    for t in triggers:
        tp = t.get("type", "unknown")
        by_type[tp] = by_type.get(tp, 0) + 1
        unique_addrs.add(t.get("address"))

    return {
        "total_triggers": len(triggers),
        "by_type": by_type,
        "unique_addresses": len(unique_addrs),
        "capped": len(triggers) >= _MAX_TRIGGERS,
        "summary": (
            f"{len(triggers)} anti-VM bypass(es) triggered across "
            f"{len(unique_addrs)} unique address(es)"
        ) if triggers else "No VM detection attempts observed",
    }
