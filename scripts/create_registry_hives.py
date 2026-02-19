#!/usr/bin/env python
"""Create minimal Windows registry hive stubs for Qiling emulation.

Qiling's RegistryManager requires NTUSER.DAT, SAM, SECURITY, SOFTWARE,
SYSTEM, and HARDWARE hive files to initialise Windows emulation.  The official
qilingframework/rootfs repo cannot legally ship these (they contain Microsoft
IP), so we generate minimal-but-structurally-valid stubs.

Each hive contains only a root key node with no subkeys or values -- enough
for Qiling to open and parse the file without crashing.

Usage:
    python scripts/create_registry_hives.py <rootfs_dir>

This is invoked by the Dockerfile at build time and can also be called at
runtime by the qiling_runner.py when hive stubs are missing.
"""
import os
import struct
import sys
from pathlib import Path


def create_minimal_registry_hive():
    """Create a minimal valid Windows registry hive (regf format).

    Returns the raw bytes of a valid hive file with an empty root key.
    """
    # === Base block (regf header, 4096 bytes) ===
    base = bytearray(4096)
    base[0:4] = b'regf'
    struct.pack_into('<I', base, 0x04, 1)        # primary sequence
    struct.pack_into('<I', base, 0x08, 1)        # secondary sequence
    struct.pack_into('<Q', base, 0x0C, 0)        # timestamp
    struct.pack_into('<I', base, 0x14, 1)        # major version
    struct.pack_into('<I', base, 0x18, 5)        # minor version (>=XP)
    struct.pack_into('<I', base, 0x1C, 0)        # type: primary
    struct.pack_into('<I', base, 0x20, 1)        # format: direct memory load
    struct.pack_into('<I', base, 0x24, 0x20)     # root cell offset (in first hbin)
    struct.pack_into('<I', base, 0x28, 0x1000)   # hive bins data size
    struct.pack_into('<I', base, 0x2C, 1)        # clustering factor

    # Checksum: XOR of first 127 DWORDs
    ck = 0
    for i in range(0, 0x1FC, 4):
        ck ^= struct.unpack_from('<I', base, i)[0]
        ck &= 0xFFFFFFFF
    struct.pack_into('<I', base, 0x1FC, ck)

    # === First hbin (4096 bytes) ===
    hbin = bytearray(4096)
    hbin[0:4] = b'hbin'
    struct.pack_into('<I', hbin, 0x08, 0x1000)   # bin size

    # Root key cell at offset 0x20
    co = 0x20
    nk = co + 4  # nk record starts after the 4-byte cell size field

    kn = b'CMI-CreateHive{00000000-0000-0000-0000-000000000000}'
    ct = (4 + 0x4C + len(kn) + 7) & ~7  # cell total = size_field + nk_header + name, 8-aligned

    struct.pack_into('<i', hbin, co, -ct)         # negative = allocated cell
    hbin[nk:nk + 2] = b'nk'                      # signature
    struct.pack_into('<H', hbin, nk + 0x02, 0x24) # flags: KEY_HIVE_ENTRY | KEY_NO_DELETE
    struct.pack_into('<I', hbin, nk + 0x10, 0xFFFFFFFF)  # parent
    struct.pack_into('<I', hbin, nk + 0x1C, 0xFFFFFFFF)  # stable subkey list
    struct.pack_into('<I', hbin, nk + 0x20, 0xFFFFFFFF)  # volatile subkey list
    struct.pack_into('<I', hbin, nk + 0x28, 0xFFFFFFFF)  # value list
    struct.pack_into('<I', hbin, nk + 0x2C, 0xFFFFFFFF)  # security descriptor
    struct.pack_into('<I', hbin, nk + 0x30, 0xFFFFFFFF)  # class name
    struct.pack_into('<H', hbin, nk + 0x48, len(kn))     # key name length
    struct.pack_into('<H', hbin, nk + 0x4A, 0)           # class name length
    hbin[nk + 0x4C:nk + 0x4C + len(kn)] = kn

    # Free cell for remaining space
    fo = co + ct
    fs = 0x1000 - fo
    if fs > 4:
        struct.pack_into('<i', hbin, fo, fs)

    return bytes(base + hbin)


HIVE_NAMES = ["NTUSER.DAT", "SAM", "SECURITY", "SOFTWARE", "SYSTEM", "HARDWARE"]
WIN_DIRS = ["x86_windows", "x8664_windows"]


def ensure_registry_hives(rootfs_dir, verbose=True):
    """Create registry hive stubs under rootfs_dir if they don't exist.

    Returns the number of hive files created.
    """
    rootfs_path = Path(rootfs_dir)
    hive_data = create_minimal_registry_hive()
    created = 0

    for win_dir in WIN_DIRS:
        reg_dir = rootfs_path / win_dir / "Windows" / "registry"
        reg_dir.mkdir(parents=True, exist_ok=True)
        for hive in HIVE_NAMES:
            hive_path = reg_dir / hive
            if not hive_path.exists():
                hive_path.write_bytes(hive_data)
                created += 1
                if verbose:
                    print(f"  Created registry stub: {win_dir}/Windows/registry/{hive}")

    return created


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rootfs_dir>", file=sys.stderr)
        sys.exit(1)

    rootfs_dir = sys.argv[1]
    if not os.path.isdir(rootfs_dir):
        print(f"Error: {rootfs_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    created = ensure_registry_hives(rootfs_dir)
    if created:
        print(f"  Created {created} registry hive stub(s).")
    else:
        print("  All registry hive stubs already exist.")


if __name__ == "__main__":
    main()
