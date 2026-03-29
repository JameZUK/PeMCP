"""Pure-Python AutoIt3 compiled script parser with dual-PRNG support.

Decrypts AutoIt3 .a3x compiled scripts protected by either standard
Mersenne Twister (MT19937) or the RanRot PRNG used by modified AutoIt3
builds (common in malware: DarkGate, StealC loaders, AsgardProtector).

Supports EA05 and EA06 formats. Works on standalone .a3x files and
PE-embedded scripts.  No external dependencies -- optionally uses
autoit-ripper's deassemble_script() for higher-fidelity source recovery.
"""

import logging
import struct
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EA05_MAGIC = bytes.fromhex("a3484bbe986c4aa9994c530a86d6487d41553321")

EA06_MARKER = b"EA06"

# LZSS compression magic headers (from autoit-ripper)
LZSS_MAGIC_EA05 = b"EA05"
LZSS_MAGIC_EA06 = b"EA06"

EA06_CONSTANTS: Dict[str, Any] = {
    "au3_ResType": 0x18EE,
    "au3_ResSize": 0x87BC,
    "au3_ResContent": 0x2477,
    "au3_ResCrcCompressed": 0xA685,
    "au3_ResSubType": (44476, 45887),
    "au3_ResName": (63520, 62585),
    "unicode": True,
}

EA05_CONSTANTS: Dict[str, Any] = {
    "au3_ResType": 0x16FA,
    "au3_ResSize": 0x45AA,
    "au3_ResContent": 0x22AF,
    "au3_ResCrcCompressed": 0xC3D2,
    "au3_ResSubType": (10668, 62046),
    "au3_ResName": (10684, 41566),
    "unicode": False,
}

# PRNG detection constants
RANROT_LCG_MULTIPLIER = 0x53A9B4FB
MT_MULTIPLIER = 0x6C078965

# MT19937 AutoIt-specific tempering constants
MT_TEMPER_MASK_B = 0xFF3A58AD
MT_TEMPER_MASK_C = 0xFFFFDF8C

# Safety limits
_MAX_INPUT_SIZE = 100 * 1024 * 1024  # 100 MB
_MAX_DECOMPRESSED_SIZE = 200 * 1024 * 1024  # 200 MB
_MAX_ENTRIES = 500
_MAX_STRING_LEN = 10 * 1024 * 1024  # 10 MB for a single string field


# ---------------------------------------------------------------------------
# PRNG: Mersenne Twister (AutoIt3 variant)
# ---------------------------------------------------------------------------

class MersenneTwisterAutoIt:
    """MT19937 with AutoIt3's custom tempering constants."""

    __slots__ = ("state", "index")

    def __init__(self, seed: int):
        self.state = [0] * 624
        self.state[0] = seed & 0xFFFFFFFF
        for i in range(1, 624):
            prev = self.state[i - 1]
            self.state[i] = (i + MT_MULTIPLIER * (prev ^ (prev >> 30))) & 0xFFFFFFFF
        self.index = 0

    def _twist(self) -> None:
        # AutoIt-specific twist (matches autoit-ripper MT.twist)
        for i in range(227):
            new_val = self.state[i + 397]
            tmp = (self.state[i + 1] ^ self.state[i]) & 0x7FFFFFFE
            new_val ^= (self.state[i] ^ tmp) >> 1
            if self.state[i + 1] & 1:
                new_val ^= 0x9908B0DF
            self.state[i] = new_val & 0xFFFFFFFF

        for i in range(396):
            new_val = self.state[i]
            tmp = (self.state[i + 228] ^ self.state[i + 227]) & 0x7FFFFFFE
            new_val ^= (self.state[i + 227] ^ tmp) >> 1
            if self.state[i + 228] & 1:
                new_val ^= 0x9908B0DF
            self.state[227 + i] = new_val & 0xFFFFFFFF

        new_val = self.state[396]
        tmp = (self.state[0] ^ self.state[623]) & 0x7FFFFFFE
        new_val ^= (self.state[623] ^ tmp) >> 1
        if self.state[0] & 1:
            new_val ^= 0x9908B0DF
        self.state[623] = new_val & 0xFFFFFFFF

    def get_byte(self) -> int:
        if self.index % 624 == 0:
            self._twist()
        rnd = self.state[self.index % 624]
        # Custom tempering (NOT standard MT19937)
        rnd = ((((rnd >> 11) ^ rnd) & MT_TEMPER_MASK_B) << 7) ^ (rnd >> 11) ^ rnd
        rnd &= 0xFFFFFFFF
        rnd = (((rnd & MT_TEMPER_MASK_C) << 15) ^ rnd
               ^ ((((rnd & MT_TEMPER_MASK_C) << 15) ^ rnd) >> 18)) >> 1
        rnd &= 0xFFFFFFFF
        self.index += 1
        return rnd & 0xFF


# ---------------------------------------------------------------------------
# PRNG: RanRot (rotate-and-add, used by modified AutoIt3)
# ---------------------------------------------------------------------------

def _rotl32(val: int, n: int) -> int:
    """32-bit left rotate."""
    n &= 31
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


class RanRotPRNG:
    """RanRot PRNG with 17-element circular buffer.

    Used by modified AutoIt3 builds (AsgardProtector, etc.) instead of MT.
    Identified by the LCG multiplier 0x53A9B4FB in the binary's .text section.
    """

    __slots__ = ("state", "p1", "p2")

    def __init__(self, seed: int):
        seed = seed & 0xFFFF  # 16-bit seed (movzx ecx, dx in binary)
        self.state = [0] * 17
        v = seed
        for i in range(17):
            v = (1 - (v * RANROT_LCG_MULTIPLIER)) & 0xFFFFFFFF
            self.state[i] = v
        self.p1 = 0
        self.p2 = 10
        # Warm up 9 steps
        for _ in range(9):
            self._step()

    def _step(self) -> int:
        a = _rotl32(self.state[self.p1], 9)
        b = _rotl32(self.state[self.p2], 13)
        result = (a + b) & 0xFFFFFFFF
        self.state[self.p1] = result
        self.p1 = (self.p1 - 1) % 17
        self.p2 = (self.p2 - 1) % 17
        return result

    def get_byte(self) -> int:
        self._step()
        v = self._step()
        return min(int((v / 0x100000000) * 256), 255)


# ---------------------------------------------------------------------------
# Decrypt helper
# ---------------------------------------------------------------------------

def decrypt_buffer(data: bytes, key: int, prng_class: type) -> bytes:
    """Decrypt a buffer by XOR with PRNG keystream."""
    prng = prng_class(key)
    return bytes((b ^ prng.get_byte()) & 0xFF for b in data)


# ---------------------------------------------------------------------------
# LZSS Decompression
# ---------------------------------------------------------------------------

def _lzss_decompress(data: bytes, max_output: int = _MAX_DECOMPRESSED_SIZE) -> Optional[bytes]:
    """Decompress AutoIt LZSS-compressed data.

    Tries autoit-ripper's implementation first (higher fidelity).
    Falls back to None if unavailable or fails.
    """
    try:
        from autoit_ripper.decompress import decompress as _ripper_decompress
        from autoit_ripper.utils import ByteStream
        stream = ByteStream(data)
        result = _ripper_decompress(stream)
        if result and len(result) <= max_output:
            return result
        if result and len(result) > max_output:
            logger.warning("LZSS output exceeds %d bytes, truncating", max_output)
            return result[:max_output]
    except ImportError:
        logger.debug("autoit-ripper not available for LZSS decompression")
    except Exception as e:
        logger.debug("autoit-ripper LZSS failed: %s", e)
    return None


# ---------------------------------------------------------------------------
# Bytecode deassembly
# ---------------------------------------------------------------------------

def deassemble_script(bytecode: bytes) -> Optional[str]:
    """Attempt to deassemble AutoIt3 bytecode to source code.

    Uses autoit-ripper's deassemble_script() when available.
    Returns None if unavailable or on failure.
    """
    try:
        from autoit_ripper.opcodes import deassemble_script as _ripper_deassemble
        return _ripper_deassemble(bytecode)
    except ImportError:
        logger.debug("autoit-ripper not available for script deassembly")
    except Exception as e:
        logger.debug("Script deassembly failed: %s", e)
    return None


# ---------------------------------------------------------------------------
# PRNG auto-detection
# ---------------------------------------------------------------------------

def detect_prng_type(pe_data: bytes) -> str:
    """Auto-detect which PRNG the AutoIt3 binary uses.

    Scans for:
    - 0x53A9B4FB (RanRot LCG multiplier) -> 'ranrot'
    - 0x6C078965 only (MT multiplier) -> 'mt'
    - Neither -> 'unknown'
    """
    ranrot_bytes = struct.pack("<I", RANROT_LCG_MULTIPLIER)
    mt_bytes = struct.pack("<I", MT_MULTIPLIER)

    has_ranrot = ranrot_bytes in pe_data
    has_mt = mt_bytes in pe_data

    if has_ranrot:
        return "ranrot"
    if has_mt:
        return "mt"
    return "unknown"


# ---------------------------------------------------------------------------
# Format detection and magic scanning
# ---------------------------------------------------------------------------

def find_autoit_script(data: bytes) -> Optional[int]:
    """Find the offset of EA05_MAGIC in binary data."""
    idx = data.find(EA05_MAGIC)
    return idx if idx >= 0 else None


def _detect_format(data: bytes, offset: int) -> str:
    """Detect EA05 vs EA06 format after the EA05 magic."""
    after_magic = offset + len(EA05_MAGIC)
    if after_magic + 4 <= len(data):
        marker = data[after_magic:after_magic + 4]
        if marker == EA06_MARKER or marker == b"AU3!":
            # Check for EA06 after AU3!
            if marker == b"AU3!":
                if after_magic + 8 <= len(data) and data[after_magic + 4:after_magic + 8] == EA06_MARKER:
                    return "ea06"
            return "ea06"
    return "ea05"


# ---------------------------------------------------------------------------
# String reading helper
# ---------------------------------------------------------------------------

def _read_encrypted_string(
    data: bytes, pos: int, len_key: int, content_key_offset: int,
    prng_class: type, is_unicode: bool
) -> Tuple[str, int]:
    """Read a length-prefixed, PRNG-encrypted string.

    Returns (decoded_string, new_position).
    """
    if pos + 4 > len(data):
        return ("", pos)
    raw_len = struct.unpack_from("<I", data, pos)[0]
    str_len = raw_len ^ len_key
    pos += 4

    if str_len <= 0 or str_len > _MAX_STRING_LEN:
        return ("", pos)

    enc_key = str_len + content_key_offset
    byte_len = str_len * 2 if is_unicode else str_len

    if pos + byte_len > len(data):
        return ("", pos)

    dec = decrypt_buffer(data[pos:pos + byte_len], enc_key, prng_class)
    pos += byte_len

    try:
        if is_unicode:
            text = dec.decode("utf-16-le", errors="replace").rstrip("\x00")
        else:
            text = dec.decode("utf-8", errors="replace").rstrip("\x00")
    except Exception:
        text = dec.hex()

    return (text, pos)


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

def parse_autoit_script(
    data: bytes,
    prng_type: str = "auto",
    constants: Optional[Dict[str, Any]] = None,
    pe_data: Optional[bytes] = None,
) -> Dict[str, Any]:
    """Parse and decrypt an AutoIt3 compiled script.

    Args:
        data: Raw bytes containing or starting with the AutoIt script.
        prng_type: 'auto' (detect from pe_data), 'mt', or 'ranrot'.
        constants: Override EA05/EA06 crypto constants (for custom keys).
        pe_data: PE binary bytes for PRNG auto-detection (when prng_type='auto').

    Returns:
        Dict with: format, prng_type, entries, errors.
        Each entry has: type, name, data, source (if script), size_compressed,
        size_uncompressed.
    """
    result: Dict[str, Any] = {
        "format": "unknown",
        "prng_type": prng_type,
        "entries": [],
        "scripts_found": 0,
        "resources_found": 0,
        "errors": [],
    }

    if len(data) > _MAX_INPUT_SIZE:
        result["errors"].append(f"Input too large ({len(data)} bytes, max {_MAX_INPUT_SIZE})")
        return result

    # 1. Find EA05 magic
    magic_offset = find_autoit_script(data)
    if magic_offset is None:
        result["errors"].append("EA05 magic not found in data")
        return result

    # 2. Detect format
    fmt = _detect_format(data, magic_offset)
    result["format"] = fmt

    if constants is None:
        constants = EA06_CONSTANTS if fmt == "ea06" else EA05_CONSTANTS

    is_unicode = constants.get("unicode", fmt == "ea06")

    # 3. PRNG selection
    if prng_type == "auto":
        if pe_data:
            prng_type = detect_prng_type(pe_data)
        else:
            prng_type = "mt"  # Default fallback
        result["prng_type"] = prng_type

    prng_class: type
    if prng_type == "ranrot":
        prng_class = RanRotPRNG
    else:
        prng_class = MersenneTwisterAutoIt

    # 4. Parse header — position after magic
    pos = magic_offset + len(EA05_MAGIC)

    # EA06: skip "EA06" marker (4 bytes) if present
    if fmt == "ea06" and pos + 4 <= len(data):
        marker = data[pos:pos + 4]
        if marker in (EA06_MARKER, b"AU3!"):
            pos += 4
            # Skip second marker if AU3! was followed by EA06
            if marker == b"AU3!" and pos + 4 <= len(data) and data[pos:pos + 4] == EA06_MARKER:
                pos += 4

    # 5. Read checksum (16 bytes)
    if pos + 16 > len(data):
        result["errors"].append("Truncated: not enough data for checksum")
        return result

    checksum = sum(data[pos:pos + 16])
    result["checksum"] = checksum
    pos += 16

    # 6. Parse entries
    entry_count = 0
    while pos + 4 <= len(data) and entry_count < _MAX_ENTRIES:
        # Decrypt FILE marker
        file_marker = decrypt_buffer(data[pos:pos + 4], constants["au3_ResType"], prng_class)
        pos += 4

        if file_marker != b"FILE":
            # End of entries
            break

        entry_count += 1

        # Read SubType
        sub_type, pos = _read_encrypted_string(
            data, pos,
            constants["au3_ResSubType"][0],
            constants["au3_ResSubType"][1],
            prng_class, is_unicode,
        )

        # Read Name
        name, pos = _read_encrypted_string(
            data, pos,
            constants["au3_ResName"][0],
            constants["au3_ResName"][1],
            prng_class, is_unicode,
        )

        entry: Dict[str, Any] = {
            "type": sub_type,
            "name": name,
        }

        if sub_type == ">>>AUTOIT NO CMDEXECUTE<<<":
            # Special: skip 1 byte + (u32 XOR au3_ResSize) + 0x18
            if pos + 5 > len(data):
                result["errors"].append(f"Truncated at NO CMDEXECUTE entry {entry_count}")
                break
            pos += 1
            skip_size = struct.unpack_from("<I", data, pos)[0] ^ constants["au3_ResSize"]
            pos += 4 + skip_size + 0x18
            entry["data"] = None
            entry["source"] = None
        else:
            # Normal entry: compressed flag + sizes + CRC + timestamps + content
            if pos + 29 > len(data):
                result["errors"].append(f"Truncated at entry {entry_count}")
                break

            is_compressed = data[pos]
            pos += 1

            size_compressed = struct.unpack_from("<I", data, pos)[0] ^ constants["au3_ResSize"]
            pos += 4
            size_uncompressed = struct.unpack_from("<I", data, pos)[0] ^ constants["au3_ResSize"]
            pos += 4
            crc = struct.unpack_from("<I", data, pos)[0] ^ constants["au3_ResCrcCompressed"]
            pos += 4

            # Timestamps (16 bytes — 2x FILETIME)
            pos += 16

            entry["size_compressed"] = size_compressed
            entry["size_uncompressed"] = size_uncompressed
            entry["crc"] = crc
            entry["is_compressed"] = is_compressed

            if size_compressed <= 0 or pos + size_compressed > len(data):
                result["errors"].append(
                    f"Invalid compressed size {size_compressed} at entry {entry_count}")
                break

            # Decrypt content
            # Try both: checksum + au3_ResContent AND au3_ResContent alone
            content_key = constants["au3_ResContent"]
            dec_content = decrypt_buffer(
                data[pos:pos + size_compressed], content_key, prng_class)

            # Verify LZSS magic
            if is_compressed == 1 and len(dec_content) >= 4:
                lzss_magic = dec_content[:4]
                if lzss_magic not in (LZSS_MAGIC_EA05, LZSS_MAGIC_EA06):
                    # Try with checksum + au3_ResContent
                    alt_key = checksum + constants["au3_ResContent"]
                    dec_alt = decrypt_buffer(
                        data[pos:pos + size_compressed], alt_key, prng_class)
                    if len(dec_alt) >= 4 and dec_alt[:4] in (LZSS_MAGIC_EA05, LZSS_MAGIC_EA06):
                        dec_content = dec_alt
                        content_key = alt_key

            pos += size_compressed

            # Decompress if needed
            final_data = dec_content
            if is_compressed == 1:
                decompressed = _lzss_decompress(dec_content)
                if decompressed:
                    final_data = decompressed
                    entry["decompressed"] = True
                else:
                    entry["decompressed"] = False

            entry["data"] = final_data

            # Deassemble if it's a script
            is_script = sub_type in (
                ">>>AUTOIT SCRIPT<<<",
                ">AUTOIT UNICODE SCRIPT<",
                ">AUTOIT SCRIPT<",
            )
            entry["is_script"] = is_script

            if is_script:
                result["scripts_found"] += 1
                source = deassemble_script(final_data)
                entry["source"] = source
                entry["source_size"] = len(source) if source else 0
            else:
                result["resources_found"] += 1
                entry["source"] = None

        result["entries"].append(entry)

    result["total_entries"] = entry_count
    return result
