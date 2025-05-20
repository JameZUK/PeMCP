#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Comprehensive PE File Analyzer (Refactored with Integrated ssdeep and capa)

This script provides extensive analysis of Portable Executable (PE) files.
It can operate in two modes:
1. CLI Mode: Analyzes a PE file and prints a detailed report to the console.
   Supports PEiD-like signature scanning, YARA scanning, capa capability detection,
   string extraction/searching, and hex dumping.
2. MCP Server Mode: Runs as a Model-Context-Protocol (MCP) server, exposing
   its analysis capabilities as callable tools. This allows programmatic
   interaction and integration into larger systems.

Key Features:
- Parses all major PE structures (relies on 'pefile' library).
- Calculates file and section hashes (MD5, SHA1, SHA256, ssdeep fuzzy hash).
- Verifies PE checksum.
- Checks for 'pefile' at startup and offers installation.
- Optional dependency handling for enhanced features:
  - `cryptography` for parsing digital signature certificates.
  - `requests` for downloading PEiD database and capa rules.
  - `signify` for Authenticode signature validation.
  - `yara-python` for YARA scanning.
  - `flare-capa` (capa) for capability detection.
  - `modelcontextprotocol` for MCP server functionality.
- Includes integrated pure-Python ssdeep (ssdeep) for fuzzy hashing.
- Automatic download and management of capa rules.
- Support for capa library identification signatures.
- Exposes general deobfuscation utilities (base64, XOR, printable check) via MCP.

Refactoring based on review 'pe_analyzer_review_v2', focusing on modularity,
asynchronous safety for MCP, data completeness, and documentation.
Includes a check for missing optional dependencies with an installation prompt.
ssdeep integration replaces the external ssdeep library dependency.
Error handling for mmap objects in ssdeep hash function added.
Capa integration for capability analysis.
SyntaxError in ensure_peid_db_exists fixed.
Capa dependency name corrected to flare-capa.
Capa library signature support added.
"""

# Standard library imports - Group them at the top
import datetime
import os
import sys
import struct
import argparse
import re
import concurrent.futures
import hashlib
import warnings
import json
import logging
import base64 # For string deobfuscation (standard library)
import codecs # For deobfuscate_base64 MCP tool
import io # For BytesIO
import asyncio # For asyncio.to_thread
import importlib.util # For checking module availability
import subprocess # For calling pip
import mmap # Added for handling mmap objects in ssdeep
import zipfile # For extracting capa rules
import shutil # For removing directories

# Crucial: Import typing early, as it's used for global type hints and throughout the script
from typing import Dict, Any, Optional, List, Tuple, Set, Union

# --- Ensure pefile is available (Critical Dependency) ---
# This check is performed early because 'pefile' is essential for the script's core functionality.
try:
    import pefile
except ImportError:
    print("[!] CRITICAL ERROR: The 'pefile' library is not found.", file=sys.stderr)
    print("[!] This library is essential for the script to function.", file=sys.stderr)
    # Attempt to guide installation
    if not sys.stdin.isatty(): # Check if in non-interactive mode
        print("[!] Non-interactive environment. Please install 'pefile' manually (e.g., 'pip install pefile') and re-run the script.", file=sys.stderr)
        sys.exit(1)
    else: # Interactive mode
        try:
            answer = input("Do you want to attempt to install 'pefile' now? (yes/no): ").strip().lower()
            if answer == 'yes' or answer == 'y':
                print("[*] Attempting to install 'pefile' (pip install pefile)...")
                try:
                    # Use sys.executable to ensure pip is called for the correct Python interpreter
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile"])
                    print("[*] 'pefile' installed successfully. Please re-run the script for the changes to take effect.")
                    sys.exit(0) # Exit cleanly for the user to re-run
                except subprocess.CalledProcessError as e_pip:
                    print(f"[!] Error installing 'pefile' via pip: {e_pip}", file=sys.stderr)
                    print("[!] Please install 'pefile' manually (e.g., 'pip install pefile') and re-run.", file=sys.stderr)
                    sys.exit(1)
                except FileNotFoundError: # Indicates pip or python executable might not be found
                    print("[!] Error: 'pip' command or Python executable not found. Is Python and pip installed correctly and in PATH?", file=sys.stderr)
                    print("[!] Please install 'pefile' manually (e.g., 'pip install pefile') and re-run.", file=sys.stderr)
                    sys.exit(1)
            else:
                print("[!] 'pefile' was not installed. The script cannot continue. Exiting.")
                sys.exit(1)
        except EOFError: # Handle cases where input is expected but not provided (e.g. piped input ends)
            print("[!] No input received for the installation prompt. Please install 'pefile' manually and re-run.", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
             print("\n[*] Installation of 'pefile' cancelled by user. This library is required. Exiting.", file=sys.stderr)
             sys.exit(1)
# If we reach here, pefile should have been successfully imported in the initial 'try' block.

class SSDeep:
    """
    Encapsulates the ssdeep fuzzy hashing logic.
    This class structure helps to keep the ssdeep code organized
    when integrated into a larger script.
    """
    BLOCKSIZE_MIN = 3
    SPAMSUM_LENGTH = 64
    STREAM_BUFF_SIZE = 8192
    HASH_PRIME = 0x01000193
    HASH_INIT = 0x28021967
    ROLL_WINDOW = 7
    B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    class _RollState(object):
        ROLL_WINDOW = 7 # Matches SSDeep.ROLL_WINDOW

        def __init__(self):
            self.win = bytearray(self.ROLL_WINDOW)
            self.h1 = int()
            self.h2 = int()
            self.h3 = int()
            self.n = int()

        def roll_hash(self, b):
            self.h2 = self.h2 - self.h1 + (self.ROLL_WINDOW * b)
            self.h1 = self.h1 + b - self.win[self.n % self.ROLL_WINDOW]
            self.win[self.n % self.ROLL_WINDOW] = b
            self.n += 1
            self.h3 = (self.h3 << 5) & 0xFFFFFFFF
            self.h3 ^= b
            return self.h1 + self.h2 + self.h3

    def _spamsum(self, stream, slen):
        roll_win = bytearray(self.ROLL_WINDOW)
        roll_h1 = int()
        roll_h2 = int()
        roll_h3 = int()
        roll_n = int()
        block_size = int()
        hash_string1 = str()
        hash_string2 = str()
        block_hash1 = int(self.HASH_INIT)
        block_hash2 = int(self.HASH_INIT)

        bs = self.BLOCKSIZE_MIN
        # Ensure slen is not zero to prevent issues with bs calculation, though hash() handles empty buf_data.
        if slen > 0:
            while (bs * self.SPAMSUM_LENGTH) < slen:
                bs = bs * 2
        block_size = bs


        while True:
            stream.seek(0)
            # Reset states for potential retry with smaller block_size
            roll_h1 = roll_h2 = roll_h3 = 0
            roll_n = 0
            roll_win = bytearray(self.ROLL_WINDOW) # Reset window
            block_hash1 = self.HASH_INIT
            block_hash2 = self.HASH_INIT
            hash_string1 = ""
            hash_string2 = ""

            buf = stream.read(self.STREAM_BUFF_SIZE)
            while buf:
                for b_val in buf: # Renamed b to b_val to avoid conflict with class B64
                    block_hash1 = ((block_hash1 * self.HASH_PRIME) & 0xFFFFFFFF) ^ b_val
                    block_hash2 = ((block_hash2 * self.HASH_PRIME) & 0xFFFFFFFF) ^ b_val

                    roll_h2 = roll_h2 - roll_h1 + (self.ROLL_WINDOW * b_val)
                    roll_h1 = roll_h1 + b_val - roll_win[roll_n % self.ROLL_WINDOW]
                    roll_win[roll_n % self.ROLL_WINDOW] = b_val
                    roll_n += 1
                    roll_h3 = (self.h3 << 5) & 0xFFFFFFFF
                    roll_h3 ^= b_val

                    rh = roll_h1 + self.h2 + self.h3 # Corrected: was roll_h1 + self.h2 + self.h3

                    if (rh % block_size) == (block_size - 1):
                        if len(hash_string1) < (self.SPAMSUM_LENGTH - 1):
                            hash_string1 += self.B64[block_hash1 % 64]
                            block_hash1 = self.HASH_INIT
                        if (rh % (block_size * 2)) == ((block_size * 2) - 1): # Check for second hash string trigger
                            if len(hash_string2) < ((self.SPAMSUM_LENGTH // 2) - 1):
                                hash_string2 += self.B64[block_hash2 % 64]
                                block_hash2 = self.HASH_INIT
                buf = stream.read(self.STREAM_BUFF_SIZE)

            # Check if we need to reduce block_size and retry
            if block_size > self.BLOCKSIZE_MIN and len(hash_string1) < (self.SPAMSUM_LENGTH // 2):
                block_size = (block_size // 2)
            else:
                if roll_n > 0:
                    if len(hash_string1) < self.SPAMSUM_LENGTH :
                        hash_string1 += self.B64[block_hash1 % 64]
                    if len(hash_string2) < (self.SPAMSUM_LENGTH // 2) :
                        hash_string2 += self.B64[block_hash2 % 64]
                break
        return '{0}:{1}:{2}'.format(block_size, hash_string1, hash_string2)

    def hash(self, buf_data_input):
        buf_data_bytes = None
        if isinstance(buf_data_input, bytes):
            buf_data_bytes = buf_data_input
        elif isinstance(buf_data_input, str):
            buf_data_bytes = buf_data_input.encode('utf-8', 'ignore')
        elif isinstance(buf_data_input, mmap.mmap):
            buf_data_bytes = buf_data_input[:]
        else:
            raise TypeError(f"Argument must be of bytes, string, or mmap.mmap type, not {type(buf_data_input)}")

        if not buf_data_bytes:
            bs = self.BLOCKSIZE_MIN
            return f"{bs}::"

        return self._spamsum(io.BytesIO(buf_data_bytes), len(buf_data_bytes))

    def _levenshtein(self, s, t):
        if s == t: return 0
        elif len(s) == 0: return len(t)
        elif len(t) == 0: return len(s)
        v0 = [None] * (len(t) + 1)
        v1 = [None] * (len(t) + 1)
        for i in range(len(v0)):
            v0[i] = i
        for i in range(len(s)):
            v1[0] = i + 1
            for j in range(len(t)):
                cost = 0 if s[i] == t[j] else 1
                v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
            for j in range(len(v0)):
                v0[j] = v1[j]
        return v1[len(t)]

    def _common_substring(self, s1, s2):
        hashes = list()
        roll = self._RollState()
        for i in range(len(s1)):
            b = ord(s1[i])
            hashes.append(roll.roll_hash(b))

        roll = self._RollState()
        for i in range(len(s2)):
            b = ord(s2[i])
            rh = roll.roll_hash(b)
            if i < (self.ROLL_WINDOW - 1):
                continue
            for j in range(self.ROLL_WINDOW - 1, len(hashes)):
                if hashes[j] != 0 and hashes[j] == rh:
                    ir = i - (self.ROLL_WINDOW - 1)
                    jr = j - (self.ROLL_WINDOW - 1)
                    if (len(s2[ir:]) >= self.ROLL_WINDOW and
                            s2[ir:ir + self.ROLL_WINDOW] == s1[jr:jr + self.ROLL_WINDOW]):
                        return True
        return False

    def _score_strings(self, s1, s2, block_size):
        if not self._common_substring(s1, s2):
            return 0
        if not s1 and not s2: return 100 if block_size >= self.BLOCKSIZE_MIN else 0
        if not s1 or not s2:
            pass # Score will be low due to Levenshtein distance

        lev_score = self._levenshtein(s1, s2)
        sum_len = len(s1) + len(s2)
        if sum_len == 0:
            return 100 # Should be caught by "not s1 and not s2"

        score = (lev_score * self.SPAMSUM_LENGTH) // sum_len
        score = (100 * score) // self.SPAMSUM_LENGTH
        score = 100 - score

        min_len_s1_s2 = min(len(s1), len(s2)) if len(s1) > 0 and len(s2) > 0 else 0
        if min_len_s1_s2 > 0 :
            cap_val = (block_size // self.BLOCKSIZE_MIN) * min_len_s1_s2
            if score > cap_val:
                score = cap_val
        elif not s1 and not s2:
            score = 100
        else: # One empty, one not
            score = 0
        return score

    def _strip_sequences(self, s):
        if len(s) <= 3: return s
        r = s[:3]
        for i in range(3, len(s)):
            if (s[i] != s[i-1] or s[i] != s[i-2] or s[i] != s[i-3]):
                r += s[i]
        return r

    def compare(self, hash1_str, hash2_str): # This method remains unused in the script
        if not (isinstance(hash1_str, str) and isinstance(hash2_str, str)):
            raise TypeError('Arguments must be of string type')
        try:
            hash1_parts = hash1_str.split(':', 2)
            hash2_parts = hash2_str.split(':', 2)
            if len(hash1_parts) != 3 or len(hash2_parts) != 3:
                    raise ValueError('Invalid hash format (must have 3 parts)')

            hash1_bs_str, hash1_s1, hash1_s2 = hash1_parts
            hash2_bs_str, hash2_s1, hash2_s2 = hash2_parts

            hash1_bs = int(hash1_bs_str)
            hash2_bs = int(hash2_bs_str)
        except ValueError as e:
            raise ValueError(f'Invalid hash format: {e}') from None

        if hash1_bs != hash2_bs and hash1_bs != (hash2_bs * 2) and hash2_bs != (hash1_bs * 2):
            return 0

        hash1_s1 = self._strip_sequences(hash1_s1)
        hash1_s2 = self._strip_sequences(hash1_s2)
        hash2_s1 = self._strip_sequences(hash2_s1)
        hash2_s2 = self._strip_sequences(hash2_s2)

        if hash1_bs == hash2_bs and hash1_s1 == hash2_s1:
            return 100

        score = 0
        if hash1_bs == hash2_bs:
            score1 = self._score_strings(hash1_s1, hash2_s1, hash1_bs)
            score2 = self._score_strings(hash1_s2, hash2_s2, hash2_bs)
            score = int(max([score1, score2]))
        elif hash1_bs == (hash2_bs * 2):
            score = int(self._score_strings(hash1_s1, hash2_s2, hash1_bs))
        else: # hash2_bs == (hash1_bs * 2)
            score = int(self._score_strings(hash1_s2, hash2_s1, hash2_bs))
        return score

ssdeep_hasher = SSDeep()

# --- Optional Library Imports & Availability Flags ---
try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import pkcs7
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

SIGNIFY_AVAILABLE = False
SIGNIFY_IMPORT_ERROR = None
try:
    from signify.authenticode import SignedPEFile, AuthenticodeVerificationResult, AuthenticodeSignedData
    SIGNIFY_AVAILABLE = True
except ImportError as e:
    SIGNIFY_IMPORT_ERROR = e

YARA_AVAILABLE = False
YARA_IMPORT_ERROR = None
try:
    import yara
    YARA_AVAILABLE = True
except ImportError as e:
    YARA_IMPORT_ERROR = e

CAPA_AVAILABLE = False
CAPA_IMPORT_ERROR = None
try:
    import capa.main
    import capa.rules
    import capa.engine
    import capa.render.json as capa_json_render
    import capa.features.extractors.pefile as capa_pefile_extractor
    from capa.exceptions import CapaError, InvalidRule, RulesAccessError, FreezingError
    CAPA_AVAILABLE = True
except ImportError as e:
    CAPA_IMPORT_ERROR = e
    # Define dummy exceptions if capa is not available to prevent NameError later
    class CapaError(Exception): pass
    class InvalidRule(CapaError): pass
    class RulesAccessError(CapaError): pass
    class FreezingError(CapaError): pass


MCP_SDK_AVAILABLE = False
try:
    from mcp.server.fastmcp import FastMCP, Context
    MCP_SDK_AVAILABLE = True
except ImportError:
    class MockSettings: host = "127.0.0.1"; port = 8081; log_level = "INFO"
    class MockMCP:
        def __init__(self, name, description=""): self.name = name; self.description = description; self.app = object(); self.settings = MockSettings(); self._run_called_with_transport = None
        def tool(self): decorator = lambda func: func; return decorator
        def run(self, transport: str = "stdio"): print(f"MockMCP '{self.name}' run method called with transport='{transport}'.")
    FastMCP = MockMCP # type: ignore
    class Context: # type: ignore
        async def info(self, msg): print(f"(mock ctx info): {msg}")
        async def error(self, msg): print(f"(mock ctx error): {msg}")
        async def warning(self, msg): print(f"(mock ctx warning): {msg}")

# --- Global State for MCP ---
ANALYZED_PE_FILE_PATH: Optional[str] = None
ANALYZED_PE_DATA: Optional[Dict[str, Any]] = None
PEFILE_VERSION_USED: Optional[str] = None
PE_OBJECT_FOR_MCP: Optional[pefile.PE] = None

# --- Constants ---
PEID_USERDB_URL = "https://raw.githubusercontent.com/GerkNL/PEid/master/userdb.txt"
CAPA_RULES_ZIP_URL = "https://github.com/mandiant/capa-rules/releases/latest/download/capa-rules.zip"
CAPA_RULES_DEFAULT_DIR = "capa_rules_store" # Base directory to store downloaded/extracted capa rules
CAPA_RULES_SUBDIR_NAME = "rules" # The name of the subdirectory within the zip that contains the actual rules

# Note: 'pefile' is handled by a check at the script's start.
DEPENDENCIES = [
    ("cryptography", "cryptography", "Cryptography (for digital signatures)", False),
    ("requests", "requests", "Requests (for PEiD DB download & capa rules)", False),
    ("signify.authenticode", "signify", "Signify (for Authenticode validation)", False), # pip_name is 'signify'
    ("yara", "yara-python", "Yara (for YARA scanning)", False),
    ("capa.main", "flare-capa", "Capa (for capability detection)", False),
    ("mcp.server", "mcp[cli]", "MCP SDK (for MCP server mode)", True) # True means critical for MCP mode
]

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

def check_and_install_dependencies(is_mcp_server_mode_arg: bool):
    """
    Checks for optional dependencies and prompts for installation if missing.
    'pefile' is considered a core dependency and is checked separately at script startup.
    """
    missing_deps_info = []
    critical_mcp_missing_for_current_mode = False 

    for spec_name, pip_name, friendly_name, is_critical_for_mcp_mode in DEPENDENCIES:
        is_missing = False
        if spec_name == "mcp.server": 
            if not MCP_SDK_AVAILABLE:
                is_missing = True
        elif spec_name == "capa.main": 
            if not CAPA_AVAILABLE:
                is_missing = True
        elif spec_name == "signify.authenticode": # Special handling for signify
            if not SIGNIFY_AVAILABLE:
                is_missing = True
        else: # Other general dependencies checked with find_spec
            spec = importlib.util.find_spec(spec_name)
            if spec is None:
                is_missing = True
        
        if is_missing:
            missing_deps_info.append({"pip": pip_name, "friendly": friendly_name, "is_critical_mcp": is_critical_for_mcp_mode})
            if is_critical_for_mcp_mode and is_mcp_server_mode_arg:
                critical_mcp_missing_for_current_mode = True

    if not missing_deps_info:
        return

    print("\n[!] Some optional libraries are missing or could not be imported:", file=sys.stderr)
    for dep in missing_deps_info:
        print(f"     - {dep['friendly']} (Python package: {dep['pip']})", file=sys.stderr)
    
    if critical_mcp_missing_for_current_mode:
        print("[!] One or more libraries critical for --mcp-server mode are missing.", file=sys.stderr)
    print("[!] These libraries enhance the script's functionality or are required for specific modes.", file=sys.stderr)

    try:
        if not sys.stdin.isatty():
            print("[!] Non-interactive environment detected. Cannot prompt for installation of optional libraries.", file=sys.stderr)
            if critical_mcp_missing_for_current_mode:
                print("[!] Please install the required MCP SDK ('pip install \"mcp[cli]\"') and/or other critical optional libraries manually and re-run.", file=sys.stderr)
                sys.exit(1) 
            print("[!] Please install other missing optional libraries manually if needed.", file=sys.stderr)
            return

        answer = input("Do you want to attempt to install the missing optional libraries now? (yes/no): ").strip().lower()
        if answer == 'yes' or answer == 'y':
            installed_any = False
            
            for dep_to_install in missing_deps_info: 
                print(f"[*] Attempting to install {dep_to_install['friendly']} (pip install \"{dep_to_install['pip']}\")...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep_to_install['pip']])
                    print(f"[*] Successfully installed {dep_to_install['friendly']}.")
                    installed_any = True
                except subprocess.CalledProcessError as e:
                    print(f"[!] Error installing {dep_to_install['friendly']}: {e}", file=sys.stderr)
                except FileNotFoundError:
                    print("[!] Error: 'pip' command not found. Is Python and pip installed correctly and in PATH?", file=sys.stderr)
                    break 
            
            if installed_any:
                print("\n[*] Optional library installation process finished. Please re-run the script for changes to take full effect.")
                sys.exit(0) 
            else:
                print("[*] No optional libraries were successfully installed.")
                if critical_mcp_missing_for_current_mode:
                    print("[!] Critical MCP dependencies were not installed. MCP server mode may not function as expected. Exiting.")
                    sys.exit(1)
        else: 
            print("[*] Skipping installation of optional libraries.")
            if critical_mcp_missing_for_current_mode:
                print("[!] Critical MCP dependencies were not installed because installation was skipped. MCP server mode cannot function. Exiting.", file=sys.stderr)
                sys.exit(1)
    except EOFError:
        print("[!] No input received for optional library installation. Skipping.", file=sys.stderr)
        if critical_mcp_missing_for_current_mode:
            print("[!] Critical MCP dependencies were not installed. Exiting.", file=sys.stderr)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Optional library installation cancelled.", file=sys.stderr)
        if critical_mcp_missing_for_current_mode:
            print("[!] Critical MCP dependencies were not installed. Exiting.", file=sys.stderr)
            sys.exit(1)

# Post-dependency check logging
if MCP_SDK_AVAILABLE: logger.info("MCP SDK found.")
else: logger.warning("MCP SDK not found. MCP server functionality will be mocked or unavailable if critical.")
if CAPA_AVAILABLE: logger.info("Capa library found.")
else: logger.warning(f"Capa library (flare-capa) not found. Capability analysis will be skipped. Import error: {CAPA_IMPORT_ERROR}")
if SIGNIFY_AVAILABLE: logger.info("Signify library found.")
else: logger.warning(f"Signify library not found. Authenticode validation will be skipped. Import error: {SIGNIFY_IMPORT_ERROR}")


def safe_print(text_to_print, verbose_prefix=""):
    try:
        print(f"{verbose_prefix}{text_to_print}")
    except UnicodeEncodeError:
        try:
            output_encoding = sys.stdout.encoding if sys.stdout.encoding else 'utf-8'
            encoded_text = str(text_to_print).encode(output_encoding, errors='backslashreplace').decode(output_encoding, errors='ignore')
            print(f"{verbose_prefix}{encoded_text} (some characters replaced/escaped)")
        except Exception:
            print(f"{verbose_prefix}<Unencodable string: contains characters not supported by output encoding>")

def format_timestamp(timestamp_val: int) -> str:
    if not isinstance(timestamp_val, int) or timestamp_val < 0: return f"{timestamp_val} (Invalid timestamp value)"
    if timestamp_val == 0: return "0 (No timestamp or invalid)"
    current_year = datetime.datetime.now(datetime.timezone.utc).year
    try:
        dt_obj = datetime.datetime.fromtimestamp(timestamp_val, datetime.timezone.utc)
        formatted_date = dt_obj.strftime('%Y-%m-%d %H:%M:%S UTC')
        if dt_obj.year > current_year + 20 or dt_obj.year < 1980:
            return f"{formatted_date} ({timestamp_val}) (Timestamp unusual)"
        return formatted_date
    except (ValueError, OSError, OverflowError):
        return f"{timestamp_val} (Invalid or out-of-range timestamp value)"

def get_file_characteristics(flags: int) -> List[str]:
    characteristics = []
    for flag_name, flag_val in pefile.IMAGE_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val): characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE"]

def get_dll_characteristics(flags: int) -> List[str]:
    characteristics = []
    for flag_name, flag_val in pefile.DLL_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val): characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE"]

def get_section_characteristics(flags: int) -> List[str]:
    characteristics = []
    for flag_name, flag_val in pefile.SECTION_CHARACTERISTICS.items():
        if isinstance(flag_val, int) and (flags & flag_val): characteristics.append(flag_name)
    return characteristics if characteristics else ["NONE"]

def get_relocation_type_str(reloc_type: int) -> str:
    reloc_types = {val: name for name, val in pefile.RELOCATION_TYPE.items()}
    return reloc_types.get(reloc_type, f"UNKNOWN_TYPE_{reloc_type}")

def get_symbol_type_str(sym_type: int) -> str:
    types = {0x0:"NULL",0x1:"VOID",0x2:"CHAR",0x3:"SHORT",0x4:"INT",0x5:"LONG",0x6:"FLOAT",0x7:"DOUBLE",0x8:"STRUCT",0x9:"UNION",0xA:"ENUM",0xB:"MOE (Member of Enum)",0xC:"BYTE",0xD:"WORD",0xE:"UINT",0xF:"DWORD"}
    base_type = sym_type & 0x000F; derived_type = (sym_type & 0x00F0) >> 4
    type_str = types.get(base_type, f"UNKNOWN_BASE({hex(base_type)})")
    if derived_type == pefile.IMAGE_SYM_DTYPE_POINTER: type_str = f"POINTER_TO_{type_str}"
    elif derived_type == pefile.IMAGE_SYM_DTYPE_FUNCTION: type_str = f"FUNCTION_RETURNING_{type_str}"
    elif derived_type == pefile.IMAGE_SYM_DTYPE_ARRAY: type_str = f"ARRAY_OF_{type_str}"
    if sym_type == 0x20: return "FUNCTION" # Special case for IMAGE_SYM_TYPE_FUNCTION
    return type_str

def get_symbol_storage_class_str(storage_class: int) -> str:
    classes = {0:"NULL",1:"AUTOMATIC",2:"EXTERNAL",3:"STATIC",4:"REGISTER",5:"EXTERNAL_DEF",6:"LABEL",7:"UNDEFINED_LABEL",8:"MEMBER_OF_STRUCT",9:"ARGUMENT",10:"STRUCT_TAG",11:"MEMBER_OF_UNION",12:"UNION_TAG",13:"TYPE_DEFINITION",14:"UNDEFINED_STATIC",15:"ENUM_TAG",16:"MEMBER_OF_ENUM",17:"REGISTER_PARAM",18:"BIT_FIELD",100:"BLOCK",101:"FUNCTION",102:"END_OF_STRUCT",103:"FILE",104:"SECTION",105:"WEAK_EXTERNAL",107:"CLR_TOKEN"}
    if hasattr(pefile, 'SYMBOL_STORAGE_CLASSES'):
        pefile_classes = {v: k.replace("IMAGE_SYM_CLASS_", "") for k, v in pefile.SYMBOL_STORAGE_CLASSES.items()}
        classes.update(pefile_classes)
    return classes.get(storage_class, f"UNKNOWN_CLASS({storage_class})")

def _dump_aux_symbol_to_dict(parent_symbol_struct, aux_symbol_struct, aux_idx: int) -> Dict[str, Any]:
    aux_dict: Dict[str, Any] = {"aux_record_index": aux_idx + 1}
    parent_storage_class = parent_symbol_struct.StorageClass
    sym_class_file=getattr(pefile,'IMAGE_SYM_CLASS_FILE',103);sym_class_section=getattr(pefile,'IMAGE_SYM_CLASS_SECTION',104);sym_class_static=getattr(pefile,'IMAGE_SYM_CLASS_STATIC',3);sym_class_function=getattr(pefile,'IMAGE_SYM_CLASS_FUNCTION',101);sym_class_weak_external=getattr(pefile,'IMAGE_SYM_CLASS_WEAK_EXTERNAL',105);sym_dtype_function=getattr(pefile,'IMAGE_SYM_DTYPE_FUNCTION',2)

    if parent_storage_class == sym_class_file:
        name_bytes = getattr(aux_symbol_struct,'Name',b'')
        if not name_bytes and hasattr(aux_symbol_struct,'strings'):name_bytes=aux_symbol_struct.strings
        name_str="N/A"
        if isinstance(name_bytes,bytes):
            try:name_str=name_bytes.decode('utf-8','ignore').rstrip('\x00')
            except:name_str=name_bytes.hex()
        elif isinstance(name_bytes,str):name_str=name_bytes.rstrip('\x00')
        aux_dict["filename"]=name_str;return aux_dict
    if parent_storage_class==sym_class_section or (parent_storage_class==sym_class_static and parent_symbol_struct.SectionNumber>0):
        aux_dict["type"]="Section Definition Aux Record"
        if hasattr(aux_symbol_struct,'Length'):aux_dict["length"]=aux_symbol_struct.Length
        if hasattr(aux_symbol_struct,'NumberOfRelocations'):aux_dict["number_of_relocations"]=aux_symbol_struct.NumberOfRelocations
        if hasattr(aux_symbol_struct,'NumberOfLinenumbers'):aux_dict["number_of_linenumbers"]=aux_symbol_struct.NumberOfLinenumbers
        if hasattr(aux_symbol_struct,'CheckSum'):aux_dict["checksum"]=hex(aux_symbol_struct.CheckSum)
        if hasattr(aux_symbol_struct,'Number'):aux_dict["number_comdat"]=aux_symbol_struct.Number
        if hasattr(aux_symbol_struct,'Selection'):sel_str={0:"NODUPLICATES",1:"ANY",2:"SAME_SIZE",3:"EXACT_MATCH",4:"ASSOCIATIVE",5:"LARGEST"}.get(aux_symbol_struct.Selection,f"UNKNOWN ({aux_symbol_struct.Selection})");aux_dict["selection_comdat"]=sel_str
        return aux_dict
    is_func_rel=(parent_symbol_struct.Type>>4)==sym_dtype_function or parent_symbol_struct.Type==0x20
    if is_func_rel or parent_storage_class==sym_class_function:
        aux_dict["type"]="Function-related Aux Record"
        if hasattr(aux_symbol_struct,'TagIndex'):aux_dict["tag_index"]=aux_symbol_struct.TagIndex
        if hasattr(aux_symbol_struct,'TotalSize'):aux_dict["total_size"]=aux_symbol_struct.TotalSize
        if hasattr(aux_symbol_struct,'PointerToLinenumber'):aux_dict["pointer_to_linenumber"]=hex(aux_symbol_struct.PointerToLinenumber)
        if hasattr(aux_symbol_struct,'PointerToNextFunction'):aux_dict["pointer_to_next_function"]=aux_symbol_struct.PointerToNextFunction
        if hasattr(aux_symbol_struct,'Linenumber'):aux_dict["linenumber_lf"]=aux_symbol_struct.Linenumber
        return aux_dict
    if parent_storage_class==sym_class_weak_external:
        aux_dict["type"]="Weak External Aux Record"
        if hasattr(aux_symbol_struct,'TagIndex'):aux_dict["tag_index"]=aux_symbol_struct.TagIndex
        if hasattr(aux_symbol_struct,'Characteristics'):char_val=aux_symbol_struct.Characteristics;char_str={1:"IMAGE_WEAK_EXTERN_SEARCH_NOLIBRARY",2:"IMAGE_WEAK_EXTERN_SEARCH_LIBRARY",3:"IMAGE_WEAK_EXTERN_SEARCH_ALIAS"}.get(char_val,f"UNKNOWN ({hex(char_val)})");aux_dict["characteristics"]=char_str
        return aux_dict
    aux_dict["type"]="Raw Auxiliary Data";raw_bytes=b''
    if isinstance(aux_symbol_struct,bytes):raw_bytes=aux_symbol_struct
    elif hasattr(aux_symbol_struct,'__pack__'):
        try:raw_bytes=aux_symbol_struct.__pack__()
        except:pass
    if raw_bytes:aux_dict["hex_data"]=raw_bytes[:18].hex()+("..."if len(raw_bytes)>18 else"")
    else:
        raw_attrs={}
        for attr_name in dir(aux_symbol_struct):
            if not attr_name.startswith('_')and not callable(getattr(aux_symbol_struct,attr_name)):
                attr_val=getattr(aux_symbol_struct,attr_name)
                if isinstance(attr_val,int):raw_attrs[attr_name]=hex(attr_val)if'Pointer'in attr_name or'Address'in attr_name or'Offset'in attr_name else attr_val
                elif isinstance(attr_val,bytes):raw_attrs[attr_name]=attr_val.hex()
                else:raw_attrs[attr_name]=str(attr_val)
        aux_dict["attributes"]=raw_attrs
    return aux_dict

def ensure_peid_db_exists(url: str, local_path: str, verbose: bool = False) -> bool:
    if os.path.exists(local_path):
        if verbose: safe_print(f"  [VERBOSE] PEiD database already exists at: {local_path}", verbose_prefix=" ")
        return True
    if not REQUESTS_AVAILABLE:
        safe_print("[!] 'requests' library not found. Cannot download PEiD database.", verbose_prefix=" ")
        return False
    safe_print(f"[*] PEiD database not found at {local_path}. Attempting download from {url}...", verbose_prefix=" ")
    try:
        response = requests.get(url, timeout=15); response.raise_for_status()
        with open(local_path, 'wb') as f: f.write(response.content)
        safe_print(f"[*] PEiD database successfully downloaded to: {local_path}", verbose_prefix=" ")
        return True
    except requests.exceptions.RequestException as e:
        safe_print(f"[!] Error downloading PEiD database: {e}", verbose_prefix=" ")
        if os.path.exists(local_path): # Corrected block
            try:
                os.remove(local_path)
            except OSError:
                pass
        return False
    except IOError as e:
        safe_print(f"[!] Error saving PEiD database to {local_path}: {e}", verbose_prefix=" ")
        return False

def ensure_capa_rules_exist(rules_base_dir: str, rules_zip_url: str, verbose: bool = False) -> Optional[str]:
    """
    Ensures capa rules are present in rules_base_dir, downloading and extracting if necessary.
    Returns the path to the actual rules directory (e.g., rules_base_dir/rules) or None on failure.
    """
    actual_rules_path = os.path.join(rules_base_dir, CAPA_RULES_SUBDIR_NAME)

    if os.path.isdir(actual_rules_path) and os.listdir(actual_rules_path):
        if verbose: logger.info(f"Capa rules found at: {actual_rules_path}")
        return actual_rules_path

    if not REQUESTS_AVAILABLE:
        logger.error("'requests' library not found. Cannot download capa rules.")
        return None

    logger.info(f"Capa rules not found or directory empty at '{actual_rules_path}'. Attempting to download and extract to '{rules_base_dir}'...")

    os.makedirs(rules_base_dir, exist_ok=True)
    zip_path = os.path.join(rules_base_dir, "capa-rules.zip")

    try:
        logger.info(f"Downloading capa rules from {rules_zip_url} to {zip_path}...")
        response = requests.get(rules_zip_url, timeout=60, stream=True)
        response.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info("Capa rules zip downloaded successfully.")

        logger.info(f"Extracting capa rules from {zip_path} to {rules_base_dir}...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(rules_base_dir)
        logger.info("Capa rules extracted successfully.")

        if os.path.isdir(actual_rules_path) and os.listdir(actual_rules_path):
            logger.info(f"Capa rules now available at: {actual_rules_path}")
            return actual_rules_path
        else:
            logger.error(f"Capa rules extracted, but the expected subdirectory '{CAPA_RULES_SUBDIR_NAME}' was not found or is empty in '{rules_base_dir}'.")
            if os.path.isdir(actual_rules_path) and not os.listdir(actual_rules_path):
                try: shutil.rmtree(actual_rules_path)
                except Exception as e_rm: logger.warning(f"Could not remove empty rules dir {actual_rules_path}: {e_rm}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Error downloading capa rules: {e}")
        return None
    except zipfile.BadZipFile:
        logger.error(f"Error: Downloaded capa rules file '{zip_path}' is not a valid zip file or is corrupted.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during capa rules download/extraction: {e}", exc_info=verbose)
        return None
    finally:
        if os.path.exists(zip_path):
            try: os.remove(zip_path)
            except OSError as e_rm_zip: logger.warning(f"Could not remove downloaded zip {zip_path}: {e_rm_zip}")
    return None


def parse_signature_file(db_path: str, verbose: bool = False) -> List[Dict[str, Any]]:
    if verbose: safe_print(f"  [VERBOSE-PEID] Starting to parse signature file: {db_path}", verbose_prefix=" ")
    signatures = []
    current_signature: Optional[Dict[str, Any]] = None
    try:
        with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith(';'): continue
                name_match = re.match(r'^\[(.*)\]$', line)
                if name_match:
                    if current_signature and 'name' in current_signature and ('pattern_bytes' in current_signature or 'regex_pattern' in current_signature):
                        signatures.append(current_signature)
                    current_signature = {'name': name_match.group(1).strip(), 'ep_only': False, 'regex_pattern': None, 'pattern_bytes': []}
                    continue
                if current_signature:
                    sig_match = re.match(r'^signature\s*=\s*(.*)',line,re.IGNORECASE)
                    if sig_match:
                        pat_str=sig_match.group(1).strip().upper();byte_pat_list:List[Optional[int]]=[];regex_b_list:List[bytes]=[];hex_b=pat_str.split();valid=True
                        for b_str in hex_b:
                            if b_str=='??':byte_pat_list.append(None);regex_b_list.append(b'.')
                            elif len(b_str)==2 and all(c in'0123456789ABCDEF'for c in b_str):
                                try:b_val=int(b_str,16);byte_pat_list.append(b_val);regex_b_list.append(re.escape(bytes([b_val])))
                                except ValueError:valid=False;break
                            elif len(b_str)==2 and(b_str[0]=='?'or b_str[1]=='?'):byte_pat_list.append(None);regex_c=b_str.replace('?','.');regex_b_list.append(regex_c.encode('ascii'))
                            else:valid=False;break
                        if valid and regex_b_list:
                            current_signature['pattern_bytes']=byte_pat_list
                            try:current_signature['regex_pattern']=re.compile(b''.join(regex_b_list))
                            except re.error:current_signature=None # Invalidate
                        else:current_signature=None # Invalidate
                        continue
                    ep_match=re.match(r'^ep_only\s*=\s*(true|false)',line,re.IGNORECASE)
                    if ep_match:current_signature['ep_only']=ep_match.group(1).lower()=='true'
        if current_signature and 'name' in current_signature and ('pattern_bytes' in current_signature or 'regex_pattern' in current_signature):
            signatures.append(current_signature)
    except FileNotFoundError: safe_print(f"[!] PEiD DB not found: {db_path}"); return []
    except Exception as e: safe_print(f"[!] Error parsing PEiD DB {db_path}: {e}"); return []
    if verbose: safe_print(f"  [VERBOSE-PEID] Loaded {len(signatures)} PEiD signatures.", verbose_prefix=" ")
    return signatures

def find_pattern_in_data_regex(data_block: bytes, signature_dict: Dict[str, Any], verbose: bool = False, section_name_for_log: str = "UnknownSection") -> Optional[str]:
    regex_pattern = signature_dict.get('regex_pattern')
    pattern_name = signature_dict.get('name', "Unknown")
    if not regex_pattern or not data_block: return None
    try:
        match = regex_pattern.search(data_block)
        if match:
            if verbose: safe_print(f"      [VERBOSE-PEID-MATCH-REGEX] Pattern '{pattern_name}' matched at offset {hex(match.start())} in {section_name_for_log}.", verbose_prefix=" ")
            return pattern_name
    except Exception as e_re_search:
        if verbose: safe_print(f"      [VERBOSE-PEID-REGEX-ERROR] Error searching for pattern '{pattern_name}': {e_re_search}", verbose_prefix=" ")
    return None

def perform_yara_scan(filepath: str, file_data: bytes, yara_rules_path: Optional[str], yara_available_flag: bool, verbose: bool = False) -> List[Dict[str, Any]]:
    scan_results: List[Dict[str, Any]] = []
    if not yara_available_flag:
        logger.warning("  'yara-python' library not found. Skipping YARA scan.")
        if verbose and YARA_IMPORT_ERROR: logger.debug(f"        [VERBOSE-DEBUG] YARA import error: {YARA_IMPORT_ERROR}")
        return scan_results
    if not yara_rules_path:
        logger.info("  No YARA rules path provided. Skipping YARA scan.")
        return scan_results
    try:
        if verbose: logger.info(f"  [VERBOSE-YARA] Loading rules from: {yara_rules_path}")
        rules = None
        if os.path.isdir(yara_rules_path):
            filepaths = {f_name: os.path.join(dirname, f_name) for dirname, _, files in os.walk(yara_rules_path) for f_name in files if f_name.lower().endswith(('.yar', '.yara'))}
            if not filepaths: logger.warning(f"  No .yar or .yara files in dir: {yara_rules_path}"); return scan_results
            rules = yara.compile(filepaths=filepaths)
        elif os.path.isfile(yara_rules_path): rules = yara.compile(filepath=yara_rules_path)
        else: logger.warning(f"  YARA rules path not valid: {yara_rules_path}"); return scan_results

        matches = rules.match(data=file_data)
        if matches:
            logger.info(f"  YARA Matches Found ({len(matches)}):")
            for match in matches:
                match_detail:Dict[str,Any]={"rule":match.rule,"namespace":match.namespace if match.namespace!='default'else None,"tags":list(match.tags)if match.tags else None,"meta":dict(match.meta)if match.meta else None,"strings":[]}
                if match.strings:
                    for s_match in match.strings:
                        try:str_data_repr=s_match[2].decode('latin-1').encode('unicode_escape').decode('ascii')
                        except:str_data_repr=s_match[2].hex()
                        if len(str_data_repr)>80:str_data_repr=str_data_repr[:77]+"..."
                        match_detail["strings"].append({"offset":hex(s_match[0]),"identifier":s_match[1],"data":str_data_repr})
                scan_results.append(match_detail)
        else: logger.info("  No YARA matches found.")
    except yara.Error as e: logger.error(f"  YARA Error: {e}"); scan_results.append({"error":f"YARA Error: {str(e)}"})
    except Exception as e: logger.error(f"  Unexpected YARA scan error: {e}",exc_info=verbose); scan_results.append({"error":f"Unexpected YARA scan error: {str(e)}"})
    return scan_results

def _parse_capa_analysis(pe_obj: pefile.PE,
                         capa_rules_dir_path: Optional[str],
                         capa_sigs_dir_path: Optional[str], 
                         verbose: bool) -> Dict[str, Any]:
    """Performs capa analysis on the PE file, optionally using library signatures."""
    capa_results: Dict[str, Any] = {"status": "Not performed", "error": None, "results": None}
    if not CAPA_AVAILABLE:
        capa_results["status"] = "Capa library not available."
        capa_results["error"] = f"Capa import error: {CAPA_IMPORT_ERROR}"
        logger.warning("Capa library not found. Skipping capa analysis.")
        return capa_results

    effective_rules_path = capa_rules_dir_path

    if not effective_rules_path or not os.path.isdir(effective_rules_path) or not os.listdir(effective_rules_path):
        logger.warning(f"Provided capa rules path '{capa_rules_dir_path}' is invalid or empty.")
        default_rules_base = os.path.join(os.getcwd(), CAPA_RULES_DEFAULT_DIR)
        logger.info(f"Attempting to ensure/download capa rules to default location: {default_rules_base}")
        effective_rules_path = ensure_capa_rules_exist(default_rules_base, CAPA_RULES_ZIP_URL, verbose)
        if not effective_rules_path:
            capa_results["status"] = "Capa rules not found or download/extraction failed."
            capa_results["error"] = f"Capa rules directory '{capa_rules_dir_path or default_rules_base}' is invalid, and default download failed."
            logger.error(capa_results["error"])
            return capa_results
        else:
            logger.info(f"Using capa rules from: {effective_rules_path}")

    try:
        # Handle library signatures if path is provided
        if capa_sigs_dir_path and os.path.isdir(capa_sigs_dir_path):
            if verbose: logger.info(f"  [VERBOSE-CAPA] Attempting to set global capa signatures from: {capa_sigs_dir_path}")
            try:
                capa.main.set_global_signatures(capa_sigs_dir_path) # Use the function to set signatures
                if verbose: logger.info(f"  [VERBOSE-CAPA] Successfully set global signatures.")
            except Exception as e_sigs:
                logger.warning(f"  [VERBOSE-CAPA] Failed to set capa global signatures from '{capa_sigs_dir_path}': {e_sigs}")
        elif capa_sigs_dir_path: # Path provided but not valid
                logger.warning(f"  [VERBOSE-CAPA] Capa signatures directory '{capa_sigs_dir_path}' is not a valid directory. Signatures will not be loaded.")


        if verbose: logger.info(f"  [VERBOSE-CAPA] Loading capa rules from: {effective_rules_path}")
        rules = capa.rules.RuleSet.from_directory(effective_rules_path)
        if verbose: logger.info(f"  [VERBOSE-CAPA] Loaded {len(rules.rules)} capa rules.")

        extractor = capa.features.extractors.pefile.PefileFeatureExtractor(pe_obj)
        if verbose: logger.info(f"  [VERBOSE-CAPA] PefileFeatureExtractor created for {pe_obj.OPTIONAL_HEADER.ImageBase:#x}.")

        capabilities, meta = capa.main.find_capabilities(rules, extractor, pe_obj.__data__)
        if verbose: logger.info(f"  [VERBOSE-CAPA] Found {len(capabilities)} capabilities.")

        doc = capa.main.get_result_document(meta, rules, capabilities)
        json_output_str = capa_json_render.render_json(doc)
        capa_results["results"] = json.loads(json_output_str)
        capa_results["status"] = "Analysis complete"

    except InvalidRule as e:
        error_msg = f"Invalid capa rule encountered: {e}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis"
        capa_results["error"] = error_msg
    except RulesAccessError as e:
        error_msg = f"Error accessing capa rules at '{effective_rules_path}': {e}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error loading rules"
        capa_results["error"] = error_msg
    except FreezingError as e:
        error_msg = f"Capa freezing error: {e}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis"
        capa_results["error"] = error_msg
    except CapaError as e:
        error_msg = f"Capa analysis error: {e}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis"
        capa_results["error"] = error_msg
    except Exception as e:
        error_msg = f"Unexpected error during capa analysis: {e}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Unexpected error"
        capa_results["error"] = error_msg

    return capa_results


# --- String Utilities ---
def _extract_strings_from_data(data_bytes: bytes, min_length: int = 5) -> List[Tuple[int, str]]:
    strings_found = []
    current_string = ""
    current_offset = -1
    for i, byte_val in enumerate(data_bytes):
        char = chr(byte_val)
        if ' ' <= char <= '~':
            if not current_string: current_offset = i
            current_string += char
        else:
            if len(current_string) >= min_length: strings_found.append((current_offset, current_string))
            current_string = ""; current_offset = -1
    if len(current_string) >= min_length: strings_found.append((current_offset, current_string))
    return strings_found

def _search_specific_strings_in_data(data_bytes: bytes, search_terms: List[str]) -> Dict[str, List[int]]:
    results: Dict[str, List[int]] = {term: [] for term in search_terms}
    for term in search_terms:
        term_bytes = term.encode('ascii', 'ignore')
        offset = 0
        while True:
            found_at = data_bytes.find(term_bytes, offset)
            if found_at == -1: break
            results[term].append(found_at)
            offset = found_at + 1
    return results

def _format_hex_dump_lines(data_chunk: bytes, start_address: int = 0, bytes_per_line: int = 16) -> List[str]:
    lines = []
    for i in range(0, len(data_chunk), bytes_per_line):
        chunk = data_chunk[i:i+bytes_per_line]
        hex_part = ' '.join(f"{b:02x}" for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        hex_part_padded = hex_part.ljust(bytes_per_line * 3 -1)
        lines.append(f"{start_address + i:08x}  {hex_part_padded}  |{ascii_part}|")
    return lines

# --- Refactored PE Parsing Helper Functions ---
def _parse_file_hashes(data: bytes) -> Dict[str, Optional[str]]:
    hashes: Dict[str, Optional[str]] = {"md5": None, "sha1": None, "sha256": None, "ssdeep": None}
    try:
        hashes["md5"] = hashlib.md5(data).hexdigest()
        hashes["sha1"] = hashlib.sha1(data).hexdigest()
        hashes["sha256"] = hashlib.sha256(data).hexdigest()
        try: hashes["ssdeep"] = ssdeep_hasher.hash(data)
        except Exception as e_ssdeep: logger.warning(f"ssdeep hash error: {e_ssdeep}"); hashes["ssdeep"] = f"Error: {e_ssdeep}"
    except Exception as e_hash: logger.warning(f"File hash error: {e_hash}")
    return hashes

def _parse_dos_header(pe: pefile.PE) -> Dict[str, Any]:
    if hasattr(pe, 'DOS_HEADER') and pe.DOS_HEADER: return pe.DOS_HEADER.dump_dict()
    return {"error": "DOS Header not found or malformed."}

def _parse_nt_headers(pe: pefile.PE) -> Tuple[Dict[str, Any], str]:
    nt_headers_info: Dict[str, Any] = {}; magic_type_str = "Unknown"
    if hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS:
        nt_headers_info['signature'] = hex(pe.NT_HEADERS.Signature)
        if hasattr(pe.NT_HEADERS, 'FILE_HEADER') and pe.NT_HEADERS.FILE_HEADER:
            fh_dict = pe.NT_HEADERS.FILE_HEADER.dump_dict()
            fh_dict['characteristics_list'] = get_file_characteristics(pe.NT_HEADERS.FILE_HEADER.Characteristics)
            fh_dict['TimeDateStamp_ISO'] = format_timestamp(pe.NT_HEADERS.FILE_HEADER.TimeDateStamp)
            nt_headers_info['file_header'] = fh_dict
        else: nt_headers_info['file_header'] = {"error": "File Header not found."}
        if hasattr(pe.NT_HEADERS, 'OPTIONAL_HEADER') and pe.NT_HEADERS.OPTIONAL_HEADER:
            oh_dict = pe.NT_HEADERS.OPTIONAL_HEADER.dump_dict()
            oh_dict['dll_characteristics_list'] = get_dll_characteristics(pe.NT_HEADERS.OPTIONAL_HEADER.DllCharacteristics)
            magic_val = pe.NT_HEADERS.OPTIONAL_HEADER.Magic
            magic_type_str = "PE32 (32-bit)" if magic_val==0x10b else "PE32+ (64-bit)" if magic_val==0x20b else "Unknown"
            oh_dict['pe_type'] = magic_type_str
            nt_headers_info['optional_header'] = oh_dict
        else: nt_headers_info['optional_header'] = {"error": "Optional Header not found."}
    else: nt_headers_info = {"error": "NT Headers not found."}
    return nt_headers_info, magic_type_str

def _parse_data_directories(pe: pefile.PE) -> List[Dict[str, Any]]:
    data_dirs_list = []
    if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
        for i, entry in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            entry_info = entry.dump_dict(); entry_info['name'] = entry.name; entry_info['index'] = i
            data_dirs_list.append(entry_info)
    return data_dirs_list

def _parse_sections(pe: pefile.PE) -> List[Dict[str, Any]]:
    sections_list = []
    if hasattr(pe, 'sections'):
        for section in pe.sections:
            sec_dict = section.dump_dict()
            sec_dict['name_str'] = section.Name.decode('utf-8','ignore').rstrip('\x00')
            sec_dict['characteristics_list'] = get_section_characteristics(section.Characteristics)
            sec_dict['entropy'] = section.get_entropy()
            try:
                section_data = section.get_data()
                sec_dict['md5']=hashlib.md5(section_data).hexdigest(); sec_dict['sha1']=hashlib.sha1(section_data).hexdigest(); sec_dict['sha256']=hashlib.sha256(section_data).hexdigest()
                try: sec_dict['ssdeep'] = ssdeep_hasher.hash(section_data)
                except Exception as e: sec_dict['ssdeep'] = f"Error: {e}"
            except Exception as e: logger.warning(f"Section hash error {sec_dict['name_str']}: {e}")
            sections_list.append(sec_dict)
    return sections_list

def _parse_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    imports_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_info:Dict[str,Any]={'dll_name':"Unknown"};
            try:dll_info['dll_name']=entry.dll.decode('utf-8','ignore')if entry.dll else"N/A"
            except:pass
            dll_info['struct']=entry.struct.dump_dict();dll_info['symbols']=[]
            if hasattr(entry,'imports'):
                for imp in entry.imports:
                    sym_info={'address':hex(imp.address)if imp.address is not None else None,'name':imp.name.decode('utf-8','ignore')if imp.name else None,'ordinal':imp.ordinal,'bound':hex(imp.bound)if imp.bound is not None else None,'hint_name_table_rva':hex(imp.hint_name_table_rva)if hasattr(imp,'hint_name_table_rva')and imp.hint_name_table_rva is not None else None,'import_by_ordinal':imp.import_by_ordinal if hasattr(imp,'import_by_ordinal')else(imp.name is None)}
                    dll_info['symbols'].append(sym_info)
            imports_list.append(dll_info)
    return imports_list

def _parse_exports(pe: pefile.PE) -> Dict[str, Any]:
    exports_info: Dict[str, Any] = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exports_info['struct'] = pe.DIRECTORY_ENTRY_EXPORT.struct.dump_dict()
        exports_info['name'] = pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8','ignore') if pe.DIRECTORY_ENTRY_EXPORT.name else None
        exports_info['symbols'] = []
        if hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                sym_info = {'address':hex(exp.address)if exp.address is not None else None,'name':exp.name.decode('utf-8','ignore')if exp.name else None,'ordinal':exp.ordinal,'forwarder':exp.forwarder.decode('utf-8','ignore')if exp.forwarder else None}
                exports_info['symbols'].append(sym_info)
    return exports_info

def _parse_resources_summary(pe: pefile.PE) -> List[Dict[str, Any]]:
    resources_summary_list = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for res_type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name_val=getattr(res_type_entry,'id',None);type_name_str=pefile.RESOURCE_TYPE.get(type_name_val,str(type_name_val))
            if hasattr(res_type_entry,'name')and res_type_entry.name is not None:
                try:type_name_str=f"{res_type_entry.name.decode('utf-16le','ignore')} ({type_name_str})"
                except:type_name_str=f"{res_type_entry.name.decode('latin-1','ignore')} ({type_name_str})"
            if hasattr(res_type_entry,'directory'):
                for res_id_entry in res_type_entry.directory.entries:
                    id_val=getattr(res_id_entry,'id',None);id_name_str=str(id_val)
                    if hasattr(res_id_entry,'name')and res_id_entry.name is not None:
                        try:id_name_str=f"{res_id_entry.name.decode('utf-16le','ignore')} (ID: {id_val if id_val is not None else 'N/A'})"
                        except:id_name_str=f"{res_id_entry.name.decode('latin-1','ignore')} (ID: {id_val if id_val is not None else 'N/A'})"
                    elif id_val is not None:id_name_str=f"ID: {id_val}"
                    else:id_name_str="Unnamed/ID-less"
                    if hasattr(res_id_entry,'directory'):
                        for res_lang_entry in res_id_entry.directory.entries:
                            if hasattr(res_lang_entry,'data')and hasattr(res_lang_entry.data,'struct'):
                                data_struct=res_lang_entry.data.struct
                                resources_summary_list.append({"type":type_name_str,"id_name":id_name_str,"lang_id":getattr(res_lang_entry,'id','N/A'),"offset_to_data_rva":hex(getattr(data_struct,'OffsetToData',0)),"size":getattr(data_struct,'Size',0),"codepage":getattr(data_struct,'CodePage',0)})
    return resources_summary_list

def _parse_version_info(pe: pefile.PE) -> Dict[str, Any]:
    ver_info:Dict[str,Any]={}
    if hasattr(pe,'VS_VERSIONINFO')and hasattr(pe.VS_VERSIONINFO,'Value'):ver_info['vs_versioninfo_value']=pe.VS_VERSIONINFO.Value.decode('ascii','ignore')if pe.VS_VERSIONINFO.Value else None
    if hasattr(pe,'VS_FIXEDFILEINFO')and pe.VS_FIXEDFILEINFO:
        fixed_list=[]
        for entry in pe.VS_FIXEDFILEINFO:
            fixed_dict=entry.dump_dict()
            fixed_dict['FileVersion_str']=f"{(entry.FileVersionMS>>16)}.{(entry.FileVersionMS&0xFFFF)}.{(entry.FileVersionLS>>16)}.{(entry.FileVersionLS&0xFFFF)}"
            fixed_dict['ProductVersion_str']=f"{(entry.ProductVersionMS>>16)}.{(entry.ProductVersionMS&0xFFFF)}.{(entry.ProductVersionLS>>16)}.{(entry.ProductVersionLS&0xFFFF)}"
            fixed_list.append(fixed_dict)
        ver_info['vs_fixedfileinfo']=fixed_list
    if hasattr(pe,'FileInfo')and pe.FileInfo:
        fi_blocks=[]
        for fi_block in pe.FileInfo:
            block_detail:Dict[str,Any]={}
            if hasattr(fi_block,'entries'):
                block_detail['type']="StringFileInfo";st_tables=[]
                for item in fi_block.entries:
                    st_entry:Dict[str,Any]={'lang_codepage':f"{item.Lang}/{item.CodePage}",'entries':{}}
                    if hasattr(item,'entries')and isinstance(item.entries,dict):
                        for k,v in item.entries.items():st_entry['entries'][k.decode('utf-8','ignore')if isinstance(k,bytes)else str(k)]=v.decode('utf-8','ignore')if isinstance(v,bytes)else str(v)
                    st_tables.append(st_entry)
                block_detail['string_tables']=st_tables
            elif hasattr(fi_block,'Var')and hasattr(fi_block.Var,'entry'):
                block_detail['type']="VarFileInfo";var_entry=fi_block.Var.entry;var_key=var_entry.szKey.decode('utf-8','ignore')if isinstance(var_entry.szKey,bytes)else str(var_entry.szKey);var_val=var_entry.Value;var_val_str=var_val
                if isinstance(var_val,bytes)and len(var_val)==4:lang_id=struct.unpack('<H',var_val[:2])[0];charset_id=struct.unpack('<H',var_val[2:])[0];var_val_str=f"LangID={hex(lang_id)}, CharsetID={hex(charset_id)}"
                elif isinstance(var_val,bytes):var_val_str=var_val.hex()
                block_detail['vars']={var_key:var_val_str}
            fi_blocks.append(block_detail)
        ver_info['file_info_blocks']=fi_blocks
    return ver_info

def _parse_debug_info(pe: pefile.PE) -> List[Dict[str, Any]]:
    debug_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_DEBUG'):
        for entry in pe.DIRECTORY_ENTRY_DEBUG:
            dbg_item:Dict[str,Any]={'struct':entry.struct.dump_dict()};dbg_item['type_str']=pefile.DEBUG_TYPE.get(entry.struct.Type,"UNKNOWN")
            if entry.entry:
                dbg_item['entry_details']=entry.entry.dump_dict()
                if entry.struct.Type==pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_CODEVIEW']and hasattr(entry.entry,'PdbFileName'):
                    try:dbg_item['pdb_filename']=entry.entry.PdbFileName.decode('utf-8','ignore').rstrip('\x00')
                    except:dbg_item['pdb_filename']=entry.entry.PdbFileName.hex()if isinstance(entry.entry.PdbFileName,bytes)else str(entry.entry.PdbFileName)
            debug_list.append(dbg_item)
    return debug_list

def _parse_digital_signature(pe: pefile.PE, filepath: str, cryptography_available_flag: bool, signify_available_flag: bool) -> Dict[str, Any]:
    sig_info: Dict[str, Any] = {}
    sec_dir_idx = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    if hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
        sec_dir_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
        sig_offset = sec_dir_entry.VirtualAddress; sig_size = sec_dir_entry.Size
        sig_info['security_directory'] = {'offset': hex(sig_offset), 'size': hex(sig_size)}
        if sig_offset != 0 and sig_size != 0:
            sig_info['embedded_signature_present'] = True
            raw_sig_block = pe.get_data(sig_offset, sig_size)
            if cryptography_available_flag:
                crypto_certs=[]
                try:
                    pkcs7_blob=None
                    if len(raw_sig_block)>8:
                        cert_type=struct.unpack_from('<H',raw_sig_block,6)[0]
                        if cert_type==0x0002:pkcs7_blob=raw_sig_block[8:]
                    if pkcs7_blob:
                        with warnings.catch_warnings():warnings.simplefilter("ignore",UserWarning);warnings.simplefilter("ignore",DeprecationWarning);parsed=pkcs7.load_der_pkcs7_certificates(pkcs7_blob)
                        for idx,cert in enumerate(parsed):crypto_certs.append({"cert_index":idx+1,"subject":str(cert.subject.rfc4514_string()),"issuer":str(cert.issuer.rfc4514_string()),"serial_number":str(cert.serial_number),"version":str(cert.version),"not_valid_before_utc":str(cert.not_valid_before_utc),"not_valid_after_utc":str(cert.not_valid_after_utc)})
                        sig_info['cryptography_parsed_certs']=crypto_certs
                except Exception as e:sig_info['cryptography_parsed_certs_error']=str(e)
            else:sig_info['cryptography_parsed_certs']="cryptography library not available"
            if signify_available_flag:
                signify_res=[]
                try:
                    with io.BytesIO(pe.__data__)as f_mem:
                        signed_pe=SignedPEFile(f_mem)
                        if not signed_pe.signed_datas:signify_res.append({"status":"No signature blocks found by signify."})
                        else:
                            for i,sdo in enumerate(signed_pe.signed_datas):
                                vr_enum,vr_exc=sdo.explain_verify()
                                item:Dict[str,Any]={"block":i+1,"status_description":str(vr_enum),"is_valid":vr_enum==AuthenticodeVerificationResult.OK,"exception":str(vr_exc)if vr_exc else None}
                                if sdo.signer_info:
                                    si=sdo.signer_info;ident_parts=[]
                                    if hasattr(si,'issuer')and si.issuer:
                                        try:ident_parts.append(f"Issuer: {si.issuer.rfc4514_string()}")
                                        except:ident_parts.append(f"Issuer: {str(si.issuer)}")
                                    else:ident_parts.append("Issuer: N/A")
                                    if hasattr(si,'serial_number')and si.serial_number is not None:ident_parts.append(f"Serial: {si.serial_number}")
                                    else:ident_parts.append("Serial: N/A")
                                    item["signer_identification_string"]=", ".join(ident_parts)
                                    if hasattr(si,'program_name')and si.program_name:item["program_name"]=si.program_name
                                if sdo.signer_info and sdo.signer_info.countersigner and hasattr(sdo.signer_info.countersigner,'signing_time'):item["timestamp_time"]=str(sdo.signer_info.countersigner.signing_time)
                                signify_res.append(item)
                except Exception as e:signify_res.append({"error":f"Signify validation error: {e}"})
                sig_info['signify_validation']=signify_res
            else:sig_info['signify_validation']={"status":"Signify library not available."}
        else:sig_info['embedded_signature_present']=False
    return sig_info

def _perform_peid_scan(pe: pefile.PE, peid_db_path: Optional[str], verbose: bool, skip_full_peid_scan: bool, peid_scan_all_sigs_heuristically: bool) -> Dict[str, Any]:
    peid_results: Dict[str, Any] = {"ep_matches": [], "heuristic_matches": [], "status": "Not performed"}
    if not peid_db_path: peid_results["status"] = "PEiD DB path not provided."; return peid_results
    if not os.path.exists(peid_db_path):
        logger.info(f"PEiD DB '{peid_db_path}' not found. Attempting download...")
        if not ensure_peid_db_exists(PEID_USERDB_URL, peid_db_path, verbose):
            peid_results["status"] = f"PEiD DB '{peid_db_path}' not found/download failed."; return peid_results
    if not os.path.exists(peid_db_path): peid_results["status"] = f"PEiD DB '{peid_db_path}' not found."; return peid_results

    custom_sigs = parse_signature_file(peid_db_path, verbose)
    if not custom_sigs: peid_results["status"] = "No PEiD signatures loaded."; return peid_results
    peid_results["status"] = "Scan performed."
    if hasattr(pe,'OPTIONAL_HEADER')and pe.OPTIONAL_HEADER.AddressOfEntryPoint:
        ep_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        try:
            ep_sec=pe.get_section_by_rva(ep_rva)
            if ep_sec:
                ep_offset_sec=ep_rva-ep_sec.VirtualAddress;ep_data=ep_sec.get_data(ep_offset_sec,2048)
                for sig in custom_sigs:
                    if sig['ep_only']:match_name=find_pattern_in_data_regex(ep_data,sig,verbose,"Entry Point Area");_ = peid_results["ep_matches"].append(match_name) if match_name else None
        except Exception as e:logger.warning(f"PEiD EP scan error: {e}",exc_info=verbose)
    if not skip_full_peid_scan:
        heuristic_matches_list:List[str]=[]
        secs_to_scan=[s for s in pe.sections if hasattr(s,'Characteristics')and bool(s.Characteristics&pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])]
        if not secs_to_scan and pe.sections:secs_to_scan=[pe.sections[0]]
        scan_tasks_args=[]
        for sec in secs_to_scan:
            try:
                sec_data=sec.get_data();sec_name=sec.Name.decode('utf-8','ignore').rstrip('\x00')
                for sig in custom_sigs:
                    if peid_scan_all_sigs_heuristically or not sig['ep_only']:scan_tasks_args.append((sec_data,sig,verbose,sec_name))
            except Exception as e:logger.warning(f"PEiD section data error {sec.Name.decode('utf-8','ignore').rstrip('\x00')}: {e}")
        if scan_tasks_args:
            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()or 1)as executor:
                futures=[executor.submit(find_pattern_in_data_regex,*args)for args in scan_tasks_args]
                for future in concurrent.futures.as_completed(futures):
                    try:res_name=future.result();_ = heuristic_matches_list.append(res_name) if res_name else None
                    except Exception as e:logger.warning(f"PEiD scan thread error: {e}",exc_info=verbose)
        peid_results["heuristic_matches"]=list(set(heuristic_matches_list))
    peid_results["ep_matches"]=list(set(peid_results["ep_matches"]))
    return peid_results

def _parse_rich_header(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    if hasattr(pe,'RICH_HEADER')and pe.RICH_HEADER:
        decoded=[];raw_vals=list(pe.RICH_HEADER.values)if pe.RICH_HEADER.values else[]
        for i in range(0,len(raw_vals),2):
            if i+1<len(raw_vals):comp_id=raw_vals[i];count=raw_vals[i+1];prod_id=comp_id>>16;build_num=comp_id&0xFFFF;decoded.append({"product_id_hex":hex(prod_id),"product_id_dec":prod_id,"build_number":build_num,"count":count,"raw_comp_id":hex(comp_id)})
        return {'key_hex':pe.RICH_HEADER.key.hex()if isinstance(pe.RICH_HEADER.key,bytes)else str(pe.RICH_HEADER.key),'checksum':hex(pe.RICH_HEADER.checksum)if pe.RICH_HEADER.checksum is not None else None,'raw_values':raw_vals,'decoded_values':decoded,'raw_data_hex':pe.RICH_HEADER.raw_data.hex()if pe.RICH_HEADER.raw_data else None,'clear_data_hex':pe.RICH_HEADER.clear_data.hex()if pe.RICH_HEADER.clear_data else None}
    return None

def _parse_delay_load_imports(pe: pefile.PE, magic_type_str: str) -> List[Dict[str, Any]]:
    delay_imports_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name="N/A"
            if entry.struct.szName:
                try:dll_name=pe.get_string_at_rva(entry.struct.szName).decode('utf-8','ignore')
                except:pass
            delay_syms=[]
            if entry.struct.pINT and hasattr(pe,'OPTIONAL_HEADER'):
                thunk_rva=entry.struct.pINT;ptr_size=8 if magic_type_str=="PE32+ (64-bit)"else 4;addr_mask=0x7FFFFFFFFFFFFFFF if ptr_size==8 else 0x7FFFFFFF;ord_flag=pefile.IMAGE_ORDINAL_FLAG64 if ptr_size==8 else pefile.IMAGE_ORDINAL_FLAG32
                while True:
                    try:
                        thunk_val=pe.get_qword_at_rva(thunk_rva)if ptr_size==8 else pe.get_dword_at_rva(thunk_rva)
                        if thunk_val==0:break
                        s_name,s_ord=None,None
                        if thunk_val&ord_flag:s_ord=thunk_val&0xFFFF
                        else:
                            name_rva=thunk_val&addr_mask
                            try:s_name=pe.get_string_at_rva(name_rva+2).decode('utf-8','ignore')
                            except:pass
                        delay_syms.append({'name':s_name,'ordinal':s_ord,'thunk_rva':hex(thunk_rva)});thunk_rva+=ptr_size
                    except:break
            delay_imports_list.append({'dll_name':dll_name,'struct':entry.struct.dump_dict(),'symbols':delay_syms})
    return delay_imports_list

def _parse_tls_info(pe: pefile.PE, magic_type_str: str) -> Optional[Dict[str, Any]]:
    if hasattr(pe,'DIRECTORY_ENTRY_TLS')and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct:
        tls_struct=pe.DIRECTORY_ENTRY_TLS.struct;tls_info:Dict[str,Any]={'struct':tls_struct.dump_dict()};callbacks=[]
        if tls_struct.AddressOfCallBacks and hasattr(pe,'OPTIONAL_HEADER'):
            cb_va=tls_struct.AddressOfCallBacks;ptr_size=8 if magic_type_str=="PE32+ (64-bit)"else 4;max_cb=20;count=0
            while cb_va!=0 and count<max_cb:
                try:
                    func_va_ptr_rva=pe.get_rva_from_offset(pe.get_offset_from_virtual_address(cb_va))
                    func_va=pe.get_qword_from_data(pe.get_data(func_va_ptr_rva,ptr_size),0)if ptr_size==8 else pe.get_dword_from_data(pe.get_data(func_va_ptr_rva,ptr_size),0)
                    if func_va==0:break
                    callbacks.append({'va':hex(func_va),'rva':hex(func_va-pe.OPTIONAL_HEADER.ImageBase)});cb_va+=ptr_size;count+=1
                except Exception as e:logger.debug(f"TLS callback parse error VA {hex(cb_va)}: {e}");break
        tls_info['callbacks']=callbacks;return tls_info
    return None

def _parse_load_config(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    if hasattr(pe,'DIRECTORY_ENTRY_LOAD_CONFIG')and pe.DIRECTORY_ENTRY_LOAD_CONFIG and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct:
        lc=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct;load_config_dict:Dict[str,Any]={'struct':lc.dump_dict()}
        if hasattr(lc,'GuardFlags'):
            gf_list=[];gf_map={0x100:"CF_INSTRUMENTED",0x200:"CFW_INSTRUMENTED",0x400:"CF_FUNCTION_TABLE_PRESENT",0x800:"SECURITY_COOKIE_UNUSED",0x1000:"PROTECT_DELAYLOAD_IAT",0x2000:"DELAYLOAD_IAT_IN_ITS_OWN_SECTION",0x4000:"CF_EXPORT_SUPPRESSION_INFO_PRESENT",0x8000:"CF_ENABLE_EXPORT_SUPPRESSION",0x10000:"CF_LONGJUMP_TABLE_PRESENT",0x100000:"RETPOLINE_PRESENT",0x1000000:"EH_CONTINUATION_TABLE_PRESENT",0x2000000:"XFG_ENABLED"}
            for flag_val,flag_name in gf_map.items():
                if lc.GuardFlags&flag_val:gf_list.append(f"IMAGE_GUARD_{flag_name}")
            load_config_dict['guard_flags_list']=gf_list
        return load_config_dict
    return None

def _parse_com_descriptor(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    com_desc_idx=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
    if hasattr(pe.OPTIONAL_HEADER,'DATA_DIRECTORY')and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>com_desc_idx and pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_desc_idx].VirtualAddress!=0 and hasattr(pe,'DIRECTORY_ENTRY_COM_DESCRIPTOR')and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR and hasattr(pe.DIRECTORY_ENTRY_COM_DESCRIPTOR,'struct'):
        com_desc=pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct;com_dict:Dict[str,Any]={'struct':com_desc.dump_dict()};flags_list=[]
        flags_map={0x1:"ILONLY",0x2:"32BITREQUIRED",0x4:"IL_LIBRARY",0x8:"STRONGNAMESIGNED",0x10:"NATIVE_ENTRYPOINT",0x10000:"TRACKDEBUGDATA",0x20000:"32BITPREFERRED"}
        if hasattr(com_desc,'Flags'):
            for val,name in flags_map.items():
                if com_desc.Flags&val:flags_list.append(f"COMIMAGE_FLAGS_{name}")
        com_dict['flags_list']=flags_list;return com_dict
    return None

def _parse_overlay_data(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    offset=pe.get_overlay_data_start_offset()
    if offset is not None:
        data=pe.get_overlay()
        return {'offset':hex(offset),'size':len(data)if data else 0,'md5':hashlib.md5(data).hexdigest()if data else None,'sha256':hashlib.sha256(data).hexdigest()if data else None,'sample_hex':data[:64].hex()if data else None}
    return None

def _parse_base_relocations(pe: pefile.PE) -> List[Dict[str, Any]]:
    relocs_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_BASERELOC'):
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            block:Dict[str,Any]={'struct':base_reloc.struct.dump_dict(),'entries':[]}
            if hasattr(base_reloc,'entries'):
                for entry in base_reloc.entries:block['entries'].append({'rva':hex(entry.rva),'type':entry.type,'type_str':get_relocation_type_str(entry.type),'is_padding':getattr(entry,'is_padding',False)})
            relocs_list.append(block)
    return relocs_list

def _parse_bound_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    bound_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_BOUND_IMPORT'):
        for desc in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
            d_dict:Dict[str,Any]={'struct':desc.struct.dump_dict(),'name':None,'forwarder_refs':[]}
            try:d_dict['name']=desc.name.decode('utf-8','ignore')if desc.name else"N/A"
            except:pass
            if hasattr(desc,'entries'):
                for ref in desc.entries:
                    r_dict:Dict[str,Any]={'struct':ref.struct.dump_dict(),'name':None}
                    try:r_dict['name']=ref.name.decode('utf-8','ignore')if ref.name else"N/A"
                    except:pass
                    d_dict['forwarder_refs'].append(r_dict)
            bound_list.append(d_dict)
    return bound_list

def _parse_exception_data(pe: pefile.PE) -> List[Dict[str, Any]]:
    ex_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_EXCEPTION')and pe.DIRECTORY_ENTRY_EXCEPTION:
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            if hasattr(entry,'struct'):
                entry_dump=entry.struct.dump_dict();machine=pe.FILE_HEADER.Machine
                if machine==pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:entry_dump['note']="x64 RUNTIME_FUNCTION"
                elif machine==pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']and hasattr(entry.struct,'ExceptionHandler'):entry_dump['note']="x86 SEH Frame"
                elif machine in[pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARMNT'],pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM64']]:entry_dump['note']="ARM/ARM64 RUNTIME_FUNCTION"
                ex_list.append(entry_dump)
    return ex_list

def _parse_coff_symbols(pe: pefile.PE) -> List[Dict[str, Any]]:
    coff_list=[]
    if hasattr(pe,'FILE_HEADER')and pe.FILE_HEADER.PointerToSymbolTable!=0 and pe.FILE_HEADER.NumberOfSymbols>0 and hasattr(pe,'SYMBOLS'):
        idx=0
        while idx<len(pe.SYMBOLS):
            symbol=pe.SYMBOLS[idx]
            sym_dict={'name_str':symbol.name.decode('utf-8','ignore').rstrip('\x00')if isinstance(symbol.name,bytes)else str(symbol.name),'value':symbol.Value,'section_number':symbol.SectionNumber,'type':symbol.Type,'storage_class':symbol.StorageClass,'number_of_aux_symbols':symbol.NumberOfAuxSymbols,'type_str':get_symbol_type_str(symbol.Type),'storage_class_str':get_symbol_storage_class_str(symbol.StorageClass),'raw_struct':symbol.struct.dump_dict(),'auxiliary_symbols':[]}
            idx+=1
            if symbol.NumberOfAuxSymbols>0:
                for aux_i in range(symbol.NumberOfAuxSymbols):
                    if idx<len(pe.SYMBOLS):
                        aux_obj=None
                        if hasattr(symbol,'auxiliary_symbols')and aux_i<len(symbol.auxiliary_symbols):aux_obj=symbol.auxiliary_symbols[aux_i]
                        elif hasattr(pe.SYMBOLS[idx],'struct'):aux_obj=pe.SYMBOLS[idx].struct
                        if aux_obj:sym_dict['auxiliary_symbols'].append(_dump_aux_symbol_to_dict(symbol.struct,aux_obj,aux_i))
                        idx+=1
                    else:break
            coff_list.append(sym_dict)
    return coff_list

def _verify_checksum(pe: pefile.PE) -> Dict[str, Any]:
    if hasattr(pe,'OPTIONAL_HEADER')and hasattr(pe.OPTIONAL_HEADER,'CheckSum'):
        hdr_sum=pe.OPTIONAL_HEADER.CheckSum;calc_sum=pe.generate_checksum()
        return {'header_checksum':hex(hdr_sum),'calculated_checksum':hex(calc_sum),'matches':hdr_sum==calc_sum if hdr_sum!=0 else"Header checksum is 0 (not verified)"}
    return {"error":"Checksum info not available."}

# --- Main PE Parsing Logic ---
def _parse_pe_to_dict(pe: pefile.PE, filepath: str,
                      peid_db_path: Optional[str],
                      yara_rules_path: Optional[str],
                      capa_rules_path: Optional[str],
                      capa_sigs_path: Optional[str], 
                      verbose: bool,
                      skip_full_peid_scan: bool,
                      peid_scan_all_sigs_heuristically: bool) -> Dict[str, Any]:
    global PEFILE_VERSION_USED
    try: PEFILE_VERSION_USED = pefile.__version__
    except AttributeError: PEFILE_VERSION_USED = "Unknown"

    pe_info_dict: Dict[str, Any] = {"filepath": filepath, "pefile_version": PEFILE_VERSION_USED}
    nt_headers_info, magic_type_str = _parse_nt_headers(pe)

    pe_info_dict['file_hashes'] = _parse_file_hashes(pe.__data__)
    pe_info_dict['dos_header'] = _parse_dos_header(pe)
    pe_info_dict['nt_headers'] = nt_headers_info
    pe_info_dict['data_directories'] = _parse_data_directories(pe)
    pe_info_dict['sections'] = _parse_sections(pe)
    pe_info_dict['imports'] = _parse_imports(pe)
    pe_info_dict['exports'] = _parse_exports(pe)
    pe_info_dict['resources_summary'] = _parse_resources_summary(pe)
    pe_info_dict['version_info'] = _parse_version_info(pe)
    pe_info_dict['debug_info'] = _parse_debug_info(pe)
    pe_info_dict['digital_signature'] = _parse_digital_signature(pe, filepath, CRYPTOGRAPHY_AVAILABLE, SIGNIFY_AVAILABLE)
    pe_info_dict['rich_header'] = _parse_rich_header(pe)
    pe_info_dict['delay_load_imports'] = _parse_delay_load_imports(pe, magic_type_str)
    pe_info_dict['tls_info'] = _parse_tls_info(pe, magic_type_str)
    pe_info_dict['load_config'] = _parse_load_config(pe)
    pe_info_dict['com_descriptor'] = _parse_com_descriptor(pe)
    pe_info_dict['overlay_data'] = _parse_overlay_data(pe)
    pe_info_dict['base_relocations'] = _parse_base_relocations(pe)
    pe_info_dict['bound_imports'] = _parse_bound_imports(pe)
    pe_info_dict['exception_data'] = _parse_exception_data(pe)
    pe_info_dict['coff_symbols'] = _parse_coff_symbols(pe)
    pe_info_dict['checksum_verification'] = _verify_checksum(pe)
    pe_info_dict['peid_matches'] = _perform_peid_scan(pe, peid_db_path, verbose, skip_full_peid_scan, peid_scan_all_sigs_heuristically)
    pe_info_dict['yara_matches'] = perform_yara_scan(filepath, pe.__data__, yara_rules_path, YARA_AVAILABLE, verbose)

    # Add capa analysis
    pe_info_dict['capa_analysis'] = _parse_capa_analysis(pe, capa_rules_path, capa_sigs_path, verbose)

    pe_info_dict['pefile_warnings'] = pe.get_warnings()
    return pe_info_dict

# --- CLI Printing Helper Functions ---
def _print_dict_structure_cli(data_dict: Dict[str, Any], indent: int = 1, title: Optional[str] = None):
    prefix = "  " * indent
    if title: safe_print(f"{prefix}{title}:")
    for key, value in data_dict.items():
        if key == "Structure": continue
        if isinstance(value, dict) and "Value" in value and isinstance(value["Value"], dict):
            _print_dict_structure_cli(value["Value"], indent + 1, title=key)
        elif isinstance(value, list) and value and isinstance(value[0], dict) and "Value" in value[0]:
            safe_print(f"{prefix}  {key}:")
            for i, item_struct_container in enumerate(value):
                _print_dict_structure_cli(item_struct_container["Value"], indent + 2, title=f"Item {i+1}")
        elif isinstance(value, list) or isinstance(value, tuple):
            safe_print(f"{prefix}  {key:<30} {', '.join(map(str, value)) if value else '[]'}")
        else:
            safe_print(f"{prefix}  {key:<30} {value}")

def _print_file_hashes_cli(hashes: Dict[str, Any]):
    safe_print("\n--- File Hashes ---")
    for algo, h_val in hashes.items(): safe_print(f"  {algo.upper():<8}: {h_val if h_val else 'N/A'}")

def _print_dos_header_cli(dos_header: Dict[str, Any]):
    safe_print("\n--- DOS Header ---")
    if "error" in dos_header: safe_print(f"  {dos_header['error']}")
    elif "Value" in dos_header: _print_dict_structure_cli(dos_header["Value"], indent=1)
    else: safe_print("  DOS Header data not found.")

def _print_nt_headers_cli(nt_headers: Dict[str, Any]):
    safe_print("\n--- NT Headers ---")
    if "error" in nt_headers: safe_print(f"  {nt_headers['error']}"); return
    safe_print(f"  Signature: {nt_headers.get('signature')}")
    if 'file_header' in nt_headers:
        safe_print("\n  --- File Header (IMAGE_FILE_HEADER) ---")
        fh = nt_headers['file_header']
        if "error" in fh: safe_print(f"    {fh['error']}")
        elif "Value" in fh:
            _print_dict_structure_cli(fh["Value"], indent=2)
            safe_print(f"    TimeDateStamp (Formatted):       {fh.get('TimeDateStamp_ISO')}")
            safe_print(f"    Characteristics Flags:         {', '.join(fh.get('characteristics_list',[]))}")
    if 'optional_header' in nt_headers:
        safe_print("\n  --- Optional Header (IMAGE_OPTIONAL_HEADER) ---")
        oh = nt_headers['optional_header']
        if "error" in oh: safe_print(f"    {oh['error']}")
        elif "Value" in oh:
            _print_dict_structure_cli(oh["Value"], indent=2)
            safe_print(f"    PE Type:                       {oh.get('pe_type')}")
            safe_print(f"    DllCharacteristics Flags:      {', '.join(oh.get('dll_characteristics_list',[]))}")

def _print_data_directories_cli(data_dirs: List[Dict[str, Any]]):
    safe_print("\n--- Data Directories (IMAGE_DATA_DIRECTORY) ---")
    if not data_dirs: safe_print("  Data Directories not found or empty."); return
    for entry_dict in data_dirs:
        entry_value = entry_dict.get('Value', {}); entry_name = entry_dict.get('name', 'Unknown')
        if entry_value.get('Size',0)>0 or entry_value.get('VirtualAddress',0)>0:
            safe_print(f"  {entry_name:<30} {'Offset' if entry_name=='IMAGE_DIRECTORY_ENTRY_SECURITY' else 'RVA'}: {hex(entry_value.get('VirtualAddress',0)):<12} Size: {hex(entry_value.get('Size',0))}")

def _print_sections_cli(sections_data: List[Dict[str, Any]], pe_obj: Optional[pefile.PE]):
    safe_print("\n--- Section Table (IMAGE_SECTION_HEADER) ---")
    if not sections_data: safe_print("  No sections found."); return
    for section_dict in sections_data:
        safe_print(f"\n  Section: {section_dict.get('name_str', 'Unknown Section')}")
        if "Value" in section_dict: _print_dict_structure_cli(section_dict["Value"], indent=2)
        safe_print(f"    Characteristics Flags:         {', '.join(section_dict.get('characteristics_list',[]))}")
        safe_print(f"    Entropy:                       {section_dict.get('entropy', 0.0):.4f}")
        if section_dict.get('md5'): safe_print(f"    MD5:                           {section_dict.get('md5')}")
        if section_dict.get('ssdeep'): safe_print(f"    SSDeep:                        {section_dict.get('ssdeep')}")
        if pe_obj and VERBOSE_CLI_OUTPUT_FLAG:
            try:
                pe_sec = next((s for s in pe_obj.sections if s.Name.decode('utf-8','ignore').rstrip('\x00') == section_dict.get('name_str')), None)
                if pe_sec:
                    data_sample = pe_sec.get_data()[:32]
                    safe_print(f"    Data Sample (first 32 bytes):")
                    for line in _format_hex_dump_lines(data_sample,0,16): safe_print(f"        {line}")
            except Exception as e: logger.debug(f"Section sample error {section_dict.get('name_str')}: {e}")

def _print_imports_cli(imports_data: List[Dict[str, Any]]):
    safe_print("\n--- Import Table ---")
    if not imports_data: safe_print("  No import table found or empty."); return
    for entry in imports_data:
        safe_print(f"\n  DLL: {entry.get('dll_name', 'N/A')}")
        if "struct" in entry and "Value" in entry["struct"]: _print_dict_structure_cli(entry["struct"]["Value"], indent=2, title="Descriptor")
        for imp_sym in entry.get('symbols', []):
            name_str = imp_sym.get('name', "N/A (Imported by Ordinal)")
            bound_str = f" (Bound to: {imp_sym.get('bound')})" if imp_sym.get('bound') else ""
            safe_print(f"    Ordinal: {str(imp_sym.get('ordinal','N/A')):<6} Address: {imp_sym.get('address','N/A'):<12} Name: {name_str}{bound_str}")

def _print_exports_cli(exports_data: Dict[str, Any]):
    safe_print("\n--- Export Table ---")
    if not exports_data or "error" in exports_data or not exports_data.get('struct'): safe_print("  No export table found or empty."); return
    if "struct" in exports_data and "Value" in exports_data["struct"]: _print_dict_structure_cli(exports_data["struct"]["Value"], indent=1, title="Descriptor")
    safe_print(f"  Exported DLL Name:               {exports_data.get('name', 'N/A')}")
    for exp_sym in exports_data.get('symbols', []):
        name_str = exp_sym.get('name', "N/A (Exported by Ordinal)")
        forwarder_str = f" -> {exp_sym.get('forwarder')}" if exp_sym.get('forwarder') else ""
        safe_print(f"    Ordinal: {str(exp_sym.get('ordinal','N/A')):<6} Address RVA: {exp_sym.get('address','N/A'):<12} Name: {name_str}{forwarder_str}")

def _print_resources_summary_cli(resources_summary: List[Dict[str, Any]]):
    safe_print("\n--- Resource Directory (Summary) ---")
    if not resources_summary: safe_print("  No resource directory or summary."); return
    for res in resources_summary: safe_print(f"  - Type: {res.get('type')}, ID/Name: {res.get('id_name')}, Lang: {res.get('lang_id')}, RVA: {res.get('offset_to_data_rva')}, Size: {res.get('size')}")

def _print_version_info_cli(ver_info: Dict[str, Any]):
    safe_print("\n--- Version Information (from RT_VERSION Resource) ---")
    if not ver_info or (not ver_info.get('vs_fixedfileinfo') and not ver_info.get('file_info_blocks')): safe_print("  No version information found."); return
    if ver_info.get('vs_fixedfileinfo'):
        for fixed_info in ver_info['vs_fixedfileinfo']:
            safe_print(f"  File Version: {fixed_info.get('FileVersion_str')}, Product Version: {fixed_info.get('ProductVersion_str')}")
            if "Value" in fixed_info:
                for k,v in fixed_info["Value"].items():
                    if k not in ['Structure','FileVersionMS','FileVersionLS','ProductVersionMS','ProductVersionLS','Signature','StrucVersion']: safe_print(f"    {k}: {v}")
    if ver_info.get('file_info_blocks'):
        for block in ver_info['file_info_blocks']:
            safe_print(f"  {block.get('type')}:")
            if block.get('string_tables'):
                for st_table in block['string_tables']:
                    safe_print(f"    Lang/Codepage: {st_table.get('lang_codepage')}")
                    for k,v_str in st_table.get('entries',{}).items(): safe_print(f"        {k}: {v_str}")
            if block.get('vars'):
                for k,v_str in block.get('vars',{}).items(): safe_print(f"    {k}: {v_str}")

def _print_digital_signatures_cli(sig_info: Dict[str, Any]):
    safe_print("\n--- Digital Signatures (Authenticode) ---")
    if not sig_info: safe_print("  No signature information."); return
    if sig_info.get('security_directory'): safe_print(f"  Security Directory Offset: {sig_info['security_directory']['offset']}, Size: {sig_info['security_directory']['size']}")
    if sig_info.get('embedded_signature_present'):
        safe_print("  Embedded digital signature data found.")
        if sig_info.get('cryptography_parsed_certs_error'): safe_print(f"  Cryptography Parsing Error: {sig_info['cryptography_parsed_certs_error']}")
        elif sig_info.get('cryptography_parsed_certs'):
            safe_print("  Certificates (parsed by 'cryptography'):")
            for cert_idx,cert_data in enumerate(sig_info['cryptography_parsed_certs']):
                safe_print(f"    --- Certificate #{cert_idx+1} ---")
                for k,v_str in cert_data.items():safe_print(f"        {k.replace('_',' ').title()}: {v_str}")
        if sig_info.get('signify_validation'):
            safe_print("\n  --- Authenticode Validation (using 'signify') ---")
            val_res=sig_info['signify_validation']
            if isinstance(val_res,list):
                for i,item in enumerate(val_res):
                    if "error" in item:safe_print(f"    Signify Error: {item['error']}");continue
                    safe_print(f"    Signify Verification Context #{i+1}:")
                    safe_print(f"      Overall Verification Status: {item.get('status_description')}")
                    safe_print(f"      Is Valid (by signify): {item.get('is_valid')}")
                    if item.get('exception'):safe_print(f"      Verification Exception: {item.get('exception')}")
                    if item.get('signer_identification_string'):safe_print(f"      Signer Identification: {item.get('signer_identification_string')}")
                    if item.get('program_name'):safe_print(f"        Program Name: {item.get('program_name')}")
                    if item.get('timestamp_time'):safe_print(f"      Timestamp Signature: Valid, Time: {item.get('timestamp_time')}")
            else:safe_print(f"    Signify Info: {val_res}")
    else:
        safe_print("  No embedded digital signature data found.")
        safe_print("  This file may be signed using a Windows Catalog (.cat) file (not checked by this script).")

def _print_peid_matches_cli(peid_res: Dict[str, Any]):
    safe_print("\n--- Packer/Compiler Detection (Custom PEiD) ---")
    if not peid_res: safe_print("  PEiD scan not performed or no results."); return
    status = peid_res.get("status", "Unknown status.")
    if status == "Scan performed":
        ep_matches = peid_res.get("ep_matches", []); heuristic_matches = peid_res.get("heuristic_matches", [])
        if ep_matches: safe_print("  Matches (Entry Point - Custom):"); [safe_print(f"    - {m}") for m in set(ep_matches)]
        else: safe_print("  No PEiD signatures matched at entry point (Custom).")

        add_heuristic = [m for m in set(heuristic_matches) if m not in set(ep_matches)]
        if add_heuristic: safe_print("\n  Additional Heuristic Matches (Full File - Custom):"); [safe_print(f"    - {m}") for m in sorted(list(set(add_heuristic)))]
        elif not ep_matches and heuristic_matches: safe_print("\n  Heuristic Matches (Full File - Custom):"); [safe_print(f"    - {m}") for m in sorted(list(set(heuristic_matches)))]
        if not ep_matches and not heuristic_matches: safe_print("  No PEiD signatures matched (Custom).")
    else: safe_print(f"  {status}")

def _print_yara_matches_cli(yara_res: List[Dict[str, Any]], yara_rules_path: Optional[str]):
    safe_print("\n--- YARA Scan Results ---")
    if not yara_rules_path: safe_print("  No YARA rules path. Scan skipped."); return
    if not yara_res: safe_print("  No YARA matches or scan not performed."); return
    if yara_res and "error" in yara_res[0]: safe_print(f"  YARA Error: {yara_res[0]['error']}"); return
    if yara_res:
        safe_print(f"  YARA Matches Found ({len(yara_res)}):")
        for match in yara_res:
            safe_print(f"    Rule: {match.get('rule')}")
            if match.get('namespace'): safe_print(f"      Namespace: {match.get('namespace')}")
            if match.get('tags'): safe_print(f"      Tags: {', '.join(match.get('tags',[]))}")
            if match.get('meta'):
                safe_print(f"      Meta:"); [safe_print(f"        {mk}: {mv}") for mk,mv in match.get('meta',{}).items()]
            if match.get('strings'):
                safe_print(f"      Strings ({len(match.get('strings',[]))}):")
                for idx,sm in enumerate(match.get('strings',[])):
                    if idx>=5 and not VERBOSE_CLI_OUTPUT_FLAG: safe_print(f"          ... ({len(match.get('strings',[]))-idx} more strings not shown)");break
                    safe_print(f"          Offset: {sm.get('offset')}, ID: {sm.get('identifier')}, Data: {sm.get('data')}")
    else: safe_print("  No YARA matches found.")

def _print_capa_analysis_cli(capa_analysis_data: Dict[str, Any], verbose_flag: bool):
    """Prints capa analysis results to the CLI."""
    safe_print("\n--- Capa Capability Analysis ---")
    if not capa_analysis_data:
        safe_print("  Capa analysis data not available.")
        return

    status = capa_analysis_data.get("status", "Unknown status")
    if status != "Analysis complete":
        safe_print(f"  Capa Status: {status}")
        if capa_analysis_data.get("error"):
            safe_print(f"  Capa Error: {capa_analysis_data['error']}")
        return

    results = capa_analysis_data.get("results")
    if not results:
        safe_print("  No capa results structure found, though analysis reported complete.")
        return

    meta = results.get("meta", {})
    rules_data = results.get("rules", {})

    safe_print("  Capa Metadata:")
    if meta.get("analysis"):
        analysis_meta = meta["analysis"]
        safe_print(f"    Format: {analysis_meta.get('format')}, Arch: {analysis_meta.get('arch')}, OS: {analysis_meta.get('os')}")
        safe_print(f"    Extractor: {analysis_meta.get('extractor')}")
        if verbose_flag and analysis_meta.get('rules'):
            safe_print(f"    Rules Paths Used: {', '.join(analysis_meta.get('rules', []))}")
    if verbose_flag and meta.get("version"):
        safe_print(f"    Capa Version: {meta.get('version')}")


    if not rules_data:
        safe_print("\n  No capabilities detected by capa.")
        return

    safe_print("\n  Detected Capabilities:")
    capability_count = 0
    for rule_name, rule_details in rules_data.items():
        capability_count +=1
        rule_meta = rule_details.get("meta", {})
        matches = rule_details.get("matches", {})

        safe_print(f"\n  Capability: {rule_meta.get('name', rule_name)}")
        if rule_meta.get('namespace'):
            safe_print(f"    Namespace: {rule_meta.get('namespace')}")

        if rule_meta.get('att&ck'):
            safe_print(f"    ATT&CK: {', '.join(rule_meta.get('att&ck', []))}")
        if rule_meta.get('mbc'):
            safe_print(f"    MBC: {', '.join(rule_meta.get('mbc', []))}")

        if verbose_flag:
            if rule_meta.get('description'):
                safe_print(f"    Description: {rule_meta.get('description')}")
            if rule_meta.get('authors'):
                safe_print(f"    Authors: {', '.join(rule_meta.get('authors',[]))}")

        if matches:
            safe_print(f"    Matches ({len(matches)}):")
            match_count = 0
            for addr_hex, match_list in matches.items():
                if not verbose_flag and match_count >=3:
                    safe_print(f"      ... (additional matches for this rule omitted, use --verbose)")
                    break
                safe_print(f"      At Address: {addr_hex}")
                if verbose_flag:
                    for match_idx, match_item in enumerate(match_list):
                        safe_print(f"        Match Detail #{match_idx+1}: Type - {match_item.get('type')}")
                match_count +=1
        else:
            safe_print("    No specific match locations found (possibly meta rule or subscope match).")

        if not verbose_flag and capability_count >= 10:
            safe_print("\n  ... (additional capabilities omitted, use --verbose to see all)")
            break

    if capability_count == 0:
        safe_print("\n  No capabilities detected by capa.")


def _print_rich_header_cli(rich_header_data: Optional[Dict[str, Any]]):
    safe_print("\n--- Rich Header ---")
    if not rich_header_data: safe_print("  No Rich Header found or empty."); return
    safe_print(f"  XOR Key: {rich_header_data.get('key_hex')}")
    safe_print(f"  Checksum (from Rich Header struct): {rich_header_data.get('checksum')}")
    if rich_header_data.get('decoded_values'):
        safe_print("  Decoded Values (CompID / Count):")
        for val_entry in rich_header_data['decoded_values']: safe_print(f"    - ProdID: {val_entry['product_id_hex']} (Dec: {val_entry['product_id_dec']}), Build: {val_entry['build_number']}, Count: {val_entry['count']} (Raw CompID: {val_entry['raw_comp_id']})")
    else: safe_print("  No decoded Rich Header values.")

def _print_coff_symbols_cli(coff_symbols: List[Dict[str, Any]], verbose_flag: bool):
    safe_print("\n--- COFF Symbol Table ---")
    if not coff_symbols: safe_print("  No COFF Symbol Table found or empty."); return
    limit = None if verbose_flag else 50; displayed_count = 0
    safe_print(f"  Total Symbol Records: {len(coff_symbols)}")
    for i,sym_data in enumerate(coff_symbols):
        if limit is not None and displayed_count>=limit: safe_print(f"  ... (omitting remaining {len(coff_symbols)-displayed_count} symbols, use --verbose)");break
        safe_print(f"\n  Symbol {i+1}: {sym_data.get('name_str')}")
        safe_print(f"    Value: {hex(sym_data.get('value',0))}");safe_print(f"    SectionNumber: {sym_data.get('section_number')}")
        safe_print(f"    Type: {hex(sym_data.get('type',0))} ({sym_data.get('type_str')})")
        safe_print(f"    StorageClass: {sym_data.get('storage_class')} ({sym_data.get('storage_class_str')})")
        safe_print(f"    NumberOfAuxSymbols: {sym_data.get('number_of_aux_symbols')}")
        if sym_data.get('auxiliary_symbols'):
            for aux_sym in sym_data['auxiliary_symbols']:
                safe_print(f"    Auxiliary Record ({aux_sym.get('aux_record_index')}): Type: {aux_sym.get('type')}")
                for k,v in aux_sym.items():
                    if k not in['aux_record_index','type']:safe_print(f"        {k}: {v}")
        displayed_count+=1

def _print_pefile_warnings_cli(warnings_list: List[str]):
    safe_print("\n--- PEFile Warnings ---")
    if warnings_list: [safe_print(f"  - {w}") for w in warnings_list]
    else: safe_print("  No warnings from pefile.")

VERBOSE_CLI_OUTPUT_FLAG = False

# --- Main CLI Printing Function ---
def _cli_analyze_and_print_pe(filepath: str, peid_db_path: Optional[str],
                              yara_rules_path: Optional[str],
                              capa_rules_dir: Optional[str],
                              capa_sigs_dir: Optional[str], 
                              verbose: bool,
                              skip_full_peid_scan: bool, peid_scan_all_sigs_heuristically: bool,
                              extract_strings_cli: bool, min_str_len_cli: int,
                              search_strings_cli: Optional[List[str]], strings_limit_cli: int,
                              hexdump_offset_cli: Optional[int], hexdump_length_cli: Optional[int],
                              hexdump_lines_cli: int):
    global PEFILE_VERSION_USED, VERBOSE_CLI_OUTPUT_FLAG
    VERBOSE_CLI_OUTPUT_FLAG = verbose
    if verbose: logger.info(f"Starting CLI analysis for: {filepath}. pefile version: {getattr(pefile,'__version__','unknown')}")
    safe_print(f"[*] Analyzing PE file: {filepath}\n")
    try:
        pe_obj_for_cli = pefile.PE(filepath, fast_load=False)
    except Exception as e: safe_print(f"[!] Error loading PE file for CLI: {e}"); return

    cli_pe_info_dict = _parse_pe_to_dict(pe_obj_for_cli, filepath, peid_db_path, yara_rules_path,
                                         capa_rules_dir,
                                         capa_sigs_dir, 
                                         verbose, skip_full_peid_scan, peid_scan_all_sigs_heuristically)

    _print_file_hashes_cli(cli_pe_info_dict.get('file_hashes',{}))
    _print_dos_header_cli(cli_pe_info_dict.get('dos_header',{}))
    _print_nt_headers_cli(cli_pe_info_dict.get('nt_headers',{}))
    _print_data_directories_cli(cli_pe_info_dict.get('data_directories',[]))
    _print_sections_cli(cli_pe_info_dict.get('sections',[]),pe_obj_for_cli)
    _print_imports_cli(cli_pe_info_dict.get('imports',[]))
    _print_exports_cli(cli_pe_info_dict.get('exports',{}))
    _print_resources_summary_cli(cli_pe_info_dict.get('resources_summary',[]))
    _print_version_info_cli(cli_pe_info_dict.get('version_info',{}))
    _print_digital_signatures_cli(cli_pe_info_dict.get('digital_signature',{}))
    _print_peid_matches_cli(cli_pe_info_dict.get('peid_matches',{}))
    _print_yara_matches_cli(cli_pe_info_dict.get('yara_matches',[]),yara_rules_path)
    _print_capa_analysis_cli(cli_pe_info_dict.get('capa_analysis',{}), verbose)
    _print_rich_header_cli(cli_pe_info_dict.get('rich_header'))

    remaining_keys=["delay_load_imports","tls_info","load_config","com_descriptor","overlay_data","base_relocations","bound_imports","exception_data","checksum_verification"]
    for key in remaining_keys:
        data_item=cli_pe_info_dict.get(key)
        if data_item is not None:
            safe_print(f"\n--- {key.replace('_',' ').title()} ---")
            if isinstance(data_item,list)and data_item:
                for i,item in enumerate(data_item):
                    if isinstance(item,dict):_print_dict_structure_cli(item,indent=1,title=f"Entry {i+1}")
                    else:safe_print(f"  Entry {i+1}: {item}")
            elif isinstance(data_item,dict):_print_dict_structure_cli(data_item,indent=1)
            else:safe_print(f"  {data_item}")
        else:safe_print(f"\n--- {key.replace('_',' ').title()} ---\n  No {key.replace('_',' ')} information found.")

    _print_coff_symbols_cli(cli_pe_info_dict.get('coff_symbols',[]),verbose)
    _print_pefile_warnings_cli(cli_pe_info_dict.get('pefile_warnings',[]))

    if extract_strings_cli:
        safe_print(f"\n--- Extracted Strings (min_length={min_str_len_cli}, limit={strings_limit_cli}) ---")
        extracted=_extract_strings_from_data(pe_obj_for_cli.__data__,min_str_len_cli)
        for i,(offset,s)in enumerate(extracted):
            if i>=strings_limit_cli:safe_print(f"  ... (output limited to {strings_limit_cli} strings)");break
            safe_print(f"  Offset: {hex(offset)}: {s}")
        if not extracted:safe_print("  No strings found matching criteria.")
    if search_strings_cli:
        safe_print(f"\n--- Searched Strings (limit {strings_limit_cli} per term) ---")
        search_res=_search_specific_strings_in_data(pe_obj_for_cli.__data__,search_strings_cli)
        for term,offsets in search_res.items():
            if offsets:
                safe_print(f"  Found '{term}' at offsets (limit {strings_limit_cli} per term shown):")
                for i,offset_val in enumerate(offsets):
                    if i>=strings_limit_cli:safe_print(f"    ... (further occurrences of '{term}' omitted)");break
                    safe_print(f"    - {hex(offset_val)}")
            else:safe_print(f"  String '{term}' not found.")
    if hexdump_offset_cli is not None and hexdump_length_cli is not None:
        safe_print(f"\n--- Hex Dump (Offset: {hex(hexdump_offset_cli)}, Length: {hexdump_length_cli}, Max Lines: {hexdump_lines_cli}) ---")
        try:
            data_chunk=pe_obj_for_cli.__data__[hexdump_offset_cli:hexdump_offset_cli+hexdump_length_cli]
            dump_lines=_format_hex_dump_lines(data_chunk,start_address=hexdump_offset_cli)
            for i,line in enumerate(dump_lines):
                if i>=hexdump_lines_cli:safe_print(f"  ... (output limited to {hexdump_lines_cli} lines)");break
                safe_print(line)
            if not dump_lines:safe_print("  No data to dump or invalid range.")
        except Exception as e:safe_print(f"  Error during hex dump: {e}")
    safe_print("\n[*] CLI Analysis complete.")
    pe_obj_for_cli.close()

# --- MCP Server Setup ---
mcp_server = FastMCP("PEFileAnalyzerMCP", description="MCP Server for PE file analysis, including deobfuscation tools.")
tool_decorator = mcp_server.tool()

# --- MCP Tools ---
@tool_decorator
async def load_and_analyze_pe_file(
    ctx: Context, filepath: str,
    peid_db_path: Optional[str] = None,
    yara_rules_path: Optional[str] = None,
    capa_rules_dir: Optional[str] = None,
    capa_sigs_dir: Optional[str] = None, 
    verbose_mcp_output: bool = False,
    skip_full_peid_scan: bool = False,
    peid_scan_all_sigs_heuristically: bool = False
) -> Dict[str, Any]:
    global ANALYZED_PE_FILE_PATH, ANALYZED_PE_DATA, PEFILE_VERSION_USED, PE_OBJECT_FOR_MCP
    await ctx.info(f"Request to load/analyze PE: {filepath}")
    if not os.path.exists(filepath): raise FileNotFoundError(f"PE file not found: {filepath}")
    if not os.path.isfile(filepath): raise ValueError(f"Path is not a file: {filepath}")

    if peid_db_path and not os.path.exists(peid_db_path):
        await ctx.info(f"PEiD DB '{peid_db_path}' not found. Attempting download...")
        dl_ok = await asyncio.to_thread(ensure_peid_db_exists, PEID_USERDB_URL, peid_db_path, verbose_mcp_output)
        if not dl_ok: await ctx.warning(f"Failed to download PEiD DB to '{peid_db_path}'.")
        else: await ctx.info(f"PEiD DB ensured at '{peid_db_path}'.")

    effective_capa_rules_dir = capa_rules_dir
    if not capa_rules_dir: # If no capa_rules_dir is provided, try to download to default
        default_capa_base = os.path.join(os.getcwd(), CAPA_RULES_DEFAULT_DIR)
        await ctx.info(f"Capa rules directory not specified, attempting default download to '{default_capa_base}'.")
        effective_capa_rules_dir = await asyncio.to_thread(ensure_capa_rules_exist, default_capa_base, CAPA_RULES_ZIP_URL, verbose_mcp_output)
        if not effective_capa_rules_dir:
            await ctx.warning(f"Failed to ensure capa rules at default location. Capa analysis may fail or use limited/no rules.")
        else:
            await ctx.info(f"Capa rules ensured/downloaded to: {effective_capa_rules_dir}")
    # capa_sigs_dir is passed directly; no default download for it.

    try:
        if PE_OBJECT_FOR_MCP: PE_OBJECT_FOR_MCP.close() # Close previously loaded PE object if any
        pe_obj = pefile.PE(filepath, fast_load=False)
        parsed_data = await asyncio.to_thread(
            _parse_pe_to_dict, pe_obj, filepath, peid_db_path, yara_rules_path,
            effective_capa_rules_dir, # Use the potentially downloaded path
            capa_sigs_dir, 
            verbose_mcp_output, skip_full_peid_scan, peid_scan_all_sigs_heuristically
        )
        PE_OBJECT_FOR_MCP = pe_obj; ANALYZED_PE_FILE_PATH = filepath; ANALYZED_PE_DATA = parsed_data
        await ctx.info(f"Successfully loaded/analyzed PE: {filepath}")
        return {"status":"success", "message":f"File '{filepath}' loaded and analyzed.", "filepath":filepath}
    except Exception as e:
        ANALYZED_PE_DATA=None; ANALYZED_PE_FILE_PATH=None
        # Ensure PE_OBJECT_FOR_MCP is also cleared and closed if it was this specific object
        if 'pe_obj' in locals() and PE_OBJECT_FOR_MCP == pe_obj: 
            PE_OBJECT_FOR_MCP.close()
            PE_OBJECT_FOR_MCP = None
        elif PE_OBJECT_FOR_MCP and not 'pe_obj' in locals(): # Should not happen if logic is correct
            PE_OBJECT_FOR_MCP.close()
            PE_OBJECT_FOR_MCP = None

        await ctx.error(f"Error analyzing PE '{filepath}': {str(e)}"); 
        logger.error(f"MCP: Error analyzing PE '{filepath}': {str(e)}", exc_info=True)
        # Re-raise as a more generic runtime error for MCP to handle
        raise RuntimeError(f"Failed to analyze PE file '{filepath}': {str(e)}") from e

@tool_decorator
async def get_analyzed_file_summary(ctx: Context, limit: Optional[int] = None) -> Dict[str, Any]:
    await ctx.info(f"Request for analyzed file summary. Limit: {limit}")
    if ANALYZED_PE_DATA is None or ANALYZED_PE_FILE_PATH is None:
        raise RuntimeError("No PE file loaded. Call 'load_and_analyze_pe_file' first.")
    summary = {
        "filepath":ANALYZED_PE_FILE_PATH,"pefile_version_used":PEFILE_VERSION_USED,
        "has_dos_header":'dos_header'in ANALYZED_PE_DATA and ANALYZED_PE_DATA['dos_header']is not None and"error"not in ANALYZED_PE_DATA['dos_header'],
        "has_nt_headers":'nt_headers'in ANALYZED_PE_DATA and ANALYZED_PE_DATA['nt_headers']is not None and"error"not in ANALYZED_PE_DATA['nt_headers'],
        "section_count":len(ANALYZED_PE_DATA.get('sections',[])),
        "import_dll_count":len(ANALYZED_PE_DATA.get('imports',[])),
        "export_symbol_count":len(ANALYZED_PE_DATA.get('exports',{}).get('symbols',[])),
        "peid_ep_match_count":len(ANALYZED_PE_DATA.get('peid_matches',{}).get('ep_matches',[])),
        "peid_heuristic_match_count":len(ANALYZED_PE_DATA.get('peid_matches',{}).get('heuristic_matches',[])),
        "yara_match_count":len([m for m in ANALYZED_PE_DATA.get('yara_matches',[])if"error"not in m]),
        "capa_status": ANALYZED_PE_DATA.get('capa_analysis',{}).get('status',"Not run"),
        "capa_capability_count": len(ANALYZED_PE_DATA.get('capa_analysis',{}).get('results',{}).get('rules',{})) if ANALYZED_PE_DATA.get('capa_analysis',{}).get('status')=="Analysis complete" else 0,
        "has_embedded_signature":ANALYZED_PE_DATA.get('digital_signature',{}).get('embedded_signature_present',False)
    }
    await ctx.info(f"Summary for {ANALYZED_PE_FILE_PATH} provided.")
    return summary

@tool_decorator
async def get_full_analysis_results(ctx: Context, limit: Optional[int] = None) -> Dict[str, Any]:
    await ctx.info(f"Request for full PE analysis. Limit: {limit}")
    if ANALYZED_PE_DATA is None: raise RuntimeError("No PE file loaded.")
    if limit is not None and isinstance(ANALYZED_PE_DATA,dict):
        return dict(list(ANALYZED_PE_DATA.items())[:limit])
    return ANALYZED_PE_DATA

def _create_mcp_tool_for_key(key_name: str, tool_description: str):
    async def _tool_func(ctx: Context, limit: Optional[int] = None) -> Any:
        await ctx.info(f"Request for '{key_name}'. Limit: {limit}")
        if ANALYZED_PE_DATA is None: raise RuntimeError(f"No PE file loaded to get '{key_name}'.")
        data_to_return = ANALYZED_PE_DATA.get(key_name)
        if data_to_return is None: await ctx.warning(f"Data for '{key_name}' not found. Returning empty."); return {}
        if limit is not None:
            if isinstance(data_to_return,list): return data_to_return[:limit]
            elif isinstance(data_to_return,dict)and key_name!="nt_headers": # Avoid limiting the complex NT_Headers structure unintentionally
                try: return dict(list(data_to_return.items())[:limit])
                except: await ctx.warning(f"Could not limit dict for '{key_name}'. Returning full.")
            else: await ctx.warning(f"Limit not applicable for '{key_name}' type ({type(data_to_return).__name__}).")
        return data_to_return
    _tool_func.__name__ = f"get_{key_name}_info"; _tool_func.__doc__ = tool_description + " Optionally use 'limit' (int) for lists/dicts."
    return tool_decorator(_tool_func)

TOOL_DEFINITIONS = {
    "file_hashes":"File hashes.","dos_header":"DOS_HEADER.","nt_headers":"NT_HEADERS.","data_directories":"Data Directories.",
    "sections":"PE sections.","imports":"Imported DLLs/symbols.","exports":"Exported symbols.","resources_summary":"Resource summary.",
    "version_info":"Version Information.","debug_info":"Debug directory.","digital_signature":"Digital signature.",
    "peid_matches":"PEiD matches.","yara_matches":"YARA matches.","capa_analysis":"Capa capability analysis results.",
    "rich_header":"Rich Header.","delay_load_imports":"Delay-Load Imports.","tls_info":"TLS Directory.",
    "load_config":"Load Configuration.","com_descriptor":".NET COM Descriptor.","overlay_data":"Overlay data.",
    "base_relocations":"Base Relocations.","bound_imports":"Bound Imports.","exception_data":"Exception Data.",
    "coff_symbols":"COFF Symbols.","checksum_verification":"PE checksum.","pefile_warnings":"pefile warnings."
}
for key, desc in TOOL_DEFINITIONS.items(): globals()[f"get_{key}_info"] = _create_mcp_tool_for_key(key, desc)

@tool_decorator
async def extract_strings_from_binary(ctx: Context, min_length: int = 5, limit: Optional[int] = 1000) -> List[Dict[str, Any]]:
    await ctx.info(f"Request to extract strings. Min_len: {min_length}, Limit: {limit}")
    if PE_OBJECT_FOR_MCP is None: raise RuntimeError("No PE file loaded. Call 'load_and_analyze_pe_file' first.")
    try:
        file_data=PE_OBJECT_FOR_MCP.__data__; found=_extract_strings_from_data(file_data,min_length)
        results=[{"offset":hex(offset),"string":s}for offset,s in found]
        return results[:limit] if limit is not None and len(results)>limit else results
    except Exception as e: await ctx.error(f"String extraction error: {e}"); raise RuntimeError(f"Failed: {e}")from e

@tool_decorator
async def search_for_specific_strings(ctx: Context, search_terms: List[str], limit: Optional[int] = 100) -> Dict[str, List[str]]:
    await ctx.info(f"Request to search strings: {search_terms}. Limit: {limit}")
    if PE_OBJECT_FOR_MCP is None: raise RuntimeError("No PE file loaded. Call 'load_and_analyze_pe_file' first.")
    if not search_terms or not isinstance(search_terms,list): raise ValueError("search_terms must be non-empty list.")
    try:
        file_data=PE_OBJECT_FOR_MCP.__data__; found=_search_specific_strings_in_data(file_data,search_terms)
        limited_res:Dict[str,List[str]]={};total_found=0
        for term,offsets in found.items():
            if not offsets:continue
            can_add=(limit-total_found)if limit is not None else len(offsets)
            if can_add<=0 and limit is not None:break
            limited_offsets=[hex(off)for off in offsets[:can_add]]
            if limited_offsets:limited_res[term]=limited_offsets;total_found+=len(limited_offsets)
        return limited_res
    except Exception as e: await ctx.error(f"String search error: {e}"); raise RuntimeError(f"Failed: {e}")from e

@tool_decorator
async def get_hex_dump(ctx: Context, start_offset: int, length: int, bytes_per_line: Optional[int]=16, limit_lines: Optional[int]=256) -> List[str]:
    await ctx.info(f"Hex dump: Offset {hex(start_offset)}, Len {length}, BPL {bytes_per_line}, LimitLines {limit_lines}")
    if PE_OBJECT_FOR_MCP is None: raise RuntimeError("No PE file loaded. Call 'load_and_analyze_pe_file' first.")
    if not isinstance(start_offset,int)or start_offset<0:raise ValueError("start_offset must be non-negative int.")
    if not isinstance(length,int)or length<=0:raise ValueError("length must be positive int.")
    bpl=bytes_per_line if bytes_per_line is not None and isinstance(bytes_per_line,int)and bytes_per_line>0 else 16
    ll=limit_lines if limit_lines is not None and isinstance(limit_lines,int)and limit_lines>0 else 256
    try:
        file_data=PE_OBJECT_FOR_MCP.__data__
        if start_offset>=len(file_data):return["Error: Start offset beyond file size."]
        actual_len=min(length,len(file_data)-start_offset)
        if actual_len<=0:return["Error: Calculated length is zero or negative."]
        data_chunk=file_data[start_offset:start_offset+actual_len]
        hex_lines=await asyncio.to_thread(_format_hex_dump_lines,data_chunk,start_offset,bpl)
        return hex_lines[:ll] if ll is not None and len(hex_lines)>ll else hex_lines
    except Exception as e:await ctx.error(f"Hex dump error: {e}");raise RuntimeError(f"Failed: {e}")from e

@tool_decorator
async def get_current_datetime(ctx: Context, limit: Optional[int]=None)->Dict[str,str]: # limit is unused but kept for signature consistency if desired
    await ctx.info("Request for current datetime.")
    now_utc=datetime.datetime.now(datetime.timezone.utc);now_local=datetime.datetime.now().astimezone()
    return{"utc_datetime":now_utc.isoformat(),"local_datetime":now_local.isoformat(),"local_timezone_name":str(now_local.tzinfo)}


# --- General Purpose MCP Deobfuscation Tools ---
@tool_decorator
async def deobfuscate_base64(ctx: Context, hex_string: str) -> Optional[str]:
    """
    Deobfuscates a hex-encoded string that represents base64 encoded data.
    The input 'hex_string' should be the hex representation of a base64 string.
    Example: If original data is "test", base64 is "dGVzdA==",
    hex of "dGVzdA==" is "6447567a64413d3d". This function takes "6447567a64413d3d".
    """
    await ctx.info(f"Attempting to deobfuscate Base64 from hex string: {hex_string[:60]}...")
    try:
        base64_encoded_bytes = bytes.fromhex(hex_string)
        decoded_payload_bytes = codecs.decode(base64_encoded_bytes, 'base64')
        result = decoded_payload_bytes.decode('utf-8', 'ignore')
        await ctx.info("Base64 deobfuscation successful.")
        return result
    except ValueError as e: # Handles errors from bytes.fromhex
        await ctx.error(f"Invalid hex string provided for Base64 deobfuscation: {str(e)}")
        logger.warning(f"MCP: Invalid hex string for Base64 deobfuscation: {hex_string[:60]}... - {str(e)}")
        return None # Or raise ValueError(f"Invalid hex string: {str(e)}")
    except Exception as e:
        await ctx.error(f"Base64 deobfuscation error: {str(e)}")
        logger.error(f"MCP: Base64 deobfuscation error for {hex_string[:60]}... - {str(e)}", exc_info=True)
        return None # Or raise RuntimeError(f"Base64 deobfuscation failed: {str(e)}")

@tool_decorator
async def deobfuscate_xor_single_byte(ctx: Context, data_hex: str, key: int) -> Dict[str, Optional[str]]:
    """
    Deobfuscates a hex-encoded data string using a single byte XOR key.
    Returns a dictionary with 'deobfuscated_hex' and 'deobfuscated_printable_string'.
    """
    await ctx.info(f"Attempting to deobfuscate hex data '{data_hex[:60]}...' with XOR key: {key:#04x} ({key})")
    if not (0 <= key <= 255):
        await ctx.error(f"XOR key must be an integer between 0 and 255. Received: {key}")
        logger.warning(f"MCP: Invalid XOR key {key} requested.")
        raise ValueError("XOR key must be an integer between 0 and 255.")

    try:
        data_bytes = bytes.fromhex(data_hex)
        deobfuscated_bytes = bytes([b ^ key for b in data_bytes])
        deobfuscated_hex_output = deobfuscated_bytes.hex()
        
        printable_representation = ""
        try:
            # Attempt to decode as UTF-8, then Latin-1, then do a safe representation
            try:
                printable_representation = deobfuscated_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    printable_representation = deobfuscated_bytes.decode('latin-1')
                except UnicodeDecodeError: # Fallback for truly binary data
                    printable_representation = "".join(chr(b) if 32 <= b <= 126 or b in [9,10,13] else '.' for b in deobfuscated_bytes)
        except Exception as e_decode: # Catch any error during string representation attempt
            logger.warning(f"MCP: Error creating printable string for XOR result (key {key}): {e_decode}")
            printable_representation = "[Decoding error for printable string]"

        await ctx.info("XOR deobfuscation successful.")
        return {
            "deobfuscated_hex": deobfuscated_hex_output,
            "deobfuscated_printable_string": printable_representation
        }
    except ValueError as e: # Specifically for bytes.fromhex
        await ctx.error(f"Invalid hex string provided for data_hex in XOR deobfuscation: {str(e)}")
        logger.warning(f"MCP: Invalid hex string for XOR data_hex: {data_hex[:60]}... - {str(e)}")
        raise 
    except Exception as e:
        await ctx.error(f"XOR deobfuscation error: {str(e)}")
        logger.error(f"MCP: XOR deobfuscation error for data_hex {data_hex[:60]}..., key {key} - {str(e)}", exc_info=True)
        raise

@tool_decorator
async def is_mostly_printable_ascii(ctx: Context, text_input: str, threshold: float = 0.8) -> bool:
    """
    Checks if the given string 'text_input' consists mostly of printable ASCII characters.
    Printable includes standard ASCII (space to ~) and common whitespace (newline, tab, CR).
    """
    await ctx.info(f"Checking if string is mostly printable ASCII. Threshold: {threshold}, String length: {len(text_input)}")
    if not text_input: # Check for empty string
        await ctx.info("Input string for printable check is empty, returning False.")
        return False
    
    if not (0.0 <= threshold <= 1.0):
        await ctx.error(f"Threshold for printable check must be between 0.0 and 1.0. Received: {threshold}")
        logger.warning(f"MCP: Invalid threshold {threshold} for printable check.")
        raise ValueError("Threshold must be between 0.0 and 1.0.")

    # This logic is from the original _is_mostly_printable_ascii
    printable_char_in_string_count = sum(1 for char_in_s in text_input
                                         if (' ' <= char_in_s <= '~') or char_in_s in '\n\r\t')
    
    # len(text_input) will be 0 if text_input is empty, which is handled by the first 'if'
    ratio = printable_char_in_string_count / len(text_input)
    result = ratio >= threshold
    await ctx.info(f"Printable character ratio: {ratio:.2f}. Result: {result}")
    return result

# --- Main Execution Block ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Comprehensive PE File Analyzer.",formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--input-file", type=str, required=True, help="REQUIRED: Path to the PE file.")
    parser.add_argument("-d", "--db", dest="peid_db", default=None, help="Path to PEiD userdb.txt. Downloads if not found.")
    parser.add_argument("-y", "--yara-rules", dest="yara_rules", default=None, help="Path to YARA rule file or directory.")
    parser.add_argument("--capa-rules-dir", default=None, help=f"Directory containing capa rule files. If not provided or empty, attempts download to '{os.path.join(os.getcwd(), CAPA_RULES_DEFAULT_DIR, CAPA_RULES_SUBDIR_NAME)}'.")
    parser.add_argument("--capa-sigs-dir", default=None, help="Directory containing capa library identification signature files (e.g., sigs/*.sig). Optional.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    parser.add_argument("--skip-full-peid-scan",action="store_true",help="Skip full PEiD scan.")
    parser.add_argument("--psah","--peid-scan-all-sigs-heuristically",action="store_true",dest="peid_scan_all_sigs_heuristically",help="Full heuristic PEiD scan with ALL signatures.")
    cli_group=parser.add_argument_group('CLI Mode Specific Options')
    cli_group.add_argument("--extract-strings",action="store_true",help="Extract strings.")
    cli_group.add_argument("--min-str-len",type=int,default=5,help="Min length for extracted strings (def:5).")
    cli_group.add_argument("--search-string",action="append",help="String to search for (multiple allowed).")
    cli_group.add_argument("--strings-limit",type=int,default=100,help="Limit for string results (def:100).")
    cli_group.add_argument("--hexdump-offset",type=lambda x:int(x,0),help="Hex dump start offset (e.g. 0x1000).")
    cli_group.add_argument("--hexdump-length",type=int,help="Hex dump length.")
    cli_group.add_argument("--hexdump-lines",type=int,default=16,help="Max hex dump lines (def:16).")
    mcp_group=parser.add_argument_group('MCP Server Mode Specific Options')
    mcp_group.add_argument("--mcp-server",action="store_true",help="Run in MCP server mode.")
    mcp_group.add_argument("--mcp-host",type=str,default="127.0.0.1",help="MCP server host (def:127.0.0.1).")
    mcp_group.add_argument("--mcp-port",type=int,default=8082,help="MCP server port (def:8082).")
    mcp_group.add_argument("--mcp-transport",type=str,default="stdio",choices=["stdio","sse"],help="MCP transport (def:stdio).")
    args=parser.parse_args()
    
    # Call dependency check for optional libraries (pefile is checked at startup)
    check_and_install_dependencies(args.mcp_server) 

    log_level=logging.DEBUG if args.verbose else logging.INFO;logger.setLevel(log_level)
    logging.getLogger('mcp').setLevel(log_level) # Set MCP library logging level
    if args.mcp_transport=='sse': # Adjust Uvicorn logging for SSE transport
        logging.getLogger('uvicorn').setLevel(log_level)
        logging.getLogger('uvicorn.error').setLevel(log_level)
        logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.verbose else logging.DEBUG)

    cli_capa_rules_path_to_use = args.capa_rules_dir
    # For CLI mode, if capa rules dir is not provided or invalid, attempt download
    if not args.mcp_server and (not cli_capa_rules_path_to_use or not os.path.isdir(cli_capa_rules_path_to_use) or not os.listdir(cli_capa_rules_path_to_use)):
        if CAPA_AVAILABLE: # Only attempt download if capa library itself is present
            logger.info(f"CLI Mode: Capa rules dir '{args.capa_rules_dir}' not valid/provided. Attempting download to default.")
            default_capa_base_cli = os.path.join(os.getcwd(), CAPA_RULES_DEFAULT_DIR)
            cli_capa_rules_path_to_use = ensure_capa_rules_exist(default_capa_base_cli, CAPA_RULES_ZIP_URL, args.verbose)
            if not cli_capa_rules_path_to_use:
                logger.error("CLI Mode: Failed to ensure capa rules. Capa analysis will be skipped or may fail.")
            else:
                logger.info(f"CLI Mode: Using capa rules from downloaded location: {cli_capa_rules_path_to_use}")
        else: # Capa library not available, so don't bother with rules
            logger.warning("CLI Mode: Capa library not available, capa rule download/check skipped.")
            cli_capa_rules_path_to_use = None # Ensure it's None if capa isn't available

    cli_capa_sigs_path_to_use = args.capa_sigs_dir # For CLI mode, directly use the provided path

    if args.mcp_server:
        if not MCP_SDK_AVAILABLE:
            logger.critical("MCP SDK ('modelcontextprotocol') not available. Cannot start MCP server. Please install it (e.g., 'pip install \"mcp[cli]\"') and re-run.");
            sys.exit(1)
            
        logger.info(f"MCP Server: Pre-loading PE file for analysis: {args.input_file}")
        try:
            # Pre-load and analyze the PE file for MCP mode
            # Note: ensure_capa_rules_exist might be called again inside load_and_analyze_pe_file if args.capa_rules_dir is None
            # This is acceptable as it checks for existence first.
            PE_OBJECT_FOR_MCP = pefile.PE(args.input_file, fast_load=False) 
            ANALYZED_PE_FILE_PATH = args.input_file
            
            # Determine capa rules path for MCP pre-load
            mcp_preload_capa_rules_dir = args.capa_rules_dir
            if not mcp_preload_capa_rules_dir: # If not specified, ensure_capa_rules_exist will be called by load_and_analyze_pe_file
                 pass # It will be handled by load_and_analyze_pe_file's logic

            ANALYZED_PE_DATA = _parse_pe_to_dict(
                PE_OBJECT_FOR_MCP, args.input_file, args.peid_db, args.yara_rules,
                mcp_preload_capa_rules_dir, # Pass the user-specified or None (to trigger download in _parse_pe_to_dict via load_and_analyze_pe_file)
                args.capa_sigs_dir, # Pass user-specified sigs dir
                args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically
            )
            logger.info(f"MCP: Successfully pre-loaded and analyzed: {args.input_file}")
        except Exception as e:
            logger.critical(f"MCP: Failed to pre-load/analyze PE file '{args.input_file}': {str(e)}", exc_info=True)
            if PE_OBJECT_FOR_MCP:
                PE_OBJECT_FOR_MCP.close()
            sys.exit(1)
            
        if args.mcp_transport=="sse":
            mcp_server.settings.host=args.mcp_host
            mcp_server.settings.port=args.mcp_port
            mcp_server.settings.log_level=logging.getLevelName(log_level).lower()
            logger.info(f"Starting MCP server (SSE) on http://{mcp_server.settings.host}:{mcp_server.settings.port}")
        else:
            logger.info("Starting MCP server (stdio).")
        
        server_exc=None
        try:
            mcp_server.run(transport=args.mcp_transport)
        except KeyboardInterrupt:
            logger.info("MCP Server stopped by user.")
        except Exception as e:
            logger.critical(f"MCP Server encountered an unhandled error: {str(e)}", exc_info=True)
            server_exc=e
        finally:
            if PE_OBJECT_FOR_MCP:
                PE_OBJECT_FOR_MCP.close()
                logger.info("MCP: Closed pre-loaded PE object.")
            sys.exit(1 if server_exc else 0)
    else: # CLI Mode
        _cli_analyze_and_print_pe(
            args.input_file, args.peid_db, args.yara_rules,
            cli_capa_rules_path_to_use, # Use the resolved capa rules path for CLI
            cli_capa_sigs_path_to_use,  # Use the resolved capa sigs path for CLI
            args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically,
            args.extract_strings, args.min_str_len, args.search_string, args.strings_limit,
            args.hexdump_offset, args.hexdump_length, args.hexdump_lines
        )
    sys.exit(0)

