#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""
Comprehensive PE File Analyzer (Refactored with Integrated ssdeep, capa, and FLOSS)

This script provides extensive analysis of Portable Executable (PE) files.
It can operate in two modes:
1. CLI Mode: Analyzes a PE file and prints a detailed report to the console.
   Supports PEiD-like signature scanning, YARA scanning, capa capability detection,
   FLOSS string extraction (static, stack, tight, decoded),
   general string extraction/searching, and hex dumping.
2. MCP Server Mode: Runs as a Model-Context-Protocol (MCP) server.
   When starting in MCP server mode, it pre-analyzes a single PE file specified
   at startup via --input-file. All MCP tools then operate on this pre-loaded file's data.
   A tool is provided to re-trigger analysis on this pre-loaded file.

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
  - `flare-floss` (FLOSS) for advanced string extraction.
  - `mcp` for MCP server functionality.
- Includes integrated pure-Python ssdeep (ssdeep) for fuzzy hashing.
- Automatic download and management of capa rules.
- Support for capa library identification signatures.
- Exposes general deobfuscation utilities (base64, XOR, printable check) via MCP.

Simplified MCP mode to analyze only the --input-file provided at server startup.
The load_and_analyze_pe_file tool is repurposed to re-analyze the pre-loaded file.
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
import io # For BytesIO
import asyncio # For asyncio.to_thread
import importlib.util # For checking module availability
import subprocess # For calling pip
import mmap # Added for handling mmap objects in ssdeep
import zipfile # For extracting capa rules
import shutil # For removing directories
import collections
import copy
import re # For regex in the new tool
import base64 # For base64 and base32 decoding in the new tool
import codecs # For existing deobfuscate_base64 tool and now for general decoding
import urllib.parse # For URL decoding
import binascii # Added to handle potential errors from codecs.decode

from pathlib import Path
import copy # For deepcopy in MCP tool limiting

# Crucial: Import typing early, as it's used for global type hints and throughout the script
from typing import Dict, Any, Optional, List, Tuple, Set, Union, Type # Added Type for FLOSS

# --- Ensure pefile is available (Critical Dependency) ---
try:
    import pefile
except ImportError:
    print("[!] CRITICAL ERROR: The 'pefile' library is not found.", file=sys.stderr)
    print("[!] This library is essential for the script to function.", file=sys.stderr)
    if not sys.stdin.isatty():
        print("[!] Non-interactive environment. Please install 'pefile' manually (e.g., 'pip install pefile') and re-run the script.", file=sys.stderr)
        sys.exit(1)
    else:
        try:
            answer = input("Do you want to attempt to install 'pefile' now? (yes/no): ").strip().lower()
            if answer == 'yes' or answer == 'y':
                print("[*] Attempting to install 'pefile' (pip install pefile)...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile"])
                    print("[*] 'pefile' installed successfully. Please re-run the script for the changes to take effect.")
                    sys.exit(0)
                except subprocess.CalledProcessError as e_pip:
                    print(f"[!] Error installing 'pefile' via pip: {e_pip}", file=sys.stderr)
                    print("[!] Please install 'pefile' manually (e.g., 'pip install pefile') and re-run.", file=sys.stderr)
                    sys.exit(1)
                except FileNotFoundError:
                    print("[!] Error: 'pip' command or Python executable not found. Is Python and pip installed correctly and in PATH?", file=sys.stderr)
                    print("[!] Please install 'pefile' manually (e.g., 'pip install pefile') and re-run.", file=sys.stderr)
                    sys.exit(1)
            else:
                print("[!] 'pefile' was not installed. The script cannot continue. Exiting.")
                sys.exit(1)
        except EOFError:
            print("[!] No input received for the installation prompt. Please install 'pefile' manually and re-run.", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Installation of 'pefile' cancelled by user. This library is required. Exiting.", file=sys.stderr)
            sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent

# --- VirusTotal API Configuration ---
VT_API_KEY = os.getenv("VT_API_KEY") # Your VirusTotal API Key
VT_API_URL_FILE_REPORT = "https://www.virustotal.com/api/v3/files/"

class SSDeep:
    BLOCKSIZE_MIN = 3
    SPAMSUM_LENGTH = 64
    STREAM_BUFF_SIZE = 8192
    HASH_PRIME = 0x01000193
    HASH_INIT = 0x28021967
    ROLL_WINDOW = 7
    B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    class _RollState(object):
        ROLL_WINDOW = 7

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
        roll_h3_val = int()
        roll_n = int()
        block_size = int()
        hash_string1 = str()
        hash_string2 = str()
        block_hash1 = int(self.HASH_INIT)
        block_hash2 = int(self.HASH_INIT)

        bs = self.BLOCKSIZE_MIN
        if slen > 0:
            while (bs * self.SPAMSUM_LENGTH) < slen:
                bs = bs * 2
        block_size = bs

        while True:
            stream.seek(0)
            roll_h1 = roll_h2 = roll_h3_val = 0
            roll_n = 0
            roll_win = bytearray(self.ROLL_WINDOW)
            block_hash1 = self.HASH_INIT
            block_hash2 = self.HASH_INIT
            hash_string1 = ""
            hash_string2 = ""

            buf = stream.read(self.STREAM_BUFF_SIZE)
            while buf:
                for b_val in buf:
                    block_hash1 = ((block_hash1 * self.HASH_PRIME) & 0xFFFFFFFF) ^ b_val
                    block_hash2 = ((block_hash2 * self.HASH_PRIME) & 0xFFFFFFFF) ^ b_val

                    roll_h2 = roll_h2 - roll_h1 + (self.ROLL_WINDOW * b_val)
                    roll_h1 = roll_h1 + b_val - roll_win[roll_n % self.ROLL_WINDOW]
                    roll_win[roll_n % self.ROLL_WINDOW] = b_val
                    roll_n += 1
                    roll_h3_val = (roll_h3_val << 5) & 0xFFFFFFFF
                    roll_h3_val ^= b_val

                    rh = roll_h1 + roll_h2 + roll_h3_val

                    if (rh % block_size) == (block_size - 1):
                        if len(hash_string1) < (self.SPAMSUM_LENGTH - 1):
                            hash_string1 += self.B64[block_hash1 % 64]
                            block_hash1 = self.HASH_INIT
                        if (rh % (block_size * 2)) == ((block_size * 2) - 1):
                            if len(hash_string2) < ((self.SPAMSUM_LENGTH // 2) - 1):
                                hash_string2 += self.B64[block_hash2 % 64]
                                block_hash2 = self.HASH_INIT
                buf = stream.read(self.STREAM_BUFF_SIZE)

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
            pass

        lev_score = self._levenshtein(s1, s2)
        sum_len = len(s1) + len(s2)
        if sum_len == 0:
            return 100

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
        else:
            score = 0
        return score

    def _strip_sequences(self, s):
        if len(s) <= 3: return s
        r = s[:3]
        for i in range(3, len(s)):
            if (s[i] != s[i-1] or s[i] != s[i-2] or s[i] != s[i-3]):
                r += s[i]
        return r

    def compare(self, hash1_str, hash2_str):
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

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

try:
    from thefuzz import fuzz
    THEFUZZ_AVAILABLE = True
except ImportError as e:
    THEFUZZ_AVAILABLE = False
    THEFUZZ_IMPORT_ERROR = str(e)

# --- START MODIFIED CAPA IMPORT SECTION ---
class CapaError(Exception):
    def __init__(self, msg="Generic Capa Error", status_code=None):
        super().__init__(msg)
        self.status_code = status_code

class InvalidRule(CapaError): pass
class RulesAccessError(CapaError): pass
class FreezingError(CapaError): pass

CAPA_AVAILABLE = False
CAPA_IMPORT_ERROR = None

# --- NEW: Constants for MCP Response Size Limit ---
MAX_MCP_RESPONSE_SIZE_KB = 64
MAX_MCP_RESPONSE_SIZE_BYTES = MAX_MCP_RESPONSE_SIZE_KB * 1024

try:
    import capa
    import capa.main
    import capa.rules
    import capa.loader
    import capa.capabilities.common
    import capa.render.result_document as rd
    import capa.engine
    import capa.render.json as capa_json_render
    import capa.features.extractors.pefile as capa_pefile_extractor
    import capa.features.common

    from capa.exceptions import (
        InvalidArgument,
        EmptyReportError,
        UnsupportedOSError,
        UnsupportedArchError,
        UnsupportedFormatError,
        UnsupportedRuntimeError,
    )

    CAPA_AVAILABLE = True
    CAPA_IMPORT_ERROR = None
    logger.info("Successfully imported capa modules and new-style exceptions. PeMCP.py will attempt to use this capa API.")

except ImportError as e:
    CAPA_IMPORT_ERROR = str(e)
    CAPA_AVAILABLE = False
    logger.warning(f"Failed to import necessary capa modules: {CAPA_IMPORT_ERROR}. Capa analysis will be skipped.")
except Exception as e_generic:
    CAPA_IMPORT_ERROR = f"An unexpected error occurred during capa import attempts: {str(e_generic)}"
    CAPA_AVAILABLE = False
    logger.error(CAPA_IMPORT_ERROR, exc_info=True)
# --- END MODIFIED CAPA IMPORT SECTION ---

# --- START FLOSS IMPORT SECTION ---
# Fallback values for FLOSS components if the library is not fully available
MIN_STR_LEN_FALLBACK_FLOSS = 4
class DebugLevelFallbackFloss: NONE, DEFAULT, TRACE, SUPERTRACE = 0, 1, 2, 3
class StringTypeFallbackFloss: STATIC, STACK, TIGHT, DECODED = "static", "stack", "tight", "decoded"

# Global variables to hold actual FLOSS components or fallbacks
FLOSS_MIN_LENGTH_DEFAULT = MIN_STR_LEN_FALLBACK_FLOSS
Actual_DebugLevel_Floss: Type = DebugLevelFallbackFloss # Will hold floss.logging_.DebugLevel or fallback
Actual_StringType_Floss: Type = StringTypeFallbackFloss # Will hold floss.main.StringType or fallback
Floss_ColorFormatter_Class: Type = logging.Formatter # Will hold floss.logging_.ColorFormatter or fallback
FLOSS_TRACE_LEVEL_CONST = logging.DEBUG # Fallback for floss.logging_.TRACE

# Flags to track FLOSS availability
FLOSS_SETUP_OK = False # Basic components like logging, main, const
FLOSS_ANALYSIS_OK = False # Analysis functions like string extractors, vivisect utils
FLOSS_AVAILABLE = False # True if both SETUP and ANALYSIS are OK
FLOSS_IMPORT_ERROR_SETUP = None
FLOSS_IMPORT_ERROR_ANALYSIS = None

# Attempt to import basic FLOSS components
try:
    import floss.logging_ as floss_logging
    import floss.main as floss_main
    from floss.const import MIN_STRING_LENGTH as FLOSS_MIN_LENGTH_FROM_LIB

    Actual_DebugLevel_Floss = floss_logging.DebugLevel
    Actual_StringType_Floss = floss_main.StringType
    FLOSS_MIN_LENGTH_DEFAULT = FLOSS_MIN_LENGTH_FROM_LIB
    Floss_ColorFormatter_Class = floss_logging.ColorFormatter
    FLOSS_TRACE_LEVEL_CONST = floss_logging.TRACE
    FLOSS_SETUP_OK = True
    logger.info("Successfully imported basic FLOSS components (logging, main, const).")
except ImportError as e_floss_setup:
    FLOSS_IMPORT_ERROR_SETUP = str(e_floss_setup)
    logger.warning(f"Warning: Error importing basic FLOSS components (logging, main, const): {e_floss_setup}")
    logger.warning("Using fallback values for FLOSS script setup. Full FLOSS functionality may be impaired.")
except Exception as e_floss_setup_generic:
    FLOSS_IMPORT_ERROR_SETUP = f"Generic error during FLOSS setup import: {str(e_floss_setup_generic)}"
    logger.error(f"FLOSS setup import failed unexpectedly: {e_floss_setup_generic}", exc_info=True)


# Attempt to import FLOSS analysis functions if setup was OK
if FLOSS_SETUP_OK:
    try:
        import viv_utils # Dependency for FLOSS analysis
        from vivisect import VivWorkspace # Dependency for FLOSS analysis
        from floss.utils import get_static_strings, set_vivisect_log_level, get_imagebase
        from floss.identify import (
            find_decoding_function_features, get_top_functions, get_function_fvas,
            get_tight_function_fvas, append_unique, get_functions_with_tightloops
        )
        from floss.stackstrings import extract_stackstrings
        from floss.tightstrings import extract_tightstrings
        from floss.string_decoder import decode_strings
        # MODIFIED IMPORT: Only import ResultDocument, Metadata, and Analysis from floss.results
        # The specific string types like StringTypeOffset are not meant for direct import.
        from floss.results import ResultDocument, Metadata as FlossMetadata, Analysis as FlossAnalysis
        FLOSS_ANALYSIS_OK = True
        logger.info("Successfully imported FLOSS analysis functions and vivisect/viv_utils.")
    except ImportError as e_floss_analysis:
        FLOSS_IMPORT_ERROR_ANALYSIS = str(e_floss_analysis)
        logger.error(f"Error importing FLOSS analysis functions (or their dependencies like vivisect): {e_floss_analysis}")
        FLOSS_ANALYSIS_OK = False
    except Exception as e_floss_analysis_generic:
        FLOSS_IMPORT_ERROR_ANALYSIS = f"Generic error during FLOSS analysis import: {str(e_floss_analysis_generic)}"
        logger.error(f"FLOSS analysis import failed unexpectedly: {e_floss_analysis_generic}", exc_info=True)
        FLOSS_ANALYSIS_OK = False
else:
    logger.warning("Skipping import of FLOSS analysis functions due to earlier FLOSS setup import errors.")

FLOSS_AVAILABLE = FLOSS_SETUP_OK and FLOSS_ANALYSIS_OK

# List of FLOSS-related loggers to configure
FLOSS_LOGGERS_LIST = [
    "floss", "floss.utils", "floss.identify", "floss.stackstrings",
    "floss.tightstrings", "floss.string_decoder", "EmulatorDriver", "Monitor",
    "envi", "envi.codeflow", "vtrace", "vtrace.platforms.win32",
    "vivisect", "vivisect.parsers.pe", "viv_utils.emulator_drivers",
]
# --- END FLOSS IMPORT SECTION ---

try:
    # StringSifter imports its own dependencies
    import stringsifter.lib.util as sifter_util
    import joblib
    import numpy
    STRINGSIFTER_AVAILABLE = True
except ImportError as e:
    STRINGSIFTER_AVAILABLE = False
    STRINGSIFTER_IMPORT_ERROR = str(e)

MCP_SDK_AVAILABLE = False
try:
    from mcp.server.fastmcp import FastMCP, Context
    MCP_SDK_AVAILABLE = True
except ImportError:
    class MockSettings: host = "127.0.0.1"; port = 8081; log_level = "INFO" # Port was 8081, changed to 8082 later
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
PE_OBJECT_FOR_MCP: Optional[pefile.PE] = None # This will hold the single pre-loaded PE object

# --- Constants ---
PEID_USERDB_URL = "https://raw.githubusercontent.com/JameZUK/PeMCP/refs/heads/main/userdb.txt"
DEFAULT_PEID_DB_PATH = SCRIPT_DIR / "userdb.txt"

CAPA_RULES_ZIP_URL = "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.1.0.zip" # Example, use a recent stable tag
CAPA_RULES_DEFAULT_DIR_NAME = "capa_rules_store"
CAPA_RULES_SUBDIR_NAME = "rules"


DEPENDENCIES = [
    ("cryptography", "cryptography", "Cryptography (for digital signatures)", False),
    ("requests", "requests", "Requests (for PEiD DB download & capa/FLOSS support)", False),
    ("signify.authenticode", "signify", "Signify (for Authenticode validation)", False),
    ("yara", "yara-python", "Yara (for YARA scanning)", False),
    ("capa.main", "flare-capa", "Capa (for capability detection)", False),
    ("floss.main", "flare-floss", "FLOSS (for advanced string extraction)", False),
    ("stringsifter", "flare-stringsifter", "StringSifter (for ranking string relevance)", False),
    ("thefuzz", "thefuzz[speedup]", "TheFuzz (for fuzzy string matching)", False),
    ("viv_utils", "vivisect", "Vivisect & Viv-Utils (for FLOSS analysis backend)", False),
    ("mcp.server", "mcp[cli]", "MCP SDK (for MCP server mode)", True)
]
def check_and_install_dependencies(is_mcp_server_mode_arg: bool):
    missing_deps_info = []
    critical_mcp_missing_for_current_mode = False

    # Determine missing dependencies
    for spec_name, pip_name, friendly_name, is_critical_for_mcp_mode in DEPENDENCIES:
        is_missing = False
        if spec_name == "mcp.server":
            if not MCP_SDK_AVAILABLE:
                is_missing = True
        elif spec_name == "capa.main":
            if not CAPA_AVAILABLE:
                is_missing = True
        elif spec_name == "signify.authenticode":
            if not SIGNIFY_AVAILABLE:
                is_missing = True
        elif spec_name == "yara":
            if not YARA_AVAILABLE:
                is_missing = True
        elif spec_name == "stringsifter":
            if not STRINGSIFTER_AVAILABLE:
                is_missing = True
        elif spec_name == "thefuzz":
            if not THEFUZZ_AVAILABLE:
                is_missing = True
        elif spec_name == "floss.main":
            if not FLOSS_SETUP_OK:
                is_missing = True
        elif spec_name == "viv_utils":
            if FLOSS_SETUP_OK and not FLOSS_ANALYSIS_OK:
                is_missing = True
            elif not FLOSS_SETUP_OK:
                pass
        else:
            spec = importlib.util.find_spec(spec_name)
            if spec is None:
                is_missing = True

        if is_missing:
            missing_reason = ""
            if spec_name == "floss.main" and FLOSS_IMPORT_ERROR_SETUP:
                missing_reason = f" (FLOSS Setup Error: {FLOSS_IMPORT_ERROR_SETUP})"
            elif spec_name == "viv_utils" and FLOSS_SETUP_OK and not FLOSS_ANALYSIS_OK and FLOSS_IMPORT_ERROR_ANALYSIS:
                 missing_reason = f" (FLOSS Analysis/Vivisect Error: {FLOSS_IMPORT_ERROR_ANALYSIS})"

            missing_deps_info.append({
                "pip": pip_name,
                "friendly": f"{friendly_name}{missing_reason}",
                "is_critical_mcp": is_critical_for_mcp_mode
            })
            if is_critical_for_mcp_mode and is_mcp_server_mode_arg:
                critical_mcp_missing_for_current_mode = True

    if not missing_deps_info:
        return # No missing dependencies, just return.

    # All prints from here onward go to stderr for better visibility
    print("\n[!] Some optional libraries are missing or could not be imported:", file=sys.stderr)
    for dep in missing_deps_info:
        print(f"     - {dep['friendly']} (Python package: {dep['pip']})", file=sys.stderr)

    if critical_mcp_missing_for_current_mode:
        print("[!] One or more libraries critical for --mcp-server mode are missing.", file=sys.stderr)
    print("[!] These libraries enhance the script's functionality or are required for specific modes/features.", file=sys.stderr)

    try:
        if not sys.stdin.isatty():
            print("[!] Non-interactive environment detected. Cannot prompt for installation of optional libraries.", file=sys.stderr)
            if critical_mcp_missing_for_current_mode:
                print("[!] Please install the required MCP SDK ('pip install \"mcp[cli]\"') and/or other critical optional libraries manually and re-run.", file=sys.stderr)
                sys.exit(1)
            print("[!] Please install other missing optional libraries manually if needed.", file=sys.stderr)
            return

        # Interactive prompt
        answer = ""
        try:
            answer = input("Do you want to attempt to install the missing optional libraries now? (yes/no): ").strip().lower()
        except RuntimeError as e_input: # Catch potential errors if input() fails (e.g. stdin closed)
             print(f"[!] Error during input prompt: {e_input}. Assuming 'no' for installation.", file=sys.stderr)
             answer = "no"


        if answer == 'yes' or answer == 'y':
            installed_any = False
            for dep_to_install in missing_deps_info:
                print(f"[*] Attempting to install {dep_to_install['friendly']} (pip install \"{dep_to_install['pip']}\")...", file=sys.stderr)
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", dep_to_install['pip']])
                    print(f"[*] Successfully installed {dep_to_install['friendly']}.", file=sys.stderr)
                    installed_any = True
                except subprocess.CalledProcessError as e_pip_install:
                    print(f"[!] Error installing {dep_to_install['friendly']}: {e_pip_install}", file=sys.stderr)
                except FileNotFoundError:
                    print("[!] Error: 'pip' command not found. Is Python and pip installed correctly and in PATH?", file=sys.stderr)
                    break

            if installed_any:
                print("\n[*] Optional library installation process finished. Please re-run the script for changes to take full effect.", file=sys.stderr)
                sys.exit(0)
            else:
                print("[*] No optional libraries were successfully installed.", file=sys.stderr)
                if critical_mcp_missing_for_current_mode:
                    print("[!] Critical MCP dependencies were not installed. MCP server mode may not function as expected. Exiting.", file=sys.stderr)
                    sys.exit(1)
        else: # User answered 'no' or input failed and defaulted to 'no'
            print("[*] Skipping installation of optional libraries.", file=sys.stderr)
            if critical_mcp_missing_for_current_mode:
                print("[!] Critical MCP dependencies were not installed because installation was skipped. MCP server mode cannot function. Exiting.", file=sys.stderr)
                sys.exit(1)
    except EOFError: # If input stream is closed during input()
        print("[!] No input received for optional library installation. Assuming 'no'. Skipping.", file=sys.stderr)
        if critical_mcp_missing_for_current_mode:
            print("[!] Critical MCP dependencies were not installed. Exiting.", file=sys.stderr)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Optional library installation cancelled by user.", file=sys.stderr)
        if critical_mcp_missing_for_current_mode:
            print("[!] Critical MCP dependencies were not installed. Exiting.", file=sys.stderr)
            sys.exit(1)

if MCP_SDK_AVAILABLE: logger.info("MCP SDK found.")
else: logger.warning("MCP SDK not found. MCP server functionality will be mocked or unavailable if critical.")
if CAPA_AVAILABLE: logger.info("Capa library found.")
else: logger.warning(f"Capa library (flare-capa) not found. Capability analysis will be skipped. Import error: {CAPA_IMPORT_ERROR}")
if SIGNIFY_AVAILABLE: logger.info("Signify library found.")
else: logger.warning(f"Signify library not found. Authenticode validation will be skipped. Import error: {SIGNIFY_IMPORT_ERROR}")
if FLOSS_AVAILABLE: logger.info("FLOSS library and analysis components found.")
elif FLOSS_SETUP_OK: logger.warning(f"FLOSS basic setup OK, but analysis components (or vivisect) failed to import. FLOSS analysis will be limited/skipped. Analysis import error: {FLOSS_IMPORT_ERROR_ANALYSIS}")
else: logger.warning(f"FLOSS library (flare-floss) not found or basic setup failed. FLOSS analysis will be skipped. Setup import error: {FLOSS_IMPORT_ERROR_SETUP}")
if STRINGSIFTER_AVAILABLE: logger.info("StringSifter library found. String ranking will be available.")
else: logger.warning(f"StringSifter library not found. String ranking will be skipped. Import error: {STRINGSIFTER_IMPORT_ERROR}")
if THEFUZZ_AVAILABLE: logger.info("TheFuzz library found. Fuzzy string search will be available.")
else: logger.warning(f"TheFuzz library not found. Fuzzy search will be skipped. Import error: {THEFUZZ_IMPORT_ERROR}")

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
        if verbose: safe_print(f"   [VERBOSE] PEiD database already exists at: {local_path}", verbose_prefix=" ")
        return True
    if not REQUESTS_AVAILABLE:
        safe_print("[!] 'requests' library not found. Cannot download PEiD database.", verbose_prefix=" ")
        return False
    safe_print(f"[*] PEiD database not found at {local_path}. Attempting download from {url}...", verbose_prefix=" ")
    try:
        response = requests.get(url, timeout=15); response.raise_for_status()
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, 'wb') as f: f.write(response.content)
        safe_print(f"[*] PEiD database successfully downloaded to: {local_path}", verbose_prefix=" ")
        return True
    except requests.exceptions.RequestException as e:
        safe_print(f"[!] Error downloading PEiD database: {e}", verbose_prefix=" ")
        if os.path.exists(local_path):
            try:
                os.remove(local_path)
            except OSError:
                pass
        return False
    except IOError as e:
        safe_print(f"[!] Error saving PEiD database to {local_path}: {e}", verbose_prefix=" ")
        return False

def ensure_capa_rules_exist(rules_base_dir: str, rules_zip_url: str, verbose: bool = False) -> Optional[str]:
    final_rules_target_path = os.path.join(rules_base_dir, CAPA_RULES_SUBDIR_NAME)

    if os.path.isdir(final_rules_target_path) and os.listdir(final_rules_target_path):
        if verbose: logger.info(f"Capa rules already available at: {final_rules_target_path}")
        return final_rules_target_path

    if not REQUESTS_AVAILABLE:
        logger.error("'requests' library not found. Cannot download capa rules.")
        return None

    logger.info(f"Capa rules not found at '{final_rules_target_path}'. Attempting to download and extract to '{rules_base_dir}'...")

    os.makedirs(rules_base_dir, exist_ok=True)
    zip_path = os.path.join(rules_base_dir, "capa-rules.zip")
    extracted_top_level_dir_path = None

    try:
        logger.info(f"Downloading capa rules from {rules_zip_url} to {zip_path}...")
        response = requests.get(rules_zip_url, timeout=60, stream=True)
        response.raise_for_status()
        with open(zip_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info("Capa rules zip downloaded successfully.")

        logger.info(f"Extracting capa rules from {zip_path} into {rules_base_dir}...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(rules_base_dir)
        logger.info("Capa rules extracted successfully from zip.")

        extracted_dir_name_found = None
        expected_prefix = "capa-rules-" # Default prefix for capa-rules releases
        # Try to find the directory that starts with the expected prefix.
        # GitHub zip files usually create a top-level directory like 'capa-rules-vX.Y.Z'.
        for item in os.listdir(rules_base_dir):
            if item.startswith(expected_prefix) and os.path.isdir(os.path.join(rules_base_dir, item)):
                extracted_dir_name_found = item
                break
        
        # If not found with prefix, try to find *any* directory that contains a 'rules' subdir
        # This is a fallback for differently structured zips, though less common for capa-rules.
        if not extracted_dir_name_found:
            for item in os.listdir(rules_base_dir):
                potential_path = os.path.join(rules_base_dir, item)
                if os.path.isdir(potential_path) and os.path.isdir(os.path.join(potential_path, CAPA_RULES_SUBDIR_NAME)):
                    extracted_dir_name_found = item # The parent dir of 'rules'
                    # In this case, the 'rules' subdir is already what we want, or we need to move its contents.
                    # For simplicity, let's assume if we find 'item/rules', we want 'item/rules'
                    # The original logic moves 'item' to 'final_rules_target_path' if 'item' is 'capa-rules-X.Y.Z'
                    # If 'item' is just 'rules', then we might need to adjust.
                    # The current logic expects to move the *container* of the rules.
                    # If the zip extracts directly as 'rules', this needs adjustment.
                    # However, capa-rules zips from GitHub are `capa-rules-TAG/rules/...`
                    break


        if not extracted_dir_name_found:
            logger.error(f"Could not find the main '{expected_prefix}*' directory or a directory containing '{CAPA_RULES_SUBDIR_NAME}' within '{rules_base_dir}' after extraction. Contents: {os.listdir(rules_base_dir)}")
            if os.path.exists(zip_path):
                try: os.remove(zip_path)
                except OSError: pass
            return None

        extracted_top_level_dir_path = os.path.join(rules_base_dir, extracted_dir_name_found)
        
        # Determine the actual source of rules: either the extracted_top_level_dir_path itself (if it's the 'rules' dir)
        # or the 'rules' subdirectory within it.
        source_rules_content_path = extracted_top_level_dir_path
        if os.path.isdir(os.path.join(extracted_top_level_dir_path, CAPA_RULES_SUBDIR_NAME)):
            source_rules_content_path = os.path.join(extracted_top_level_dir_path, CAPA_RULES_SUBDIR_NAME)
            logger.info(f"Found rules content within subdirectory: {source_rules_content_path}")
        else:
             logger.info(f"Using extracted directory as rules content source: {source_rules_content_path}")


        if os.path.exists(final_rules_target_path):
            logger.warning(f"Target rules directory '{final_rules_target_path}' already exists. Removing it before placing newly extracted rules.")
            try:
                shutil.rmtree(final_rules_target_path)
            except Exception as e_rm:
                logger.error(f"Failed to remove existing target rules directory '{final_rules_target_path}': {e_rm}")
                if os.path.isdir(extracted_top_level_dir_path): # Clean up the originally extracted folder
                    try: shutil.rmtree(extracted_top_level_dir_path)
                    except Exception: pass
                if os.path.exists(zip_path):
                    try: os.remove(zip_path)
                    except OSError: pass
                return None

        logger.info(f"Moving rules from '{source_rules_content_path}' to '{final_rules_target_path}'...")
        try:
            # shutil.move might fail if src is a subdir of a dir we want to remove later.
            # It's safer to copy and then remove the original extracted structure.
            shutil.copytree(source_rules_content_path, final_rules_target_path)
            logger.info(f"Successfully copied rules to '{final_rules_target_path}'.")
        except Exception as e_mv_cp: # Changed from move to copytree
            logger.error(f"Failed to copy rules from '{source_rules_content_path}' to '{final_rules_target_path}': {e_mv_cp}")
            # Clean up potentially partially copied target
            if os.path.isdir(final_rules_target_path):
                try: shutil.rmtree(final_rules_target_path) 
                except Exception: pass
            # Clean up the originally extracted folder in any case
            if os.path.isdir(extracted_top_level_dir_path):
                 try: shutil.rmtree(extracted_top_level_dir_path)
                 except Exception: pass
            if os.path.exists(zip_path):
                try: os.remove(zip_path)
                except OSError: pass
            return None
        finally:
            # Clean up the entire originally extracted top-level directory after successful copy
            if os.path.isdir(extracted_top_level_dir_path):
                try: 
                    shutil.rmtree(extracted_top_level_dir_path)
                    logger.info(f"Cleaned up temporary extraction directory: {extracted_top_level_dir_path}")
                except Exception as e_rm_extracted:
                    logger.warning(f"Could not remove temporary extraction directory {extracted_top_level_dir_path}: {e_rm_extracted}")


        if os.path.isdir(final_rules_target_path) and os.listdir(final_rules_target_path):
            logger.info(f"Capa rules now correctly organized at: {final_rules_target_path}")
            return final_rules_target_path
        else:
            logger.error(f"Capa rules were processed, but the final target directory '{final_rules_target_path}' is still not found or is empty.")
            if os.path.exists(zip_path): # Ensure zip is removed if process failed here
                try: os.remove(zip_path)
                except OSError: pass
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Error downloading capa rules: {e}")
    except zipfile.BadZipFile:
        logger.error(f"Error: Downloaded capa rules file '{zip_path}' is not a valid zip file or is corrupted.")
    except Exception as e:
        logger.error(f"An unexpected error occurred during capa rules download/extraction/organization: {e}", exc_info=verbose)
        if extracted_top_level_dir_path and os.path.isdir(extracted_top_level_dir_path): # If top level was created
            try: shutil.rmtree(extracted_top_level_dir_path) # Clean it up
            except Exception: pass
    finally:
        if os.path.exists(zip_path):
            try: os.remove(zip_path)
            except OSError as e_rm_zip: logger.warning(f"Could not remove downloaded zip {zip_path}: {e_rm_zip}")
    return None

def parse_signature_file(db_path: str, verbose: bool = False) -> List[Dict[str, Any]]:
    if verbose: safe_print(f"   [VERBOSE-PEID] Starting to parse signature file: {db_path}", verbose_prefix=" ")
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
                            except re.error:current_signature=None # Invalid regex pattern
                        else:current_signature=None # Invalid hex byte pattern
                        continue # Processed signature line
                    ep_match=re.match(r'^ep_only\s*=\s*(true|false)',line,re.IGNORECASE)
                    if ep_match:current_signature['ep_only']=ep_match.group(1).lower()=='true'
        if current_signature and 'name' in current_signature and ('pattern_bytes' in current_signature or 'regex_pattern' in current_signature):
            signatures.append(current_signature)
    except FileNotFoundError: safe_print(f"[!] PEiD DB not found: {db_path}"); return []
    except Exception as e: safe_print(f"[!] Error parsing PEiD DB {db_path}: {e}"); return []
    if verbose: safe_print(f"   [VERBOSE-PEID] Loaded {len(signatures)} PEiD signatures.", verbose_prefix=" ")
    return signatures

def find_pattern_in_data_regex(data_block: bytes, signature_dict: Dict[str, Any], verbose: bool = False, section_name_for_log: str = "UnknownSection") -> Optional[str]:
    regex_pattern = signature_dict.get('regex_pattern')
    pattern_name = signature_dict.get('name', "Unknown")
    if not regex_pattern or not data_block: return None
    try:
        match = regex_pattern.search(data_block)
        if match:
            if verbose: safe_print(f"       [VERBOSE-PEID-MATCH-REGEX] Pattern '{pattern_name}' matched at offset {hex(match.start())} in {section_name_for_log}.", verbose_prefix=" ")
            return pattern_name
    except Exception as e_re_search:
        if verbose: safe_print(f"       [VERBOSE-PEID-REGEX-ERROR] Error searching for pattern '{pattern_name}': {e_re_search}", verbose_prefix=" ")
    return None

def perform_yara_scan(filepath: str, file_data: bytes, yara_rules_path: Optional[str], yara_available_flag: bool, verbose: bool = False) -> List[Dict[str, Any]]:
    scan_results: List[Dict[str, Any]] = []
    if not yara_available_flag:
        logger.warning("   'yara-python' library not found. Skipping YARA scan.")
        if verbose and YARA_IMPORT_ERROR: logger.debug(f"         [VERBOSE-DEBUG] YARA import error: {YARA_IMPORT_ERROR}")
        return scan_results
    if not yara_rules_path: # yara_rules_path is expected to be absolute if provided
        logger.info("   No YARA rules path provided. Skipping YARA scan.")
        return scan_results
    try:
        if verbose: logger.info(f"   [VERBOSE-YARA] Loading rules from: {yara_rules_path}")
        rules = None
        if os.path.isdir(yara_rules_path):
            filepaths = {f_name: os.path.join(dirname, f_name) for dirname, _, files in os.walk(yara_rules_path) for f_name in files if f_name.lower().endswith(('.yar', '.yara'))}
            if not filepaths: logger.warning(f"   No .yar or .yara files in dir: {yara_rules_path}"); return scan_results
            rules = yara.compile(filepaths=filepaths)
        elif os.path.isfile(yara_rules_path): rules = yara.compile(filepath=yara_rules_path)
        else: logger.warning(f"   YARA rules path not valid: {yara_rules_path}"); return scan_results

        matches = rules.match(data=file_data)
        if matches:
            logger.info(f"   YARA Matches Found ({len(matches)}):")
            for match in matches:
                match_detail:Dict[str,Any]={"rule":match.rule,"namespace":match.namespace if match.namespace!='default'else None,"tags":list(match.tags)if match.tags else None,"meta":dict(match.meta)if match.meta else None,"strings":[]}
                if match.strings:
                    for s_match_offset, s_match_id, s_match_data_bytes in match.strings: # Unpack tuple
                        try:
                            # Attempt to decode as UTF-8 first, then latin-1, then fall back to hex
                            try: str_data_repr = s_match_data_bytes.decode('utf-8')
                            except UnicodeDecodeError:
                                try: str_data_repr = s_match_data_bytes.decode('latin-1')
                                except UnicodeDecodeError: str_data_repr = s_match_data_bytes.hex()
                        except Exception: str_data_repr = s_match_data_bytes.hex() # Final fallback

                        if len(str_data_repr)>80:str_data_repr=str_data_repr[:77]+"..."
                        match_detail["strings"].append({"offset":hex(s_match_offset),"identifier":s_match_id,"data":str_data_repr})
                scan_results.append(match_detail)
        else: logger.info("   No YARA matches found.")
    except yara.Error as e: logger.error(f"   YARA Error: {e}"); scan_results.append({"error":f"YARA Error: {str(e)}"})
    except Exception as e: logger.error(f"   Unexpected YARA scan error: {e}",exc_info=verbose); scan_results.append({"error":f"Unexpected YARA scan error: {str(e)}"})
    return scan_results

def perform_floss_analysis(args):
    """
    Controller function to perform FLOSS analysis based on command-line arguments.
    """
    logger.info(f"Starting FLOSS analysis for {args.filepath}")
    
    disabled_types = [t.strip() for t in args.floss_disable.split(',')] if args.floss_disable else []
    only_types = [t.strip() for t in args.floss_only.split(',')] if args.floss_only else []
    
    # --- MODIFIED: Added regex_search_pattern=args.regex_pattern ---
    floss_results = _parse_floss_analysis(
        pe_filepath_str=args.filepath,
        min_length=args.min_length,
        floss_verbose_level=args.verbose,
        floss_script_debug_level=Actual_DebugLevel_Floss.DEFAULT, # Or map from script verbosity
        floss_format_hint=args.floss_format,
        floss_disabled_types=disabled_types,
        floss_only_types=only_types,
        floss_functions_to_analyze=[], # Placeholder for function analysis
        quiet_mode_for_floss_progress=args.quiet,
        regex_search_pattern=args.regex_pattern 
    )

    output_path = args.output
    if not output_path:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = Path(args.filepath).stem
        output_path = f"{filename}_floss_results_{timestamp}.json"

    try:
        with open(output_path, 'w') as f:
            json.dump(floss_results, f, indent=4)
        logger.info(f"FLOSS analysis results saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save FLOSS results to {output_path}: {e}")

def _parse_capa_analysis(pe_obj: pefile.PE,
                         pe_filepath_original: str,
                         capa_rules_dir_path: Optional[str],
                         capa_sigs_dir_path: Optional[str],
                         verbose: bool) -> Dict[str, Any]:
    capa_results: Dict[str, Any] = {"status": "Not performed", "error": None, "results": None}

    if not CAPA_AVAILABLE:
        capa_results["status"] = "Capa library components not available."
        capa_results["error"] = f"Capa import error: {CAPA_IMPORT_ERROR}"
        logger.warning(f"Capa components not available. Error: {CAPA_IMPORT_ERROR}")
        return capa_results

    effective_rules_path_str = capa_rules_dir_path
    if not effective_rules_path_str:
        default_rules_base = str(SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME)
        logger.info(f"Capa rules directory not specified, using default script-relative base: '{default_rules_base}'")
        effective_rules_path_str = ensure_capa_rules_exist(default_rules_base, CAPA_RULES_ZIP_URL, verbose)
    elif not os.path.isdir(effective_rules_path_str) or not os.listdir(effective_rules_path_str):
        logger.warning(f"Provided capa_rules_dir_path '{capa_rules_dir_path}' is invalid. Attempting script-relative default.")
        default_rules_base = str(SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME)
        effective_rules_path_str = ensure_capa_rules_exist(default_rules_base, CAPA_RULES_ZIP_URL, verbose)

    if not effective_rules_path_str:
        err_path_msg_part = capa_rules_dir_path if capa_rules_dir_path else str(SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME / CAPA_RULES_SUBDIR_NAME)
        capa_results["status"] = "Capa rules not found or download/extraction failed."
        capa_results["error"] = f"Failed to ensure capa rules at '{err_path_msg_part}'."
        logger.error(capa_results["error"])
        return capa_results
    else:
        logger.info(f"Using capa rules from: {effective_rules_path_str}")


    class MockCapaCliArgs: pass
    mock_args = MockCapaCliArgs()
    mock_args.input_file = Path(pe_filepath_original)

    logger.info(f"Attempting capa analysis using capa.main workflow for: {mock_args.input_file}")

    setattr(mock_args, 'rules', [Path(effective_rules_path_str)])
    if hasattr(mock_args, 'is_default_rules'): setattr(mock_args, 'is_default_rules', False)

    effective_capa_sigs_path_str_for_mock_args = ""
    if capa_sigs_dir_path and Path(capa_sigs_dir_path).is_dir():
        effective_capa_sigs_path_str_for_mock_args = str(capa_sigs_dir_path)
        logger.info(f"Using user-provided Capa signatures directory: {effective_capa_sigs_path_str_for_mock_args}")
    else:
        if capa_sigs_dir_path:
            logger.warning(f"User-provided capa_sigs_dir '{capa_sigs_dir_path}' is not a valid directory.")
        else:
            logger.info("Capa signatures directory not explicitly provided by user.")

        potential_script_relative_sigs = SCRIPT_DIR / "capa_sigs"
        if potential_script_relative_sigs.is_dir():
             effective_capa_sigs_path_str_for_mock_args = str(potential_script_relative_sigs.resolve())
             logger.info(f"Found and using script-relative 'capa_sigs' directory: {effective_capa_sigs_path_str_for_mock_args}")
        elif (SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME / "sigs").is_dir():
             effective_capa_sigs_path_str_for_mock_args = str((SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME / "sigs").resolve())
             logger.info(f"Found 'sigs' directory near default rules store: {effective_capa_sigs_path_str_for_mock_args}")
        else:
            logger.warning("Capa signatures directory not found locally (e.g., ./capa_sigs or next to default rules). Explicitly telling Capa to load no library function signatures to prevent potential errors if Capa's internal default path is problematic.")
            effective_capa_sigs_path_str_for_mock_args = "" # Tell capa to load no library sigs

    setattr(mock_args, 'signatures', effective_capa_sigs_path_str_for_mock_args)
    if hasattr(mock_args, 'is_default_signatures'):
        is_capa_internal_default_path = False
        if hasattr(capa.main, 'SIGNATURES_PATH_DEFAULT_STRING'): # Check if this attribute exists in the capa version
             is_capa_internal_default_path = (effective_capa_sigs_path_str_for_mock_args == getattr(capa.main, 'SIGNATURES_PATH_DEFAULT_STRING'))
        setattr(mock_args, 'is_default_signatures', (not bool(capa_sigs_dir_path)) and is_capa_internal_default_path and effective_capa_sigs_path_str_for_mock_args != "")


    setattr(mock_args, 'format', getattr(capa.features.common, 'FORMAT_PE', 'pe')) # Default to PE
    setattr(mock_args, 'backend', getattr(capa.loader, 'BACKEND_AUTO', 'auto')) # Default to auto backend
    setattr(mock_args, 'os', getattr(capa.features.common, 'OS_WINDOWS', 'windows')) # Default to Windows
    setattr(mock_args, 'tag', None) # No specific tag filtering by default
    setattr(mock_args, 'verbose', verbose) # Propagate verbosity
    setattr(mock_args, 'vverbose', False) # Not super verbose by default
    setattr(mock_args, 'json', True) # We want JSON output internally
    setattr(mock_args, 'color', "never") # No color codes in internal JSON
    setattr(mock_args, 'debug', verbose) # Propagate debug
    setattr(mock_args, 'quiet', not verbose) # Quiet if not verbose

    # Ensure these exist for newer capa versions if they are checked by capa.main functions
    if not hasattr(mock_args, 'restrict_to_functions'): setattr(mock_args, 'restrict_to_functions', [])
    if not hasattr(mock_args, 'restrict_to_processes'): setattr(mock_args, 'restrict_to_processes', [])

    try:
        if verbose:
            sig_val = getattr(mock_args, 'signatures', 'N/A')
            if isinstance(sig_val, Path): sig_val = str(sig_val)
            rules_val_str_list = [str(r) for r in getattr(mock_args, 'rules', [])]
            logger.info(f"   [VERBOSE-CAPA] Mocked CLI args for capa.main: input_file='{mock_args.input_file}', rules={rules_val_str_list}, format='{mock_args.format}', backend='{mock_args.backend}', os='{mock_args.os}', signatures='{sig_val}'")

        # Call capa's main argument handling and setup functions if they exist
        if hasattr(capa.main, 'handle_common_args'):
            capa.main.handle_common_args(mock_args)

        if hasattr(capa.main, 'ensure_input_exists_from_cli'):
            capa.main.ensure_input_exists_from_cli(mock_args)

        input_format = mock_args.format
        if hasattr(capa.main, 'get_input_format_from_cli'):
            input_format = capa.main.get_input_format_from_cli(mock_args)
        mock_args.format = input_format # Update mock_args with potentially deduced format

        rules = capa.main.get_rules_from_cli(mock_args)
        logger.info(f"Rules loaded via capa.main.get_rules_from_cli. Rule count: {len(rules.rules) if hasattr(rules, 'rules') and hasattr(rules.rules, '__len__') else 'N/A'}")

        backend = mock_args.backend
        if hasattr(capa.main, 'get_backend_from_cli'):
            backend = capa.main.get_backend_from_cli(mock_args, input_format)
        mock_args.backend = backend # Update mock_args

        if hasattr(capa.main, 'get_os_from_cli'): # os might be deduced
            mock_args.os = capa.main.get_os_from_cli(mock_args, backend)

        extractor = capa.main.get_extractor_from_cli(mock_args, input_format, backend)
        logger.info(f"Extractor obtained via capa.main.get_extractor_from_cli: {type(extractor).__name__}")

        capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=True)
        logger.info("Capabilities search complete.")

        # Prepare metadata for the ResultDocument
        # Simulate argv for capa's metadata collection
        simulated_argv_for_meta = ["PeMCP.py", str(mock_args.input_file)] # Basic argv

        actual_rule_paths_for_meta = mock_args.rules
        # Ensure actual_rule_paths_for_meta is List[Path] for collect_metadata
        if not (isinstance(actual_rule_paths_for_meta, list) and \
                all(isinstance(p, Path) for p in actual_rule_paths_for_meta)):
            logger.warning(f"Rules paths for capa.loader.collect_metadata ('mock_args.rules': {actual_rule_paths_for_meta}) are not List[Path] as expected. Metadata might be incomplete.")
            # Attempt to convert if they are strings, otherwise use empty list
            temp_paths = []
            all_valid = True
            if isinstance(actual_rule_paths_for_meta, list):
                for p_item in actual_rule_paths_for_meta:
                    if isinstance(p_item, Path): temp_paths.append(p_item)
                    elif isinstance(p_item, str) and os.path.exists(p_item): temp_paths.append(Path(p_item))
                    else: all_valid = False; break
            else: all_valid = False
            actual_rule_paths_for_meta = temp_paths if all_valid else []


        meta = capa.loader.collect_metadata(
            simulated_argv_for_meta,
            mock_args.input_file, # sample_path (Path object)
            input_format,         # format (str)
            mock_args.os,         # analysis_os (str)
            actual_rule_paths_for_meta, # rules_paths (List[Path])
            extractor,            # extractor (FeatureExtractor)
            capabilities          # capabilities (RuleSetCapabilities)
        )
        # Compute layout if necessary (newer capa versions handle this internally or via ResultDocument)
        if hasattr(meta, 'analysis') and hasattr(capabilities, 'matches') and hasattr(meta.analysis, 'layout') and hasattr(capa.loader, 'compute_layout'):
            meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

        # Create the ResultDocument and render to JSON
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
        # Render to JSON string, then parse back to dict to ensure consistent structure
        json_output_str = doc.model_dump_json(exclude_none=True) # exclude_none=True is good practice

        capa_results["results"] = json.loads(json_output_str)
        capa_results["status"] = "Analysis complete (adapted workflow)"

    except (InvalidArgument, EmptyReportError, UnsupportedOSError, UnsupportedArchError, UnsupportedFormatError, UnsupportedRuntimeError) as e_specific_api:
        error_msg = f"Capa analysis failed with specific API exception: {type(e_specific_api).__name__} - {str(e_specific_api)}"
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (API specific)"
        capa_results["error"] = error_msg
    except AttributeError as e_attr:
        error_msg = f"Capa API call failed (AttributeError): {e_attr}. This may indicate an API incompatibility or missing component in the capa version."
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (API incompatibility)"
        capa_results["error"] = error_msg
    except FileNotFoundError as e_fnf: # Catch if capa tries to access a file that's not there (e.g. during extraction)
        error_msg = f"Capa analysis failed (FileNotFoundError): {e_fnf}."
        logger.error(error_msg, exc_info=verbose)
        capa_results["status"] = "Error during analysis (File Not Found for capa)"
        capa_results["error"] = error_msg
    except Exception as e:
        # Check if it's a capa-defined exit error
        should_exit_error_type = getattr(capa.main, 'ShouldExitError', None) # Gracefully check if this exists
        if should_exit_error_type and isinstance(e, should_exit_error_type):
            error_msg = f"Capa analysis aborted ({type(e).__name__}): {e} (status_code: {getattr(e, 'status_code', 'N/A')})"
            capa_results["status"] = f"Error during analysis ({type(e).__name__})"
        else:
            error_msg = f"Unexpected error during adapted capa analysis: {type(e).__name__} - {e}"
            capa_results["status"] = "Unexpected error"
        logger.error(error_msg, exc_info=verbose)
        capa_results["error"] = error_msg

    return capa_results

# --- String Utilities ---
def _extract_strings_from_data(data_bytes: bytes, min_length: int = 5) -> List[Tuple[int, str]]:
    strings_found = []
    current_string = ""
    current_offset = -1
    for i, byte_val in enumerate(data_bytes):
        char = chr(byte_val)
        if ' ' <= char <= '~': # Printable ASCII range
            if not current_string: current_offset = i
            current_string += char
        else:
            if len(current_string) >= min_length: strings_found.append((current_offset, current_string))
            current_string = ""; current_offset = -1
    if len(current_string) >= min_length: strings_found.append((current_offset, current_string)) # Catch trailing string
    return strings_found

def _search_specific_strings_in_data(data_bytes: bytes, search_terms: List[str]) -> Dict[str, List[int]]:
    results: Dict[str, List[int]] = {term: [] for term in search_terms}
    for term in search_terms:
        term_bytes = term.encode('ascii', 'ignore') # Assume ASCII search terms for simplicity
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
        # Ensure hex_part is padded to align the ASCII part correctly
        hex_part_padded = hex_part.ljust(bytes_per_line * 3 -1) # (byte_hex + space) * count - last_space
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
            except:pass # Keep 'Unknown' or 'N/A' if decoding fails
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
                except:type_name_str=f"{res_type_entry.name.decode('latin-1','ignore')} ({type_name_str})" # Fallback
            if hasattr(res_type_entry,'directory'):
                for res_id_entry in res_type_entry.directory.entries:
                    id_val=getattr(res_id_entry,'id',None);id_name_str=str(id_val)
                    if hasattr(res_id_entry,'name')and res_id_entry.name is not None:
                        try:id_name_str=f"{res_id_entry.name.decode('utf-16le','ignore')} (ID: {id_val if id_val is not None else 'N/A'})"
                        except:id_name_str=f"{res_id_entry.name.decode('latin-1','ignore')} (ID: {id_val if id_val is not None else 'N/A'})" # Fallback
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
            if hasattr(fi_block,'entries'): # StringFileInfo
                block_detail['type']="StringFileInfo";st_tables=[]
                for item in fi_block.entries: # StringTable
                    st_entry:Dict[str,Any]={'lang_codepage':f"{item.Lang}/{item.CodePage}",'entries':{}}
                    if hasattr(item,'entries')and isinstance(item.entries,dict): # String entries
                        for k,v in item.entries.items():st_entry['entries'][k.decode('utf-8','ignore')if isinstance(k,bytes)else str(k)]=v.decode('utf-8','ignore')if isinstance(v,bytes)else str(v)
                    st_tables.append(st_entry)
                block_detail['string_tables']=st_tables
            elif hasattr(fi_block,'Var')and hasattr(fi_block.Var,'entry'): # VarFileInfo
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
            if entry.entry: # The parsed debug entry (e.g., CV_INFO_PDB70)
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
            raw_sig_block = pe.get_data(sig_offset, sig_size) # This can raise PEFormatError if offset/size invalid
            if cryptography_available_flag:
                crypto_certs=[]
                try:
                    pkcs7_blob=None
                    # The PKCS#7 data starts 8 bytes into the security directory data block
                    # after the WIN_CERTIFICATE structure header.
                    if len(raw_sig_block)>8:
                        # dwLength = struct.unpack_from('<I', raw_sig_block, 0)[0] # Total length of WIN_CERTIFICATE
                        # wRevision = struct.unpack_from('<H', raw_sig_block, 4)[0] # Revision
                        cert_type=struct.unpack_from('<H',raw_sig_block,6)[0] # wCertificateType
                        if cert_type==0x0002:pkcs7_blob=raw_sig_block[8:] # WIN_CERT_TYPE_PKCS_SIGNED_DATA
                    if pkcs7_blob:
                        with warnings.catch_warnings():warnings.simplefilter("ignore",UserWarning);warnings.simplefilter("ignore",DeprecationWarning);parsed=pkcs7.load_der_pkcs7_certificates(pkcs7_blob)
                        for idx,cert in enumerate(parsed):crypto_certs.append({"cert_index":idx+1,"subject":str(cert.subject.rfc4514_string()),"issuer":str(cert.issuer.rfc4514_string()),"serial_number":str(cert.serial_number),"version":str(cert.version),"not_valid_before_utc":str(cert.not_valid_before_utc),"not_valid_after_utc":str(cert.not_valid_after_utc)})
                        sig_info['cryptography_parsed_certs']=crypto_certs
                except Exception as e:sig_info['cryptography_parsed_certs_error']=str(e)
            else:sig_info['cryptography_parsed_certs']="cryptography library not available"
            if signify_available_flag:
                signify_res=[]
                try:
                    # Signify expects a file-like object or path. Since we have pe.__data__, use BytesIO.
                    with io.BytesIO(pe.__data__)as f_mem:
                        signed_pe=SignedPEFile(f_mem) # Pass the file-like object
                        if not signed_pe.signed_datas:signify_res.append({"status":"No signature blocks found by signify."})
                        else:
                            for i,sdo in enumerate(signed_pe.signed_datas): # AuthenticodeSignedData object
                                vr_enum,vr_exc=sdo.explain_verify()
                                item:Dict[str,Any]={"block":i+1,"status_description":str(vr_enum),"is_valid":vr_enum==AuthenticodeVerificationResult.OK,"exception":str(vr_exc)if vr_exc else None}
                                if sdo.signer_info: # SignerInfo object
                                    si=sdo.signer_info;ident_parts=[]
                                    if hasattr(si,'issuer')and si.issuer: # Name object
                                        try:ident_parts.append(f"Issuer: {si.issuer.rfc4514_string()}")
                                        except:ident_parts.append(f"Issuer: {str(si.issuer)}") # Fallback
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

    if not peid_db_path:
        logger.error("PEiD scan called without a database path (this indicates an issue with path defaulting).")
        peid_results["status"] = "PEiD DB path was not resolved prior to scan."
        return peid_results

    str_peid_db_path = str(peid_db_path)

    if not os.path.exists(str_peid_db_path):
        logger.info(f"PEiD DB '{str_peid_db_path}' not found. Attempting download...")
        if not ensure_peid_db_exists(PEID_USERDB_URL, str_peid_db_path, verbose):
            peid_results["status"] = f"PEiD DB '{str_peid_db_path}' not found and download failed."
            return peid_results

    custom_sigs = parse_signature_file(str_peid_db_path, verbose)
    if not custom_sigs:
        peid_results["status"] = f"No PEiD signatures loaded from '{str_peid_db_path}' (file might be empty or malformed)."
        return peid_results

    peid_results["status"] = "Scan performed."
    # Entry Point Scan
    if hasattr(pe,'OPTIONAL_HEADER')and pe.OPTIONAL_HEADER.AddressOfEntryPoint:
        ep_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        try:
            ep_sec=pe.get_section_by_rva(ep_rva)
            if ep_sec:
                ep_offset_sec=ep_rva-ep_sec.VirtualAddress;ep_data=ep_sec.get_data(ep_offset_sec,2048) # Read 2KB from EP
                for sig in custom_sigs:
                    if sig['ep_only']:match_name=find_pattern_in_data_regex(ep_data,sig,verbose,"Entry Point Area");_ = peid_results["ep_matches"].append(match_name) if match_name else None
        except Exception as e:logger.warning(f"PEiD EP scan error: {e}",exc_info=verbose)
    # Full File / Heuristic Scan
    if not skip_full_peid_scan:
        heuristic_matches_list:List[str]=[]
        # Scan executable sections, or first section if none are marked executable
        secs_to_scan=[s for s in pe.sections if hasattr(s,'Characteristics')and bool(s.Characteristics&pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])]
        if not secs_to_scan and pe.sections:secs_to_scan=[pe.sections[0]] # Fallback to first section
        scan_tasks_args=[]
        for sec in secs_to_scan:
            try:
                section_name_cleaned = sec.Name.decode('utf-8','ignore').rstrip('\x00')
                sec_data=sec.get_data()
                for sig in custom_sigs:
                    if peid_scan_all_sigs_heuristically or not sig['ep_only']:scan_tasks_args.append((sec_data,sig,verbose,section_name_cleaned))
            except Exception as e:
                section_name_cleaned_for_log = "UnknownSection"
                try:
                    section_name_cleaned_for_log = sec.Name.decode('utf-8','ignore').rstrip('\x00')
                except: pass
                logger.warning(f"PEiD section data error {section_name_cleaned_for_log}: {e}")

        if scan_tasks_args:
            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count()or 1)as executor:
                futures=[executor.submit(find_pattern_in_data_regex,*args)for args in scan_tasks_args]
                for future in concurrent.futures.as_completed(futures):
                    try:res_name=future.result();_ = heuristic_matches_list.append(res_name) if res_name else None
                    except Exception as e:logger.warning(f"PEiD scan thread error: {e}",exc_info=verbose)
        peid_results["heuristic_matches"]=list(set(heuristic_matches_list)) # Unique matches
    peid_results["ep_matches"]=list(set(peid_results["ep_matches"])) # Unique EP matches
    return peid_results

def _parse_rich_header(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    if hasattr(pe,'RICH_HEADER')and pe.RICH_HEADER:
        decoded=[];raw_vals=list(pe.RICH_HEADER.values)if pe.RICH_HEADER.values else[]
        for i in range(0,len(raw_vals),2): # Iterate in pairs (CompID, Count)
            if i+1<len(raw_vals):comp_id=raw_vals[i];count=raw_vals[i+1];prod_id=comp_id>>16;build_num=comp_id&0xFFFF;decoded.append({"product_id_hex":hex(prod_id),"product_id_dec":prod_id,"build_number":build_num,"count":count,"raw_comp_id":hex(comp_id)})
        return {'key_hex':pe.RICH_HEADER.key.hex()if isinstance(pe.RICH_HEADER.key,bytes)else str(pe.RICH_HEADER.key),'checksum':hex(pe.RICH_HEADER.checksum)if pe.RICH_HEADER.checksum is not None else None,'raw_values':raw_vals,'decoded_values':decoded,'raw_data_hex':pe.RICH_HEADER.raw_data.hex()if pe.RICH_HEADER.raw_data else None,'clear_data_hex':pe.RICH_HEADER.clear_data.hex()if pe.RICH_HEADER.clear_data else None}
    return None

def _parse_delay_load_imports(pe: pefile.PE, magic_type_str: str) -> List[Dict[str, Any]]:
    # Constants for ordinal flags
    IMG_ORDINAL_FLAG64 = 0x8000000000000000
    IMG_ORDINAL_FLAG32 = 0x80000000

    delay_imports_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            dll_name="N/A"
            if entry.struct.szName: # RVA to DLL name string
                try:dll_name=pe.get_string_at_rva(entry.struct.szName).decode('utf-8','ignore')
                except:pass # Keep N/A if error
            delay_syms=[]
            # pINT (PointerToINT) points to the Import Name Table for this DLL
            if entry.struct.pINT and hasattr(pe,'OPTIONAL_HEADER'):
                thunk_rva=entry.struct.pINT
                ptr_size=8 if magic_type_str=="PE32+ (64-bit)"else 4
                ord_flag = IMG_ORDINAL_FLAG64 if ptr_size==8 else IMG_ORDINAL_FLAG32

                while True:
                    try:
                        # Read the thunk value (RVA to import name or ordinal)
                        thunk_val_raw = pe.get_qword_at_rva(thunk_rva) if ptr_size==8 else pe.get_dword_at_rva(thunk_rva)
                        if thunk_val_raw == 0: break # End of table

                        s_name, s_ord = None, None
                        if thunk_val_raw & ord_flag: # Import by ordinal
                            s_ord = thunk_val_raw & 0xFFFF # Ordinal is lower 16 bits for PE32, lower 16 for PE32+ too (though flag is 64-bit)
                        else: # Import by name
                            name_rva = thunk_val_raw # This is an RVA to an IMAGE_IMPORT_BY_NAME structure
                            try:
                                # IMAGE_IMPORT_BY_NAME: Hint (WORD), Name (NULL-terminated string)
                                s_name = pe.get_string_at_rva(name_rva + 2).decode('utf-8','ignore') # Skip Hint
                            except Exception as e_str:
                                logger.debug(f"Delay-load import string fetch error at RVA {hex(name_rva+2)}: {e_str}")
                                s_name = "ErrorFetchingName"

                        delay_syms.append({'name':s_name,'ordinal':s_ord,'thunk_rva':hex(thunk_rva)})
                        thunk_rva += ptr_size
                    except pefile.PEFormatError as e_pe: # Reading past valid data
                        logger.debug(f"Delay-load import table parsing error (PEFormatError): {e_pe}")
                        break
                    except Exception as e_gen:
                        logger.warning(f"Unexpected error parsing delay-load import entry: {e_gen}")
                        break
            delay_imports_list.append({'dll_name':dll_name,'struct':entry.struct.dump_dict(),'symbols':delay_syms})
    return delay_imports_list

def _parse_tls_info(pe: pefile.PE, magic_type_str: str) -> Optional[Dict[str, Any]]:
    if hasattr(pe,'DIRECTORY_ENTRY_TLS')and pe.DIRECTORY_ENTRY_TLS and pe.DIRECTORY_ENTRY_TLS.struct:
        tls_struct=pe.DIRECTORY_ENTRY_TLS.struct;tls_info:Dict[str,Any]={'struct':tls_struct.dump_dict()};callbacks=[]
        # AddressOfCallBacks is a VA (Virtual Address)
        if tls_struct.AddressOfCallBacks and hasattr(pe,'OPTIONAL_HEADER'):
            cb_va=tls_struct.AddressOfCallBacks;ptr_size=8 if magic_type_str=="PE32+ (64-bit)"else 4;max_cb=20;count=0 # Limit callbacks parsed
            while cb_va!=0 and count<max_cb: # Callbacks are VA pointers, array terminated by a NULL pointer
                try:
                    # Convert VA of the callback pointer to file offset
                    func_va_ptr_offset = pe.get_offset_from_virtual_address(cb_va)
                    # Read the actual callback function's VA from that offset
                    func_va=pe.get_qword_from_data(pe.get_data(func_va_ptr_offset,ptr_size),0)if ptr_size==8 else pe.get_dword_from_data(pe.get_data(func_va_ptr_offset,ptr_size),0)
                    if func_va==0:break # End of callback array
                    callbacks.append({'va':hex(func_va),'rva':hex(func_va-pe.OPTIONAL_HEADER.ImageBase)});cb_va+=ptr_size;count+=1
                except AttributeError as e_pefile_va: # get_offset_from_virtual_address can fail if VA is not mapped
                    logger.debug(f"TLS callback VA {hex(cb_va)}->RVA/offset conversion error: {e_pefile_va} (likely VA out of mapped range)")
                    break
                except Exception as e:logger.debug(f"TLS callback parse error VA {hex(cb_va)}: {e}");break
        tls_info['callbacks']=callbacks;return tls_info
    return None

def _parse_load_config(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    if hasattr(pe,'DIRECTORY_ENTRY_LOAD_CONFIG')and pe.DIRECTORY_ENTRY_LOAD_CONFIG and pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct:
        lc=pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct;load_config_dict:Dict[str,Any]={'struct':lc.dump_dict()}
        if hasattr(lc,'GuardFlags'):
            gf_list=[];gf_map={0x100:"CF_INSTRUMENTED",0x200:"CFW_INSTRUMENTED",0x400:"CF_FUNCTION_TABLE_PRESENT",0x800:"SECURITY_COOKIE_UNUSED",0x1000:"PROTECT_DELAYLOAD_IAT",0x2000:"DELAYLOAD_IAT_IN_ITS_OWN_SECTION",0x4000:"CF_EXPORT_SUPPRESSION_INFO_PRESENT",0x8000:"CF_ENABLE_EXPORT_SUPPRESSION",0x10000:"CF_LONGJUMP_TABLE_PRESENT",0x100000:"RETPOLINE_PRESENT",0x1000000:"EH_CONTINUATION_TABLE_PRESENT",0x2000000:"XFG_ENABLED",0x4000000:"MEMTAG_PRESENT",0x8000000:"CET_SHADOW_STACK_PRESENT"} # From winnt.h
            for flag_val,flag_name in gf_map.items():
                if lc.GuardFlags&flag_val:gf_list.append(f"IMAGE_GUARD_{flag_name}")
            load_config_dict['guard_flags_list']=gf_list
        return load_config_dict
    return None

def _parse_com_descriptor(pe: pefile.PE) -> Optional[Dict[str, Any]]:
    # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR is index 14
    com_desc_idx=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
    if hasattr(pe.OPTIONAL_HEADER,'DATA_DIRECTORY')and len(pe.OPTIONAL_HEADER.DATA_DIRECTORY)>com_desc_idx and pe.OPTIONAL_HEADER.DATA_DIRECTORY[com_desc_idx].VirtualAddress!=0 and hasattr(pe,'DIRECTORY_ENTRY_COM_DESCRIPTOR')and pe.DIRECTORY_ENTRY_COM_DESCRIPTOR and hasattr(pe.DIRECTORY_ENTRY_COM_DESCRIPTOR,'struct'):
        com_desc=pe.DIRECTORY_ENTRY_COM_DESCRIPTOR.struct;com_dict:Dict[str,Any]={'struct':com_desc.dump_dict()};flags_list=[]
        # Flags from CorHdr.h (COMIMAGE_FLAGS_...)
        flags_map={0x1:"ILONLY",0x2:"32BITREQUIRED",0x4:"IL_LIBRARY",0x8:"STRONGNAMESIGNED",0x10:"NATIVE_ENTRYPOINT",0x10000:"TRACKDEBUGDATA",0x20000:"32BITPREFERRED"} # Some common flags
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
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC: # IMAGE_BASE_RELOCATION blocks
            block:Dict[str,Any]={'struct':base_reloc.struct.dump_dict(),'entries':[]}
            if hasattr(base_reloc,'entries'): # Relocation entries within this block
                for entry in base_reloc.entries:block['entries'].append({'rva':hex(entry.rva),'type':entry.type,'type_str':get_relocation_type_str(entry.type),'is_padding':getattr(entry,'is_padding',False)})
            relocs_list.append(block)
    return relocs_list

def _parse_bound_imports(pe: pefile.PE) -> List[Dict[str, Any]]:
    bound_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_BOUND_IMPORT'):
        for desc in pe.DIRECTORY_ENTRY_BOUND_IMPORT: # IMAGE_BOUND_IMPORT_DESCRIPTOR
            d_dict:Dict[str,Any]={'struct':desc.struct.dump_dict(),'name':None,'forwarder_refs':[]}
            try:d_dict['name']=desc.name.decode('utf-8','ignore')if desc.name else"N/A"
            except:pass # Keep N/A if error
            if hasattr(desc,'entries'): # IMAGE_BOUND_FORWARDER_REF entries
                for ref in desc.entries:
                    r_dict:Dict[str,Any]={'struct':ref.struct.dump_dict(),'name':None}
                    try:r_dict['name']=ref.name.decode('utf-8','ignore')if ref.name else"N/A"
                    except:pass # Keep N/A
                    d_dict['forwarder_refs'].append(r_dict)
            bound_list.append(d_dict)
    return bound_list

def _parse_exception_data(pe: pefile.PE) -> List[Dict[str, Any]]:
    ex_list=[]
    if hasattr(pe,'DIRECTORY_ENTRY_EXCEPTION')and pe.DIRECTORY_ENTRY_EXCEPTION:
        # For x64, these are RUNTIME_FUNCTION entries. For x86, it's different (SEH).
        # pefile parses them generically based on arch.
        for entry in pe.DIRECTORY_ENTRY_EXCEPTION:
            if hasattr(entry,'struct'):
                entry_dump=entry.struct.dump_dict();machine=pe.FILE_HEADER.Machine
                if machine==pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:entry_dump['note']="x64 RUNTIME_FUNCTION ( unwind info at UnwindInfoAddressRVA )"
                elif machine==pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']and hasattr(entry.struct,'ExceptionHandler'):entry_dump['note']="x86 SEH Frame (uncommon, usually handled by OS)"
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
            idx+=1 # Move to next symbol index
            if symbol.NumberOfAuxSymbols>0:
                for aux_i in range(symbol.NumberOfAuxSymbols):
                    if idx<len(pe.SYMBOLS):
                        aux_obj=None
                        # The auxiliary symbol data is directly in pe.SYMBOLS[idx].struct
                        if hasattr(pe.SYMBOLS[idx],'struct'):aux_obj=pe.SYMBOLS[idx].struct
                        if aux_obj:sym_dict['auxiliary_symbols'].append(_dump_aux_symbol_to_dict(symbol.struct,aux_obj,aux_i))
                        idx+=1 # Consume auxiliary symbol
                    else:break # Should not happen if NumberOfAuxSymbols is correct
            coff_list.append(sym_dict)
    return coff_list

def _verify_checksum(pe: pefile.PE) -> Dict[str, Any]:
    if hasattr(pe,'OPTIONAL_HEADER')and hasattr(pe.OPTIONAL_HEADER,'CheckSum'):
        hdr_sum=pe.OPTIONAL_HEADER.CheckSum;calc_sum=pe.generate_checksum()
        return {'header_checksum':hex(hdr_sum),'calculated_checksum':hex(calc_sum),'matches':hdr_sum==calc_sum if hdr_sum!=0 else"Header checksum is 0 (not verified)"}
    return {"error":"Checksum info not available."}

# --- FLOSS Analysis Helper Functions ---
def _setup_floss_logging(script_verbose_level: int, floss_internal_verbose_level: int):
    """
    Configures FLOSS internal loggers based on script's verbosity settings.
    script_verbose_level: Corresponds to FLOSS DebugLevel (NONE, DEFAULT, TRACE, SUPERTRACE)
    floss_internal_verbose_level: Corresponds to FLOSS's own -v, -vv flags (0, 1, 2)
                                   This is primarily for the verbosity of string output, not general logging.
                                   The script's general --verbose controls FLOSS's internal loggers.
    """
    if not FLOSS_SETUP_OK: # If basic FLOSS logging components aren't even available
        logger.debug("FLOSS setup not OK, skipping FLOSS logger configuration.")
        return

    # Determine the overall logging level for FLOSS components
    # This maps the script's --verbose/--debug type flags to FLOSS's internal logger levels
    floss_log_level_setting = logging.WARNING # Default to WARNING to keep FLOSS quiet unless specified
    if script_verbose_level >= Actual_DebugLevel_Floss.SUPERTRACE: # e.g. script --floss-debug-level SUPERTRACE
        floss_log_level_setting = FLOSS_TRACE_LEVEL_CONST # Show TRACE and above from FLOSS
    elif script_verbose_level >= Actual_DebugLevel_Floss.TRACE: # e.g. script --floss-debug-level TRACE
        floss_log_level_setting = FLOSS_TRACE_LEVEL_CONST
    elif script_verbose_level >= Actual_DebugLevel_Floss.DEFAULT: # e.g. script --floss-debug-level DEBUG
        floss_log_level_setting = logging.DEBUG
    elif script_verbose_level > Actual_DebugLevel_Floss.NONE : # A general verbose flag for the script might imply INFO for FLOSS
        floss_log_level_setting = logging.INFO


    logger.info(f"Setting FLOSS-related loggers to: {logging.getLevelName(floss_log_level_setting)}")
    for logger_name_floss in FLOSS_LOGGERS_LIST:
        # Special handling for very verbose loggers in FLOSS if needed
        if logger_name_floss in ("floss.api_hooks", "floss.function_argument_getter") and \
           script_verbose_level < Actual_DebugLevel_Floss.SUPERTRACE:
            logging.getLogger(logger_name_floss).setLevel(logging.WARNING) # Keep these quieter unless SUPERTRACE
        else:
            logging.getLogger(logger_name_floss).setLevel(floss_log_level_setting)

    # Configure Vivisect log level based on FLOSS debug level
    if FLOSS_ANALYSIS_OK: # set_vivisect_log_level is in floss.utils
        if script_verbose_level < Actual_DebugLevel_Floss.TRACE:
            set_vivisect_log_level(logging.CRITICAL)
            logging.getLogger("viv_utils.emulator_drivers").setLevel(logging.ERROR)
        else: # TRACE or SUPERTRACE for FLOSS
            set_vivisect_log_level(logging.DEBUG)
            logging.getLogger("viv_utils.emulator_drivers").setLevel(logging.DEBUG)
        logger.info(f"Vivisect loggers configured based on FLOSS debug level {script_verbose_level}.")
    else:
        logger.debug("FLOSS analysis components (like floss.utils) not available, cannot set Vivisect log level via FLOSS.")

def _load_floss_vivisect_workspace(sample_path_obj: Path, format_hint: str) -> Optional[VivWorkspace]:
    """Loads a Vivisect workspace for FLOSS analysis."""
    if not FLOSS_ANALYSIS_OK or not viv_utils: # Check if viv_utils was imported
        logger.error("Vivisect utilities (viv_utils) required by FLOSS are not available. Cannot load workspace.")
        return None
    
    logger.info(f"FLOSS: Loading Vivisect workspace for: {sample_path_obj} (format: {format_hint})")
    vw = None
    try:
        if format_hint == "auto":
            # Basic auto-detection based on suffix, FLOSS might do more internally
            if sample_path_obj.suffix.lower() in (".sc32", ".raw32"): format_hint = "sc32"
            elif sample_path_obj.suffix.lower() in (".sc64", ".raw64"): format_hint = "sc64"
            # else, it will be treated as 'pe' by default by viv_utils.getWorkspace

        if format_hint == "sc32":
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(sample_path_obj), arch="i386", analyze=True)
        elif format_hint == "sc64":
            vw = viv_utils.getShellcodeWorkspaceFromFile(str(sample_path_obj), arch="amd64", analyze=True)
        else: # "pe" or other formats viv_utils can handle
            vw = viv_utils.getWorkspace(str(sample_path_obj), analyze=True, should_save=False)
        
        if vw: logger.info("FLOSS: Vivisect workspace analysis complete.")
        else: logger.warning("FLOSS: Vivisect workspace loading returned None.")
        return vw
    except Exception as e:
        logger.error(f"FLOSS: Error loading Vivisect workspace: {e}", exc_info=True)
        return None

def _parse_floss_analysis(
    pe_filepath_str: str,
    min_length: int,
    floss_verbose_level: int, # This is FLOSS's own -v, -vv for string output (0,1,2)
    floss_script_debug_level: int, # This is this script's verbosity mapped to FLOSS DebugLevel enum
    floss_format_hint: str,
    floss_disabled_types: List[str],
    floss_only_types: List[str],
    floss_functions_to_analyze: List[int], # List of function RVAs/VAs
    quiet_mode_for_floss_progress: bool, # For disabling FLOSS's own progress bars
    regex_search_pattern: Optional[str] = None
    ) -> Dict[str, Any]:
    """
    Performs string extraction using FLOSS, enriches with context, ranks with StringSifter,
    and returns a structured result.
    """
    floss_results_dict: Dict[str, Any] = {
        "status": "Not performed", "error": None,
        "metadata": {}, "analysis_config": {},
        "strings": {
            "static_strings": [], "stack_strings": [],
            "tight_strings": [], "decoded_strings": []
        },
        "regex_matches": []
    }

    if not FLOSS_AVAILABLE:
        floss_results_dict["status"] = "FLOSS library not available."
        floss_results_dict["error"] = f"Setup: {FLOSS_IMPORT_ERROR_SETUP}, Analysis: {FLOSS_IMPORT_ERROR_ANALYSIS}"
        logger.warning("FLOSS analysis requested but FLOSS is not fully available.")
        return floss_results_dict

    _setup_floss_logging(floss_script_debug_level, floss_verbose_level)

    log_progress = floss_script_debug_level >= Actual_DebugLevel_Floss.DEFAULT

    if log_progress:
        logger.info(f"--- Starting FLOSS Analysis for: {pe_filepath_str} ---")
    sample_path = Path(pe_filepath_str)

    analysis_conf = FlossAnalysis(
        enable_static_strings=Actual_StringType_Floss.STATIC not in floss_disabled_types,
        enable_stack_strings=Actual_StringType_Floss.STACK not in floss_disabled_types,
        enable_tight_strings=Actual_StringType_Floss.TIGHT not in floss_disabled_types,
        enable_decoded_strings=Actual_StringType_Floss.DECODED not in floss_disabled_types,
    )
    if floss_only_types:
        analysis_conf.enable_static_strings = Actual_StringType_Floss.STATIC in floss_only_types
        analysis_conf.enable_stack_strings = Actual_StringType_Floss.STACK in floss_only_types
        analysis_conf.enable_tight_strings = Actual_StringType_Floss.TIGHT in floss_only_types
        analysis_conf.enable_decoded_strings = Actual_StringType_Floss.DECODED in floss_only_types

    floss_results_dict["analysis_config"] = {
        "static_enabled": analysis_conf.enable_static_strings,
        "stack_enabled": analysis_conf.enable_stack_strings,
        "tight_enabled": analysis_conf.enable_tight_strings,
        "decoded_enabled": analysis_conf.enable_decoded_strings,
        "min_length": min_length,
        "format_hint": floss_format_hint,
        "functions_to_analyze_count": len(floss_functions_to_analyze),
        "floss_internal_verbosity": floss_verbose_level,
    }

    if analysis_conf.enable_static_strings:
        if log_progress: logger.info("FLOSS: Extracting static strings...")
        try:
            static_strings_gen = get_static_strings(sample_path, min_length)
            static_list = []
            for s_obj in static_strings_gen:
                static_list.append({"offset": hex(s_obj.offset), "string": s_obj.string})
            floss_results_dict["strings"]["static_strings"] = static_list
            logger.info(f"FLOSS: Found {len(static_list)} static strings.")
        except Exception as e:
            logger.error(f"FLOSS: Error extracting static strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
            floss_results_dict["strings"]["static_strings"] = [{"error": str(e)}]

    vw: Optional[VivWorkspace] = None
    selected_functions_fvas_set: Set[int] = set()
    needs_vivisect = (analysis_conf.enable_stack_strings or \
                      analysis_conf.enable_tight_strings or \
                      analysis_conf.enable_decoded_strings or \
                      analysis_conf.enable_static_strings)

    if needs_vivisect:
        if log_progress: logger.info("FLOSS: Preparing Vivisect workspace for deeper analysis...")
        vw = _load_floss_vivisect_workspace(sample_path, floss_format_hint)
        if vw:
            try:
                imagebase = get_imagebase(vw)
                floss_results_dict["metadata"]["imagebase"] = imagebase # Store as int for calculations
                all_vw_functions_vas = set(vw.getFunctions())
                if floss_functions_to_analyze:
                    valid_user_functions = set()
                    for fva_or_rva in floss_functions_to_analyze:
                        fva = fva_or_rva
                        if imagebase is not None and fva < imagebase :
                            fva = imagebase + fva_or_rva
                        if fva in all_vw_functions_vas:
                            valid_user_functions.add(fva)
                        else:
                            logger.warning(f"FLOSS: Requested function 0x{fva_or_rva:x} (resolved to VA 0x{fva:x}) not found in Vivisect workspace.")
                    selected_functions_fvas_set = valid_user_functions
                    if log_progress: logger.info(f"FLOSS: User specified {len(valid_user_functions)} valid functions for analysis.")
                else:
                    selected_functions_fvas_set = all_vw_functions_vas
                    if log_progress: logger.info(f"FLOSS: Will analyze all {len(all_vw_functions_vas)} functions found in Vivisect workspace.")
            except Exception as e_vw_setup:
                logger.error(f"FLOSS: Error during Vivisect workspace post-processing: {e_vw_setup}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                vw = None
        else:
            logger.error("FLOSS: Failed to load Vivisect workspace. Deeper analysis will be skipped.")
            floss_results_dict["status"] = "Vivisect workspace load failed"
            floss_results_dict["error"] = "Failed to load Vivisect workspace for FLOSS advanced analysis."

    if vw and analysis_conf.enable_static_strings and floss_results_dict["strings"]["static_strings"]:
        logger.info("FLOSS: Starting static string context enrichment...")
        image_base_from_meta = floss_results_dict.get("metadata", {}).get("imagebase")
        if image_base_from_meta:
            static_strings_list = floss_results_dict["strings"]["static_strings"]
            total_enriched_strings = 0
            logger.debug(f"Attempting to enrich {len(static_strings_list)} static strings.")
            for i, string_item in enumerate(static_strings_list):
                try:
                    string_offset = int(string_item["offset"], 16)
                    string_va = image_base_from_meta + string_offset
                    xrefs = vw.getXrefsTo(string_va)
                    
                    if i > 0 and i % 100 == 0:
                        logger.debug(f"Processing string {i}/{len(static_strings_list)} at VA {hex(string_va)}...")

                    if xrefs:
                        total_enriched_strings += 1
                        logger.debug(f"Found {len(xrefs)} cross-references for string at {hex(string_va)}")
                        string_item["references"] = []
                        for ref_tuple in xrefs:
                            from_va = ref_tuple[0]
                            ref_func_va = vw.getFunction(from_va)
                            context_snippet = []
                            for j in range(-2, 3):
                                try:
                                    op = vw.getOpcode(from_va + (j * 4))
                                    if op:
                                        context_snippet.append(f"{hex(op.va)}: {op.mnem} {op.getOperands() if op else ''}")
                                except Exception:
                                    pass
                            
                            string_item["references"].append({
                                "ref_from_va": hex(from_va),
                                "function_va": hex(ref_func_va) if ref_func_va else None,
                                "disassembly_context": context_snippet
                            })
                except Exception as e_xref:
                    logger.warning(f"Could not get xrefs for string at {string_item['offset']}: {e_xref}")
            logger.info(f"FLOSS: Context enrichment complete. Enriched {total_enriched_strings} out of {len(static_strings_list)} static strings with references.")
        else:
            logger.warning("FLOSS: Skipping static string context enrichment because imagebase could not be determined.")

    if vw and FLOSS_ANALYSIS_OK:
        decoding_features_map: Dict[int, Any] = {}
        if analysis_conf.enable_decoded_strings or analysis_conf.enable_tight_strings:
            if log_progress: logger.info("FLOSS: Identifying decoding function features...")
            try:
                decoding_features_map, _ = find_decoding_function_features(vw, list(selected_functions_fvas_set), disable_progress=quiet_mode_for_floss_progress)
                if log_progress: logger.info(f"FLOSS: Found decoding features for {len(decoding_features_map)} functions.")
            except Exception as e:
                logger.error(f"FLOSS: Error finding decoding features: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                err_msg_feat = {"error": f"Feature identification error: {str(e)}"}
                if analysis_conf.enable_decoded_strings: floss_results_dict["strings"]["decoded_strings"] = [err_msg_feat]
                if analysis_conf.enable_tight_strings: floss_results_dict["strings"]["tight_strings"] = [err_msg_feat]

        if analysis_conf.enable_stack_strings:
            if log_progress: logger.info("FLOSS: Extracting stack strings...")
            try:
                stack_strings_gen = extract_stackstrings(
                    vw, list(selected_functions_fvas_set), min_length,
                    verbosity=floss_verbose_level,
                    disable_progress=quiet_mode_for_floss_progress
                )
                stack_list = []
                for s_obj in stack_strings_gen:
                    stack_list.append({
                        "function_va": hex(s_obj.function),
                        "string_va": hex(s_obj.offset),
                        "string": s_obj.string
                    })
                floss_results_dict["strings"]["stack_strings"] = stack_list
                logger.info(f"FLOSS: Found {len(stack_list)} stack strings.")
            except Exception as e:
                logger.error(f"FLOSS: Error extracting stack strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                floss_results_dict["strings"]["stack_strings"] = [{"error": str(e)}]

        if analysis_conf.enable_tight_strings:
            if log_progress: logger.info("FLOSS: Extracting tight strings...")
            try:
                if not decoding_features_map and (analysis_conf.enable_decoded_strings or analysis_conf.enable_tight_strings):
                    logger.warning("FLOSS: Decoding features map is empty, cannot identify functions with tight loops.")
                    floss_results_dict["strings"]["tight_strings"] = [{"error": "Decoding features map was empty, prerequisite for tight strings."}]
                else:
                    tightloop_fvas_dict = get_functions_with_tightloops(decoding_features_map)

                    if log_progress: logger.info(f"FLOSS: Identified {len(tightloop_fvas_dict)} functions with tight loops for tight string analysis.")

                    if tightloop_fvas_dict:
                        tight_strings_gen = extract_tightstrings(
                            vw, tightloop_fvas_dict, min_length,
                            verbosity=floss_verbose_level,
                            disable_progress=quiet_mode_for_floss_progress
                        )
                        tight_list = []
                        for s_obj in tight_strings_gen:
                            tight_list.append({
                                # FIX: Changed s_obj.function_address to s_obj.function
                                "function_va": hex(s_obj.function),
                                "address_or_offset": hex(s_obj.address if hasattr(s_obj, 'address') else s_obj.offset),
                                "string": s_obj.string
                            })
                        floss_results_dict["strings"]["tight_strings"] = tight_list
                        logger.info(f"FLOSS: Found {len(tight_list)} tight strings.")
                    else:
                        if log_progress: logger.info("FLOSS: No functions with tight loops identified from features. Skipping tight string extraction.")
                        floss_results_dict["strings"]["tight_strings"] = []
            except Exception as e:
                logger.error(f"FLOSS: Error extracting tight strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                floss_results_dict["strings"]["tight_strings"] = [{"error": str(e)}]

        if analysis_conf.enable_decoded_strings:
            if log_progress: logger.info("FLOSS: Extracting decoded strings...")
            try:
                if not decoding_features_map and (analysis_conf.enable_decoded_strings or analysis_conf.enable_tight_strings):
                    logger.warning("FLOSS: Decoding features map is empty, cannot identify top candidate functions for decoding.")
                    floss_results_dict["strings"]["decoded_strings"] = [{"error": "Decoding features map was empty, prerequisite for decoded strings."}]
                else:
                    top_candidate_funcs_features = get_top_functions(decoding_features_map, 20)
                    fvas_to_emulate_set = get_function_fvas(top_candidate_funcs_features)
                    if log_progress: logger.info(f"FLOSS: Identified {len(fvas_to_emulate_set)} top candidate functions for decoded string emulation.")
                    if fvas_to_emulate_set:
                        decoded_strings_gen = decode_strings(
                            vw, list(fvas_to_emulate_set), min_length,
                            verbosity=floss_verbose_level,
                            disable_progress=quiet_mode_for_floss_progress
                        )
                        decoded_list = []
                        for s_obj in decoded_strings_gen:
                            decoded_list.append({
                                "string_va": hex(s_obj.address),
                                "string": s_obj.string,
                                "decoding_routine_va": hex(s_obj.decoding_routine)
                            })
                        floss_results_dict["strings"]["decoded_strings"] = decoded_list
                        logger.info(f"FLOSS: Found {len(decoded_list)} decoded strings.")
                    else:
                        if log_progress: logger.info("FLOSS: No candidate functions found for decoded string emulation from features.")
                        floss_results_dict["strings"]["decoded_strings"] = []
            except Exception as e:
                logger.error(f"FLOSS: Error extracting decoded strings: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
                floss_results_dict["strings"]["decoded_strings"] = [{"error": str(e)}]

        floss_results_dict["status"] = "FLOSS analysis complete."
    elif needs_vivisect and not vw:
        floss_results_dict["status"] = "FLOSS analysis incomplete due to Vivisect workspace load failure."
        floss_results_dict["error"] = floss_results_dict.get("error", "Vivisect workspace could not be loaded.")
        err_msg_vw = {"error": "Vivisect workspace load failed"}
        if analysis_conf.enable_stack_strings: floss_results_dict["strings"]["stack_strings"] = [err_msg_vw]
        if analysis_conf.enable_tight_strings: floss_results_dict["strings"]["tight_strings"] = [err_msg_vw]
        if analysis_conf.enable_decoded_strings: floss_results_dict["strings"]["decoded_strings"] = [err_msg_vw]
    elif not needs_vivisect:
         floss_results_dict["status"] = "FLOSS analysis complete (only static strings requested/enabled)."
    else:
        floss_results_dict["status"] = "FLOSS analysis status unclear."

    if regex_search_pattern:
        if log_progress:
            logger.info(f"Performing regex search with pattern: '{regex_search_pattern}'")

        try:
            pattern = re.compile(regex_search_pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid regex pattern provided: {e}", exc_info=(floss_script_debug_level > Actual_DebugLevel_Floss.NONE))
            floss_results_dict["regex_matches"] = [{"error": f"Invalid regex pattern: {e}"}]
            return floss_results_dict

        all_found_strings = []
        for source_type, string_list in floss_results_dict["strings"].items():
            for string_item in string_list:
                if isinstance(string_item, dict) and "string" in string_item:
                    contextual_item = string_item.copy()
                    contextual_item["source_type"] = source_type.replace("_strings", "")
                    all_strings_with_context.append(contextual_item)

        matched_strings = []
        for string_item in all_strings_with_context:
            string_to_search = string_item["string"]
            if pattern.search(string_to_search):
                matched_strings.append(string_item)

        floss_results_dict["regex_matches"] = matched_strings
        if log_progress:
            logger.info(f"Found {len(matched_strings)} strings matching the regex pattern.")

    if log_progress or "complete" not in floss_results_dict["status"].lower():
        logger.info(f"--- FLOSS Analysis for: {pe_filepath_str} Finished (Status: {floss_results_dict['status']}) ---")

    return floss_results_dict

def _perform_unified_string_sifting(pe_info_dict: Dict[str, Any]):
    """
    Finds all strings from all sources, categorizes them, ranks them with
    StringSifter, and adds the enriched data back into the dictionary.
    This function modifies pe_info_dict in place.
    """
    if not STRINGSIFTER_AVAILABLE:
        logger.info("StringSifter not available, skipping string ranking.")
        return

    logger.info("Performing unified string categorization and sifting...")
    try:
        all_strings_for_sifter = []
        string_object_map = collections.defaultdict(list)

        all_string_sources = [
            pe_info_dict.get('floss_analysis', {}).get('strings', {}).values(),
            [pe_info_dict.get('basic_ascii_strings', [])]
        ]

        for source_group in all_string_sources:
            for string_list in source_group:
                if not isinstance(string_list, list): continue
                for string_item in string_list:
                    if isinstance(string_item, dict) and "string" in string_item and "error" not in string_item:
                        str_val = string_item["string"]
                        # --- NEW: Categorization Step ---
                        string_item['category'] = _get_string_category(str_val)
                        # --- End of New Step ---
                        all_strings_for_sifter.append(str_val)
                        string_object_map[str_val].append(string_item)

        if not all_strings_for_sifter:
            logger.info("No strings found from any source to rank.")
            return

        logger.info(f"Ranking {len(all_strings_for_sifter)} total strings with StringSifter...")
        modeldir = os.path.join(sifter_util.package_base(), "model")
        featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
        ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))

        X_test = featurizer.transform(all_strings_for_sifter)
        y_scores = ranker.predict(X_test)

        string_score_map = {s: score for s, score in zip(all_strings_for_sifter, y_scores)}
        for str_val, score in string_score_map.items():
            for original_item_dict in string_object_map.get(str_val, []):
                original_item_dict['sifter_score'] = round(float(score), 4)

        logger.info("Unified string sifting and categorization complete.")

    except Exception as e_sifter:
        logger.error(f"Error during unified string analysis: {e_sifter}", exc_info=True)
        pe_info_dict["sifter_error"] = str(e_sifter)

def _correlate_strings_and_capa(pe_info_dict: Dict[str, Any]):
    """
    Correlates string usage with Capa's behavioral findings by checking if
    a string's referencing function is also flagged by a Capa rule.
    Modifies pe_info_dict in place.
    """
    logger.info("Correlating strings with Capa behavioral indicators...")
    try:
        capa_analysis = pe_info_dict.get('capa_analysis')
        floss_analysis = pe_info_dict.get('floss_analysis')

        if not capa_analysis or not floss_analysis or 'results' not in capa_analysis or not capa_analysis.get('results'):
            logger.info("Skipping correlation: Capa or FLOSS results are missing or incomplete.")
            return

        capa_rules = capa_analysis.get('results', {}).get('rules', {})
        if not capa_rules:
            logger.info("No Capa rules found in results to correlate.")
            return

        # 1. Build a map of Function VA -> List of Capa Rule Names
        capa_func_map = collections.defaultdict(list)
        for rule_name, rule_details in capa_rules.items():
            rule_meta = rule_details.get('meta', {})
            capa_id = rule_meta.get('name', rule_name)
            if rule_meta.get('namespace'):
                capa_id = f"{rule_meta['namespace']}/{capa_id}"

            matches_data = rule_details.get("matches", {})
            match_addresses = set()
            if isinstance(matches_data, dict):
                match_addresses.update(matches_data.keys())
            elif isinstance(matches_data, list):
                for item in matches_data:
                    if isinstance(item, list) and len(item) > 0 and isinstance(item[0], dict) and 'value' in item[0]:
                        match_addresses.add(item[0]['value'])
            
            for addr in match_addresses:
                capa_func_map[addr].append(capa_id)

        # 2. Iterate through all FLOSS strings and check for correlation
        all_strings_with_refs = []
        floss_string_types = floss_analysis.get('strings', {})
        for str_type, str_list in floss_string_types.items():
            if not isinstance(str_list, list): continue
            for string_item in str_list:
                if not isinstance(string_item, dict): continue
                
                # Handle static strings with their list of references
                if 'references' in string_item:
                    for ref in string_item.get('references', []):
                        if ref.get('function_va'):
                            try:
                                all_strings_with_refs.append((string_item, int(ref['function_va'], 16)))
                            except (ValueError, TypeError): continue
                # Handle stack, tight, and decoded strings
                elif 'function_va' in string_item:
                    try:
                        all_strings_with_refs.append((string_item, int(string_item['function_va'], 16)))
                    except (ValueError, TypeError): continue
                elif 'decoding_routine_va' in string_item:
                    try:
                        all_strings_with_refs.append((string_item, int(string_item['decoding_routine_va'], 16)))
                    except (ValueError, TypeError): continue

        # 3. Add correlation data back to the string items
        for string_item, func_va in all_strings_with_refs:
            if func_va in capa_func_map:
                if 'related_capabilities' not in string_item:
                    string_item['related_capabilities'] = []
                
                for capa_rule in capa_func_map[func_va]:
                    if capa_rule not in string_item['related_capabilities']:
                        string_item['related_capabilities'].append(capa_rule)
        
        logger.info("String and Capa correlation complete.")

    except Exception as e:
        logger.error(f"Failed to correlate strings and Capa results: {e}", exc_info=True)
        pe_info_dict['correlation_error'] = str(e)

def _get_string_category(string_value: str) -> Optional[str]:
    """
    Categorizes a string based on a set of regular expressions for common
    indicator of compromise (IOC) patterns.

    Args:
        string_value: The string to categorize.

    Returns:
        A string representing the category (e.g., 'ipv4', 'url') or None if no category matches.
    """
    # Note: These regexes are examples and can be refined for better accuracy.
    # The order matters, as it will return the first category that matches.
    REGEX_CATEGORIES = {
        "ipv4": re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"),
        "url": re.compile(r"^(https?|ftp)://[^\s/$.?#].[^\s]*$"),
        "domain": re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}$"),
        "filepath_windows": re.compile(r"^[a-zA-Z]:\\[\\\S|*\S].*"),
        "registry_key": re.compile(r"^(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKCR|HKEY_CLASSES_ROOT|HKU|HKEY_USERS)\\[\w\\\s\-. ]+"),
        "email": re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
    }

    for category, pattern in REGEX_CATEGORIES.items():
        if pattern.match(string_value):
            return category
    return None

def _xor_bytes(data: bytes, key_bytes: bytes) -> bytes:
    """Helper function to perform XOR on a byte string with a key of any length."""
    key_len = len(key_bytes)
    if key_len == 0:
        return data
    return bytes([data[i] ^ key_bytes[i % key_len] for i in range(len(data))])

def _extract_staged_payloads(data: bytes, ctx: Optional[Context] = None, loop: Optional[asyncio.AbstractEventLoop] = None) -> List[Tuple[str, bytes]]:
    """
    Scans data for a common 4-byte XOR stager pattern and decodes the payload.
    This pattern consists of a header [type][payload_size][xor_key][id] followed by the payload.
    This version includes more robust checks to find embedded PE files.
    """
    staged_payloads = []
    header_format = '<IIII' # payload_type, payload_size, xor_key, id2
    header_size = struct.calcsize(header_format)

    for i in range(len(data) - header_size):
        try:
            payload_type, payload_size, xor_key, id2 = struct.unpack(header_format, data[i:i+header_size])

            if xor_key == 0 or not (4096 < payload_size < len(data)):
                continue
            
            payload_start = i + header_size
            if payload_start + payload_size > len(data):
                continue

            encrypted_payload = data[payload_start : payload_start + payload_size]
            xor_key_bytes = struct.pack('<I', xor_key)
            
            decoded_payload = _xor_bytes(encrypted_payload, xor_key_bytes)

            # --- BUG FIX ---
            # Instead of a strict startswith, find the MZ header near the beginning.
            # Some packers add a few bytes of junk before the PE.
            mz_offset = decoded_payload.find(b'MZ')
            
            # Check if 'MZ' is found and is within the first few bytes (e.g., 16)
            if mz_offset != -1 and mz_offset < 16:
                location_desc = f"Staged PE Payload (found at offset 0x{i:x}, key 0x{xor_key:x}, size 0x{payload_size:x})"
                # --- ASYNC BUG FIX ---
                # Pass the main event loop to the thread to safely call async functions.
                if ctx and loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(ctx.info(f"Config Hunter: Found potential staged payload at offset 0x{i:x}"), loop)
                
                # Append the *trimmed* payload, starting from the MZ header.
                staged_payloads.append((location_desc, decoded_payload[mz_offset:]))

        except struct.error:
            continue
            
    return staged_payloads

def _parse_config_from_profile(data: bytes, profile: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parses a decrypted data blob according to a dynamically constructed configuration profile.
    """
    parsed_config = {}
    endian_char = '>' if profile.get('structure_definition', {}).get('endian', 'big') == 'big' else '<'
    fields = profile.get('structure_definition', {}).get('fields', [])
    field_map = {field['id']: field for field in fields}

    offset = 0
    try:
        while offset < len(data) - 6: 
            setting_id_raw, data_type_raw, length = struct.unpack(f'{endian_char}HHH', data[offset:offset+6])
            offset += 6

            setting_id_str = f"{setting_id_raw:04x}"

            if setting_id_raw == 0:
                break 

            if setting_id_str not in field_map:
                offset += length
                continue

            field_def = field_map[setting_id_str]
            field_name = field_def['name']
            field_type = field_def['type']
            value_data = data[offset:offset+length]
            offset += length

            if field_type == 'short':
                parsed_config[field_name] = struct.unpack(f'{endian_char}H', value_data)[0]
            elif field_type == 'integer':
                parsed_config[field_name] = struct.unpack(f'{endian_char}I', value_data)[0]
            elif field_type == 'string':
                parsed_config[field_name] = value_data.split(b'\x00', 1)[0].decode('utf-8', 'ignore')
            elif field_type == 'bytes':
                parsed_config[field_name] = value_data.hex()
            elif field_type == 'raw_bytes':
                 parsed_config[field_name] = value_data
            else:
                parsed_config[field_name] = value_data.hex()

    except (struct.error, IndexError) as e:
        logger.warning(f"Config Hunter: Error parsing structure at offset {offset}: {e}")
        return None

    return parsed_config

# --- Main PE Parsing Logic ---
def _parse_pe_to_dict(pe: pefile.PE, filepath: str,
                      peid_db_path: Optional[str],
                      yara_rules_path: Optional[str],
                      capa_rules_path: Optional[str],
                      capa_sigs_path: Optional[str],
                      verbose: bool, # General script verbosity
                      skip_full_peid_scan: bool, 
                      peid_scan_all_sigs_heuristically: bool,
                      # FLOSS specific args
                      floss_min_len_arg: int,
                      floss_verbose_level_arg: int, # FLOSS's own -v, -vv (0,1,2)
                      floss_script_debug_level_arg: int, # Script's verbosity for FLOSS loggers (DebugLevel enum)
                      floss_format_hint_arg: str,
                      floss_disabled_types_arg: List[str],
                      floss_only_types_arg: List[str],
                      floss_functions_to_analyze_arg: List[int],
                      floss_quiet_mode_arg: bool, # For FLOSS progress bars
                      analyses_to_skip: Optional[List[str]] = None
                      ) -> Dict[str, Any]:
    global PEFILE_VERSION_USED
    try: PEFILE_VERSION_USED = pefile.__version__
    except AttributeError: PEFILE_VERSION_USED = "Unknown"

    if analyses_to_skip is None:
        analyses_to_skip = []
    analyses_to_skip = [analysis.lower() for analysis in analyses_to_skip]


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

    if "peid" not in analyses_to_skip:
        pe_info_dict['peid_matches'] = _perform_peid_scan(pe, peid_db_path, verbose, skip_full_peid_scan, peid_scan_all_sigs_heuristically)
    else:
        pe_info_dict['peid_matches'] = {"status": "Skipped by user request", "ep_matches": [], "heuristic_matches": []}
        logger.info("PEiD analysis skipped by request.")

    if "yara" not in analyses_to_skip:
        pe_info_dict['yara_matches'] = perform_yara_scan(filepath, pe.__data__, yara_rules_path, YARA_AVAILABLE, verbose)
    else:
        pe_info_dict['yara_matches'] = [{"status": "Skipped by user request"}]
        logger.info("YARA analysis skipped by request.")

    if "capa" not in analyses_to_skip:
        pe_info_dict['capa_analysis'] = _parse_capa_analysis(pe, filepath, capa_rules_path, capa_sigs_path, verbose)
    else:
        pe_info_dict['capa_analysis'] = {"status": "Skipped by user request", "results": None, "error": None}
        logger.info("Capa analysis skipped by request.")
    
    if "floss" not in analyses_to_skip:
        pe_info_dict['floss_analysis'] = _parse_floss_analysis(
            filepath,
            floss_min_len_arg,
            floss_verbose_level_arg,
            floss_script_debug_level_arg,
            floss_format_hint_arg,
            floss_disabled_types_arg,
            floss_only_types_arg,
            floss_functions_to_analyze_arg,
            floss_quiet_mode_arg
        )
    else:
        pe_info_dict['floss_analysis'] = {"status": "Skipped by user request", "strings": {}}
        logger.info("FLOSS analysis skipped by request.")

    pe_info_dict['basic_ascii_strings'] = [
        {"offset": hex(offset), "string": s, "source_type": "basic_ascii"}
        for offset, s in _extract_strings_from_data(pe.__data__, 5)
    ]

    _perform_unified_string_sifting(pe_info_dict)
    
    _correlate_strings_and_capa(pe_info_dict)

    pe_info_dict['pefile_warnings'] = pe.get_warnings()
    return pe_info_dict

def _decode_single_byte_xor(data: bytes) -> Optional[Tuple[bytes, int]]:
    """
    Attempts to decode data by bruteforcing a single-byte XOR key.

    It tries every possible key from 1 to 255. For each result, it checks
    how much of the output is printable ASCII. It returns the decoded bytes
    and the key that produced the most printable result, but only if that
    result meets a minimum printability threshold.

    Args:
        data: The byte string to decode.

    Returns:
        A tuple containing the decoded bytes and the key used, or None if no
        key produces a sufficiently printable result.
    """
    best_result = None
    max_printable_score = 0
    best_key = 0

    # A successful XOR decode should be mostly ASCII text
    required_printable_ratio = 0.85

    for key in range(1, 256):
        decoded_bytes = bytes([b ^ key for b in data])
        
        # Score the result based on how many characters are printable
        printable_chars = sum(1 for b in decoded_bytes if 32 <= b <= 126 or b in [9, 10, 13])
        
        try:
            printable_score = printable_chars / len(decoded_bytes)
        except ZeroDivisionError:
            printable_score = 0

        if printable_score > max_printable_score:
            max_printable_score = printable_score
            best_result = decoded_bytes
            best_key = key

    # Only return a result if it's highly likely to be text
    if max_printable_score > required_printable_ratio:
        return (best_result, best_key)

    return None

# --- CLI Printing Helper Functions ---
VERBOSE_CLI_OUTPUT_FLAG = False # Global to control verbosity in print helpers

def _print_dict_structure_cli(data_dict: Dict[str, Any], indent: int = 1, title: Optional[str] = None):
    prefix = "  " * indent
    if title: safe_print(f"{prefix}{title}:")
    for key, value in data_dict.items():
        if key == "Structure": continue # Skip the "Structure" key if present from pefile dump_dict
        if isinstance(value, dict) and "Value" in value and isinstance(value["Value"], dict): # Nested pefile structure
            _print_dict_structure_cli(value["Value"], indent + 1, title=key)
        elif isinstance(value, list) and value and isinstance(value[0], dict) and "Value" in value[0] and "Structure" in value[0]: # List of pefile structures
            safe_print(f"{prefix}  {key}:")
            for i, item_struct_container in enumerate(value):
                if isinstance(item_struct_container, dict) and "Value" in item_struct_container:
                     _print_dict_structure_cli(item_struct_container["Value"], indent + 2, title=f"Item {i+1}")
                else: # Should not happen if format is consistent
                    safe_print(f"{prefix}    Item {i+1}: {item_struct_container}")
        elif isinstance(value, list) or isinstance(value, tuple):
            val_str = ', '.join(map(str, value)) if value else '[]'
            if len(val_str) > 120 and not VERBOSE_CLI_OUTPUT_FLAG : val_str = val_str[:117] + "..."
            safe_print(f"{prefix}  {key:<30} {val_str}")
        else:
            val_str = str(value)
            if len(val_str) > 120 and not VERBOSE_CLI_OUTPUT_FLAG: val_str = val_str[:117] + "..."
            safe_print(f"{prefix}  {key:<30} {val_str}")


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
        safe_print("\n   --- File Header (IMAGE_FILE_HEADER) ---")
        fh = nt_headers['file_header']
        if "error" in fh: safe_print(f"     {fh['error']}")
        elif "Value" in fh:
            _print_dict_structure_cli(fh["Value"], indent=2)
            safe_print(f"     TimeDateStamp (Formatted):        {fh.get('TimeDateStamp_ISO')}")
            safe_print(f"     Characteristics Flags:            {', '.join(fh.get('characteristics_list',[]))}")
    if 'optional_header' in nt_headers:
        safe_print("\n   --- Optional Header (IMAGE_OPTIONAL_HEADER) ---")
        oh = nt_headers['optional_header']
        if "error" in oh: safe_print(f"     {oh['error']}")
        elif "Value" in oh:
            _print_dict_structure_cli(oh["Value"], indent=2)
            safe_print(f"     PE Type:                          {oh.get('pe_type')}")
            safe_print(f"     DllCharacteristics Flags:         {', '.join(oh.get('dll_characteristics_list',[]))}")

def _print_data_directories_cli(data_dirs: List[Dict[str, Any]]):
    safe_print("\n--- Data Directories (IMAGE_DATA_DIRECTORY) ---")
    if not data_dirs: safe_print("  Data Directories not found or empty."); return
    for entry_dict in data_dirs:
        entry_value = entry_dict.get('Value', {}); entry_name = entry_dict.get('name', 'Unknown')
        # Only print if directory has size or address, or if verbose
        if entry_value.get('Size',0)>0 or entry_value.get('VirtualAddress',0)>0 or VERBOSE_CLI_OUTPUT_FLAG:
            safe_print(f"  {entry_name:<30} {'Offset' if entry_name=='IMAGE_DIRECTORY_ENTRY_SECURITY' else 'RVA'}: {hex(entry_value.get('VirtualAddress',0)):<12} Size: {hex(entry_value.get('Size',0))}")

def _print_sections_cli(sections_data: List[Dict[str, Any]], pe_obj: Optional[pefile.PE]):
    safe_print("\n--- Section Table (IMAGE_SECTION_HEADER) ---")
    if not sections_data: safe_print("  No sections found."); return
    for section_dict in sections_data:
        safe_print(f"\n  Section: {section_dict.get('name_str', 'Unknown Section')}")
        if "Value" in section_dict: _print_dict_structure_cli(section_dict["Value"], indent=2)
        safe_print(f"    Characteristics Flags:           {', '.join(section_dict.get('characteristics_list',[]))}")
        safe_print(f"    Entropy:                         {section_dict.get('entropy', 0.0):.4f}")
        if section_dict.get('md5'): safe_print(f"    MD5:                             {section_dict.get('md5')}")
        if section_dict.get('ssdeep'): safe_print(f"    SSDeep:                          {section_dict.get('ssdeep')}")
        if pe_obj and VERBOSE_CLI_OUTPUT_FLAG: # Only print data sample if verbose
            try:
                # Find the pefile.Section() object corresponding to this dict
                pe_sec = next((s for s in pe_obj.sections if s.Name.decode('utf-8','ignore').rstrip('\x00') == section_dict.get('name_str')), None)
                if pe_sec:
                    data_sample = pe_sec.get_data()[:32] # Get first 32 bytes
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
    safe_print(f"  Exported DLL Name:                 {exports_data.get('name', 'N/A')}")
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
            if "Value" in fixed_info: # Print other fixed file info if verbose or structure is simple
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
            else:safe_print(f"    Signify Info: {val_res}") # Should be a list or error string
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

    if yara_res and isinstance(yara_res[0], dict) and yara_res[0].get("status") == "Skipped by user request":
        safe_print(f"  YARA Status: {yara_res[0]['status']}")
        return
    if yara_res and isinstance(yara_res[0], dict) and "error" in yara_res[0]:
        safe_print(f"  YARA Error: {yara_res[0]['error']}")
        return

    if yara_res:
        safe_print(f"  YARA Matches Found ({len(yara_res)}):")
        for match in yara_res:
            if isinstance(match, dict):
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
            else:
                safe_print(f"    Unexpected YARA match format: {type(match)}")
    else: safe_print("  No YARA matches found.")


def _print_capa_analysis_cli(capa_analysis_data: Dict[str, Any], verbose_flag: bool):
    safe_print("\n--- Capa Capability Analysis ---")
    if not capa_analysis_data:
        safe_print("  Capa analysis data not available.")
        return

    status = capa_analysis_data.get("status", "Unknown status")
    if status != "Analysis complete (adapted workflow)" and status != "Analysis complete":
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

        safe_print(f"\n  Capability: {rule_meta.get('name', rule_name)}")
        if rule_meta.get('namespace'):
            safe_print(f"    Namespace: {rule_meta.get('namespace')}")

        attck_entries = rule_meta.get('att&ck', [])
        if attck_entries:
            attck_display_list = []
            for entry in attck_entries:
                if isinstance(entry, dict):
                    display_str = entry.get('id', entry.get('name', str(entry)))
                    attck_display_list.append(str(display_str))
                else:
                    attck_display_list.append(str(entry))
            safe_print(f"    ATT&CK: {', '.join(attck_display_list)}")

        mbc_entries = rule_meta.get('mbc', [])
        if mbc_entries:
            mbc_display_list = []
            for entry in mbc_entries:
                if isinstance(entry, dict):
                    display_str = entry.get('id', entry.get('objective', entry.get('name', str(entry))))
                    mbc_display_list.append(str(display_str))
                else:
                    mbc_display_list.append(str(entry))
            safe_print(f"    MBC: {', '.join(mbc_display_list)}")


        if verbose_flag:
            if rule_meta.get('description'):
                safe_print(f"    Description: {rule_meta.get('description')}")
            if rule_meta.get('authors'):
                safe_print(f"    Authors: {', '.join(rule_meta.get('authors',[]))}")

        matches_data = rule_details.get("matches")
        
        # This block is updated to handle both dict and list formats
        match_locations = collections.defaultdict(list)
        if isinstance(matches_data, dict):
            for addr, details in matches_data.items():
                match_locations[addr].extend(details)
        elif isinstance(matches_data, list) and matches_data:
            for item in matches_data:
                if isinstance(item, list) and len(item) == 2:
                    addr_obj, detail_obj = item[0], item[1]
                    if isinstance(addr_obj, dict) and "value" in addr_obj:
                        addr_val = addr_obj["value"]
                        match_locations[addr_val].append(detail_obj)

        if match_locations:
            safe_print(f"    Matches ({len(match_locations)}):")
            match_count_on_cli = 0
            for addr_val, match_list_at_addr in sorted(match_locations.items()):
                addr_hex = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)
                if not verbose_flag and match_count_on_cli >= 3:
                    safe_print(f"      ... (additional matches for this rule omitted, use --verbose)")
                    break
                safe_print(f"      At Address: {addr_hex}")
                if verbose_flag and isinstance(match_list_at_addr, list):
                    for match_idx, match_item_detail in enumerate(match_list_at_addr):
                        feature_desc = "N/A"
                        if isinstance(match_item_detail, dict):
                            feature_dict = match_item_detail.get('feature', {})
                            if isinstance(feature_dict, dict):
                                feature_type = feature_dict.get('type', 'N/A')
                                feature_value = feature_dict.get('value', '')
                                feature_description = feature_dict.get('description', '')
                                parts = [f"Type: {feature_type}"]
                                if feature_value: parts.append(f"Value: {str(feature_value)[:50]}")
                                if feature_description: parts.append(f"Desc: {str(feature_description)[:50]}")
                                feature_desc = ", ".join(parts)
                            else:
                                feature_desc = f"Feature: {str(feature_dict)[:100]}"
                        else:
                            feature_desc = f"Match item: {str(match_item_detail)[:100]}"
                        safe_print(f"        Match Detail #{match_idx+1}: {feature_desc}")
                match_count_on_cli += 1
        else:
            safe_print("    No specific address match locations found.")


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
    limit = None if verbose_flag else 50; displayed_count = 0 # Limit if not verbose
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

def _print_floss_analysis_cli(floss_data: Dict[str, Any], verbose_flag: bool):
    """Prints FLOSS analysis results to the console."""
    safe_print("\n--- FLOSS Advanced String Analysis ---")
    if not floss_data or "status" not in floss_data:
        safe_print("  FLOSS analysis data not available or malformed.")
        return

    status = floss_data.get("status", "Unknown status")
    safe_print(f"  Status: {status}")
    if floss_data.get("error"):
        safe_print(f"  Error: {floss_data['error']}")
    
    if verbose_flag and floss_data.get("metadata"):
        safe_print("  FLOSS Metadata:")
        for k, v in floss_data["metadata"].items():
            safe_print(f"    {k.replace('_', ' ').title()}: {v}")
            
    if verbose_flag and floss_data.get("analysis_config"):
        safe_print("  FLOSS Analysis Configuration:")
        for k, v in floss_data["analysis_config"].items():
            safe_print(f"    {k.replace('_', ' ').title()}: {v}")

    strings_results = floss_data.get("strings", {})
    if not strings_results and status == "FLOSS library not available.":
        return

    for str_type, str_list in strings_results.items():
        type_name_pretty = str_type.replace("_", " ").title()
        safe_print(f"\n  --- {type_name_pretty} ---")
        if isinstance(str_list, list) and str_list:
            if isinstance(str_list[0], dict) and "error" in str_list[0]:
                safe_print(f"    Error during extraction: {str_list[0]['error']}")
                continue

            # If verbose, sort by sifter score to show most relevant first
            if verbose_flag and 'sifter_score' in str_list[0]:
                str_list_sorted = sorted(str_list, key=lambda x: x.get('sifter_score', 0.0), reverse=True)
            else:
                str_list_sorted = str_list

            limited_str_list = str_list_sorted[:20] if not verbose_flag and len(str_list_sorted) > 20 else str_list_sorted
            for item_idx, item_dict in enumerate(limited_str_list):
                sifter_score_str = ""
                if verbose_flag and 'sifter_score' in item_dict:
                    sifter_score_str = f" (Sifter Score: {item_dict['sifter_score']:.2f})"

                if str_type == "static_strings":
                    safe_print(f"    Offset: {item_dict.get('offset', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}")
                elif str_type == "stack_strings":
                    safe_print(f"    Function VA: {item_dict.get('function_va', 'N/A')}, String VA: {item_dict.get('string_va', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}")
                elif str_type == "tight_strings":
                    safe_print(f"    Function VA: {item_dict.get('function_va', 'N/A')}, Addr/Offset: {item_dict.get('address_or_offset', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}")
                elif str_type == "decoded_strings":
                    char_str = f" (Characteristics: {', '.join(item_dict.get('characteristics',[]))})" if item_dict.get('characteristics') else ""
                    safe_print(f"    String VA: {item_dict.get('string_va', 'N/A')}, Routine VA: {item_dict.get('decoding_routine_va', 'N/A')}, String: \"{item_dict.get('string', '')}\"{sifter_score_str}{char_str}")
                else:
                    safe_print(f"    {item_dict}")
            
            if not verbose_flag and len(str_list_sorted) > 20:
                safe_print(f"    ... ({len(str_list_sorted) - 20} more strings omitted, use --verbose for all {type_name_pretty})")
        elif not str_list:
             safe_print(f"    No {type_name_pretty.lower()} found.")
        else:
            safe_print(f"    Unexpected data format for {type_name_pretty}: {type(str_list)}")


# --- Main CLI Printing Function ---
def _cli_analyze_and_print_pe(filepath: str, peid_db_path: Optional[str],
                              yara_rules_path: Optional[str],
                              capa_rules_dir: Optional[str], 
                              capa_sigs_dir: Optional[str],
                              verbose: bool,
                              skip_full_peid_scan: bool, 
                              peid_scan_all_sigs_heuristically: bool,
                              # FLOSS args
                              floss_min_len_cli: int,
                              floss_verbose_level_cli: int,
                              floss_script_debug_level_cli: int,
                              floss_format_hint_cli: str,
                              floss_disabled_types_cli: List[str],
                              floss_only_types_cli: List[str],
                              floss_functions_to_analyze_cli: List[int],
                              floss_quiet_mode_cli: bool,
                              # General CLI args
                              extract_strings_cli: bool, 
                              min_str_len_cli: int,
                              search_strings_cli: Optional[List[str]], 
                              strings_limit_cli: int,
                              hexdump_offset_cli: Optional[int], 
                              hexdump_length_cli: Optional[int],
                              hexdump_lines_cli: int,
                              analyses_to_skip_cli_arg: Optional[List[str]] = None 
                              ):
    global PEFILE_VERSION_USED, VERBOSE_CLI_OUTPUT_FLAG
    VERBOSE_CLI_OUTPUT_FLAG = verbose 
    
    pefile_version_str = "unknown"
    try: pefile_version_str = pefile.__version__
    except AttributeError: pass

    if verbose: 
        logger.info(f"Starting CLI analysis for: {filepath}. pefile version: {pefile_version_str}")
    
    safe_print(f"[*] Analyzing PE file: {filepath}\n")
    
    pe_obj_for_cli = None 
    try:
        pe_obj_for_cli = pefile.PE(filepath, fast_load=False)
    except pefile.PEFormatError as e_pe_format:
        safe_print(f"[!] Error: Not a valid PE file or PE format error: {e_pe_format}")
        logger.error(f"PEFormatError for CLI file '{filepath}': {e_pe_format}", exc_info=verbose)
        raise 
    except FileNotFoundError:
        safe_print(f"[!] Error: Input file not found: {filepath}")
        logger.error(f"FileNotFoundError for CLI file '{filepath}'")
        raise
    except Exception as e_load:
        safe_print(f"[!] Error loading PE file for CLI analysis: {type(e_load).__name__} - {e_load}")
        logger.error(f"Generic error loading PE file '{filepath}' for CLI: {e_load}", exc_info=verbose)
        raise

    effective_analyses_to_skip = analyses_to_skip_cli_arg if analyses_to_skip_cli_arg is not None else []

    cli_pe_info_dict = _parse_pe_to_dict(
        pe_obj_for_cli, filepath, peid_db_path, yara_rules_path,
        capa_rules_dir, 
        capa_sigs_dir,
        verbose, skip_full_peid_scan, peid_scan_all_sigs_heuristically,
        # FLOSS args
        floss_min_len_cli,
        floss_verbose_level_cli,
        floss_script_debug_level_cli,
        floss_format_hint_cli,
        floss_disabled_types_cli,
        floss_only_types_cli,
        floss_functions_to_analyze_cli,
        floss_quiet_mode_cli,
        analyses_to_skip=effective_analyses_to_skip 
    )

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
    
    if "peid" not in effective_analyses_to_skip:
        _print_peid_matches_cli(cli_pe_info_dict.get('peid_matches',{}))
    else:
        safe_print("\n--- Packer/Compiler Detection (Custom PEiD) ---")
        safe_print("  Skipped by user request.")

    if "yara" not in effective_analyses_to_skip:
        _print_yara_matches_cli(cli_pe_info_dict.get('yara_matches',[]), yara_rules_path)
    else:
        safe_print("\n--- YARA Scan Results ---")
        safe_print("  Skipped by user request.")
        
    if "capa" not in effective_analyses_to_skip:
        _print_capa_analysis_cli(cli_pe_info_dict.get('capa_analysis',{}), verbose)
    else:
        safe_print("\n--- Capa Capability Analysis ---")
        safe_print("  Skipped by user request.")

    if "floss" not in effective_analyses_to_skip:
        _print_floss_analysis_cli(cli_pe_info_dict.get('floss_analysis',{}), verbose)
    else:
        safe_print("\n--- FLOSS Advanced String Analysis ---")
        safe_print("  Skipped by user request.")

    _print_rich_header_cli(cli_pe_info_dict.get('rich_header'))

    remaining_keys_to_print_generic = [
        ("delay_load_imports","Delay-Load Imports"), ("tls_info", "TLS Information"),
        ("load_config", "Load Configuration"), ("com_descriptor", ".NET COM Descriptor"),
        ("overlay_data", "Overlay Data"), ("base_relocations", "Base Relocations"),
        ("bound_imports", "Bound Imports"), ("exception_data", "Exception Data"),
        ("checksum_verification", "Checksum Verification")
    ]
    for key, title_str in remaining_keys_to_print_generic:
        data_item = cli_pe_info_dict.get(key)
        safe_print(f"\n--- {title_str} ---")
        if data_item is not None and data_item != {} and data_item != []: 
            if isinstance(data_item, list) and data_item: 
                for i, item_in_list in enumerate(data_item):
                    if isinstance(item_in_list, dict):
                        _print_dict_structure_cli(item_in_list, indent=1, title=f"Entry {i+1}")
                    else:
                        safe_print(f"  Entry {i+1}: {item_in_list}")
            elif isinstance(data_item, dict): 
                 _print_dict_structure_cli(data_item, indent=1)
            else: 
                safe_print(f"  {data_item}")
        else:
            safe_print(f"  No {title_str.lower()} information found.")

    _print_coff_symbols_cli(cli_pe_info_dict.get('coff_symbols',[]),verbose)
    _print_pefile_warnings_cli(cli_pe_info_dict.get('pefile_warnings',[]))

    if extract_strings_cli:
        safe_print(f"\n--- Extracted Strings (min_length={min_str_len_cli}, limit={strings_limit_cli}) ---")
        try:
            extracted_strings_list = _extract_strings_from_data(pe_obj_for_cli.__data__, min_str_len_cli)
            if not extracted_strings_list:
                safe_print("  No strings found matching criteria.")
            else:
                for i, (offset, s_val) in enumerate(extracted_strings_list):
                    if i >= strings_limit_cli:
                        safe_print(f"  ... (output limited to {strings_limit_cli} strings)")
                        break
                    safe_print(f"  Offset: {hex(offset)}: {s_val}")
        except Exception as e_str:
            safe_print(f"  Error during string extraction: {e_str}")
            logger.warning("CLI: Error during string extraction", exc_info=verbose)

    if search_strings_cli:
        safe_print(f"\n--- Searched Strings (limit {strings_limit_cli} per term) ---")
        try:
            search_results_dict = _search_specific_strings_in_data(pe_obj_for_cli.__data__, search_strings_cli)
            found_any_terms = False
            for term, offsets_list in search_results_dict.items():
                if offsets_list:
                    found_any_terms = True
                    safe_print(f"  Found '{term}' at offsets (limit {strings_limit_cli} per term shown):")
                    for i, offset_val in enumerate(offsets_list):
                        if i >= strings_limit_cli:
                            safe_print(f"    ... (further occurrences of '{term}' omitted)")
                            break
                        safe_print(f"      - {hex(offset_val)}")
                else:
                    safe_print(f"  String '{term}' not found.")
            if not found_any_terms and not search_results_dict: 
                 safe_print("  No specified strings found or search terms were empty.")

        except Exception as e_search:
            safe_print(f"  Error during specific string search: {e_search}")
            logger.warning("CLI: Error during specific string search", exc_info=verbose)

    if hexdump_offset_cli is not None and hexdump_length_cli is not None:
        safe_print(f"\n--- Hex Dump (Offset: {hex(hexdump_offset_cli)}, Length: {hexdump_length_cli}, Max Lines: {hexdump_lines_cli}) ---")
        try:
            file_size = len(pe_obj_for_cli.__data__)
            if hexdump_offset_cli >= file_size:
                safe_print("  Error: Start offset is beyond the file size.")
            else:
                actual_dump_length = min(hexdump_length_cli, file_size - hexdump_offset_cli)
                if actual_dump_length <= 0:
                    safe_print("  Error: Calculated length for hex dump is zero or negative (start_offset might be at or past EOF).")
                else:
                    data_chunk_to_dump = pe_obj_for_cli.__data__[hexdump_offset_cli : hexdump_offset_cli + actual_dump_length]
                    dump_lines_list = _format_hex_dump_lines(data_chunk_to_dump, start_address=hexdump_offset_cli)
                    
                    if not dump_lines_list:
                        safe_print("  No data to dump for the specified range (or range was empty).")
                    else:
                        for i, line_str in enumerate(dump_lines_list):
                            if i >= hexdump_lines_cli:
                                safe_print(f"  ... (output limited to {hexdump_lines_cli} lines)")
                                break
                            safe_print(f"  {line_str}") 
        except IndexError:
             safe_print("  Error: Hex dump range is invalid or out of bounds for the file data.")
        except Exception as e_dump:
            safe_print(f"  Error during hex dump: {e_dump}")
            logger.warning("CLI: Error during hex dump", exc_info=verbose)
            
    safe_print("\n[*] CLI Analysis complete.")

    if pe_obj_for_cli:
        pe_obj_for_cli.close()

# --- MCP Server Setup ---
mcp_server = FastMCP("PEFileAnalyzerMCP", description="MCP Server for PE file analysis. Pre-analyzes the --input-file at startup. Tools operate on this pre-loaded file.")
tool_decorator = mcp_server.tool()

# --- MCP Tools ---

@tool_decorator
async def search_floss_strings(
    ctx: Context,
    regex_patterns: List[str],
    min_sifter_score: Optional[float] = None,
    max_sifter_score: Optional[float] = None,
    sort_order: Optional[str] = None,
    min_length: int = 0,
    limit: int = 100,
    case_sensitive: bool = False
) -> Dict[str, Any]:
    """
    Performs a regex search against FLOSS strings, with advanced score filtering and sorting.

    Args:
        ctx: The MCP Context object.
        regex_patterns: (List[str]) A list of regex patterns to search for.
        min_sifter_score: (Optional[float]) If provided, only include strings with a sifter_score >= this value.
        max_sifter_score: (Optional[float]) If provided, only include strings with a sifter_score <= this value.
        sort_order: (Optional[str]) If provided, sorts results by score. Valid: 'ascending', 'descending'. Defaults to None (no sorting).
        min_length: (int) The minimum length for a matched string to be included. Defaults to 0.
        limit: (int) The maximum number of matches to return. Defaults to 100.
        case_sensitive: (bool) If True, the regex search will be case-sensitive. Defaults to False.

    Returns:
        A dictionary containing a list of matched strings and pagination information.

    Raises:
        RuntimeError: If no FLOSS analysis data is available or sifter is required but unavailable.
        ValueError: For invalid parameters or if the response size is too large.
    """
    await ctx.info(f"Request to search FLOSS strings. Patterns: {len(regex_patterns)}, Score Range: {min_sifter_score}-{max_sifter_score}, Sort: {sort_order}, Limit: {limit}")
    
    # --- Parameter Validation ---
    if (min_sifter_score is not None or max_sifter_score is not None or sort_order is not None) and not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("Score filtering/sorting is requested, but StringSifter is not available on the server.")
    if min_sifter_score is not None and not isinstance(min_sifter_score, (int, float)):
        raise ValueError("Parameter 'min_sifter_score' must be a number if provided.")
    if max_sifter_score is not None and not isinstance(max_sifter_score, (int, float)):
        raise ValueError("Parameter 'max_sifter_score' must be a number if provided.")
    if sort_order is not None and sort_order.lower() not in ['ascending', 'descending']:
        raise ValueError("Parameter 'sort_order' must be either 'ascending', 'descending', or None.")
    if not regex_patterns or not isinstance(regex_patterns, list):
        raise ValueError("The 'regex_patterns' parameter must be a non-empty list of strings.")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("The 'limit' parameter must be a positive integer.")

    # --- Data Retrieval ---
    if ANALYZED_PE_DATA is None or 'floss_analysis' not in ANALYZED_PE_DATA:
        raise RuntimeError("No FLOSS analysis data found. Please run an analysis first.")
    floss_data = ANALYZED_PE_DATA.get('floss_analysis', {})
    if not floss_data.get("strings"):
        return {"matches": [], "message": "No FLOSS strings available to search."}

    # --- Filtering Logic ---
    compiled_patterns = []
    try:
        flags = 0 if case_sensitive else re.IGNORECASE
        for pattern_str in regex_patterns:
            compiled_patterns.append(re.compile(pattern_str, flags))
    except re.error as e:
        raise ValueError(f"Invalid regex pattern provided in the list: {e}")

    all_strings_with_context = []
    for source_type, string_list in floss_data.get("strings", {}).items():
        for string_item in string_list:
            if isinstance(string_item, dict) and "string" in string_item:
                contextual_item = string_item.copy()
                contextual_item["source_type"] = source_type.replace("_strings", "")
                all_strings_with_context.append(contextual_item)

    matches = []
    for item in all_strings_with_context:
        # Score filtering
        score = item.get('sifter_score', -999.0)
        min_ok = (min_sifter_score is None) or (score >= min_sifter_score)
        max_ok = (max_sifter_score is None) or (score <= max_sifter_score)
        
        if min_ok and max_ok:
            # Length and Regex filtering
            string_to_search = item["string"]
            if any(p.search(string_to_search) for p in compiled_patterns):
                if len(string_to_search) >= min_length:
                    matches.append(item)

    # --- Sorting Logic ---
    if sort_order:
        is_reversed = (sort_order.lower() == 'descending')
        matches.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=is_reversed)

    # --- Finalize and Return ---
    paginated_matches = matches[:limit]
    response = {
        "matches": paginated_matches,
        "pagination_info": {
            "limit": limit,
            "returned_matches": len(paginated_matches),
            "total_matches_found": len(matches)
        }
    }
    
    limit_info_str = "the 'limit' parameter or by using more specific filters ('regex_patterns', 'min_sifter_score', etc.)"
    return await _check_mcp_response_size(ctx, response, "search_floss_strings", limit_info_str)

@tool_decorator
async def get_virustotal_report_for_loaded_file(ctx: Context) -> Dict[str, Any]:
    """
    Retrieves a summary report from VirusTotal for the pre-loaded PE file using its hash.
    Requires the 'requests' library and a VirusTotal API key set in the VT_API_KEY environment variable.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing VirusTotal report summary or an error status.
        Includes hashes (MD5, SHA1, SHA256, ssdeep) reported by VirusTotal,
        detection statistics, and other relevant metadata.

    Raises:
        RuntimeError: If no PE file is loaded or hashes are unavailable.
        ValueError: If the response size exceeds the server limit.
    """
    global ANALYZED_PE_DATA, VT_API_KEY, VT_API_URL_FILE_REPORT, REQUESTS_AVAILABLE

    tool_name = "get_virustotal_report_for_loaded_file"
    await ctx.info(f"Request for VirusTotal report for the loaded file.")

    if not ANALYZED_PE_DATA or 'file_hashes' not in ANALYZED_PE_DATA:
        raise RuntimeError("No PE file loaded or file hashes are unavailable. Cannot query VirusTotal.")

    file_hashes = ANALYZED_PE_DATA['file_hashes']
    main_hash_value: Optional[str] = None
    hash_type_used: Optional[str] = None

    if file_hashes.get('sha256'):
        main_hash_value = file_hashes['sha256']
        hash_type_used = "sha256"
    elif file_hashes.get('sha1'):
        main_hash_value = file_hashes['sha1']
        hash_type_used = "sha1"
    elif file_hashes.get('md5'):
        main_hash_value = file_hashes['md5']
        hash_type_used = "md5"

    if not main_hash_value or not hash_type_used:
        await ctx.error("No suitable hash (SHA256, SHA1, MD5) available for VirusTotal query.")
        # Check size for error message, though it will be small
        return await _check_mcp_response_size(ctx, {
            "status": "error",
            "message": "No suitable file hash (SHA256, SHA1, MD5) available for VirusTotal query.",
            "query_hash_type": None,
            "query_hash": None
        }, tool_name)


    if not VT_API_KEY:
        await ctx.warning("VirusTotal API key (VT_API_KEY) is not configured. Skipping VirusTotal lookup.")
        return await _check_mcp_response_size(ctx, {
            "status": "api_key_missing",
            "message": "VirusTotal API key (VT_API_KEY) is not configured in the environment.",
            "query_hash_type": hash_type_used,
            "query_hash": main_hash_value
        }, tool_name)

    if not REQUESTS_AVAILABLE:
        await ctx.warning("'requests' library is not available. Skipping VirusTotal lookup.")
        return await _check_mcp_response_size(ctx, {
            "status": "requests_unavailable",
            "message": "'requests' library is not installed/available, which is required for VirusTotal queries.",
            "query_hash_type": hash_type_used,
            "query_hash": main_hash_value
        }, tool_name)

    headers = {"x-apikey": VT_API_KEY}
    api_url = f"{VT_API_URL_FILE_REPORT}{main_hash_value}"
    response_payload: Dict[str, Any] = { # Default error/info structure
        "status": "pending",
        "query_hash_type": hash_type_used,
        "query_hash": main_hash_value,
        "locally_calculated_ssdeep": file_hashes.get('ssdeep'),
    }

    try:
        await ctx.info(f"Querying VirusTotal API for hash: {main_hash_value}")
        # Pyright might complain about requests.get in async, use to_thread
        http_response = await asyncio.to_thread(requests.get, api_url, headers=headers, timeout=20)

        if http_response.status_code == 200:
            vt_json_response = http_response.json()
            vt_attributes = vt_json_response.get("data", {}).get("attributes", {})

            vt_data_summary = {
                "report_link": f"https://www.virustotal.com/gui/file/{main_hash_value}",
                "retrieved_hashes": {
                    "md5": vt_attributes.get("md5"),
                    "sha1": vt_attributes.get("sha1"),
                    "sha256": vt_attributes.get("sha256"),
                    "ssdeep_from_vt": vt_attributes.get("ssdeep"), # ssdeep as reported by VT
                },
                "detection_stats": vt_attributes.get("last_analysis_stats"),
                "last_analysis_date_utc": datetime.datetime.fromtimestamp(vt_attributes.get("last_analysis_date"), datetime.timezone.utc).isoformat() if vt_attributes.get("last_analysis_date") else None,
                "first_submission_date_utc": datetime.datetime.fromtimestamp(vt_attributes.get("first_submission_date"), datetime.timezone.utc).isoformat() if vt_attributes.get("first_submission_date") else None,
                "last_submission_date_utc": datetime.datetime.fromtimestamp(vt_attributes.get("last_submission_date"), datetime.timezone.utc).isoformat() if vt_attributes.get("last_submission_date") else None,
                "reputation": vt_attributes.get("reputation"),
                "tags": vt_attributes.get("tags", []),
                "suggested_threat_label": vt_attributes.get("popular_threat_classification", {}).get("suggested_threat_label"),
                "trid": vt_attributes.get("trid", []), # TrID results if available
                "meaningful_name": vt_attributes.get("meaningful_name"),
                "names": list(set(vt_attributes.get("names", [])))[:10], # Unique names, limited count
                "size": vt_attributes.get("size"),
            }
            response_payload["status"] = "success"
            response_payload["message"] = "VirusTotal report summary retrieved successfully."
            response_payload["virustotal_report_summary"] = vt_data_summary
            await ctx.info(f"Successfully retrieved VirusTotal report for {main_hash_value}")

        elif http_response.status_code == 404:
            response_payload["status"] = "not_found"
            response_payload["message"] = f"Hash {main_hash_value} not found on VirusTotal."
            await ctx.info(f"Hash {main_hash_value} not found on VirusTotal.")
        elif http_response.status_code == 401:
            response_payload["status"] = "error_auth"
            response_payload["message"] = "VirusTotal API authentication failed. Check your VT_API_KEY."
            await ctx.error("VirusTotal API authentication failed (401).")
        elif http_response.status_code == 429:
            response_payload["status"] = "error_rate_limit"
            response_payload["message"] = "VirusTotal API rate limit exceeded. Please try again later."
            await ctx.warning("VirusTotal API rate limit exceeded (429).")
        else:
            response_payload["status"] = "error_api"
            response_payload["message"] = f"VirusTotal API returned an error. Status Code: {http_response.status_code}. Response: {http_response.text[:200]}"
            await ctx.error(f"VirusTotal API error for {main_hash_value}: {http_response.status_code} - {http_response.text[:200]}")

    except requests.exceptions.Timeout:
        response_payload["status"] = "error_timeout"
        response_payload["message"] = "Request to VirusTotal API timed out."
        await ctx.error(f"VirusTotal API request timed out for hash {main_hash_value}.")
    except requests.exceptions.RequestException as e_req:
        response_payload["status"] = "error_request"
        response_payload["message"] = f"Error during VirusTotal API request: {str(e_req)}"
        await ctx.error(f"VirusTotal API request error for {main_hash_value}: {e_req}")
    except Exception as e:
        response_payload["status"] = "error_unexpected"
        response_payload["message"] = f"An unexpected error occurred while fetching VirusTotal data: {str(e)}"
        logger.error(f"MCP: Unexpected error in {tool_name} for {main_hash_value}: {e}", exc_info=True)
        await ctx.error(f"Unexpected error in {tool_name}: {e}")

    limit_info_str = "parameters for this tool (none currently, rely on server-side summarization)"
    return await _check_mcp_response_size(ctx, response_payload, tool_name, limit_info_str)
    
@tool_decorator
async def reanalyze_loaded_pe_file(
    ctx: Context,
    peid_db_path: Optional[str] = None,
    yara_rules_path: Optional[str] = None,
    capa_rules_dir: Optional[str] = None,
    capa_sigs_dir: Optional[str] = None,
    analyses_to_skip: Optional[List[str]] = None,
    skip_capa_analysis: Optional[bool] = None,
    skip_floss_analysis: Optional[bool] = None, # New FLOSS skip flag
    # FLOSS specific args for re-analysis
    floss_min_length: Optional[int] = None,
    floss_verbose_level: Optional[int] = None, # FLOSS's own -v, -vv (0,1,2)
    floss_script_debug_level_for_floss_loggers: Optional[str] = None, # Script's verbosity for FLOSS (e.g. "INFO", "DEBUG", "TRACE", "SUPERTRACE")
    floss_format: Optional[str] = None,
    floss_no_static: Optional[bool] = None,
    floss_no_stack: Optional[bool] = None,
    floss_no_tight: Optional[bool] = None,
    floss_no_decoded: Optional[bool] = None,
    floss_only_static: Optional[bool] = None,
    floss_only_stack: Optional[bool] = None,
    floss_only_tight: Optional[bool] = None,
    floss_only_decoded: Optional[bool] = None,
    floss_functions: Optional[List[str]] = None, # Hex strings for function VAs/RVAs
    floss_quiet: Optional[bool] = None, # For FLOSS progress bars
    # General args
    verbose_mcp_output: bool = False,
    skip_full_peid_scan: bool = False,
    peid_scan_all_sigs_heuristically: bool = False
    ) -> Dict[str, Any]:
    """
    Re-triggers a full or partial analysis of the PE file that was pre-loaded at server startup.
    Allows skipping heavy analyses (PEiD, YARA, Capa, FLOSS) via 'analyses_to_skip' list or specific flags.
    The analysis results are updated globally. FLOSS specific parameters can also be provided.

    Args:
        ctx: The MCP Context object.
        peid_db_path: (Optional[str]) Path to PEiD userdb.txt.
        yara_rules_path: (Optional[str]) Path to YARA rule file/directory.
        capa_rules_dir: (Optional[str]) Path to capa rule directory.
        capa_sigs_dir: (Optional[str]) Path to capa library ID signature files.
        analyses_to_skip: (Optional[List[str]]) Analyses to skip ("peid", "yara", "capa", "floss").
        skip_capa_analysis: (Optional[bool]) If True, capa analysis will be skipped.
        skip_floss_analysis: (Optional[bool]) If True, FLOSS analysis will be skipped.
        floss_min_length: (Optional[int]) Min string length for FLOSS.
        floss_verbose_level: (Optional[int]) FLOSS's internal verbosity (0,1,2).
        floss_script_debug_level_for_floss_loggers: (Optional[str]) Logging level for FLOSS loggers (e.g. "INFO", "TRACE").
        floss_format: (Optional[str]) File format hint for FLOSS (auto, pe, sc32, sc64).
        floss_no_static: (Optional[bool]) Disable static string extraction in FLOSS.
        floss_no_stack: (Optional[bool]) Disable stack string extraction in FLOSS.
        floss_no_tight: (Optional[bool]) Disable tight string extraction in FLOSS.
        floss_no_decoded: (Optional[bool]) Disable decoded string extraction in FLOSS.
        floss_only_static: (Optional[bool]) Only extract static strings with FLOSS.
        floss_only_stack: (Optional[bool]) Only extract stack strings with FLOSS.
        floss_only_tight: (Optional[bool]) Only extract tight strings with FLOSS.
        floss_only_decoded: (Optional[bool]) Only extract decoded strings with FLOSS.
        floss_functions: (Optional[List[str]]) Hex addresses of functions for FLOSS to analyze.
        floss_quiet: (Optional[bool]) Suppress FLOSS progress indicators.
        verbose_mcp_output: (bool) Enables detailed logging for the analysis. Defaults to False.
        skip_full_peid_scan: (bool) If True and PEiD is not skipped, PEiD scan is entry point only. Defaults to False.
        peid_scan_all_sigs_heuristically: (bool) If True (PEiD not skipped, full scan not skipped), all PEiD sigs are used heuristically. Defaults to False.

    Returns:
        A dictionary indicating status: {"status": "success", "message": "File '...' re-analyzed.", "filepath": "..."}

    Raises:
        RuntimeError: If no PE file was successfully pre-loaded at startup, or if re-analysis fails.
        asyncio.CancelledError: If the underlying analysis task is cancelled by the MCP framework.
    """
    global ANALYZED_PE_FILE_PATH, ANALYZED_PE_DATA, PE_OBJECT_FOR_MCP

    if ANALYZED_PE_FILE_PATH is None or not os.path.exists(ANALYZED_PE_FILE_PATH) :
        await ctx.error("No PE file was successfully pre-loaded at server startup, or path is invalid. Cannot re-analyze.")
        raise RuntimeError("No PE file pre-loaded or pre-loaded file path is invalid. Cannot re-analyze.")

    await ctx.info(f"Request to re-analyze pre-loaded PE: {ANALYZED_PE_FILE_PATH}")

    normalized_analyses_to_skip = []
    if analyses_to_skip:
        normalized_analyses_to_skip = [analysis.lower() for analysis in analyses_to_skip]
    
    if skip_capa_analysis is True and "capa" not in normalized_analyses_to_skip:
        normalized_analyses_to_skip.append("capa")
        await ctx.info("Capa analysis will be skipped due to 'skip_capa_analysis=True'.")
    elif skip_capa_analysis is False and "capa" in normalized_analyses_to_skip:
        normalized_analyses_to_skip.remove("capa")
        await ctx.info("Capa analysis will be performed as 'skip_capa_analysis=False'.")

    if skip_floss_analysis is True and "floss" not in normalized_analyses_to_skip:
        normalized_analyses_to_skip.append("floss")
        await ctx.info("FLOSS analysis will be skipped due to 'skip_floss_analysis=True'.")
    elif skip_floss_analysis is False and "floss" in normalized_analyses_to_skip:
        normalized_analyses_to_skip.remove("floss")
        await ctx.info("FLOSS analysis will be performed as 'skip_floss_analysis=False'.")
            
    if normalized_analyses_to_skip:
        await ctx.info(f"Final list of analyses to skip during re-analysis: {', '.join(normalized_analyses_to_skip) if normalized_analyses_to_skip else 'None'}")

    current_peid_db_path = str(Path(peid_db_path).resolve()) if peid_db_path and Path(peid_db_path).exists() else str(DEFAULT_PEID_DB_PATH)
    current_yara_rules_path = str(Path(yara_rules_path).resolve()) if yara_rules_path and Path(yara_rules_path).exists() else None
    
    current_capa_rules_dir_to_use = None
    if "capa" not in normalized_analyses_to_skip and CAPA_AVAILABLE:
        if capa_rules_dir and Path(capa_rules_dir).is_dir() and os.listdir(Path(capa_rules_dir)):
            current_capa_rules_dir_to_use = str(Path(capa_rules_dir).resolve())
        else:
            if capa_rules_dir: await ctx.warning(f"Provided capa_rules_dir '{capa_rules_dir}' is invalid/empty. Capa will use its default logic.")
            current_capa_rules_dir_to_use = capa_rules_dir 

    current_capa_sigs_dir_to_use = None
    if "capa" not in normalized_analyses_to_skip and CAPA_AVAILABLE:
        if capa_sigs_dir and Path(capa_sigs_dir).is_dir():
            current_capa_sigs_dir_to_use = str(Path(capa_sigs_dir).resolve())
        else:
            current_capa_sigs_dir_to_use = capa_sigs_dir

    # FLOSS specific argument preparation for _parse_pe_to_dict
    # Use provided values if not None, otherwise use defaults or previously established values (e.g. from initial load)
    # For simplicity in re-analysis, if a FLOSS arg is None, it implies "use default for this run"
    # rather than trying to fetch from ANALYZED_PE_DATA (which might be complex).
    # The _parse_pe_to_dict will use FLOSS_MIN_LENGTH_DEFAULT if floss_min_length is None.

    mcp_floss_min_len = floss_min_length if floss_min_length is not None else FLOSS_MIN_LENGTH_DEFAULT
    mcp_floss_verbose_level = floss_verbose_level if floss_verbose_level is not None else 0 # Default to 0 (non-verbose FLOSS output)
    
    # Map FLOSS script debug level string to enum value
    mcp_floss_script_debug_level_enum_val = Actual_DebugLevel_Floss.NONE # Default
    if floss_script_debug_level_for_floss_loggers:
        floss_debug_map = {
            "NONE": Actual_DebugLevel_Floss.NONE, "DEFAULT": Actual_DebugLevel_Floss.DEFAULT,
            "DEBUG": Actual_DebugLevel_Floss.DEFAULT, # Map general "DEBUG" to FLOSS "DEFAULT"
            "TRACE": Actual_DebugLevel_Floss.TRACE, "SUPERTRACE": Actual_DebugLevel_Floss.SUPERTRACE
        }
        mcp_floss_script_debug_level_enum_val = floss_debug_map.get(floss_script_debug_level_for_floss_loggers.upper(), Actual_DebugLevel_Floss.NONE)
    
    mcp_floss_format_hint = floss_format if floss_format is not None else "auto"
    
    mcp_floss_disabled_types = []
    if floss_no_static: mcp_floss_disabled_types.append(Actual_StringType_Floss.STATIC)
    if floss_no_stack: mcp_floss_disabled_types.append(Actual_StringType_Floss.STACK)
    if floss_no_tight: mcp_floss_disabled_types.append(Actual_StringType_Floss.TIGHT)
    if floss_no_decoded: mcp_floss_disabled_types.append(Actual_StringType_Floss.DECODED)

    mcp_floss_only_types = []
    if floss_only_static: mcp_floss_only_types.append(Actual_StringType_Floss.STATIC)
    if floss_only_stack: mcp_floss_only_types.append(Actual_StringType_Floss.STACK)
    if floss_only_tight: mcp_floss_only_types.append(Actual_StringType_Floss.TIGHT)
    if floss_only_decoded: mcp_floss_only_types.append(Actual_StringType_Floss.DECODED)

    mcp_floss_functions_to_analyze = []
    if floss_functions:
        for func_str in floss_functions:
            try: mcp_floss_functions_to_analyze.append(int(func_str, 0)) # Auto-detect base (0x for hex)
            except ValueError: await ctx.warning(f"Invalid FLOSS function address '{func_str}', skipping.")
    
    mcp_floss_quiet_mode = floss_quiet if floss_quiet is not None else (not verbose_mcp_output)


    def perform_analysis_in_thread():
        temp_pe_obj = None 
        try:
            temp_pe_obj = pefile.PE(ANALYZED_PE_FILE_PATH, fast_load=False) 
            
            new_parsed_data = _parse_pe_to_dict(
                temp_pe_obj, ANALYZED_PE_FILE_PATH, current_peid_db_path, current_yara_rules_path,
                current_capa_rules_dir_to_use, 
                current_capa_sigs_dir_to_use,  
                verbose_mcp_output, skip_full_peid_scan, peid_scan_all_sigs_heuristically,
                # FLOSS args for _parse_pe_to_dict
                floss_min_len_arg=mcp_floss_min_len,
                floss_verbose_level_arg=mcp_floss_verbose_level,
                floss_script_debug_level_arg=mcp_floss_script_debug_level_enum_val,
                floss_format_hint_arg=mcp_floss_format_hint,
                floss_disabled_types_arg=mcp_floss_disabled_types,
                floss_only_types_arg=mcp_floss_only_types,
                floss_functions_to_analyze_arg=mcp_floss_functions_to_analyze,
                floss_quiet_mode_arg=mcp_floss_quiet_mode,
                analyses_to_skip=normalized_analyses_to_skip 
            )
            return temp_pe_obj, new_parsed_data
        except Exception as e_thread: 
            if temp_pe_obj:
                temp_pe_obj.close()
            logger.error(f"Error during threaded re-analysis of {ANALYZED_PE_FILE_PATH}: {e_thread}", exc_info=verbose_mcp_output)
            raise 

    try:
        new_pe_obj_from_thread, new_parsed_data_from_thread = await asyncio.to_thread(perform_analysis_in_thread)
        
        if PE_OBJECT_FOR_MCP: 
            PE_OBJECT_FOR_MCP.close()
        
        PE_OBJECT_FOR_MCP = new_pe_obj_from_thread 
        ANALYZED_PE_DATA = new_parsed_data_from_thread 

        await ctx.info(f"Successfully re-analyzed PE: {ANALYZED_PE_FILE_PATH}")
        skipped_msg_part = f" (Skipped: {', '.join(normalized_analyses_to_skip) if normalized_analyses_to_skip else 'None'})"
        return {"status":"success", "message":f"File '{ANALYZED_PE_FILE_PATH}' re-analyzed{skipped_msg_part}.", "filepath":ANALYZED_PE_FILE_PATH}

    except asyncio.CancelledError: 
        await ctx.warning(f"Re-analysis task for {ANALYZED_PE_FILE_PATH} was cancelled by MCP framework.")
        logger.info(f"Re-analysis of {ANALYZED_PE_FILE_PATH} cancelled. Global PE data remains from previous successful load/analysis.")
        raise 
    except Exception as e_outer: 
        await ctx.error(f"Error re-analyzing PE '{ANALYZED_PE_FILE_PATH}': {str(e_outer)}");
        logger.error(f"MCP: Error re-analyzing PE '{ANALYZED_PE_FILE_PATH}': {str(e_outer)}", exc_info=verbose_mcp_output)
        raise RuntimeError(f"Failed to re-analyze PE file '{ANALYZED_PE_FILE_PATH}': {str(e_outer)}") from e_outer

@tool_decorator
async def get_analyzed_file_summary(ctx: Context, limit: int) -> Dict[str, Any]:
    """
    Retrieves a high-level summary of the pre-loaded and analyzed PE file.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. Limits the number of top-level key-value pairs returned. Must be positive.

    Returns:
        A dictionary containing summary information.
    Raises:
        RuntimeError: If no PE file is currently loaded.
        ValueError: If limit is not a positive integer.
    """
    await ctx.info(f"Request for analyzed file summary. Limit: {limit}")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
        
    if ANALYZED_PE_DATA is None or ANALYZED_PE_FILE_PATH is None:
        raise RuntimeError("No PE file loaded. Server may not have pre-loaded the input file successfully.")

    floss_analysis_summary = ANALYZED_PE_DATA.get('floss_analysis', {})
    floss_strings_summary = floss_analysis_summary.get('strings', {})

    full_summary = {
        "filepath":ANALYZED_PE_FILE_PATH,"pefile_version_used":PEFILE_VERSION_USED,
        "has_dos_header":'dos_header'in ANALYZED_PE_DATA and ANALYZED_PE_DATA['dos_header']is not None and"error"not in ANALYZED_PE_DATA['dos_header'],
        "has_nt_headers":'nt_headers'in ANALYZED_PE_DATA and ANALYZED_PE_DATA['nt_headers']is not None and"error"not in ANALYZED_PE_DATA['nt_headers'],
        "section_count":len(ANALYZED_PE_DATA.get('sections',[])),
        "import_dll_count":len(ANALYZED_PE_DATA.get('imports',[])),
        "export_symbol_count":len(ANALYZED_PE_DATA.get('exports',{}).get('symbols',[])),
        "peid_ep_match_count":len(ANALYZED_PE_DATA.get('peid_matches',{}).get('ep_matches',[])),
        "peid_heuristic_match_count":len(ANALYZED_PE_DATA.get('peid_matches',{}).get('heuristic_matches',[])),
        "peid_status": ANALYZED_PE_DATA.get('peid_matches',{}).get('status',"Not run/Skipped"),
        "yara_match_count":len([m for m in ANALYZED_PE_DATA.get('yara_matches',[])if isinstance(m, dict) and "error" not in m and "status" not in m]),
        "yara_status": ANALYZED_PE_DATA.get('yara_matches',[{}])[0].get('status', "Run/No Matches or Not Run/Skipped") if ANALYZED_PE_DATA.get('yara_matches') and isinstance(ANALYZED_PE_DATA.get('yara_matches'), list) and ANALYZED_PE_DATA.get('yara_matches')[0] else "Not run/Skipped",
        "capa_status": ANALYZED_PE_DATA.get('capa_analysis',{}).get('status',"Not run/Skipped"),
        "capa_capability_count": len(ANALYZED_PE_DATA.get('capa_analysis',{}).get('results',{}).get('rules',{})) if ANALYZED_PE_DATA.get('capa_analysis',{}).get('status')=="Analysis complete (adapted workflow)" else 0,
        "floss_status": floss_analysis_summary.get('status', "Not run/Skipped"),
        "floss_static_string_count": len(floss_strings_summary.get('static_strings', [])),
        "floss_stack_string_count": len(floss_strings_summary.get('stack_strings', [])),
        "floss_tight_string_count": len(floss_strings_summary.get('tight_strings', [])),
        "floss_decoded_string_count": len(floss_strings_summary.get('decoded_strings', [])),
        "has_embedded_signature":ANALYZED_PE_DATA.get('digital_signature',{}).get('embedded_signature_present',False)
    }
    await ctx.info(f"Summary for {ANALYZED_PE_FILE_PATH} generated.")
    return dict(list(full_summary.items())[:limit])

# --- NEW: MCP Response Size Check Helper ---
async def _check_mcp_response_size(
    ctx: Context,
    data_to_return: Any,
    tool_name: str,
    limit_param_info: Optional[str] = None
) -> Any:
    """
    Checks if the serialized size of data_to_return exceeds MAX_MCP_RESPONSE_SIZE_BYTES.
    If it does, logs an error via ctx, and raises a ValueError.
    Otherwise, returns data_to_return.
    """
    try:
        # Serialize to JSON to get a representative size.
        # Ensure ensure_ascii=False to correctly measure UTF-8 byte length.
        serialized_data = json.dumps(data_to_return, ensure_ascii=False)
        data_size_bytes = len(serialized_data.encode('utf-8'))

        if data_size_bytes > MAX_MCP_RESPONSE_SIZE_BYTES:
            param_guidance = limit_param_info or "your request parameters (e.g., using limits, offsets, or stricter filters)"
            error_message = (
                f"Response from tool '{tool_name}' (approx. {data_size_bytes // 1024}KB) "
                f"exceeds the maximum allowed size ({MAX_MCP_RESPONSE_SIZE_KB}KB). "
                f"Please request less data by adjusting {param_guidance}."
            )
            await ctx.error(error_message)
            logger.warning(f"MCP: {tool_name} response too large ({data_size_bytes} bytes). Client needs to adjust request.")
            raise ValueError(error_message)
        
        return data_to_return
    except TypeError as e_json: # Handle cases where data might not be JSON serializable
        await ctx.error(f"Internal error in tool '{tool_name}': Could not serialize response data to check size. Error: {e_json}")
        logger.error(f"MCP: Failed to serialize response for '{tool_name}' for size check: {e_json}", exc_info=True)
        # Depending on policy, either raise or return an error dict. Raising is cleaner.
        raise ValueError(f"Internal error: Could not determine response size for tool '{tool_name}'.") from e_json
    except Exception as e_check: # Catch any other unexpected errors during the check
        await ctx.error(f"Internal error in tool '{tool_name}' while checking response size: {e_check}")
        logger.error(f"MCP: Unexpected error during response size check for '{tool_name}': {e_check}", exc_info=True)
        raise ValueError(f"Internal error: Failed response size check for tool '{tool_name}'.") from e_check

@tool_decorator
async def get_full_analysis_results(ctx: Context, limit: int) -> Dict[str, Any]:
    """
    Retrieves the complete analysis results for the pre-loaded PE file.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. Limits the number of top-level key-value pairs. Must be positive.

    Returns:
        A potentially large dictionary containing all parsed PE structures, hashes, scan results, etc.
    Raises:
        RuntimeError: If no PE file is currently loaded.
        ValueError: If limit is not a positive integer, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request for full PE analysis. Limit: {limit}")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")

    if ANALYZED_PE_DATA is None: raise RuntimeError("No PE file loaded. Server may not have pre-loaded the input file successfully.")
    
    # Prepare the data according to the client's limit on top-level keys
    data_to_send = dict(list(ANALYZED_PE_DATA.items())[:limit])
    
    # Now check the size of this potentially limited data
    limit_info = "the 'limit' parameter (to request fewer top-level keys) or use more specific data retrieval tools"
    return await _check_mcp_response_size(ctx, data_to_send, "get_full_analysis_results", limit_info)

def _create_mcp_tool_for_key(key_name: str, tool_description: str):
    async def _tool_func(ctx: Context, limit: int, offset: Optional[int] = 0) -> Any:
        await ctx.info(f"Request for '{key_name}'. Limit: {limit}, Offset: {offset}")
        if not (isinstance(limit, int) and limit > 0):
            raise ValueError(f"Parameter 'limit' for '{key_name}' must be a positive integer.")

        if ANALYZED_PE_DATA is None:
            raise RuntimeError(f"No PE file loaded. Server may not have pre-loaded the input file successfully. Cannot get '{key_name}'.")

        original_data = ANALYZED_PE_DATA.get(key_name)
        if original_data is None:
            await ctx.warning(f"Data for '{key_name}' not found in analyzed results. Returning empty structure.")
            # For empty structure, size check is trivial but let's be consistent
            return await _check_mcp_response_size(ctx, {}, f"get_{key_name}_info")


        # Apply offset first if data is a list
        processed_data = original_data
        if isinstance(original_data, list) and offset is not None:
            if not (isinstance(offset, int) and offset >= 0):
                await ctx.warning(f"Invalid 'offset' value '{offset}' for '{key_name}'. Using offset 0.")
                offset = 0
            if offset > 0:
                processed_data = original_data[offset:]
        elif offset != 0 and offset is not None: # Offset provided but not applicable
            await ctx.warning(f"Parameter 'offset' is provided but not applicable for data type '{type(original_data).__name__}' of key '{key_name}'. Ignoring offset.")
        
        # Apply limit
        data_to_send: Any
        if isinstance(processed_data, list):
            data_to_send = processed_data[:limit]
        elif isinstance(processed_data, dict): # Offset doesn't apply to dicts in this simple way
            try:
                data_to_send = dict(list(processed_data.items())[:limit])
            except Exception as e_dict_limit:
                await ctx.warning(f"Could not apply generic dictionary limit for '{key_name}': {e_dict_limit}. Will check size of full data for this key.")
                data_to_send = processed_data # Send full dict if limiting failed, size check will catch if too big
        else: # For other types, limit might not be directly applicable in this way
            await ctx.info(f"Data for key '{key_name}' is type '{type(processed_data).__name__}'. 'limit' parameter acknowledged but not directly used for slicing this type.")
            data_to_send = processed_data

        limit_info_str = f"the 'limit' or 'offset' parameters for data key '{key_name}'"
        return await _check_mcp_response_size(ctx, data_to_send, f"get_{key_name}_info", limit_info_str)

    _tool_func.__name__ = f"get_{key_name}_info"
    doc = f"""Retrieves the '{key_name}' portion of the PE analysis results for the pre-loaded file.

Prerequisites:
- A PE file must have been successfully pre-loaded at server startup.

Args:
    ctx: The MCP Context object.
    limit: (int) Mandatory. Limits the number of items returned. Must be a positive integer.
           For lists, it's the number of elements. For dictionaries, it's the number of top-level key-value pairs.
    offset: (Optional[int], default 0) Specifies the starting index for lists. Ignored for dictionaries.

Returns:
    The data associated with '{key_name}'. Structure depends on the key:
    - {tool_description}
    The return type is typically a dictionary or a list of dictionaries.

Raises:
    RuntimeError: If no PE file is currently loaded.
    ValueError: If limit is not a positive integer, or if the response size exceeds the server limit.
"""
    _tool_func.__doc__ = doc
    return tool_decorator(_tool_func)

TOOL_DEFINITIONS = {
    "file_hashes":"Cryptographic hashes (MD5, SHA1, SHA256, ssdeep) for the entire loaded PE file. Output is a dictionary.",
    "dos_header":"Detailed breakdown of the DOS_HEADER structure from the PE file. Output is a dictionary.",
    "nt_headers":"Detailed breakdown of NT_HEADERS, including File Header and Optional Header. Output is a dictionary.",
    "data_directories":"Information on all Data Directories (e.g., import, export, resource tables), including their RVAs and sizes. Output is a list of dictionaries.",
    "sections":"Detailed information for each section in the PE file (name, RVA, size, characteristics, entropy, hashes). Output is a list of dictionaries.",
    "imports":"List of imported DLLs and, for each DLL, the imported symbols (functions/ordinals). Output is a list of dictionaries.",
    "exports":"Information on exported symbols from the PE file, including name, RVA, ordinal, and any forwarders. Output is a dictionary.",
    "resources_summary":"A summary list of resources found in the PE file, detailing type, ID/name, language, RVA, and size. Output is a list of dictionaries.",
    "version_info":"Version information extracted from the PE file's version resource (e.g., FileVersion, ProductName). Output is a dictionary.",
    "debug_info":"Details from the debug directory, which may include PDB paths or CodeView information. Output is a list of dictionaries.",
    "digital_signature":"Information about the PE file's Authenticode digital signature, including certificate details and validation status (if 'cryptography' and 'signify' libs are available). Output is a dictionary.",
    "peid_matches":"Results from PEiD-like signature scanning, indicating potential packers or compilers. Includes entry-point and heuristic matches. Output is a dictionary.",
    "yara_matches":"Results from YARA scanning, listing any matched rules, tags, metadata, and string identifiers. Output is a list of dictionaries.",
    # "floss_analysis" will have its own dedicated tool due to complexity.
    "rich_header":"Decoded Microsoft Rich Header information, often indicating compiler/linker versions. Output is a dictionary.",
    "delay_load_imports":"Information on delay-loaded imported DLLs and their symbols. Output is a list of dictionaries.",
    "tls_info":"Details from the Thread Local Storage (TLS) directory, including any callback function addresses. Output is a dictionary.",
    "load_config":"Information from the Load Configuration directory, including flags like Control Flow Guard (CFG) status. Output is a dictionary.",
    "com_descriptor":"Information from the .NET COM Descriptor (IMAGE_COR20_HEADER) if the PE is a .NET assembly. Output is a dictionary.",
    "overlay_data":"Information about any data appended to the end of the PE file (overlay), including offset, size, and hashes. Output is a dictionary.",
    "base_relocations":"Details of base relocations within the PE file. Output is a list of dictionaries.",
    "bound_imports":"Information on bound imports, if present. Output is a list of dictionaries.",
    "exception_data":"Data from the exception directory (e.g., RUNTIME_FUNCTION entries for x64). Output is a list of dictionaries.",
    "coff_symbols":"COFF (Common Object File Format) symbol table entries, if present. Output is a list of dictionaries.",
    "checksum_verification":"Verification of the PE file's checksum against the value in the Optional Header. Output is a dictionary.",
    "pefile_warnings":"Any warnings generated by the 'pefile' library during parsing. Output is a list of strings."
}
for key, desc in TOOL_DEFINITIONS.items(): globals()[f"get_{key}_info"] = _create_mcp_tool_for_key(key, desc)

@tool_decorator
async def get_floss_analysis_info(ctx: Context,
                                  string_type: Optional[str] = None,
                                  only_with_references: bool = False,
                                  limit: int = 100,
                                  offset: Optional[int] = 0
                                 ) -> Dict[str, Any]:
    """
    Retrieves FLOSS analysis results, with new option to filter for strings with code context.

    Args:
        ctx: The MCP Context object.
        string_type: (Optional[str]) The type of FLOSS strings to retrieve. Valid values: "static_strings", "stack_strings", "tight_strings", "decoded_strings". If None, returns metadata.
        only_with_references: (bool) If True and string_type is 'static_strings', only return strings that have code cross-references. Defaults to False.
        limit: (int) Max number of strings to return if string_type is specified. Defaults to 100.
        offset: (Optional[int]) Starting index for string pagination if string_type is specified. Defaults to 0.

    Returns:
        A dictionary containing the requested FLOSS information.
    """
    await ctx.info(f"Request for FLOSS info. Type: {string_type}, Refs Only: {only_with_references}, Limit: {limit}")

    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if offset is not None and not (isinstance(offset, int) and offset >= 0):
        raise ValueError("Parameter 'offset' must be a non-negative integer if provided.")

    valid_string_types = ["static_strings", "stack_strings", "tight_strings", "decoded_strings"]
    if string_type is not None and string_type not in valid_string_types:
        raise ValueError(f"Invalid 'string_type'. Must be one of: {', '.join(valid_string_types)} or None.")

    if ANALYZED_PE_DATA is None or 'floss_analysis' not in ANALYZED_PE_DATA:
        raise RuntimeError("No PE file loaded or FLOSS analysis data unavailable.")

    floss_data_block = ANALYZED_PE_DATA.get('floss_analysis', {})
    status = floss_data_block.get("status", "Unknown")

    if status != "FLOSS analysis complete." and "incomplete" not in status:
         data_to_send = {"status": status, "error": floss_data_block.get("error", "FLOSS analysis did not complete successfully."), "data": {}}
         return await _check_mcp_response_size(ctx, data_to_send, "get_floss_analysis_info")

    response_data: Dict[str, Any] = {"status": status}
    if floss_data_block.get("error"): response_data["error_details"] = floss_data_block.get("error")


    if string_type is None: # Return metadata and config
        response_data["metadata"] = floss_data_block.get("metadata", {})
        response_data["analysis_config"] = floss_data_block.get("analysis_config", {})
        await ctx.info("Returning FLOSS metadata and analysis configuration.")
    else: # Return specific string type with pagination
        all_strings_of_type = floss_data_block.get("strings", {}).get(string_type, [])
        
        # --- NEW FILTERING LOGIC ---
        if string_type == 'static_strings' and only_with_references:
            await ctx.info("Filtering static strings for only those with code references.")
            all_strings_of_type = [item for item in all_strings_of_type if item.get('references')]

        if isinstance(all_strings_of_type, list):
            current_offset_val = offset if offset is not None else 0
            paginated_strings = all_strings_of_type[current_offset_val : current_offset_val + limit]
            response_data["strings"] = paginated_strings
            response_data["pagination_info"] = {
                'offset': current_offset_val,
                'limit': limit,
                'current_items_count': len(paginated_strings),
                'total_items_for_type': len(all_strings_of_type)
            }
            await ctx.info(f"Returning {len(paginated_strings)} {string_type} (total available after filter: {len(all_strings_of_type)}).")
        else:
            response_data["strings"] = []
            response_data["error_in_type"] = f"Data for {string_type} is not in the expected list format."
            response_data["pagination_info"] = {'offset': 0, 'limit': limit, 'current_items_count': 0, 'total_items_for_type': 0}
            
    limit_info_str = f"parameters like 'limit' or 'offset' for string_type '{string_type}'" if string_type else "parameters (none for metadata)"
    return await _check_mcp_response_size(ctx, response_data, "get_floss_analysis_info", limit_info_str)

@tool_decorator 
async def get_capa_analysis_info(ctx: Context,
                                 limit: int, 
                                 offset: Optional[int] = 0,
                                 filter_rule_name: Optional[str] = None,
                                 filter_namespace: Optional[str] = None,
                                 filter_attck_id: Optional[str] = None,
                                 filter_mbc_id: Optional[str] = None,
                                 fields_per_rule: Optional[List[str]] = None,
                                 get_report_metadata_only: bool = False,
                                 source_string_limit: Optional[int] = None
                                 ) -> Dict[str, Any]:
    """
    Retrieves an overview of Capa capability rules, with filtering and pagination.
    For each rule, 'matches' are summarized by a count of unique addresses found. 
    Use 'get_capa_rule_match_details' to fetch detailed match information for a specific rule.

    Args:
        ctx: The MCP Context object.
        limit: (int) Max capability rules to return. Must be positive.
        offset: (Optional[int]) Starting index for rule pagination. Defaults to 0.
        filter_rule_name: (Optional[str]) Filter rules by name/ID (substring, case-insensitive).
        filter_namespace: (Optional[str]) Filter rules by namespace (exact, case-insensitive).
        filter_attck_id: (Optional[str]) Filter rules by ATT&CK ID/tactic (substring, case-insensitive).
        filter_mbc_id: (Optional[str]) Filter rules by MBC ID/objective (substring, case-insensitive).
        fields_per_rule: (Optional[List[str]]) Specific top-level fields for each rule (e.g., ["meta", "source", "matches"]).
                         If "matches" is included, it will be a summary count.
        get_report_metadata_only: (bool) If True, returns only trimmed top-level 'meta' of the Capa report.
        source_string_limit: (Optional[int]) Limits length of a rule's 'source' string if requested. None for no limit.

    Returns:
        Dict with "rules" (summarized), "pagination", "report_metadata", and optionally "error".
    Raises:
        RuntimeError: If no Capa analysis data is found.
        ValueError: If parameters are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request for 'capa_analysis_overview'. Limit(rules): {limit}, Offset(rules): {offset}, "
                   f"Filters: rule='{filter_rule_name}', ns='{filter_namespace}', att&ck='{filter_attck_id}', mbc='{filter_mbc_id}'. "
                   f"FieldsPerRule: {fields_per_rule}, MetaOnly: {get_report_metadata_only}, "
                   f"SourceStrLimit: {source_string_limit}")

    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' for Capa analysis must be a positive integer.")
    if source_string_limit is not None and not (isinstance(source_string_limit, int) and source_string_limit >= 0):
        raise ValueError("Parameter 'source_string_limit' must be a non-negative integer if provided.")

    if ANALYZED_PE_DATA is None or 'capa_analysis' not in ANALYZED_PE_DATA:
        raise RuntimeError("No Capa analysis data found. Ensure Capa analysis ran at startup or via re-analyze.")

    capa_data_block = ANALYZED_PE_DATA.get('capa_analysis', {})
    capa_full_results = capa_data_block.get('results') 
    capa_status = capa_data_block.get("status", "Unknown")
    
    current_offset = 0
    if offset is not None and isinstance(offset, int) and offset >= 0:
        current_offset = offset
    elif offset is not None:
        await ctx.warning(f"Invalid 'offset' parameter for rules, defaulting to 0. Received: {offset}")

    base_pagination_info = {
        'offset': current_offset, 'limit': limit, 'current_items_count': 0,
        'total_items_after_filtering': 0, 'total_capabilities_in_report': 0
    }

    report_meta_from_capa_original = capa_full_results.get('meta', {}) if capa_full_results else {}
    processed_report_meta = copy.deepcopy(report_meta_from_capa_original)
    
    if 'analysis' in processed_report_meta and isinstance(processed_report_meta['analysis'], dict):
        analysis_section = processed_report_meta['analysis']
        if 'layout' in analysis_section: del analysis_section['layout']
        if 'feature_counts' in analysis_section: del analysis_section['feature_counts']

    if capa_status == "Skipped by user request":
        data_to_send = {"error": "Capa analysis was skipped.", "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")
        
    if capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete" or not capa_full_results:
        data_to_send = {"error": f"Capa analysis not complete/results missing. Status: {capa_status}", 
                        "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")


    if get_report_metadata_only:
        data_to_send = {"report_metadata": processed_report_meta, "rules": {}, "pagination": base_pagination_info}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")


    all_rules_dict_from_capa = capa_full_results.get('rules', {})
    if not isinstance(all_rules_dict_from_capa, dict):
        base_pagination_info['total_capabilities_in_report'] = 0
        data_to_send = {"error": "Capa 'rules' data malformed.", "rules": {}, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", "parameters like 'limit' or filters")
        
    base_pagination_info['total_capabilities_in_report'] = len(all_rules_dict_from_capa)

    filtered_rule_items = [] 
    for rule_id, rule_details_original in all_rules_dict_from_capa.items():
        if not isinstance(rule_details_original, dict): 
            await ctx.warning(f"Skipping malformed rule entry for ID '{rule_id}'.")
            continue
        
        meta = rule_details_original.get("meta", {})
        if not isinstance(meta, dict): meta = {}

        passes_filter = True
        if filter_rule_name and filter_rule_name.lower() not in str(meta.get("name", rule_id)).lower(): passes_filter = False
        if passes_filter and filter_namespace and meta.get("namespace", "").lower() != filter_namespace.lower(): passes_filter = False
        
        if passes_filter and filter_attck_id:
            attck_values = meta.get("att&ck", [])
            if not isinstance(attck_values, list): attck_values = [str(attck_values)] 
            if not any(filter_attck_id.lower() in (" ".join(str(v) for v in entry.values()) if isinstance(entry, dict) else str(entry)).lower() for entry in attck_values):
                passes_filter = False

        if passes_filter and filter_mbc_id:
            mbc_values = meta.get("mbc", [])
            if not isinstance(mbc_values, list): mbc_values = [str(mbc_values)]
            if not any(filter_mbc_id.lower() in (" ".join(str(v) for v in entry.values()) if isinstance(entry, dict) else str(entry)).lower() for entry in mbc_values):
                passes_filter = False
        if passes_filter:
            filtered_rule_items.append((rule_id, rule_details_original))
    
    base_pagination_info['total_items_after_filtering'] = len(filtered_rule_items)
    paginated_rule_items_tuples = filtered_rule_items[current_offset : current_offset + limit]
    base_pagination_info['current_items_count'] = len(paginated_rule_items_tuples)

    final_rules_output_dict = {}
    for rule_id, rule_details_original_for_page in paginated_rule_items_tuples:
        rule_data_to_process = copy.deepcopy(rule_details_original_for_page)

        if fields_per_rule:
            rule_data_to_process = {k: v for k, v in rule_data_to_process.items() if k in fields_per_rule}
        
        if 'source' in rule_data_to_process and isinstance(rule_data_to_process['source'], str) and source_string_limit is not None:
            if len(rule_data_to_process['source']) > source_string_limit:
                rule_data_to_process['source'] = rule_data_to_process['source'][:source_string_limit] + "... (truncated)"

        if 'matches' in rule_data_to_process: 
            original_matches_field = rule_details_original_for_page.get('matches') 
            match_address_count = 0
            note = None
            error_msg = None

            if original_matches_field is None:
                note = "Matches field was null/None in original data."
            elif isinstance(original_matches_field, dict):
                match_address_count = len(original_matches_field)
            elif isinstance(original_matches_field, list):
                unique_addresses = set()
                for item in original_matches_field:
                    if isinstance(item, list) and len(item) > 0 and isinstance(item[0], dict) and "value" in item[0]:
                        unique_addresses.add(item[0]["value"]) 
                match_address_count = len(unique_addresses)
                if not unique_addresses and original_matches_field: 
                    note = "Matches field was a list, but no standard address objects found within it."
                elif not original_matches_field: 
                    note = "Matches field was an empty list."
            else: 
                error_msg = f"Original matches data not a dictionary or list (was {type(original_matches_field).__name__})."
            
            summary_matches = {"match_address_count": match_address_count}
            if note: summary_matches["note"] = note
            if error_msg: summary_matches["error"] = error_msg
            rule_data_to_process['matches'] = summary_matches
        
        final_rules_output_dict[rule_id] = rule_data_to_process

    await ctx.info(f"Returning capa_analysis_overview. Rules on page: {base_pagination_info['current_items_count']} of {base_pagination_info['total_items_after_filtering']}.")
    data_to_send = {"rules": final_rules_output_dict, "pagination": base_pagination_info, "report_metadata": processed_report_meta}
    limit_info_str = "parameters like 'limit' (for rules), 'offset', or by using filters (e.g., 'filter_rule_name')"
    return await _check_mcp_response_size(ctx, data_to_send, "get_capa_analysis_info", limit_info_str)

@tool_decorator
async def get_capa_rule_match_details(ctx: Context,
                                      rule_id: str,
                                      address_limit: int,
                                      address_offset: Optional[int] = 0,
                                      detail_limit_per_address: Optional[int] = None,
                                      selected_feature_fields: Optional[List[str]] = None,
                                      feature_value_string_limit: Optional[int] = None
                                      ) -> Dict[str, Any]:
    """
    Retrieves detailed match information for a single, specified Capa rule, with pagination and content control.
    Handles cases where 'matches' in Capa output is a dictionary OR a list of match instances.

    Args:
        ctx: The MCP Context object.
        rule_id: (str) Mandatory. The ID/name of the rule to fetch matches for.
        address_limit: (int) Mandatory. Max number of match addresses to return. Must be positive.
        address_offset: (Optional[int]) Starting index for paginating match addresses. Defaults to 0.
        detail_limit_per_address: (Optional[int]) Limits feature match details per address. None for no limit.
        selected_feature_fields: (Optional[List[str]]) Specific fields from 'feature' object (e.g., ["type", "value"]).
        feature_value_string_limit: (Optional[int]) Limits length of string 'value' in feature fields.

    Returns:
        Dict with "rule_id", "matches_data" (address-keyed dict), "address_pagination", and optionally "error".
    Raises:
        RuntimeError: If no Capa analysis data is found.
        ValueError: If parameters are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request for 'capa_rule_match_details'. RuleID: {rule_id}, AddressLimit: {address_limit}, AddressOffset: {address_offset}, "
                   f"DetailLimitPerAddr: {detail_limit_per_address}, SelectedFeatFields: {selected_feature_fields}, "
                   f"FeatureValStrLimit: {feature_value_string_limit}")

    if not rule_id: raise ValueError("Parameter 'rule_id' is mandatory.")
    if not (isinstance(address_limit, int) and address_limit > 0): raise ValueError("'address_limit' must be positive.")
    for param_name, param_val in [
        ('address_offset', address_offset),
        ('detail_limit_per_address', detail_limit_per_address),
        ('feature_value_string_limit', feature_value_string_limit)
    ]:
        if param_val is not None and not (isinstance(param_val, int) and param_val >= 0):
            raise ValueError(f"Parameter '{param_name}' must be a non-negative integer if provided.")
    if selected_feature_fields is not None and not isinstance(selected_feature_fields, list):
        raise ValueError("'selected_feature_fields' must be a list of strings if provided.")

    if ANALYZED_PE_DATA is None or 'capa_analysis' not in ANALYZED_PE_DATA:
        raise RuntimeError("No Capa analysis data found.")

    capa_data_block = ANALYZED_PE_DATA.get('capa_analysis', {})
    capa_full_results = capa_data_block.get('results')
    capa_status = capa_data_block.get("status", "Unknown")

    current_addr_offset = 0
    if address_offset is not None: current_addr_offset = address_offset
        
    empty_address_pagination = {
        'offset': current_addr_offset, 'limit': address_limit,
        'current_items_count': 0, 'total_addresses_for_rule': 0
    }

    if capa_status != "Analysis complete (adapted workflow)" and capa_status != "Analysis complete" or not capa_full_results:
        data_to_send = {"error": f"Capa analysis not complete/results missing. Status: {capa_status}", 
                        "rule_id": rule_id, "matches_data": {}, "address_pagination": empty_address_pagination}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_rule_match_details", "parameters like 'address_limit'")


    all_rules_dict = capa_full_results.get('rules', {})
    if rule_id not in all_rules_dict:
        data_to_send = {"error": f"Rule ID '{rule_id}' not found.", 
                        "rule_id": rule_id, "matches_data": {}, "address_pagination": empty_address_pagination}
        return await _check_mcp_response_size(ctx, data_to_send, "get_capa_rule_match_details", "parameters like 'address_limit'")


    original_rule_details = all_rules_dict[rule_id]
    original_matches_field = original_rule_details.get('matches') 
    
    standardized_matches_dict = {}

    if isinstance(original_matches_field, dict):
        for addr_val, details_list in original_matches_field.items():
            addr_str_key = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)
            standardized_matches_dict[addr_str_key] = details_list 
            
    elif isinstance(original_matches_field, list):
        await ctx.info(f"Matches for rule '{rule_id}' is a list. Attempting to standardize.")
        for item in original_matches_field:
            if isinstance(item, list) and len(item) == 2:
                addr_obj, detail_obj = item[0], item[1]
                if isinstance(addr_obj, dict) and "value" in addr_obj:
                    addr_val = addr_obj["value"]
                    addr_str_key = hex(addr_val) if isinstance(addr_val, int) else str(addr_val)
                    
                    if addr_str_key not in standardized_matches_dict:
                        standardized_matches_dict[addr_str_key] = []
                    standardized_matches_dict[addr_str_key].append(detail_obj) 
                else:
                    await ctx.warning(f"Skipping item in matches list for rule '{rule_id}': address object malformed. Item: {str(item)[:100]}")
            else:
                await ctx.warning(f"Skipping item in matches list for rule '{rule_id}': item not a pair. Item: {str(item)[:100]}")
    elif original_matches_field is None:
        await ctx.info(f"Matches data for rule '{rule_id}' was None. No address-specific matches.")
    else:
        await ctx.warning(f"Matches data for rule '{rule_id}' is unexpected type '{type(original_matches_field).__name__}'. Treating as no matches.")

    all_match_addresses_items = list(standardized_matches_dict.items())
    total_addresses_for_rule = len(all_match_addresses_items)
    
    paginated_address_items = all_match_addresses_items[current_addr_offset : current_addr_offset + address_limit]

    processed_matches_data = {} 
    for addr_key_str, original_addr_details_list_for_addr in paginated_address_items:
        details_list_copy = copy.deepcopy(original_addr_details_list_for_addr) 
        
        if not isinstance(details_list_copy, list): 
            processed_matches_data[addr_key_str] = [{"error": "Match details structure error after standardization."}]
            continue

        processed_addr_details_for_this_addr = []
        num_details_to_process = len(details_list_copy)

        if detail_limit_per_address is not None:
            if detail_limit_per_address == 0:
                processed_matches_data[addr_key_str] = [] 
                continue 
            num_details_to_process = min(len(details_list_copy), detail_limit_per_address)

        for i in range(num_details_to_process):
            detail_item_processed = details_list_copy[i] 

            if isinstance(detail_item_processed, dict) and 'feature' in detail_item_processed and \
               isinstance(detail_item_processed['feature'], dict):
                
                feature_obj_for_processing = detail_item_processed['feature'] 

                if selected_feature_fields is not None:
                    feature_obj_for_processing = {
                        f_key: feature_obj_for_processing[f_key]
                        for f_key in selected_feature_fields
                        if f_key in feature_obj_for_processing
                    }
                
                if 'value' in feature_obj_for_processing and \
                   isinstance(feature_obj_for_processing['value'], str) and \
                   feature_value_string_limit is not None:
                    feat_val_str = feature_obj_for_processing['value']
                    if len(feat_val_str) > feature_value_string_limit:
                        feature_obj_for_processing['value'] = feat_val_str[:feature_value_string_limit] + "... (truncated)"
                
                detail_item_processed['feature'] = feature_obj_for_processing
            
            processed_addr_details_for_this_addr.append(detail_item_processed)
        
        processed_matches_data[addr_key_str] = processed_addr_details_for_this_addr

    address_pagination_info = {
        'offset': current_addr_offset,
        'limit': address_limit,
        'current_items_count': len(processed_matches_data),
        'total_addresses_for_rule': total_addresses_for_rule
    }

    await ctx.info(f"Returning match details for rule '{rule_id}'. Addresses on page: {len(processed_matches_data)} of {total_addresses_for_rule}.")
    data_to_send = {"rule_id": rule_id, "matches_data": processed_matches_data, "address_pagination": address_pagination_info}
    limit_info_str = "parameters like 'address_limit', 'address_offset', or 'detail_limit_per_address'"
    return await _check_mcp_response_size(ctx, data_to_send, "get_capa_rule_match_details", limit_info_str)

@tool_decorator
async def extract_strings_from_binary(
    ctx: Context,
    limit: int,
    min_length: int = 5,
    rank_with_sifter: bool = False,
    min_sifter_score: Optional[float] = None,
    sort_by_score: bool = False
) -> List[Dict[str, Any]]:
    """
    Extracts printable ASCII strings and can optionally rank them with StringSifter.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. The maximum number of strings to return. Must be positive.
        min_length: (int) The minimum length for a sequence of characters to be considered a string. Defaults to 5.
        rank_with_sifter: (bool) If True, rank extracted strings using StringSifter. Defaults to False.
        min_sifter_score: (Optional[float]) If ranking, only include strings with a score >= this value.
        sort_by_score: (bool) If ranking, sort the results by relevance score (descending).

    Returns:
        A list of dictionaries, where each dictionary contains "offset", "string", and optionally "sifter_score".
        Returns an empty list if no PE file is loaded or no strings are found.

    Raises:
        RuntimeError: If no PE file is currently loaded, a ranking error occurs, or if StringSifter is required but unavailable.
        ValueError: If parameters are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request to extract strings. MinLen: {min_length}, Limit: {limit}, Sifter: {rank_with_sifter}")

    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if rank_with_sifter and not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("Ranking is requested, but StringSifter is not available on the server.")
    if min_sifter_score is not None and not rank_with_sifter:
        await ctx.warning("'min_sifter_score' is set, but 'rank_with_sifter' is False. The score filter will be ignored.")
    if min_sifter_score is not None and not (0.0 <= min_sifter_score <= 1.0):
        raise ValueError("Parameter 'min_sifter_score' must be between 0.0 and 1.0.")

    if PE_OBJECT_FOR_MCP is None or not hasattr(PE_OBJECT_FOR_MCP, '__data__'):
        raise RuntimeError("No PE file loaded or PE data unavailable. Server may not have pre-loaded the input file successfully.")

    try:
        file_data = PE_OBJECT_FOR_MCP.__data__
        found = _extract_strings_from_data(file_data, min_length)
        results = [{"offset": hex(offset), "string": s} for offset, s in found]

        # --- StringSifter Integration Logic ---
        if rank_with_sifter:
            await ctx.info("Ranking extracted strings with StringSifter...")
            
            # Get just the string values for ranking
            string_values = [res["string"] for res in results]
            if not string_values:
                return [] # No strings to rank

            # Load model and rank
            modeldir = os.path.join(sifter_util.package_base(), "model")
            featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
            ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))
            X_test = await asyncio.to_thread(featurizer.transform, string_values)
            y_scores = await asyncio.to_thread(ranker.predict, X_test)

            # Add scores back to the results
            for i, res_dict in enumerate(results):
                res_dict['sifter_score'] = round(float(y_scores[i]), 4)

            # Filter by score if requested
            if min_sifter_score is not None:
                results = [res for res in results if res.get('sifter_score', -1.0) >= min_sifter_score]

            # Sort by score if requested
            if sort_by_score:
                results.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)

        data_to_send = results[:limit]
        limit_info_str = "the 'limit' parameter or by adjusting 'min_sifter_score'"
        return await _check_mcp_response_size(ctx, data_to_send, "extract_strings_from_binary", limit_info_str)

    except Exception as e:
        await ctx.error(f"String extraction/ranking error: {e}")
        raise RuntimeError(f"Failed during string extraction: {e}") from e

@tool_decorator
async def search_for_specific_strings(ctx: Context, search_terms: List[str], limit_per_term: Optional[int] = 100) -> Dict[str, List[str]]:
    """
    Searches for occurrences of specific ASCII strings within the pre-loaded PE file's binary data.
    'limit_per_term' controls occurrences per search term.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        search_terms: (List[str]) A list of ASCII strings to search for. Case-sensitive.
        limit_per_term: (Optional[int]) The maximum number of occurrences to report for each search term.
                          Defaults to 100. If None or 0 or negative, a default internal limit may apply.

    Returns:
        A dictionary where keys are the search terms and values are lists of hexadecimal offsets.
    Raises:
        RuntimeError: If no PE file is currently loaded or a search error occurs.
        ValueError: If `search_terms` is empty or not a list, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Request to search strings: {search_terms}. Limit per term: {limit_per_term}")
    if PE_OBJECT_FOR_MCP is None or not hasattr(PE_OBJECT_FOR_MCP, '__data__'):
        raise RuntimeError("No PE file loaded or PE data unavailable. Server may not have pre-loaded the input file successfully.")
    if not search_terms or not isinstance(search_terms,list): raise ValueError("search_terms must be a non-empty list of strings.")

    effective_limit_pt = 100
    if limit_per_term is not None and isinstance(limit_per_term, int) and limit_per_term > 0:
        effective_limit_pt = limit_per_term
    elif limit_per_term is not None:
        await ctx.warning(f"Invalid limit_per_term value '{limit_per_term}'. Using default of {effective_limit_pt}.")

    try:
        file_data=PE_OBJECT_FOR_MCP.__data__; found_offsets_dict=_search_specific_strings_in_data(file_data,search_terms)

        limited_results:Dict[str,List[str]]={}
        for term, offsets_list_int in found_offsets_dict.items():
            limited_results[term] = [hex(off) for off in offsets_list_int[:effective_limit_pt]]
        
        limit_info_str = "the 'limit_per_term' parameter or by providing fewer/more specific 'search_terms'"
        return await _check_mcp_response_size(ctx, limited_results, "search_for_specific_strings", limit_info_str)
    except Exception as e: await ctx.error(f"String search error: {e}"); raise RuntimeError(f"Failed during specific string search: {e}")from e

@tool_decorator
async def get_hex_dump(ctx: Context, start_offset: int, length: int, bytes_per_line: Optional[int]=16, limit_lines: Optional[int]=256) -> List[str]:
    """
    Retrieves a hex dump of a specified region from the pre-loaded PE file.
    'limit_lines' controls the number of lines in the output.

    Prerequisites:
    - A PE file must have been successfully pre-loaded at server startup.

    Args:
        ctx: The MCP Context object.
        start_offset: (int) The starting offset (0-based) in the file from which to begin the hex dump.
        length: (int) The number of bytes to include in the hex dump. Must be positive.
        bytes_per_line: (Optional[int]) The number of bytes to display per line. Defaults to 16. Must be positive.
        limit_lines: (Optional[int]) The maximum number of lines to return. Defaults to 256. Must be positive.

    Returns:
        A list of strings, where each string is a formatted line of the hex dump.
    Raises:
        RuntimeError: If no PE file is currently loaded or a hex dump error occurs.
        ValueError: If inputs are invalid, or if the response size exceeds the server limit.
    """
    await ctx.info(f"Hex dump requested: Offset {hex(start_offset)}, Length {length}, Bytes/Line {bytes_per_line}, Limit Lines {limit_lines}")
    if PE_OBJECT_FOR_MCP is None or not hasattr(PE_OBJECT_FOR_MCP, '__data__'):
        raise RuntimeError("No PE file loaded or PE data unavailable. Server may not have pre-loaded the input file successfully.")
    if not isinstance(start_offset,int)or start_offset<0:raise ValueError("start_offset must be a non-negative integer.")
    if not isinstance(length,int)or length<=0:raise ValueError("length must be a positive integer.")

    bpl = 16
    if bytes_per_line is not None:
        if isinstance(bytes_per_line, int) and bytes_per_line > 0: bpl = bytes_per_line
        else: raise ValueError("bytes_per_line must be a positive integer.")

    ll = 256
    if limit_lines is not None:
        if isinstance(limit_lines, int) and limit_lines > 0: ll = limit_lines
        else: raise ValueError("limit_lines must be a positive integer.")

    try:
        file_data=PE_OBJECT_FOR_MCP.__data__
        if start_offset>=len(file_data):
            # This case results in an empty list or error message, which is small.
            return ["Error: Start offset is beyond the file size."]
        actual_len=min(length,len(file_data)-start_offset)
        if actual_len<=0:
            # This case results in an empty list or error message, which is small.
            return["Error: Calculated length for hex dump is zero or negative (start_offset might be at or past EOF)."]

        data_chunk=file_data[start_offset:start_offset+actual_len]
        hex_lines=await asyncio.to_thread(_format_hex_dump_lines,data_chunk,start_offset,bpl)
        
        data_to_send = hex_lines[:ll]
        limit_info_str = "parameters like 'length' or 'limit_lines'"
        return await _check_mcp_response_size(ctx, data_to_send, "get_hex_dump", limit_info_str)
    except Exception as e:await ctx.error(f"Hex dump error: {e}");raise RuntimeError(f"Failed during hex dump generation: {e}")from e

@tool_decorator
async def deobfuscate_base64(ctx: Context, hex_string: str) -> Optional[str]:
    """
    Deobfuscates a hex-encoded string that is presumed to represent Base64 encoded data.
    The input 'hex_string' should be the hexadecimal representation of a Base64 string.
    Example: If original data is "test", its Base64 is "dGVzdA==", and the hex of "dGVzdA==" is "6447567a64413d3d".
             This function expects "6447567a64413d3d" as input.

    Args:
        ctx: The MCP Context object.
        hex_string: (str) The hex-encoded string of the Base64 data.

    Returns:
        (Optional[str]) The deobfuscated string (UTF-8 decoded, errors ignored).
        Returns None if deobfuscation fails (e.g., invalid hex, not valid Base64).
    Raises:
        ValueError: If the response size exceeds the server limit.
    """
    await ctx.info(f"Attempting to deobfuscate Base64 from hex string: {hex_string[:60]}...")
    try:
        base64_encoded_bytes = bytes.fromhex(hex_string)
        decoded_payload_bytes = codecs.decode(base64_encoded_bytes, 'base64') # pyright: ignore [reportUnknownMemberType]
        result = decoded_payload_bytes.decode('utf-8', 'ignore')
        await ctx.info("Base64 deobfuscation successful.")
        
        limit_info_str = "a shorter 'hex_string' if the decoded content is too large (this tool has no direct data limiting parameters)"
        # Note: `result` can be None if decoding fails in a way that doesn't raise an exception but returns None (though unlikely for base64)
        # The _check_mcp_response_size helper handles `None` by attempting to JSON serialize it, which is fine.
        return await _check_mcp_response_size(ctx, result, "deobfuscate_base64", limit_info_str)

    except ValueError as e: # Handles bytes.fromhex error or other ValueErrors
        await ctx.error(f"Invalid hex string or Base64 content for deobfuscation: {str(e)}")
        logger.warning(f"MCP: Invalid hex/Base64 for deobfuscation: {hex_string[:60]}... - {str(e)}")
        return None # Return None on decoding failure before size check
    except Exception as e: # Catch other errors like binascii.Error from codecs.decode
        await ctx.error(f"Base64 deobfuscation error: {str(e)}")
        logger.error(f"MCP: Base64 deobfuscation error for {hex_string[:60]}... - {str(e)}", exc_info=True)
        return None # Return None on decoding failure


@tool_decorator
async def deobfuscate_xor_single_byte(ctx: Context, data_hex: str, key: int) -> Dict[str, Optional[str]]:
    """
    Deobfuscates a hex-encoded data string using a single-byte XOR key.

    Args:
        ctx: The MCP Context object.
        data_hex: (str) The hex-encoded data string to be XORed.
        key: (int) The single byte (0-255) to use as the XOR key.

    Returns:
        A dictionary containing:
        - "deobfuscated_hex": (str) The hex representation of the XORed data.
        - "deobfuscated_printable_string": (Optional[str]) A printable representation of the XORed data
          (UTF-8 or Latin-1 decoded if possible, otherwise dot-replaced non-printables).
          Can be None if an error occurs during string representation.

    Raises:
        ValueError: If `key` is not between 0-255 or `data_hex` is not valid hex, or if the response size exceeds the server limit.
        RuntimeError: For other deobfuscation errors.
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

        printable_representation = None
        try:
            try: printable_representation = deobfuscated_bytes.decode('utf-8')
            except UnicodeDecodeError:
                try: printable_representation = deobfuscated_bytes.decode('latin-1')
                except UnicodeDecodeError: printable_representation = "".join(chr(b) if 32 <= b <= 126 or b in [9,10,13] else '.' for b in deobfuscated_bytes)
        except Exception as e_decode:
            logger.warning(f"MCP: Error creating printable string for XOR result (key {key}): {e_decode}")
            printable_representation = "[Error creating printable string]"

        await ctx.info("XOR deobfuscation successful.")
        data_to_send = {
            "deobfuscated_hex": deobfuscated_hex_output,
            "deobfuscated_printable_string": printable_representation
        }
        limit_info_str = "a shorter 'data_hex' if the decoded content is too large (this tool has no direct data limiting parameters)"
        return await _check_mcp_response_size(ctx, data_to_send, "deobfuscate_xor_single_byte", limit_info_str)

    except ValueError as e_val: # Handles bytes.fromhex error
        await ctx.error(f"Invalid hex string provided for data_hex in XOR deobfuscation: {str(e_val)}")
        logger.warning(f"MCP: Invalid hex string for XOR data_hex: {data_hex[:60]}... - {str(e_val)}")
        raise # Re-raise to be handled by MCP framework
    except Exception as e_gen:
        await ctx.error(f"XOR deobfuscation error: {str(e_gen)}")
        logger.error(f"MCP: XOR deobfuscation error for data_hex {data_hex[:60]}..., key {key} - {str(e_gen)}", exc_info=True)
        raise RuntimeError(f"XOR deobfuscation failed: {str(e_gen)}") from e_gen

@tool_decorator
async def is_mostly_printable_ascii(ctx: Context, text_input: str, threshold: float = 0.8) -> bool:
    """
    Checks if the given string 'text_input' consists mostly of printable ASCII characters.
    Printable includes standard ASCII (space to '~') and common whitespace (newline, tab, carriage return).

    Args:
        ctx: The MCP Context object.
        text_input: (str) The string to check.
        threshold: (float) The minimum ratio (0.0 to 1.0) of printable characters to total characters
                   for the string to be considered "mostly printable". Defaults to 0.8 (80%).

    Returns:
        (bool) True if the ratio of printable ASCII characters meets or exceeds the threshold, False otherwise.
               Returns False for an empty input string.

    Raises:
        ValueError: If `threshold` is not between 0.0 and 1.0.
    """
    await ctx.info(f"Checking if string is mostly printable ASCII. Threshold: {threshold}, String length: {len(text_input)}")
    if not text_input:
        await ctx.info("Input string for printable check is empty, returning False.")
        return False

    if not (0.0 <= threshold <= 1.0):
        await ctx.error(f"Threshold for printable check must be between 0.0 and 1.0. Received: {threshold}")
        logger.warning(f"MCP: Invalid threshold {threshold} for printable check.")
        raise ValueError("Threshold must be between 0.0 and 1.0.")

    printable_char_in_string_count = sum(1 for char_in_s in text_input
                                         if (' ' <= char_in_s <= '~') or char_in_s in '\n\r\t')

    ratio = printable_char_in_string_count / len(text_input)
    result = ratio >= threshold
    await ctx.info(f"Printable character ratio: {ratio:.2f}. Result: {result}")
    return result

# --- Helper for find_and_decode_encoded_strings ---
def _is_mostly_printable_ascii_sync(text_input: str, threshold: float = 0.8) -> bool:
    """
    Synchronous helper to check if a string consists mostly of printable ASCII characters.
    Printable includes standard ASCII (space to '~') and common whitespace (newline, tab, carriage return).
    """
    if not text_input:
        return False # Empty string is not considered printable for this purpose

    printable_char_in_string_count = sum(1 for char_in_s in text_input
                                         if (' ' <= char_in_s <= '~') or char_in_s in '\n\r\t')
    
    if not text_input: return False # Should be caught by the first check, but defensive.

    ratio = printable_char_in_string_count / len(text_input)
    return ratio >= threshold
   
@tool_decorator
async def find_and_decode_encoded_strings(
    ctx: Context,
    limit: int,
    rank_with_sifter: bool = False,
    min_sifter_score: Optional[float] = None,
    min_confidence: float = 0.6,
    min_candidate_len_b64: int = 20,
    min_candidate_len_b32: int = 24,
    min_candidate_len_hex: int = 8,
    min_candidate_len_url: int = 3,
    min_decoded_printable_length: int = 4,
    printable_threshold: float = 0.8,
    max_decode_layers: int = 3,
    decoded_regex_patterns: Optional[List[str]] = None,
    verbose_mcp_output: bool = False
) -> List[Dict[str, Any]]:
    """
    Finds, decodes (recursively), and optionally ranks encoded strings with heuristics.

    This enhanced tool implements multi-layer decoding, adds a confidence score based
    on the location of the string, and includes a single-byte XOR bruteforce decoder.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. Maximum number of decoded results to return.
        rank_with_sifter: (bool) If True, rank the successfully decoded strings.
        min_sifter_score: (Optional[float]) If ranking, only include strings with a score >= this value.
        min_confidence: (float) Minimum confidence score (0.0-1.0) for a result to be included. Based on heuristics like PE section. Defaults to 0.6.
        min_candidate_len_b64: (int) Minimum length of a potential Base64 sequence.
        min_candidate_len_b32: (int) Minimum length of a potential Base32 sequence.
        min_candidate_len_hex: (int) Minimum length of a potential Hex sequence.
        min_candidate_len_url: (int) Minimum length of a potential URL-encoded sequence.
        min_decoded_printable_length: (int) Minimum length of a successfully decoded string.
        printable_threshold: (float) Ratio (0.0-1.0) of printable chars for decoded data.
        max_decode_layers: (int) The maximum number of encoding layers to decode. Defaults to 3.
        decoded_regex_patterns: (Optional[List[str]]) Regex patterns to search within decoded strings.
        verbose_mcp_output: (bool) Enables more detailed server-side logging.

    Returns:
        A list of dictionaries, each representing a successfully decoded and filtered string.
    """
    await ctx.info(f"Request to find/decode strings. Limit: {limit}, Max Layers: {max_decode_layers}, Min Confidence: {min_confidence}")
    
    # --- Parameter Validation ---
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if rank_with_sifter and not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("Ranking is requested, but StringSifter is not available on the server.")
    if not (0.0 <= min_confidence <= 1.0):
        raise ValueError("Parameter 'min_confidence' must be between 0.0 and 1.0.")
    if not (isinstance(max_decode_layers, int) and 1 <= max_decode_layers <= 10):
        raise ValueError("Parameter 'max_decode_layers' must be an integer between 1 and 10.")

    # --- Setup ---
    if PE_OBJECT_FOR_MCP is None or not hasattr(PE_OBJECT_FOR_MCP, '__data__'):
        raise RuntimeError("No PE file loaded or PE data unavailable.")

    pe = PE_OBJECT_FOR_MCP
    file_data = pe.__data__
    found_decoded_strings = []

    base64_pattern = re.compile(rb"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)")
    hex_pattern = re.compile(rb"(?:[0-9a-fA-F]{2}){4,}") # Require at least 4 hex pairs

    initial_candidates = []
    for pat, min_len in [(base64_pattern, min_candidate_len_b64), (hex_pattern, min_candidate_len_hex)]:
        for match in pat.finditer(file_data):
            if len(match.group(0)) >= min_len:
                initial_candidates.append(match)
    
    decoding_attempts = [
        ("base64", lambda b: codecs.decode(b, 'base64')),
        ("hex", lambda b: bytes.fromhex(b.decode('ascii'))),
    ]

    for match in initial_candidates:
        if len(found_decoded_strings) >= limit: break

        original_encoded_bytes = match.group(0)
        start_offset = match.start()
        
        # --- HEURISTIC: Calculate confidence based on section ---
        confidence = 0.5 # Default low confidence
        try:
            section = pe.get_section_by_offset(start_offset)
            if section:
                sec_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                if '.data' in sec_name or '.rdata' in sec_name:
                    confidence = 1.0 # High confidence for data sections
                elif '.text' not in sec_name:
                    confidence = 0.8 # Medium confidence for other non-code sections
        except Exception:
            pass # Keep default confidence if section lookup fails

        if confidence < min_confidence:
            continue

        # --- MULTI-LAYER DECODING ---
        current_bytes = original_encoded_bytes
        encoding_layers = []
        final_decoded_text = None

        for _ in range(max_decode_layers):
            decoded_this_layer = False
            # Try standard decoders first
            for enc_name, dec_func in decoding_attempts:
                try:
                    decoded_bytes = await asyncio.to_thread(dec_func, current_bytes)
                    if decoded_bytes and decoded_bytes != current_bytes:
                        encoding_layers.append(enc_name)
                        current_bytes = decoded_bytes
                        decoded_this_layer = True
                        break 
                except Exception:
                    continue
            
            # If standard decoders found something, check if the result is printable
            if decoded_this_layer:
                try:
                    text_candidate = current_bytes.decode('utf-8', 'ignore')
                    if _is_mostly_printable_ascii_sync(text_candidate, printable_threshold):
                        final_decoded_text = text_candidate
                        break # Found final printable payload
                except Exception:
                    pass # Not printable, continue to next layer or XOR
            
            # If standard decoders failed OR result wasn't printable, try XOR
            if not final_decoded_text:
                xor_result = await asyncio.to_thread(_decode_single_byte_xor, current_bytes)
                if xor_result:
                    decoded_bytes, key = xor_result
                    encoding_layers.append(f"xor(0x{key:02x})")
                    current_bytes = decoded_bytes
                    final_decoded_text = current_bytes.decode('utf-8', 'ignore')
                    break # Assume XOR result is final payload

            if not decoded_this_layer:
                break # No decoders worked on this layer, stop

        # --- Final filtering and result creation ---
        if final_decoded_text and len(final_decoded_text) >= min_decoded_printable_length:
            if decoded_regex_patterns:
                try:
                    if not any(re.search(p, final_decoded_text) for p in decoded_regex_patterns):
                        continue
                except re.error:
                    await ctx.warning("An invalid regex was skipped during search.")
                    continue
            
            snippet_start = max(0, start_offset - 16)
            snippet_end = min(len(file_data), match.end() + 16)

            found_decoded_strings.append({
                "original_match_offset": hex(start_offset),
                "encoded_substring_repr": original_encoded_bytes.decode('ascii', 'replace')[:200],
                "encoding_layers": encoding_layers,
                "decoded_string": final_decoded_text,
                "confidence": round(confidence, 2),
                "context_snippet_hex": file_data[snippet_start:snippet_end].hex()
            })

    # --- Final Ranking, Filtering and Return ---
    final_results = found_decoded_strings
    if rank_with_sifter and final_results:
        string_values = [res["decoded_string"] for res in final_results]
        if string_values:
            modeldir = os.path.join(sifter_util.package_base(), "model")
            featurizer = joblib.load(os.path.join(modeldir, "featurizer.pkl"))
            ranker = joblib.load(os.path.join(modeldir, "ranker.pkl"))
            X_test = await asyncio.to_thread(featurizer.transform, string_values)
            y_scores = await asyncio.to_thread(ranker.predict, X_test)
            
            for i, res_dict in enumerate(final_results):
                res_dict['sifter_score'] = round(float(y_scores[i]), 4)
        
        if min_sifter_score is not None:
            final_results = [res for res in final_results if res.get('sifter_score', -999.0) >= min_sifter_score]
        
        final_results.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)

    return await _check_mcp_response_size(ctx, final_results[:limit], "find_and_decode_encoded_strings", "the 'limit' parameter or by adjusting filters")

@tool_decorator
async def get_top_sifted_strings(
    ctx: Context,
    limit: int,
    string_sources: Optional[List[str]] = None,
    min_sifter_score: Optional[float] = 5.0,
    max_sifter_score: Optional[float] = None,
    sort_order: str = 'descending',
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    filter_regex: Optional[str] = None,
    filter_by_category: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Returns top-ranked strings from all sources with advanced, granular filtering.

    Args:
        ctx: The MCP Context object.
        limit: (int) Mandatory. The maximum number of ranked strings to return.
        string_sources: (Optional[List[str]]) Sources to include: 'floss', 'basic_ascii'. Defaults to all.
        min_sifter_score: (Optional[float]) The minimum relevance score for a string to be included.
        max_sifter_score: (Optional[float]) The maximum relevance score for a string to be included.
        sort_order: (str) Sort order: 'ascending', 'descending'. Defaults to 'descending'.
        min_length: (Optional[int]) Filter for strings with a minimum length.
        max_length: (Optional[int]) Filter for strings with a maximum length.
        filter_regex: (Optional[str]) A regex pattern that strings must match.
        filter_by_category: (Optional[str]) Filter for a specific category (e.g., 'url', 'ipv4').

    Returns:
        A list of unique string dictionaries, filtered and sorted as requested.
    """
    await ctx.info(f"Request for top sifted strings with granular filters.")

    # --- Parameter Validation ---
    # (Includes validation for all new and existing parameters)
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if not STRINGSIFTER_AVAILABLE:
        raise RuntimeError("StringSifter is not available, so no scores were computed.")
    if min_sifter_score is not None and not isinstance(min_sifter_score, (int, float)):
        raise ValueError("Parameter 'min_sifter_score' must be a number if provided.")
    if max_sifter_score is not None and not isinstance(max_sifter_score, (int, float)):
        raise ValueError("Parameter 'max_sifter_score' must be a number if provided.")
    if sort_order.lower() not in ['ascending', 'descending']:
        raise ValueError("Parameter 'sort_order' must be either 'ascending' or 'descending'.")
    if filter_regex:
        try:
            re.compile(filter_regex)
        except re.error as e:
            raise ValueError(f"Invalid 'filter_regex': {e}")

    # --- Data Retrieval and Aggregation ---
    if ANALYZED_PE_DATA is None:
        raise RuntimeError("No analysis data found.")

    all_strings = []
    seen_string_values = set()
    sources_to_check = string_sources or ['floss', 'basic_ascii']

    if 'floss' in sources_to_check and 'floss_analysis' in ANALYZED_PE_DATA:
        floss_strings = ANALYZED_PE_DATA['floss_analysis'].get('strings', {})
        for str_type, str_list in floss_strings.items():
            for item in str_list:
                if isinstance(item, dict) and 'sifter_score' in item:
                    str_val = item.get("string")
                    if str_val and str_val not in seen_string_values:
                        item_with_context = item.copy()
                        item_with_context['source_type'] = f"floss_{str_type.replace('_strings', '')}"
                        all_strings.append(item_with_context)
                        seen_string_values.add(str_val)

    if 'basic_ascii' in sources_to_check and 'basic_ascii_strings' in ANALYZED_PE_DATA:
        for item in ANALYZED_PE_DATA['basic_ascii_strings']:
            if isinstance(item, dict) and 'sifter_score' in item:
                str_val = item.get("string")
                if str_val and str_val not in seen_string_values:
                    all_strings.append(item)
                    seen_string_values.add(str_val)

    # --- Granular Filtering Logic ---
    filtered_strings = []
    for item in all_strings:
        score = item['sifter_score']
        str_val = item['string']
        category = item.get('category')

        if min_sifter_score is not None and score < min_sifter_score: continue
        if max_sifter_score is not None and score > max_sifter_score: continue
        if min_length is not None and len(str_val) < min_length: continue
        if max_length is not None and len(str_val) > max_length: continue
        if filter_by_category is not None and category != filter_by_category: continue
        if filter_regex and not re.search(filter_regex, str_val): continue

        filtered_strings.append(item)

    # --- Sorting Logic ---
    is_reversed = (sort_order.lower() == 'descending')
    filtered_strings.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=is_reversed)

    # --- Finalize and Return ---
    data_to_send = filtered_strings[:limit]
    return await _check_mcp_response_size(ctx, data_to_send, "get_top_sifted_strings", "the 'limit' parameter or by adding more filters")

@tool_decorator
async def get_strings_for_function(
    ctx: Context,
    function_va: int,
    limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Finds and returns all strings that are referenced by a specific function.

    Args:
        ctx: The MCP Context object.
        function_va: (int) The virtual address of the function to query.
        limit: (int) The maximum number of strings to return. Defaults to 100.

    Returns:
        A list of string dictionaries that are associated with the given function.
    """
    await ctx.info(f"Request for strings referenced by function: {hex(function_va)}")
    if ANALYZED_PE_DATA is None or 'floss_analysis' not in ANALYZED_PE_DATA:
        raise RuntimeError("FLOSS analysis data with function context is not available.")

    found_strings = []
    all_floss_strings = ANALYZED_PE_DATA['floss_analysis'].get('strings', {})
    for str_type, str_list in all_floss_strings.items():
        if not isinstance(str_list, list): continue
        for item in str_list:
            if not isinstance(item, dict): continue
            is_match = False
            if 'references' in item:
                for ref in item.get('references', []):
                    if ref.get('function_va') and int(ref.get('function_va', '0x0'), 16) == function_va:
                        is_match = True; break
            elif 'function_va' in item and int(item.get('function_va', '0x0'), 16) == function_va:
                is_match = True
            elif 'decoding_routine_va' in item and int(item.get('decoding_routine_va', '0x0'), 16) == function_va:
                is_match = True
            
            if is_match:
                item_with_context = item.copy()
                item_with_context['source_type'] = f"floss_{str_type.replace('_strings', '')}"
                found_strings.append(item_with_context)
    
    if found_strings and 'sifter_score' in found_strings[0]:
        found_strings.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)

    return await _check_mcp_response_size(ctx, found_strings[:limit], "get_strings_for_function", "the 'limit' parameter")

@tool_decorator
async def get_string_usage_context(
    ctx: Context,
    string_offset: int,
    limit: int = 20
) -> List[Dict[str, Any]]:
    """
    Finds a static string by its file offset and returns the disassembly
    context for each location where it is referenced in code.

    **IMPORTANT PREREQUISITES FOR THIS FUNCTION TO RETURN RESULTS:**
    1.  The `string_offset` MUST correspond to a **static string**. This tool does not work for stack, tight, or decoded strings.
    2.  The static string must have code cross-references (xrefs). An unused string will have no references.
    3.  FLOSS analysis, including the vivisect workspace analysis, must have run successfully during the initial PE file loading, as this is what generates the context.

    Args:
        ctx: The MCP Context object.
        string_offset: (int) The file offset (e.g., 12345) of the static string to look up.
        limit: (int) Max number of reference contexts to return. Defaults to 20.

    Returns:
        A list of reference objects, where each object contains the function VA and
        a snippet of disassembly code showing how the string is used. Returns an
        empty list if the offset is not found or has no references.
    """
    await ctx.info(f"Request for usage context for string at offset: {hex(string_offset)}")
    if ANALYZED_PE_DATA is None or 'floss_analysis' not in ANALYZED_PE_DATA:
        raise RuntimeError("FLOSS analysis data with context is not available.")

    static_strings = ANALYZED_PE_DATA['floss_analysis'].get('strings', {}).get('static_strings', [])
    for item in static_strings:
        # Ensure we handle both '0x...' hex strings and integer offsets
        try:
            item_offset = int(item.get('offset', '-1'), 16)
        except (ValueError, TypeError):
            continue

        if item_offset == string_offset:
            references = item.get('references', [])
            return await _check_mcp_response_size(ctx, references[:limit], "get_string_usage_context", "the 'limit' parameter")

    return []

@tool_decorator
async def fuzzy_search_strings(
    ctx: Context,
    query_string: str,
    limit: int,
    string_sources: Optional[List[str]] = None,
    min_similarity_ratio: int = 85
) -> List[Dict[str, Any]]:
    """
    Performs a fuzzy search to find strings similar to the query string across
    all specified sources. Results are sorted by similarity.

    Args:
        ctx: The MCP Context object.
        query_string: (str) The string to search for.
        limit: (int) The maximum number of similar strings to return.
        string_sources: (Optional[List[str]]) A list of sources to search. Valid: 'floss', 'basic_ascii'. Defaults to all.
        min_similarity_ratio: (int) The minimum similarity score (0-100) required for a string to be considered a match. Defaults to 85.

    Returns:
        A list of string dictionaries that meet the similarity threshold, sorted by similarity score.
    """
    await ctx.info(f"Fuzzy search request for '{query_string}'. Min Ratio: {min_similarity_ratio}, Limit: {limit}")

    # --- Parameter Validation ---
    if not THEFUZZ_AVAILABLE:
        raise RuntimeError("Fuzzy search is not available because the 'thefuzz' library is not installed.")
    if not query_string:
        raise ValueError("Parameter 'query_string' cannot be empty.")
    if not (isinstance(limit, int) and limit > 0):
        raise ValueError("Parameter 'limit' must be a positive integer.")
    if not (isinstance(min_similarity_ratio, int) and 0 <= min_similarity_ratio <= 100):
        raise ValueError("Parameter 'min_similarity_ratio' must be an integer between 0 and 100.")

    # --- Data Retrieval and Aggregation (with deduplication) ---
    if ANALYZED_PE_DATA is None:
        raise RuntimeError("No analysis data found.")

    all_strings = []
    seen_string_values = set()
    sources_to_check = string_sources or ['floss', 'basic_ascii']

    # Process FLOSS first to prioritize its richer context
    if 'floss' in sources_to_check and 'floss_analysis' in ANALYZED_PE_DATA:
        floss_strings = ANALYZED_PE_DATA['floss_analysis'].get('strings', {})
        for str_type, str_list in floss_strings.items():
            for item in str_list:
                if isinstance(item, dict):
                    str_val = item.get("string")
                    if str_val and str_val not in seen_string_values:
                        item_with_context = item.copy()
                        item_with_context['source_type'] = f"floss_{str_type.replace('_strings', '')}"
                        all_strings.append(item_with_context)
                        seen_string_values.add(str_val)

    # Process Basic ASCII strings
    if 'basic_ascii' in sources_to_check and 'basic_ascii_strings' in ANALYZED_PE_DATA:
        for item in ANALYZED_PE_DATA['basic_ascii_strings']:
            if isinstance(item, dict):
                str_val = item.get("string")
                if str_val and str_val not in seen_string_values:
                    all_strings.append(item)
                    seen_string_values.add(str_val)

    if not all_strings:
        return []

    # --- Fuzzy Matching Logic ---
    matches = []
    for item in all_strings:
        target_string = item.get("string")
        if not target_string:
            continue
        
        # Calculate the similarity ratio
        ratio = await asyncio.to_thread(fuzz.ratio, query_string, target_string)
        
        if ratio >= min_similarity_ratio:
            match_item = item.copy()
            match_item['similarity_ratio'] = ratio
            matches.append(match_item)

    # --- Sorting and Finalizing ---
    matches.sort(key=lambda x: x.get('similarity_ratio', 0), reverse=True)

    data_to_send = matches[:limit]
    limit_info = "the 'limit' parameter or by adjusting 'min_similarity_ratio'"
    return await _check_mcp_response_size(ctx, data_to_send, "fuzzy_search_strings", limit_info)

@tool_decorator
async def get_triage_report(
    ctx: Context,
    sifter_score_threshold: float = 8.0,
    indicator_limit: int = 15
) -> Dict[str, Any]:
    """
    Runs an automated triage workflow to find the most suspicious indicators
    and behaviors in the analyzed file, returning a condensed summary.

    Args:
        ctx: The MCP Context object.
        sifter_score_threshold: (float) The minimum sifter score for a string to be considered a high-value indicator.
        indicator_limit: (int) The max number of items to return for each category in the report.

    Returns:
        A dictionary summarizing the most critical findings.
    """
    await ctx.info(f"Generating automated triage report...")

    if ANALYZED_PE_DATA is None:
        raise RuntimeError("No analysis data available to generate a triage report.")

    triage_report = {
        "HighValueIndicators": [],
        "SuspiciousCapabilities": [],
        "SuspiciousImports": [],
        "SignatureAndPacker": {},
    }

    # --- 1. Find High-Value String Indicators ---
    all_strings = []
    # This logic is a simplified version of get_top_sifted_strings aggregation
    if 'floss_analysis' in ANALYZED_PE_DATA:
        for str_list in ANALYZED_PE_DATA['floss_analysis'].get('strings', {}).values():
            all_strings.extend(str_list)
    all_strings.extend(ANALYZED_PE_DATA.get('basic_ascii_strings', []))
    
    high_value_strings = [
        s for s in all_strings
        if isinstance(s, dict) and s.get('sifter_score', 0.0) >= sifter_score_threshold and s.get('category') is not None
    ]
    high_value_strings.sort(key=lambda x: x.get('sifter_score', 0.0), reverse=True)
    triage_report["HighValueIndicators"] = high_value_strings[:indicator_limit]

    # --- 2. Find High-Severity Capa Capabilities ---
    CAPA_SEVERITY_MAP = {
        # High severity namespaces
        "anti-analysis": "High",
        "collection": "High",
        "credential-access": "High",
        "defense-evasion": "High",
        "execution": "High",
        "impact": "High",
        "persistence": "High",
        "privilege-escalation": "High",
        "caching": "High",
        # Medium severity
        "bootloader": "Medium",
        "communication": "Medium",
        "data-manipulation": "Medium",
        "discovery": "Medium",
    }
    if 'capa_analysis' in ANALYZED_PE_DATA:
        capa_rules = ANALYZED_PE_DATA['capa_analysis'].get('results', {}).get('rules', {})
        for rule_name, rule_details in capa_rules.items():
            namespace = rule_details.get('meta', {}).get('namespace', '').split('/')[0]
            severity = CAPA_SEVERITY_MAP.get(namespace, "Low")
            if severity in ["High", "Medium"]:
                triage_report["SuspiciousCapabilities"].append({
                    "capability": rule_details.get('meta', {}).get('name', rule_name),
                    "namespace": rule_details.get('meta', {}).get('namespace'),
                    "severity": severity
                })
        triage_report["SuspiciousCapabilities"].sort(key=lambda x: x['severity'], reverse=True)
        triage_report["SuspiciousCapabilities"] = triage_report["SuspiciousCapabilities"][:indicator_limit]

    # --- 3. Find Suspicious Imports ---
    SUSPICIOUS_IMPORTS = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx', 'ShellExecute',
        'LdrLoadDll', 'IsDebuggerPresent', 'URLDownloadToFile', 'InternetOpen', 'HttpSendRequest'
    ]
    if 'imports' in ANALYZED_PE_DATA:
        for dll in ANALYZED_PE_DATA['imports']:
            for imp in dll.get('symbols', []):
                imp_name = imp.get('name')
                if imp_name and imp_name in SUSPICIOUS_IMPORTS:
                    triage_report["SuspiciousImports"].append(f"{dll.get('dll_name', 'unknown.dll')}!{imp_name}")
    
    # --- 4. Get Packer and Signature Info ---
    if 'peid_matches' in ANALYZED_PE_DATA:
        triage_report["SignatureAndPacker"]['peid'] = ANALYZED_PE_DATA['peid_matches'].get('ep_matches', [])
    if 'digital_signature' in ANALYZED_PE_DATA:
        triage_report["SignatureAndPacker"]['is_signed'] = ANALYZED_PE_DATA['digital_signature'].get('embedded_signature_present', False)

    return await _check_mcp_response_size(ctx, triage_report, "get_triage_report", "This tool has no size-limiting parameters.")

@tool_decorator
async def find_generic_c2_config(
    ctx: Context,
    validation_pattern_hex: str,
    structure_definition_fields: List[Dict[str, str]],
    endianness: str = 'big',
    known_xor_keys_hex: Optional[List[str]] = None,
    entropy_threshold: float = 7.0,
    search_pe_overlay: bool = True,
    bruteforce_all_keys: bool = True,
    limit_scan_to_section: Optional[str] = None
) -> Dict[str, Any]:
    """
    Finds and decodes a hidden C2 configuration, with robust support for packed/staged payloads.

    This tool is designed for maximum flexibility. Instead of using a static profile, it accepts
    the core components of a configuration profile as direct arguments. This allows an LLM
    to define and hunt for custom C2 structures on the fly without complex JSON escaping.

    Args:
        ctx: The MCP Context object.
        validation_pattern_hex: Hex string of magic bytes appearing at the start of a decrypted config.
        structure_definition_fields: List of dicts defining the config fields.
                                     Each must have 'id' (hex), 'name' (str), 'type' (str).
        endianness: Endianness of the data ('big' or 'little'). Defaults to 'big'.
        known_xor_keys_hex: (Optional) List of known single-byte XOR keys (hex strings) to test first.
        entropy_threshold: Minimum entropy for a section to be scanned. Defaults to 7.0.
        search_pe_overlay: If True, scans data appended to the PE file. Defaults to True.
        bruteforce_all_keys: If True, tests all 256 single-byte XOR keys. Defaults to True.
        limit_scan_to_section: (Optional) If set, ONLY the specified section from the original PE is
                               added to the candidate list (staged payloads are still added).

    Returns:
        A dictionary with the decoded configuration and discovery metadata, or a status message.

    Example Usage for Cobalt Strike v4:
    ```python
    find_generic_c2_config(
        validation_pattern_hex='000100010002',
        known_xor_keys_hex=['69', '2e'],
        bruteforce_all_keys=True,
        structure_definition_fields=[
          {"id": "0001", "name": "BeaconType", "type": "short"},
          {"id": "0002", "name": "Port", "type": "short"},
          {"id": "0003", "name": "SleepTime", "type": "integer"},
          {"id": "0004", "name": "MaxGetSize", "type": "integer"},
          {"id": "0005", "name": "Jitter", "type": "short"},
          {"id": "0007", "name": "PublicKey", "type": "bytes"},
          {"id": "0008", "name": "C2Server", "type": "string"},
          {"id": "0009", "name": "UserAgent", "type": "string"},
          {"id": "000a", "name": "HttpPostUri", "type": "string"},
          {"id": "000b", "name": "Malleable_C2_Instructions", "type": "raw_bytes"},
          {"id": "001a", "name": "HttpGetVerb", "type": "string"},
          {"id": "001b", "name": "HttpPostVerb", "type": "string"},
          {"id": "001d", "name": "SpawnTo_x86", "type": "string"},
          {"id": "001e", "name": "SpawnTo_x64", "type": "string"},
          {"id": "0025", "name": "Watermark", "type": "integer"}
        ]
    )
    ```
    """
    await ctx.info("Starting generic C2 config hunter with stager-aware logic.")
    if PE_OBJECT_FOR_MCP is None:
        raise RuntimeError("No PE file loaded. Cannot perform configuration analysis.")

    try:
        profile = {
            "validation_pattern": {"value": validation_pattern_hex},
            "known_xor_keys": known_xor_keys_hex or [],
            "structure_definition": {"endian": endianness, "fields": structure_definition_fields}
        }
        validation_bytes = bytes.fromhex(validation_pattern_hex)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid dynamic profile parameters: {e}")

    candidate_blocks: List[Tuple[str, bytes]] = []

    await ctx.info("Performing pre-scan for known stager patterns...")
    loop = asyncio.get_running_loop()
    staged_payloads = await asyncio.to_thread(_extract_staged_payloads, PE_OBJECT_FOR_MCP.__data__, ctx, loop)
    
    if staged_payloads:
        await ctx.info(f"Found {len(staged_payloads)} potential staged payload(s). Adding their sections to scan candidates.")
        for desc, payload_data in staged_payloads:
            try:
                embedded_pe = pefile.PE(data=payload_data)
                for section in embedded_pe.sections:
                    section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                    candidate_blocks.append((f"{desc} -> Section '{section_name}'", section.get_data()))
            except pefile.PEFormatError:
                candidate_blocks.append((f"{desc} (raw blob)", payload_data))
    
    if limit_scan_to_section:
        await ctx.info(f"Adding user-specified section '{limit_scan_to_section}' from original PE to candidates.")
        section_found = False
        for section in PE_OBJECT_FOR_MCP.sections:
            if section.Name.decode('utf-8', 'ignore').strip('\x00') == limit_scan_to_section:
                candidate_blocks.append((f"Original PE -> Section '{limit_scan_to_section}'", section.get_data()))
                section_found = True
                break
        if not section_found and not staged_payloads:
            return {"status": "error", "message": f"Section '{limit_scan_to_section}' not found and no staged payloads detected."}
    else:
        await ctx.info(f"Adding high-entropy sections and overlay from original PE to candidates.")
        for section in PE_OBJECT_FOR_MCP.sections:
            if section.get_entropy() > entropy_threshold:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                candidate_blocks.append((f"Original PE -> Section '{section_name}' (Entropy: {section.get_entropy():.2f})", section.get_data()))
        if search_pe_overlay:
            overlay_data = PE_OBJECT_FOR_MCP.get_overlay()
            if overlay_data:
                candidate_blocks.append(("Original PE -> Overlay", overlay_data))

    if not candidate_blocks:
        return {"status": "not_found", "message": "No candidate blocks (staged, high-entropy, or overlay) found to scan."}

    keys_to_test = []
    if profile.get('known_xor_keys'):
        keys_to_test.extend([int(k, 16) for k in profile['known_xor_keys']])
    if bruteforce_all_keys:
        keys_to_test.extend(list(set(range(256)) - set(keys_to_test)))

    await ctx.info(f"Scanning {len(candidate_blocks)} total candidate block(s) with {len(keys_to_test)} single-byte XOR key(s).")

    for location_desc, data_block in candidate_blocks:
        for key in keys_to_test:
            decrypted_data = _xor_bytes(data_block, bytes([key]))
            
            # --- BUG FIX ---
            # The config isn't always at the start. Search for the pattern within the block.
            config_offset = decrypted_data.find(validation_bytes)
            
            if config_offset != -1:
                await ctx.info(f"Validation pattern found in '{location_desc}' with key 0x{key:02x} at offset 0x{config_offset:x}.")
                
                # Parse the config starting from the found offset.
                found_config = _parse_config_from_profile(decrypted_data[config_offset:], profile)
                
                if found_config:
                    return {
                        "status": "success",
                        "profile_name": "DynamicProfile",
                        "discovery_metadata": {
                            "found_in": location_desc,
                            "block_offset_of_config": f"0x{config_offset:x}",
                            "decryption_key_hex": f"{key:02x}"
                        },
                        "decoded_config": found_config
                    }
                else:
                     await ctx.warning(f"Validation pattern matched but failed to parse structure in '{location_desc}' with key 0x{key:02x}.")

    return {"status": "not_found", "message": "Scanned all candidate blocks but no matching configuration was found."}

@tool_decorator
async def get_current_datetime(ctx: Context) -> Dict[str,str]:
    """
    Retrieves the current date and time in UTC and the server's local timezone.
    This tool does not depend on a PE file being loaded.

    Args:
        ctx: The MCP Context object.

    Returns:
        A dictionary containing:
        - "utc_datetime": (str) Current UTC date and time in ISO 8601 format.
        - "local_datetime": (str) Current local date and time in ISO 8601 format (includes timezone offset).
        - "local_timezone_name": (str) Name of the server's local timezone.
    """
    await ctx.info("Request for current datetime.")
    now_utc=datetime.datetime.now(datetime.timezone.utc);now_local=datetime.datetime.now().astimezone()
    return{"utc_datetime":now_utc.isoformat(),"local_datetime":now_local.isoformat(),"local_timezone_name":str(now_local.tzinfo)}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Comprehensive PE File Analyzer.",formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("--input-file", type=str, required=True, help="REQUIRED: Path to the PE file to be analyzed at server startup (for MCP mode) or for CLI analysis.")
    parser.add_argument("-d", "--db", dest="peid_db", default=None, help=f"Path to PEiD userdb.txt. If not specified, defaults to '{DEFAULT_PEID_DB_PATH}'. Downloads if not found.")
    parser.add_argument("-y", "--yara-rules", dest="yara_rules", default=None, help="Path to YARA rule file or directory.")
    parser.add_argument("--capa-rules-dir", default=None, help=f"Directory containing capa rule files. If not provided or empty/invalid, attempts download to '{SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME / CAPA_RULES_SUBDIR_NAME}'.")
    parser.add_argument("--capa-sigs-dir", default=None, help="Directory containing capa library identification signature files (e.g., sigs/*.sig). Optional. If not provided, attempts to find a script-relative 'capa_sigs' or uses Capa's internal default.")
    
    parser.add_argument("--skip-capa", action="store_true", help="Skip capa capability analysis entirely.")
    parser.add_argument("--skip-floss", action="store_true", help="Skip FLOSS advanced string analysis entirely.")
    parser.add_argument("--skip-peid", action="store_true", help="Skip PEiD signature scanning entirely.")
    parser.add_argument("--skip-yara", action="store_true", help="Skip YARA scanning entirely.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output for CLI mode and more detailed MCP logging.")
    
    peid_group = parser.add_argument_group('PEiD Specific Options (if PEiD scan is not skipped)')
    peid_group.add_argument("--skip-full-peid-scan",action="store_true",help="Skip full PEiD scan (only scan entry point).")
    peid_group.add_argument("--psah","--peid-scan-all-sigs-heuristically",action="store_true",dest="peid_scan_all_sigs_heuristically",help="During full heuristic PEiD scan, use ALL signatures (not just non-EP_only).")

    floss_group = parser.add_argument_group('FLOSS Specific Options (if FLOSS scan is not skipped)')
    floss_group.add_argument("--floss-min-length", "-n", type=int, default=None, 
                             help=f"Minimum string length for FLOSS (default: {FLOSS_MIN_LENGTH_DEFAULT}).")
    floss_group.add_argument("--floss-format", "-f", default="auto", choices=["auto", "pe", "sc32", "sc64"],
                             help="File format hint for FLOSS/Vivisect (auto, pe, sc32, sc64). Default: auto.")
    floss_group.add_argument("--floss-no-static", action="store_true", help="FLOSS: Do not extract static strings.")
    floss_group.add_argument("--floss-no-stack", action="store_true", help="FLOSS: Do not extract stack strings.")
    floss_group.add_argument("--floss-no-tight", action="store_true", help="FLOSS: Do not extract tight strings.")
    floss_group.add_argument("--floss-no-decoded", action="store_true", help="FLOSS: Do not extract decoded strings.")
    floss_group.add_argument("--floss-only-static", action="store_true", help="FLOSS: Only extract static strings.")
    floss_group.add_argument("--floss-only-stack", action="store_true", help="FLOSS: Only extract stack strings.")
    floss_group.add_argument("--floss-only-tight", action="store_true", help="FLOSS: Only extract tight strings.")
    floss_group.add_argument("--floss-only-decoded", action="store_true", help="FLOSS: Only extract decoded strings.")
    floss_group.add_argument("--floss-functions", type=str, nargs="+", default=[], 
                             help="FLOSS: Hex addresses (e.g., 0x401000) of functions to analyze for stack/decoded strings.")
    floss_group.add_argument("--floss-verbose-level", "--fv",type=int, default=0, choices=[0,1,2],
                             help="FLOSS internal verbosity for string output (0=default, 1=verbose, 2=more verbose). Default: 0.")
    floss_group.add_argument("--floss-quiet", "--fq", action="store_true",
                             help="FLOSS: Suppress FLOSS's own progress indicators. Overrides script verbosity for FLOSS progress bars.")
    floss_group.add_argument("--floss-script-debug-level", default="NONE", 
                             choices=["NONE", "DEFAULT", "DEBUG", "TRACE", "SUPERTRACE"], 
                             help="Set logging level for FLOSS internal loggers (NONE, DEFAULT, TRACE, SUPERTRACE). Default: NONE.")
    floss_group.add_argument(
        "-r", "--regex",
        dest="regex_pattern",
        type=str,
        default=None,
        help="A regex pattern to search for within all extracted FLOSS strings (case-insensitive)."
    )

    cli_group=parser.add_argument_group('CLI Mode Specific Options (ignored if --mcp-server is used)')
    cli_group.add_argument("--extract-strings",action="store_true",help="Extract and print strings from the PE file (basic method, use FLOSS for advanced).")
    cli_group.add_argument("--min-str-len",type=int,default=5,help="Minimum length for basic extracted strings (default: 5).")
    cli_group.add_argument("--search-string",action="append",help="String to search for within the PE file (multiple allowed, basic method).")
    cli_group.add_argument("--strings-limit",type=int,default=100,help="Limit for basic string extraction and search results display (default: 100).")
    cli_group.add_argument("--hexdump-offset",type=lambda x:int(x,0),help="Hex dump start offset (e.g., 0x1000 or 4096).")
    cli_group.add_argument("--hexdump-length",type=int,help="Hex dump length in bytes.")
    cli_group.add_argument("--hexdump-lines",type=int,default=16,help="Maximum number of lines to display for hex dump (default: 16).")

    mcp_group=parser.add_argument_group('MCP Server Mode Specific Options')
    mcp_group.add_argument("--mcp-server",action="store_true",help="Run in MCP server mode. The --input-file is pre-analyzed, and tools operate on this file.")
    mcp_group.add_argument("--mcp-host",type=str,default="127.0.0.1",help="MCP server host (default: 127.0.0.1).")
    mcp_group.add_argument("--mcp-port",type=int,default=8082,help="MCP server port (default: 8082).") 
    mcp_group.add_argument("--mcp-transport",type=str,default="stdio",choices=["stdio","sse"],help="MCP transport protocol (default: stdio).")
    
    args = None
    try:
        args = parser.parse_args()
    except SystemExit as e:
        # Argparse calls sys.exit on errors like -h or invalid arguments.
        # We want to allow this to happen naturally.
        sys.exit(e.code) 
    except Exception as e_parse: # Should ideally not be reached if argparse handles its exits.
        print(f"[!] Exception during argument parsing: {type(e_parse).__name__} - {e_parse}", file=sys.stderr)
        sys.exit(1) 

    if args is None: # Should also not be reached if argparse exits on error.
        print("[!] Args is None after parsing attempt, exiting.", file=sys.stderr)
        sys.exit(1)
 
    check_and_install_dependencies(args.mcp_server)

    # Configure logging level based on verbosity AFTER args are parsed
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger.setLevel(log_level)
    logging.getLogger('mcp').setLevel(log_level) 
    if args.mcp_transport == 'sse': 
        logging.getLogger('uvicorn').setLevel(log_level)
        logging.getLogger('uvicorn.error').setLevel(log_level)
        logging.getLogger('uvicorn.access').setLevel(logging.WARNING if not args.verbose else logging.DEBUG)

    abs_input_file = str(Path(args.input_file).resolve())
    abs_peid_db_path = str(Path(args.peid_db).resolve()) if args.peid_db else str(DEFAULT_PEID_DB_PATH)
    abs_yara_rules_path = str(Path(args.yara_rules).resolve()) if args.yara_rules else None
    abs_capa_rules_dir_arg = str(Path(args.capa_rules_dir).resolve()) if args.capa_rules_dir else None
    abs_capa_sigs_dir_arg = str(Path(args.capa_sigs_dir).resolve()) if args.capa_sigs_dir else None

    analyses_to_skip_arg_list = []
    if args.skip_capa: analyses_to_skip_arg_list.append("capa")
    if args.skip_floss: analyses_to_skip_arg_list.append("floss")
    if args.skip_peid: analyses_to_skip_arg_list.append("peid")
    if args.skip_yara: analyses_to_skip_arg_list.append("yara")
    if analyses_to_skip_arg_list:
        logger.info(f"User requested to skip the following analyses via command line: {', '.join(analyses_to_skip_arg_list)}")

    floss_min_len_resolved = args.floss_min_length if args.floss_min_length is not None else FLOSS_MIN_LENGTH_DEFAULT
    
    floss_debug_level_map = {
        "NONE": Actual_DebugLevel_Floss.NONE, "DEFAULT": Actual_DebugLevel_Floss.DEFAULT,
        "DEBUG": Actual_DebugLevel_Floss.DEFAULT, 
        "TRACE": Actual_DebugLevel_Floss.TRACE, "SUPERTRACE": Actual_DebugLevel_Floss.SUPERTRACE
    }
    floss_script_debug_level_enum_val_resolved = floss_debug_level_map.get(args.floss_script_debug_level.upper(), Actual_DebugLevel_Floss.NONE)

    if args.verbose and floss_script_debug_level_enum_val_resolved == Actual_DebugLevel_Floss.NONE:
        floss_script_debug_level_enum_val_resolved = Actual_DebugLevel_Floss.TRACE 
        logger.info(f"Main script verbose (-v) is active, elevating FLOSS script debug level for its loggers to TRACE for detailed FLOSS logs.")


    floss_disabled_types_resolved = []
    if args.floss_no_static: floss_disabled_types_resolved.append(Actual_StringType_Floss.STATIC)
    if args.floss_no_stack: floss_disabled_types_resolved.append(Actual_StringType_Floss.STACK)
    if args.floss_no_tight: floss_disabled_types_resolved.append(Actual_StringType_Floss.TIGHT)
    if args.floss_no_decoded: floss_disabled_types_resolved.append(Actual_StringType_Floss.DECODED)

    floss_only_types_resolved = []
    if args.floss_only_static: floss_only_types_resolved.append(Actual_StringType_Floss.STATIC)
    if args.floss_only_stack: floss_only_types_resolved.append(Actual_StringType_Floss.STACK)
    if args.floss_only_tight: floss_only_types_resolved.append(Actual_StringType_Floss.TIGHT)
    if args.floss_only_decoded: floss_only_types_resolved.append(Actual_StringType_Floss.DECODED)

    floss_functions_to_analyze_resolved = []
    if args.floss_functions:
        for func_str in args.floss_functions:
            try: floss_functions_to_analyze_resolved.append(int(func_str, 0)) 
            except ValueError: logger.warning(f"Invalid FLOSS function address '{func_str}' in --floss-functions, skipping.")
    
    floss_quiet_resolved = args.floss_quiet or (not args.verbose and args.mcp_server and not (floss_script_debug_level_enum_val_resolved > Actual_DebugLevel_Floss.NONE) )

    if args.mcp_server:
        if not MCP_SDK_AVAILABLE:
            logger.critical("MCP SDK ('modelcontextprotocol') not available. Cannot start MCP server. Please install it (e.g., 'pip install \"mcp[cli]\"') and re-run.");
            sys.exit(1)

        logger.info(f"MCP Server: Pre-loading and analyzing PE file: {abs_input_file}")
        logger.info("The MCP server will become available once this initial analysis is complete.")
        try:
            if not os.path.exists(abs_input_file):
                logger.critical(f"Input PE file for MCP server not found: {abs_input_file}")
                sys.exit(1)
            if not os.path.isfile(abs_input_file):
                logger.critical(f"Input path for MCP server is not a file: {abs_input_file}")
                sys.exit(1)

            temp_pe_obj_for_preload = pefile.PE(abs_input_file, fast_load=False)
            ANALYZED_PE_FILE_PATH = abs_input_file

            ANALYZED_PE_DATA = _parse_pe_to_dict(
                temp_pe_obj_for_preload, abs_input_file, abs_peid_db_path, abs_yara_rules_path,
                abs_capa_rules_dir_arg,
                abs_capa_sigs_dir_arg,
                args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically,
                floss_min_len_arg=floss_min_len_resolved,
                floss_verbose_level_arg=args.floss_verbose_level,
                floss_script_debug_level_arg=floss_script_debug_level_enum_val_resolved,
                floss_format_hint_arg=args.floss_format,
                floss_disabled_types_arg=floss_disabled_types_resolved,
                floss_only_types_arg=floss_only_types_resolved,
                floss_functions_to_analyze_arg=floss_functions_to_analyze_resolved,
                floss_quiet_mode_arg=floss_quiet_resolved,
                analyses_to_skip=analyses_to_skip_arg_list 
            )
            PE_OBJECT_FOR_MCP = temp_pe_obj_for_preload 
            logger.info(f"MCP: Successfully pre-loaded and analyzed: {abs_input_file}. Server is ready.")

        except Exception as e:
            logger.critical(f"MCP: Failed to pre-load/analyze PE file '{abs_input_file}': {str(e)}", exc_info=True) 
            if 'temp_pe_obj_for_preload' in locals() and temp_pe_obj_for_preload: 
                temp_pe_obj_for_preload.close()
            ANALYZED_PE_FILE_PATH = None 
            ANALYZED_PE_DATA = None
            PE_OBJECT_FOR_MCP = None
            logger.error("MCP server will not start due to pre-load analysis failure.")
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
            logger.info("MCP Server stopped by user (KeyboardInterrupt).")
        except Exception as e:
            logger.critical(f"MCP Server encountered an unhandled error: {str(e)}", exc_info=True)
            server_exc=e
        finally:
            if PE_OBJECT_FOR_MCP: 
                PE_OBJECT_FOR_MCP.close()
                logger.info("MCP: Closed pre-loaded PE object upon server exit.")
            sys.exit(1 if server_exc else 0) 

    else: # CLI Mode
        cli_capa_rules_to_use = abs_capa_rules_dir_arg
        if "capa" not in analyses_to_skip_arg_list and CAPA_AVAILABLE: 
            if not cli_capa_rules_to_use or not os.path.isdir(cli_capa_rules_to_use) or not os.listdir(cli_capa_rules_to_use):
                logger.info(f"CLI Mode: Capa rules dir '{cli_capa_rules_to_use if cli_capa_rules_to_use else 'not specified'}' is invalid or empty. Attempting download to script-relative default.")
                default_capa_base_cli = str(SCRIPT_DIR / CAPA_RULES_DEFAULT_DIR_NAME)
                cli_capa_rules_to_use = ensure_capa_rules_exist(default_capa_base_cli, CAPA_RULES_ZIP_URL, args.verbose)
                if not cli_capa_rules_to_use:
                    logger.error("CLI Mode: Failed to ensure capa rules. Capa analysis will be skipped or may fail if attempted.")
                else:
                    logger.info(f"CLI Mode: Using capa rules from: {cli_capa_rules_to_use}")
        elif "capa" in analyses_to_skip_arg_list:
             logger.info("CLI Mode: Capa analysis is skipped by user, not attempting to load rules.")
             cli_capa_rules_to_use = None 
        elif not CAPA_AVAILABLE:
             logger.warning("CLI Mode: Capa library not available, capa rule download/check skipped.")
             cli_capa_rules_to_use = None

        try:
            _cli_analyze_and_print_pe(
                abs_input_file, abs_peid_db_path, abs_yara_rules_path,
                cli_capa_rules_to_use, 
                abs_capa_sigs_dir_arg,
                args.verbose, args.skip_full_peid_scan, args.peid_scan_all_sigs_heuristically,
                # FLOSS CLI args
                floss_min_len_cli=floss_min_len_resolved,
                floss_verbose_level_cli=args.floss_verbose_level,
                floss_script_debug_level_cli=floss_script_debug_level_enum_val_resolved,
                floss_format_hint_cli=args.floss_format,
                floss_disabled_types_cli=floss_disabled_types_resolved,
                floss_only_types_cli=floss_only_types_resolved,
                floss_functions_to_analyze_cli=floss_functions_to_analyze_resolved,
                floss_quiet_mode_cli=floss_quiet_resolved,
                # General CLI args
                extract_strings_cli=args.extract_strings, 
                min_str_len_cli=args.min_str_len, 
                search_strings_cli=args.search_string, 
                strings_limit_cli=args.strings_limit,
                hexdump_offset_cli=args.hexdump_offset, 
                hexdump_length_cli=args.hexdump_length, 
                hexdump_lines_cli=args.hexdump_lines,
                analyses_to_skip_cli_arg=analyses_to_skip_arg_list 
            )
        except KeyboardInterrupt:
            safe_print("\n[*] CLI Analysis interrupted by user. Exiting.")
            sys.exit(1) 
        except Exception as e_cli_main:
            safe_print(f"\n[!] An critical unexpected error occurred during CLI analysis: {type(e_cli_main).__name__} - {e_cli_main}")
            logger.critical("Critical unexpected error in CLI main execution", exc_info=True)
            sys.exit(1) 

    sys.exit(0)
